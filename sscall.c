/* See LICENSE file for copyright and license details */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/time.h>
#include <time.h>
#include <stdint.h>

#include <ao/ao.h>
#include <pthread.h>
#include <speex/speex.h>

#include "list.h"

/* Input/Output PCM buffer size */
#define PCM_BUF_SIZE (8000)
/* Input/Output compressed buffer size */
#define COMPRESSED_BUF_SIZE (640)
/* Sleep at least 50ms between each sendto() call */
#define UDELAY_SEND (50 * 1000)

/* Command line option, bits per sample */
static int fbits;
/* Command line option, samples per second (in a single channel) */
static int frate;
/* Command line option, number of channels */
static int fchan;
/* Command line option, device driver ID */
static int fdevid;
/* Command line option, verbosity flag */
static int fverbose;

/* Libspeex state */
void *speex_enc_state;
void *speex_dec_state;
/* Desired frame size, queried at run-time */
static int speex_frame_size;
/* Libao handle */
static ao_device *device;
/* Output PCM thread */
static pthread_t output_pcm_thread;
/* Input PCM thread */
static pthread_t input_pcm_thread;

/* Shared buf between do_output_pcm()
 * and output_pcm thread */
struct pcm_buf {
	/* PCM buffer */
	char *buf;
	/* PCM buffer size */
	size_t len;
	struct list_head list;
} pcm_buf;

/* Private structure for the
 * input_pcm thread */
struct inp_pcm_priv {
	/* Input file descriptor */
	int fd;
	/* Client socket */
	int sockfd;
	/* Client address info */
	struct addrinfo *servinfo;
} inp_pcm_priv;

/* Lock that protects pcm_buf */
static pthread_mutex_t pcm_buf_lock;
/* Condition variable on which ao_play() blocks */
static pthread_cond_t tx_pcm_cond;

/* State of the output_pcm thread */
struct output_pcm_state {
	int quit;
} output_pcm_state;

/* State of the input_pcm thread */
struct input_pcm_state {
	int quit;
} input_pcm_state;

/* Lock that protects output_pcm_state */
static pthread_mutex_t output_pcm_state_lock;
/* Lock that protects input_pcm_state */
static pthread_mutex_t input_pcm_state_lock;

/* Set to 1 when SIGINT is received */
static volatile int handle_sigint;

/* Play back audio from the client */
static void *
output_pcm(void *data)
{
	struct pcm_buf *pctx;
	struct list_head *iter, *q;
	struct output_pcm_state *state = data;
	struct timespec ts;
	struct timeval tp;
	int rc;
	SpeexBits bits;
	short *out;
	uint8_t *frame_len;
	char *p;

	speex_bits_init(&bits);
	do {
		pthread_mutex_lock(&pcm_buf_lock);
		gettimeofday(&tp, NULL);
		/* Convert from timeval to timespec */
		ts.tv_sec = tp.tv_sec;
		ts.tv_nsec = tp.tv_usec * 1000;
		/* Default to a 3 second wait internal */
		ts.tv_sec += 3;

		if (list_empty(&pcm_buf.list)) {
			/* Wait in the worst case 3 seconds to give some
			 * grace to perform cleanup if necessary */
			rc = pthread_cond_timedwait(&tx_pcm_cond,
						    &pcm_buf_lock,
						    &ts);
			if (rc == ETIMEDOUT)
				if (fverbose)
					printf("Output thread is starving...\n");
		}

		pthread_mutex_lock(&output_pcm_state_lock);
		if (state->quit) {
			pthread_mutex_unlock(&output_pcm_state_lock);
			pthread_mutex_unlock(&pcm_buf_lock);
			break;
		}
		pthread_mutex_unlock(&output_pcm_state_lock);

		out = malloc(speex_frame_size * sizeof(*out));
		if (!out)
			err(1, "malloc");

		/* Dequeue, decode and play buffers via libao */
		list_for_each_safe(iter, q, &pcm_buf.list) {
			pctx = list_entry(iter, struct pcm_buf,
					  list);
			p = pctx->buf;
			while (1) {
				frame_len = (uint8_t *)p;
				if (!*frame_len) {
					warnx("Invalid frame length: %hhu\n",
					      *frame_len);
					break;
				}
				if (p + 1 + *frame_len >
				    pctx->buf + pctx->len - 1)
					break;
				p++;
				speex_bits_reset(&bits);
				/* Copy the data into the bit-stream format */
				speex_bits_read_from(&bits, p,
						     *frame_len);
				p += *frame_len;
				/* Ensure output buffer is zero-filled */
				memset(out, 0,
				       speex_frame_size * sizeof(*out));
				/* Decode it */
				speex_decode_int(speex_dec_state, &bits,
						 out);
				/* Play it! */
				ao_play(device, (char *)out,
					speex_frame_size * sizeof(*out));
				/* Each frame is approximately 20ms */
				usleep(20);
			}
			free(pctx->buf);
			list_del(&pctx->list);
			free(pctx);
		}
		free(out);
		pthread_mutex_unlock(&pcm_buf_lock);
	} while (1);

	pthread_exit(NULL);

	return NULL;
}

/* Prepare for output PCM, enqueue buffer
 * and signal output_pcm thread */
static void
do_output_pcm(const void *buf, size_t len)
{
	struct pcm_buf *pctx;

	pctx = malloc(sizeof(*pctx));
	if (!pctx)
		err(1, "malloc");
	memset(pctx, 0, sizeof(*pctx));

	pctx->buf = malloc(len);
	if (!pctx->buf)
		err(1, "malloc");

	pctx->len = len;
	memcpy(pctx->buf, buf, len);

	pthread_mutex_lock(&pcm_buf_lock);
	INIT_LIST_HEAD(&pctx->list);
	list_add_tail(&pctx->list, &pcm_buf.list);
	pthread_cond_signal(&tx_pcm_cond);
	pthread_mutex_unlock(&pcm_buf_lock);
}

/* Input PCM thread, outbound path */
static void *
input_pcm(void *data)
{
	struct input_pcm_state *state = data;
	SpeexBits bits;
	char inbuf[PCM_BUF_SIZE];
	char outbuf[COMPRESSED_BUF_SIZE];
	ssize_t inbytes;
	size_t outbytes;
	char *p, *q;
	short *in;
	int nr_frames;
	/* Expected number of bytes for compressed frame */
	int out_expected;
	uint8_t *frame_len;
	ssize_t i;
	ssize_t ret;

	speex_bits_init(&bits);
	do {
		pthread_mutex_lock(&input_pcm_state_lock);
		if (state->quit) {
			pthread_mutex_unlock(&input_pcm_state_lock);
			break;
		}
		pthread_mutex_unlock(&input_pcm_state_lock);

		inbytes = read(inp_pcm_priv.fd, inbuf, sizeof(inbuf));
		if (inbytes > 0) {
			outbytes = 0;
			/* Fixed to 16 bits for now */
			nr_frames = (inbytes / 2) / speex_frame_size;
			/* Allocate buffer for Speex processing */
			in = malloc(speex_frame_size * sizeof(*in));
			if (!in)
				err(1, "malloc");

			p = outbuf;
			q = inbuf;
			for (i = 0; i < nr_frames; i++) {
				/* Reset the bit-stream struct */
				speex_bits_reset(&bits);
				/* Copy in PCM into input buffer for Speex
				 * to process it */
				memcpy(in, q, speex_frame_size * sizeof(*in));
				q += speex_frame_size * sizeof(*in);
				/* Encode the input stream */
				speex_encode_int(speex_enc_state, in, &bits);
				/* Fetch the size of the compressed frame */
				out_expected = speex_bits_nbytes(&bits);
				if (p + out_expected + 1 >
				    &outbuf[sizeof(outbuf) - 1])
					break;
				frame_len = (uint8_t *)p;
				/* Pre-append the size of the frame */
				*frame_len = out_expected;
				p++;
				outbytes++;
				/* Fill up the buffer with the encoded stream */
				speex_bits_write(&bits, p,
						 out_expected);
				p += out_expected;
				outbytes += out_expected;
				if (q >= &inbuf[inbytes - 1])
					break;
			}
			free(in);

			ret = sendto(inp_pcm_priv.sockfd, outbuf,
				     outbytes, 0,
				     inp_pcm_priv.servinfo->ai_addr,
				     inp_pcm_priv.servinfo->ai_addrlen);
			if (ret < 0)
				warn("sendto");
			usleep(UDELAY_SEND);
		}
	} while (1);

	pthread_exit(NULL);

	return NULL;
}

static void
usage(const char *s)
{
	fprintf(stderr,
		"usage: %s [OPTIONS] <remote-addr> <remote-port> <local-port>\n", s);
	fprintf(stderr, " -b\tBits per sample\n");
	fprintf(stderr, " -r\tSamples per second (in a single channel)\n");
	fprintf(stderr, " -c\tNumber of channels\n");
	fprintf(stderr, " -d\tOverride default driver ID\n");
	fprintf(stderr, " -v\tEnable verbose output\n");
	fprintf(stderr, " -h\tThis help screen\n");
}

static void
sig_handler(int signum)
{
	switch (signum) {
	case SIGINT:
		handle_sigint = 1;
		break;
	default:
		break;
	}
}

void
set_nonblocking(int fd)
{
	int opts;

	opts = fcntl(fd, F_GETFL);
	if (opts < 0)
		err(1, "fcntl");
	opts = (opts | O_NONBLOCK);
	if (fcntl(fd, F_SETFL, opts) < 0)
		err(1, "fcntl");
}

static void
init_libao(int rate, int bits, int chans,
	   int *devid)
{
	ao_sample_format format;
	int default_driver;

	ao_initialize();

	default_driver = ao_default_driver_id();

	memset(&format, 0, sizeof(format));
	format.bits = bits;
	format.channels = chans;
	format.rate = rate;
	format.byte_format = AO_FMT_LITTLE;

	if (!*devid)
		*devid = default_driver;

	device = ao_open_live(*devid, &format, NULL);
	if (!device)
		errx(1, "Error opening output device: %d\n",
		     fdevid);
}

static void
init_speex(void)
{
	int tmp;

	/* Create a new encoder/decoder state in narrowband mode */
	speex_enc_state = speex_encoder_init(&speex_nb_mode);
	speex_dec_state = speex_decoder_init(&speex_nb_mode);
	/* Set the quality to 8 (15 kbps), we should make
	 * this configurable in the future */
	tmp = 8;
	speex_encoder_ctl(speex_enc_state, SPEEX_SET_QUALITY, &tmp);
	/* Set the perceptual enhancement on */
	tmp = 1;
	speex_decoder_ctl(speex_dec_state, SPEEX_SET_ENH, &tmp);
	/* Retrieve the preferred frame size */
	speex_encoder_ctl(speex_enc_state, SPEEX_GET_FRAME_SIZE,
			  &speex_frame_size);
}

int
main(int argc, char *argv[])
{
	int recfd = STDIN_FILENO;
	ssize_t bytes;
	char buf[PCM_BUF_SIZE];
	int cli_sockfd, srv_sockfd;
	struct addrinfo cli_hints, *cli_servinfo, *p0, *p1;
	struct addrinfo srv_hints, *srv_servinfo;
	int rv;
	int ret;
	socklen_t addr_len;
	struct sockaddr_storage their_addr;
	char *prog;
	int c;
	char host[NI_MAXHOST];
	int optval;

	prog = *argv;
	while ((c = getopt(argc, argv, "hb:c:r:d:v")) != -1) {
		switch (c) {
		case 'h':
			usage(prog);
			exit(0);
			break;
		case 'b':
			fbits = strtol(optarg, NULL, 10);
			break;
		case 'c':
			fchan = strtol(optarg, NULL, 10);
			break;
		case 'r':
			frate = strtol(optarg, NULL, 10);
			break;
		case 'd':
			fdevid = strtol(optarg, NULL, 10);
			break;
		case 'v':
			fverbose = 1;
			break;
		case '?':
		default:
			exit(1);
		}
	}
	argc -= optind;
	argv += optind;

	if (argc != 3) {
		usage(prog);
		exit(1);
	}

	if (!fbits)
		fbits = 16;

	if (!fchan)
		fchan = 1;

	if (!frate)
		frate = 8000;

	init_libao(frate, fbits, fchan, &fdevid);
	init_speex();

	if (fverbose) {
		printf("Bits per sample: %d\n", fbits);
		printf("Number of channels: %d\n", fchan);
		printf("Sample rate: %d\n", frate);
		printf("Default driver ID: %d\n", fdevid);
		fflush(stdout);
	}

	memset(&cli_hints, 0, sizeof(cli_hints));
	cli_hints.ai_family = AF_INET;
	cli_hints.ai_socktype = SOCK_DGRAM;

	rv = getaddrinfo(argv[0], argv[1], &cli_hints, &cli_servinfo);
	if (rv)
		errx(1, "getaddrinfo: %s", gai_strerror(rv));

	for (p0 = cli_servinfo; p0; p0 = p0->ai_next) {
		cli_sockfd = socket(p0->ai_family, p0->ai_socktype,
				    p0->ai_protocol);
		if (cli_sockfd < 0)
			continue;
		break;
	}

	if (!p0)
		errx(1, "failed to bind socket");

	memset(&srv_hints, 0, sizeof(srv_hints));
	srv_hints.ai_family = AF_INET;
	srv_hints.ai_socktype = SOCK_DGRAM;
	srv_hints.ai_flags = AI_PASSIVE;

	rv = getaddrinfo(NULL, argv[2], &srv_hints, &srv_servinfo);
	if (rv)
		errx(1, "getaddrinfo: %s", gai_strerror(rv));

	for(p1 = srv_servinfo; p1; p1 = p1->ai_next) {
		srv_sockfd = socket(p1->ai_family, p1->ai_socktype,
				    p1->ai_protocol);
		if (srv_sockfd < 0)
			continue;
		optval = 1;
		ret = setsockopt(srv_sockfd, SOL_SOCKET,
				 SO_REUSEADDR, &optval, sizeof(optval));
		if (ret < 0) {
			close(srv_sockfd);
			warn("setsockopt");
			continue;
		}
		if (bind(srv_sockfd, p1->ai_addr, p1->ai_addrlen) < 0) {
			close(srv_sockfd);
			warn("bind");
			continue;
		}
		break;
	}

	if (!p1)
		errx(1, "failed to bind socket");

	INIT_LIST_HEAD(&pcm_buf.list);

	pthread_mutex_init(&pcm_buf_lock, NULL);
	pthread_cond_init(&tx_pcm_cond, NULL);

	pthread_mutex_init(&output_pcm_state_lock, NULL);
	pthread_mutex_init(&input_pcm_state_lock, NULL);

	ret = pthread_create(&output_pcm_thread, NULL,
			     output_pcm, &output_pcm_state);
	if (ret < 0)
		err(1, "pthread_create");

	inp_pcm_priv.fd = recfd;
	inp_pcm_priv.sockfd = cli_sockfd;
	inp_pcm_priv.servinfo = p0;

	set_nonblocking(inp_pcm_priv.fd);

	ret = pthread_create(&input_pcm_thread, NULL,
			     input_pcm, &input_pcm_state);
	if (ret < 0)
		err(1, "pthread_create");

	if (signal(SIGINT, sig_handler) == SIG_ERR)
		err(1, "signal");

	/* Receive audio data from other end and prepare
	 * for playback */
	do {
		/* Handle SIGINT gracefully */
		if (handle_sigint) {
			if (fverbose)
				printf("Interrupted, exiting...\n");
			break;
		}

		addr_len = sizeof(their_addr);
		bytes = recvfrom(srv_sockfd, buf,
				 sizeof(buf), MSG_DONTWAIT,
				 (struct sockaddr *)&their_addr,
				 &addr_len);
		if (bytes > 0) {
			if (fverbose) {
				ret = getnameinfo((struct sockaddr *)&their_addr,
						  addr_len, host,
						  sizeof(host), NULL, 0, 0);
				if (ret < 0) {
					warn("getnameinfo");
					snprintf(host, sizeof(host), "unknown");
				}
				printf("Received %zd bytes from %s\n",
				       bytes, host);
			}
			do_output_pcm(buf, bytes);
		}
	} while (1);

	/* Prepare input thread to be killed */
	pthread_mutex_lock(&input_pcm_state_lock);
	input_pcm_state.quit = 1;
	pthread_mutex_unlock(&input_pcm_state_lock);

	/* Wait for it */
	pthread_join(input_pcm_thread, NULL);

	/* Prepare output thread to be killed */
	pthread_mutex_lock(&output_pcm_state_lock);
	output_pcm_state.quit = 1;
	pthread_mutex_unlock(&output_pcm_state_lock);

	/* Wake up the output thread if it is
	 * sleeping */
	pthread_mutex_lock(&pcm_buf_lock);
	pthread_cond_signal(&tx_pcm_cond);
	pthread_mutex_unlock(&pcm_buf_lock);

	/* Wait for it */
	pthread_join(output_pcm_thread, NULL);

	ao_close(device);
	ao_shutdown();

	freeaddrinfo(cli_servinfo);
	freeaddrinfo(srv_servinfo);

	return EXIT_SUCCESS;
}
