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

#include <ao/ao.h>
#include <pthread.h>

#include "list.h"

/* Input/Output PCM buffer size */
#define PCM_BUF_SIZE (8192)
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

/* Libao handle */
static ao_device *device;
/* Libao sample format, currently only 44.1kHz */
static ao_sample_format format;
/* Default driver ID */
static int default_driver;
/* Output PCM thread */
static pthread_t output_pcm_thread;
/* Input PCM thread */
static pthread_t input_pcm_thread;

struct pcm_buf {
	/* PCM buffer */
	void *buf;
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

/* Set to 1 when SIGINT is received */
static volatile int handle_sigint;

/* Play back audio from the client */
static void *
output_pcm(void *data __attribute__ ((unused)))
{
	struct pcm_buf *pctx;
	struct list_head *iter, *q;

	do {
		pthread_mutex_lock(&pcm_buf_lock);
		if (list_empty(&pcm_buf.list))
			pthread_cond_wait(&tx_pcm_cond,
					  &pcm_buf_lock);
		/* Dequeue and play buffers via libao */
		list_for_each_safe(iter, q, &pcm_buf.list) {
			pctx = list_entry(iter, struct pcm_buf,
					  list);
			ao_play(device, pctx->buf, pctx->len);
			free(pctx->buf);
			list_del(&pctx->list);
			free(pctx);
		}
		pthread_mutex_unlock(&pcm_buf_lock);
	} while (1);

	return NULL;
}

/* Prepare for output PCM, enqueue buffer
 * and signal output_pcm thread */
static void
do_output_pcm(const void *buf, size_t len)
{
	struct pcm_buf *pctx;

	pthread_mutex_lock(&pcm_buf_lock);
	pctx = malloc(sizeof(*pctx));
	if (!pctx)
		err(1, "malloc");
	memset(pctx, 0, sizeof(*pctx));
	pctx->buf = malloc(len);
	if (!pctx->buf)
		err(1, "malloc");
	pctx->len = len;
	memcpy(pctx->buf, buf, len);
	INIT_LIST_HEAD(&pctx->list);
	list_add_tail(&pctx->list, &pcm_buf.list);
	pthread_cond_signal(&tx_pcm_cond);
	pthread_mutex_unlock(&pcm_buf_lock);
}

/* Input PCM thread, outbound path */
static void *
input_pcm(void *data __attribute__ ((unused)))
{
	char buf[PCM_BUF_SIZE];
	ssize_t bytes;

	do {
		bytes = read(inp_pcm_priv.fd, buf, sizeof(buf));
		if (bytes > 0) {
			bytes = sendto(inp_pcm_priv.sockfd, buf,
				       bytes, 0,
				       inp_pcm_priv.servinfo->ai_addr,
				       inp_pcm_priv.servinfo->ai_addrlen);
			if (bytes < 0)
				warn("sendto");
			usleep(UDELAY_SEND);
		}
	} while (1);

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
	exit(EXIT_SUCCESS);
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

	if (signal(SIGINT, sig_handler) == SIG_ERR)
		err(1, "signal");

	prog = *argv;
	while ((c = getopt(argc, argv, "hb:c:r:d:v")) != -1) {
		switch (c) {
		case 'h':
			usage(prog);
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
			exit(EXIT_FAILURE);
		}
	}
	argc -= optind;
	argv += optind;

	if (argc != 3)
		usage(prog);

	ao_initialize();

	default_driver = ao_default_driver_id();

	memset(&format, 0, sizeof(format));

	if (!fbits)
		fbits = 16;

	if (!fchan)
		fchan = 1;

	if (!frate)
		frate = 8000;

	format.bits = fbits;
	format.channels = fchan;
	format.rate = frate;
	format.byte_format = AO_FMT_LITTLE;

	if (!fdevid)
		fdevid = default_driver;

	device = ao_open_live(fdevid, &format, NULL);
	if (!device)
		errx(1, "Error opening output device: %d\n",
		     fdevid);

	if (fverbose) {
		printf("Bits per sample: %d\n", fbits);
		printf("Number of channels: %d\n", fchan);
		printf("Sample rate: %d\n", frate);
		printf("Default driver ID: %d\n", default_driver);
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

	freeaddrinfo(cli_servinfo);

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
		if (bind(srv_sockfd, p1->ai_addr, p1->ai_addrlen) < 0) {
			close(srv_sockfd);
			warn("bind");
			continue;
		}
		break;
	}

	if (!p1)
		errx(1, "failed to bind socket");

	freeaddrinfo(srv_servinfo);

	INIT_LIST_HEAD(&pcm_buf.list);

	pthread_mutex_init(&pcm_buf_lock, NULL);
	pthread_cond_init(&tx_pcm_cond, NULL);

	ret = pthread_create(&output_pcm_thread, NULL,
			     output_pcm,
			     NULL);
	if (ret < 0)
		errx(1, "pthread_creapte failed: %d", ret);

	inp_pcm_priv.fd = recfd;
	inp_pcm_priv.sockfd = cli_sockfd;
	inp_pcm_priv.servinfo = p0;

	ret = pthread_create(&input_pcm_thread, NULL,
			     input_pcm,
			     NULL);
	if (ret < 0)
		errx(1, "pthread_create failed: %d", ret);

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
				if (ret < 0)
					warn("getnameinfo");
				printf("Received %ld bytes from %s\n",
				       bytes, host);
			}
			do_output_pcm(buf, bytes);
		}
	} while (1);

	ao_close(device);
	ao_shutdown();

	return EXIT_SUCCESS;
}
