/* Copyright (C) 2002 Jean-Marc Valin */
#ifndef _SPEEX_JITTER_BUFFER_H
#define _SPEEX_JITTER_BUFFER_H

typedef struct SpeexJitter {
	/* Current Speex packet */
	SpeexBits current_packet;
	/* True if Speex bits are valid */
	int valid_bits;
	/* Generic jitter buffer state */
	JitterBuffer *packets;
	/* Pointer to Speex decoder */
	void *dec;
	/* Frame sizeo f Speex decoder */
	spx_int32_t frame_size;
} SpeexJitter;

extern void speex_jitter_init(SpeexJitter *jitter, void *decoder);
extern void speex_jitter_destroy(SpeexJitter *jitter);
extern void speex_jitter_put(SpeexJitter *jitter, void *packet, int len, int timestamp);
extern void speex_jitter_get(SpeexJitter *jitter, spx_int16_t *out, int *start_offset);
extern int speex_jitter_get_pointer_timestamp(SpeexJitter *jitter);

#endif
