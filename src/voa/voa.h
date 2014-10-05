#ifndef VOA_H

#ifdef RTP
#define AUDIO_CAPS "application/x-rtp,media=(string)audio,payload=(int)96,clock-rate=(int)48000,encoding-name=(string)X-GST-OPUS-DRAFT-SPITTKA-00"
#else
#define AUDIO_CAPS "audio/x-opus,media=(string)audio,clockrate=(int)48000,channels=(int)1"
#endif /* RTP */

#define ALLNET_VOA_HMAC_SIZE 32
#define ALLNET_VOA_COUNTER_SIZE 32

struct allnet_voa_header {
  char msg_type;
};

enum allnet_voa_msg_type {
  ALLNET_VOA_HANDSHAKE,
  ALLNET_VOA_DATA
};

struct allnet_voa_header_handshake {
  char msg_hmac[ALLNET_VOA_HMAC_SIZE];
  char msg_counter[ALLNET_VOA_COUNTER_SIZE];
};

struct allnet_voa_header_data {
};

#endif /* VOA_H */
