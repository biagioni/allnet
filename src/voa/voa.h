#ifndef VOA_H

#ifdef RTP
#define AUDIO_CAPS "application/x-rtp,media=(string)audio,payload=(int)96,clock-rate=(int)48000,encoding-name=(string)X-GST-OPUS-DRAFT-SPITTKA-00"
#else
#define AUDIO_CAPS "audio/x-opus,media=(string)audio,clockrate=(int)48000,channels=(int)1"
#endif /* RTP */

/*  { 'V', 'O', 'A', '\0' } */
#define ALLNET_MEDIA_APP_VOA 0x564F4100
#define ALLNET_VOA_HANDSHAKE_SYN 0x564F4153
#define ALLNET_VOA_HANDSHAKE_ACK 0x564F4141
#define ALLNET_VOA_EOS_BUF "VOA-EOS"
#define ALLNET_VOA_HMAC_SIZE 6
#define ALLNET_VOA_COUNTER_SIZE 2
#define ALLNET_VOA_NUM_MEDIA_TYPE_SIZE 2

/**
 * Struct used when initiating a handshake
 * The actual data is extended beyond the header when num_media_types > 1
 */
struct allnet_voa_hs_syn_header {
  char enc_key [ALLNET_STREAM_KEY_SIZE];
  char enc_secret [ALLNET_STREAM_SECRET_SIZE];
  char stream_id [STREAM_ID_SIZE];
  /* indicates the number n of media_type entries. Minimum 1 required.
   * n-1 are thus following the header! Big-endian encoded */
  char num_media_types [ALLNET_VOA_NUM_MEDIA_TYPE_SIZE];
  char media_type [ALLNET_MEDIA_ID_SIZE];
};

/** header used when accepting a handshake */
struct allnet_voa_hs_ack_header {
  char stream_id [STREAM_ID_SIZE];
  char media_type [ALLNET_MEDIA_ID_SIZE];
};

#endif /* VOA_H */
