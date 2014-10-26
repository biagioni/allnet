/* Copyright (c) 2014 Andreas Brauchli <andreasb@hawaii.edu>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <assert.h>
#include <stdio.h>
#include <glib.h>         /* g_*, ... */
#include <gst/gst.h>
#include <gst/app/gstappsrc.h>
#include <gst/app/gstappsink.h>
#include <stdlib.h>       /* atoi */
#include <string.h>       /* memcmp, memcpy */
#include <sys/time.h>     /* gettimeofday */

#include "lib/app_util.h" /* connect_to_local */
#include "lib/cipher.h"   /* allnet_encrypt, allnet_sign, allnet_verify */
#include "lib/crypt_sel.h"/* allnet_rsa_prvkey, allnet_rsa_pubkey */
#include "lib/keys.h"     /* struct bc_key_info, get_other_keys */
#include "lib/media.h"    /* ALLNET_MEDIA_AUDIO_OPUS */
#include "lib/packet.h"
#include "lib/pipemsg.h"  /* send_pipe_message */
#include "lib/priority.h"
#include "lib/stream.h"   /* allnet_stream_* */
#include "lib/util.h"     /* create_packet, random_bytes, add_us, delta_us */

#include "voa.h"

// TODO: remove
#define DEBUG 0

typedef struct _DecoderData {
  GstElement * voa_source; /* Voice-over-allnet source */
#ifdef RTP
  GstElement * jitterbuffer;
  GstElement * rtpdepay;
#endif /* RTP */
  GstElement * decoder;
  GstElement * sink; /* playback device */
  int stream_id_set;
} DecoderData;

typedef struct _EncoderData {
  GstElement * source; /* recording device */
  GstElement * convert;
  GstElement * resample;
  GstElement * encoder;
#ifdef RTP
  GstElement * rtp;
#endif /* RTP */
  GstElement * voa_sink; /* Voice-over-allnet sink */
} EncoderData;

typedef struct _VOAData {
  GstElement * pipeline;
  GstBus * bus;
  int is_encoder;
  int accept_unsigned;
  int allnet_socket;
  int my_addr_bits;
  int dest_addr_bits;
  unsigned char my_address [ADDRESS_SIZE];
  unsigned char dest_address [ADDRESS_SIZE];
  unsigned char stream_id [STREAM_ID_SIZE];
  unsigned long media_type;
  const char * dest_contact;
  struct allnet_stream_encryption_state enc_state;
  union {
    EncoderData enc;
    DecoderData dec;
  };
} VOAData;

static VOAData data;
/** exit main loop when set, -1 indicates an error */
static int term = 0;

/**
 * Initialize the global data struct
 * my_address and dest_address are zeroed out
 */
static void init_data ()
{
  data.accept_unsigned = 1;
  data.dest_contact = NULL;
  data.my_addr_bits = 0;
  data.dest_addr_bits = 0;
  /* set any unused address parts to all zeros */
  bzero (data.my_address, ADDRESS_SIZE);
  bzero (data.dest_address, ADDRESS_SIZE);
}

/**
 * Inject buffers into the audio system pipeline
 * @param buf buffer to be injected
 * @param bufsize size of buf
 * @return 1 on success, 0 on error
 */
static int dec_handle_data (const char * buf, int bufsize)
{
  gchar * buffer = g_new (gchar, bufsize);
  memcpy (buffer, buf, bufsize);
  GstFlowReturn ret;

#if DEBUG > 1
  printf ("read %d bytes\n", bufsize);
#endif /* DEBUG */
  if (bufsize == 0)
    return 1;

  GstBuffer * gstbuf = gst_buffer_new_wrapped (buffer, bufsize);

  /* Push the buffer into the appsrc */
  g_signal_emit_by_name (data.dec.voa_source, "push-buffer", gstbuf, &ret);
#ifdef RTP
  GValue val = G_VALUE_INIT;
  g_value_init (&val, G_TYPE_INT);
  g_object_get_property (G_OBJECT (data.dec.jitterbuffer), "percent", &val);
  gint percent = g_value_get_int (&val);
  printf ("Jitterbuffer %d\n", percent);
#endif /* RTP */
  gst_buffer_unref (gstbuf);
  if (ret != GST_FLOW_OK) {
    fprintf (stderr, "error inserting packets into gst pipeline\n");
    return 0; /* We got some error, stop sending data */
  }
  GstState st, pst;
  gst_element_get_state (data.pipeline, &st, &pst, 0);
#if DEBUG > 1
  printf ("state: %d, pending: %d\n", st, pst);
#endif /* DEBUG */
  if (st != GST_STATE_PLAYING && pst != GST_STATE_PLAYING && pst != GST_STATE_PLAYING)
    gst_element_set_state (data.pipeline, GST_STATE_PLAYING);

  return 1;
}

static void get_key_for_contact (const char * contact,
                                 allnet_rsa_prvkey * prvkey,
                                 allnet_rsa_pubkey * pubkey)
{
  /* method mostly copy-pasted from xchat/xcommon.c */
  /* get the keys */
  keyset * keys;
  int nkeys = all_keys ((char *)contact, &keys);
  if (nkeys <= 0) {
    printf ("unable to locate key for contact %s (%d)\n", contact, nkeys);
    return;
  }

/*
  If there are multiple keys, we could check if one matches this address and
  use that
      unsigned char address [ADDRESS_SIZE];
      int na_bits = get_remote (keysets [ink], address);
      if (matches (addr, addr_bits, (const unsigned char *)address, na_bits) > 0)
*/
  if (prvkey != NULL)
    get_my_privkey (keys [0], prvkey);
  if (pubkey != NULL)
    get_contact_pubkey (keys [0], pubkey);
}

/**
 * Initialize the stream cipher
 * @param [in,out] key ptr to ALLNET_STREAM_KEY_SIZE bytes for the stream key
 * @param [in,out] secret ptr to ALLNET_STREAM_SECRET_SIZE bytes for the hmac
 * @param is_encoder when 0 the stream cipher is initialized with the passed
                     key and secret. Otherwise the initialized values are
                     written into key and secret.
 */
static void stream_cipher_init (char * key, char * secret, int is_encoder)
{
  allnet_stream_init (&data.enc_state, key, is_encoder, secret, is_encoder,
                      ALLNET_VOA_COUNTER_SIZE, ALLNET_VOA_HMAC_SIZE);
#ifdef DEBUG
  int i;
  printf ("stream key: ");
  for (i = 0; i < ALLNET_STREAM_KEY_SIZE; ++i)
    printf ("%02x ", (unsigned char) key [i]);
  printf ("\nstream sec: ");
  for (i = 0; i < ALLNET_STREAM_SECRET_SIZE; ++i)
    printf ("%02x ", (unsigned char) secret [i]);
  printf ("\n");
#endif /* DEBUG */
}

/**
 * Check if contact's signature on a message is valid
 * @param payload start of signed part of the message
 * @param vsize size of playload block to verify
 * @param sig start of signature block
 * @param ssize size of signature block
 * @param contact name of contact to verify against.
 * @param [in,out] prvkey Set to private key corresponding to signature when
 *                        not NULL and verification is successful.
 * @return 1 if message signature is valid,
 *         0 if message signature is invalid or missing
 */
static int check_contact_signature (const char * payload, int vsize,
                                    const char * sig, int ssize,
                                    const char * contact,
                                    allnet_rsa_prvkey * prvkey)
{
  keyset * keysets;
  int nk = all_keys (contact, &keysets);
  int ink;
  for (ink = 0; ink < nk; ink++) {
    allnet_rsa_pubkey pubkey;
    get_contact_pubkey (keysets [ink], &pubkey);
    if (allnet_verify (payload, vsize, sig, ssize, pubkey)) {
      if (prvkey != NULL)
        get_my_privkey (keysets [ink], prvkey);
      return 1;
    }
  }
  return 0;
}

/**
 * Check if the signature on a message is valid
 * @param hp message to check
 * @param payload start of signed part of the message
 * @param msize total size of message
 * @param contact name of contact to verify against. All contacts when NULL.
 * @param [in,out] prvkey Set to private key corresponding to signature when
 *                        not NULL and verification is successful.
 * @return length of signature block, including signature length, if message
 *         signature is valid or 0 if message signature is invalid or missing.
 */
static int check_signature (const struct allnet_header * hp,
                            const char * payload, int msize,
                            const char * contact,
                            allnet_rsa_prvkey * prvkey)
{
  int psize = msize - (payload - ((const char *)hp));
  int vsize = psize;
  int ssize = 0;
  const char * sig = NULL;
  #define SIG_LENGTH_SIZE 2
  if ((psize > SIG_LENGTH_SIZE) && (hp->sig_algo == ALLNET_SIGTYPE_RSA_PKCS1)) {
/* RSA_PKCS1 is the only type of signature supported for now */
    ssize = readb16 (payload + (psize - SIG_LENGTH_SIZE));
    if (ssize + SIG_LENGTH_SIZE < psize) {
      sig = payload + (psize - ssize - SIG_LENGTH_SIZE);
      vsize -= ssize + SIG_LENGTH_SIZE;
    }
  }
  assert (vsize > 0);

  if (sig == NULL)  /* ignore */
    return 0;

  if (contact == NULL) {
    /* ..try all contact's keys */
    char ** contacts;
    int nc = all_contacts (&contacts);
    int ic;
    for (ic = 0; ic < nc; ic++) {
      int valid = check_contact_signature (payload, vsize, sig, ssize,
                                           contacts [ic], prvkey);
      if (valid) {
        printf ("voa: message signed by %s\n", contacts [ic]);
        return ssize + SIG_LENGTH_SIZE;
      }
    }

  } else {
    if (check_contact_signature (payload, vsize, sig, ssize, contact, prvkey))
      return ssize + SIG_LENGTH_SIZE;
  }
  return 0;
}

/**
 * Check whether to accept an incomming stream request (decoder)
 * When accepted, sets data.stream_id, data.dest_address and initializes the
 * stream cipher.
 * @param hp incoming message
 * @param payload pointer to the struct app_media_header within the message
 * @param msize total message size
 * @param [out] prvkey the private key for signing the accept response
 * @return 0 if stream is to be rejected, 1 otherwise
 */
static int accept_stream (const struct allnet_header * hp,
                          const char * payload, int msize,
                          allnet_rsa_prvkey * prvkey)
{
  /* verify signature */
  int sigsize;
  if (!(sigsize = check_signature (hp, payload, msize, data.dest_contact, prvkey))) {
    if (data.dest_contact == NULL)
      fprintf (stderr, "voa: WARNING: invalid or unsigned request\n");
    else
      printf ("voa: received request from unexpected party, discarding\n");
    return 0;
  }

  /* decrypt */
  payload += sizeof (struct allnet_app_media_header);
  int ciphersize = msize - (payload - (const char *)hp) - sigsize;
  char * decbuf;
  int bufsize = allnet_decrypt (payload, ciphersize, *prvkey, &decbuf);
  if (bufsize == 0) {
    fprintf (stderr, "voa: couldn't decrypt request\n");
    return 0;
  }
  assert (bufsize >= sizeof (struct allnet_voa_hs_syn_header));

  const struct allnet_voa_hs_syn_header * avhhp =
      (const struct allnet_voa_hs_syn_header *)decbuf;

  int ret = 0;
  unsigned int nmt = readb16u ((const unsigned char *)(&avhhp->num_media_types));
  if (nmt < 1)
    return 0;
  unsigned long media_type;
  const unsigned char * mtp;
  for (mtp = (const unsigned char *)(&avhhp->media_type);
       /* &array jumps by sizeof(array) */
       (mtp < ((const unsigned char *)(&avhhp->media_type + nmt))) &&
       (mtp < (const unsigned char *)decbuf + bufsize);
       mtp += sizeof (avhhp->media_type)) {
    media_type = readb32u (mtp);
    if (media_type == ALLNET_MEDIA_AUDIO_OPUS)
      break;
    else
      media_type = 0;
  }
  if (!media_type) {
    printf ("voa: Unsupported media type requested, can't accept stream\n");
    goto accept_cleanup;
  }

  /* accepted stream, initialize stream cipher and sender address */
  memcpy (data.stream_id, avhhp->stream_id, STREAM_ID_SIZE);
  data.media_type = media_type;
#ifdef DEBUG
  printf ("stream id: ");
  int i;
  for (i=0; i < STREAM_ID_SIZE; ++i)
    printf ("%02x ", data.stream_id[i]);
  printf ("\n");
#endif /* DEBUG */
  data.dec.stream_id_set = 1;
  stream_cipher_init ((char *)avhhp->enc_key, (char *)avhhp->enc_secret, 0);
  memcpy (data.dest_address, hp->source, ADDRESS_SIZE);
  data.dest_addr_bits = hp->src_nbits;
  ret = 1;
accept_cleanup:
  free (decbuf);
  return ret;
}

/** Send an acceptance to a received stream request (decoder) */
static int send_accept_response (allnet_rsa_prvkey prvkey)
{
  unsigned int amhpsize = sizeof (struct allnet_app_media_header);
  unsigned int avhhsize = sizeof (struct allnet_voa_hs_ack_header);
  int estsigsize = allnet_rsa_prvkey_size (prvkey) + 2;
  int bufsize = amhpsize + avhhsize + estsigsize;
  int pak_size;
  struct allnet_header * pak = create_packet (bufsize,
       ALLNET_TYPE_DATA, 3 /*max hops*/, ALLNET_SIGTYPE_RSA_PKCS1,
       data.my_address, data.my_addr_bits,
       data.dest_address, data.dest_addr_bits, NULL /*stream*/, NULL /*ack*/,
       &pak_size);
  unsigned int ahsize = ALLNET_SIZE_HEADER (pak);

  /* allnet app media headers */
  struct allnet_app_media_header * amhp =
      (struct allnet_app_media_header *) ((char *)pak + ahsize);
  writeb32u ((unsigned char *)(&amhp->app), ALLNET_MEDIA_APP_VOA);
  writeb32u ((unsigned char *)(&amhp->media), ALLNET_VOA_HANDSHAKE_ACK);

  /* voa ACK header */
  struct allnet_voa_hs_ack_header * avhh =
      (struct allnet_voa_hs_ack_header *)((char *)amhp + amhpsize);
  memcpy (&avhh->stream_id, data.stream_id, STREAM_ID_SIZE);
  writeb32u ((unsigned char *)&avhh->media_type, data.media_type);

  /* sign response (app media header + stream_id) */
  char * sig;
  int sigsize = allnet_sign ((char *)amhp, amhpsize + avhhsize, prvkey, &sig);
  assert (sigsize + 2 == estsigsize);
  if (sigsize == 0) {
    fprintf (stderr, "voa: WARNING could not sign outgoing acceptance response\n");
    ((struct allnet_header *)pak)->sig_algo = ALLNET_SIGTYPE_NONE;
  } else {
    memcpy ((char *)avhh + avhhsize, sig, sigsize);
    free (sig);
    assert (ahsize + amhpsize + avhhsize + sigsize + 2 == pak_size);
  }

  if (!send_pipe_message (data.allnet_socket, (const char *)pak, pak_size, ALLNET_PRIORITY_DEFAULT)) {
    fprintf (stderr, "voa: error sending stream accept\n");
    return 0;
  }
  return 1;
}

/**
 * Checks an incoming stream ACK for validity:
 * - is it a reply to a request we sent
 * - is the signature valid
 * @param hp mesage beginning
 * @param payload pointer to struct app_media_header part after header
 * @param msize total raw message size
 */
static int check_voa_reply (const struct allnet_header * hp,
                            const char * payload, int msize)
{
  unsigned int amhsize = sizeof (struct allnet_app_media_header);
  /* check for matching stream id */
  const struct allnet_voa_hs_ack_header * avhhp =
      (const struct allnet_voa_hs_ack_header *)(payload + amhsize);
  if (memcmp (data.stream_id, &avhhp->stream_id, STREAM_ID_SIZE) != 0) {
    printf ("voa: discarding reply for unknown stream ");
    int i = 0;
    for (; i < STREAM_ID_SIZE; ++i)
      printf ("%02x ", *((unsigned char *)payload + amhsize + i));
    printf ("\n");
    return 0;
  }
  /* check for matching media type */
  int mt = readb32u ((const unsigned char *)&avhhp->media_type);
  if (mt != ALLNET_MEDIA_AUDIO_OPUS) {
    printf ("voa: Unsupported media type requested, can't start streaming\n");
    return 0;
  }
  data.media_type = mt;

  /* verify media header + stream_id sig */
  if (!check_signature (hp, payload, msize, data.dest_contact, NULL)) {
    fprintf (stderr, "voa: WARNING: unsigned response\n");
    if (!data.accept_unsigned)
      return 0;
  }
  return 1;
}

/**
 * Handle any incoming packets and filter relevant ones
 * @param message pointer to struct allnet_header
 * @param msize total size of message
 * @param reply_only only process VoA ACK messages when reply_only != 0 (for encoder)
 * @return 1 packet was handled successfully (encoder: stream was accepted),
 *         0 packet is discarded (encoder: or not accepted)
 *        -1 an error happened while processing an expected packet
 *           like failure to decrypt a packet
 */
static int handle_packet (const char * message, int msize, int reply_only)
{
  if (! is_valid_message (message, msize)) {
    printf ("got invalid message of size %d\n", msize);
    return 0;
  }
  const struct allnet_header * hp = (const struct allnet_header *) message;
  int hsize = ALLNET_SIZE_HEADER (hp);
  int amhsize = sizeof (struct allnet_app_media_header);
  int headersizes = hsize + (data.dec.stream_id_set ? 0 : amhsize);
#if DEBUG > 1
  printf ("voa: got message of size %d (%d data)\n", msize, msize - headersizes);
#endif /* DEBUG */

  if (msize <= headersizes)
    return 0;
  if (hp->message_type != ALLNET_TYPE_DATA)
    return 0;
  if (matches (hp->destination, hp->dst_nbits, data.my_address, data.my_addr_bits) == 0)
    return 0;

#if DEBUG > 2
  const struct allnet_header * pak = (const struct allnet_header *)message;
  printf ("-\n");
  int i=0;
  for (; i < ALLNET_SIZE_HEADER(pak); ++i)
    printf ("%02x ", *((const unsigned char *)pak+i));
  printf (".\n");
  for (; i-ALLNET_SIZE_HEADER(pak) < sizeof(struct allnet_app_media_header); ++i)
    printf ("%02x ", *((const unsigned char *)pak+i));
  printf (".\n");
  for (; i < msize-514; ++i)
    printf ("%02x ", *((const unsigned char *)pak+i));
  printf (".\n");
  for (; i < msize; ++i)
    printf ("%02x ", *((const unsigned char *)pak+i));
  printf ("\n\n");
#endif /* DEBUG */

  const char * payload = (const char *)message + hsize;
  if (!reply_only && data.dec.stream_id_set) {
    char * streamp = ALLNET_STREAM_ID (hp, hp->transport, msize);
    if (streamp == NULL)
      return 0;
    if (memcmp (data.stream_id, streamp, STREAM_ID_SIZE) != 0) {
      printf ("discarding packet from unknown stream\n");
      return 0;
    }

  } else {
    const struct allnet_app_media_header * amhp =
      (const struct allnet_app_media_header *) payload;
    if (readb32u ((const unsigned char *)(&amhp->app)) != ALLNET_MEDIA_APP_VOA)
      return 0;
    unsigned int hs = readb32u ((const unsigned char *)(&amhp->media));
    if (reply_only) {
      if (hs == ALLNET_VOA_HANDSHAKE_ACK)
        return check_voa_reply (hp, payload, msize);
      return 0;
    }
    if (hs != ALLNET_VOA_HANDSHAKE_SYN)
      return 0;

    /* new stream, check if we're interested */
    allnet_rsa_prvkey prvkey;
    if (accept_stream (hp, payload, msize, &prvkey))
      return send_accept_response (prvkey);
    return 0;
  }

  /* valid packet: stream packet candidate */
  int encbufsize = msize - headersizes;
  int bufsize = encbufsize - ALLNET_VOA_HMAC_SIZE - ALLNET_VOA_COUNTER_SIZE;
  char buf [bufsize];
  if (!allnet_stream_decrypt_buffer (&data.enc_state, payload,
                                     encbufsize, buf, sizeof (buf)))
    return -1;
#if DEBUG > 1
  static int c=0;
  static int s=0;
  printf ("%d\n", c);
  ++c;
  s += encbufsize;
  printf ("raw audio (%d, %d so far):\n", bufsize, s);
  int i;
  for (i=0; i < bufsize; ++i)
    printf ("%02x ", *((const unsigned char *)buf+i));
  printf (".\n");
#endif /* DEBUG */
  assert (buf[0] == 0x08); /* Narrow band 20ms VBR opus frame */
  if (!dec_handle_data (buf, bufsize))
    return -1;
  return 1;
}

/**
 * Create a VoA handshake packet
 * @param key key that will be used to encrypt the stream packets
 * @param secret secret that will be used to sign the stream packets
 * @param stream_id stream_id that will be used to identify the stream
 * @param [out] size of the returned packet
 * @return created message
 */
static struct allnet_header * create_voa_hs_packet (const char * key,
                                                    const char * secret,
                                                    const char * stream_id,
                                                    int * paksize)
{
  unsigned int num_media_types = 1;
  unsigned int amhpsize = sizeof (struct allnet_app_media_header);
  unsigned int avhhsize = sizeof (struct allnet_voa_hs_syn_header) +
                          ((num_media_types - 1) * ALLNET_MEDIA_ID_SIZE);
  allnet_rsa_prvkey prvkey = NULL;
  allnet_rsa_pubkey pubkey = NULL;
  get_key_for_contact (data.dest_contact, &prvkey, &pubkey);
  int bufsize = amhpsize;
  if (prvkey != NULL)
    bufsize += allnet_rsa_prvkey_size (prvkey) + 2; /* space for signature */
  if (pubkey == NULL) {
    fprintf (stderr, "voa: failed to get public key for %s\n", data.dest_contact);
    return NULL;
  }

  /* voa handshake header */
  struct allnet_voa_hs_syn_header avhh;
  memcpy (&avhh.enc_key, key, ALLNET_STREAM_KEY_SIZE);
  memcpy (&avhh.enc_secret, secret, ALLNET_STREAM_SECRET_SIZE);
  memcpy (&avhh.stream_id, stream_id, STREAM_ID_SIZE);
  writeb16u ((unsigned char *)(&avhh.num_media_types), num_media_types);
  writeb32u ((unsigned char *)(&avhh.media_type + 0), ALLNET_MEDIA_AUDIO_OPUS);
  char * encbuf;
  int encbufsize = allnet_encrypt ((void *)&avhh, avhhsize, pubkey, &encbuf);
  if (encbufsize == 0) {
    fprintf (stderr, "voa: error encrypting handshake\n");
    return NULL;
  }
  bufsize += encbufsize;

  /* create packet */
  struct allnet_header * pak = create_packet (bufsize,
       ALLNET_TYPE_DATA, 3 /*max hops*/, ALLNET_SIGTYPE_RSA_PKCS1,
       data.my_address, data.my_addr_bits,
       data.dest_address, data.dest_addr_bits, NULL /*stream*/, NULL /*ack*/,
       paksize);
  unsigned int ahsize = ALLNET_SIZE_HEADER (pak);

  /* allnet media headers */
  struct allnet_app_media_header * amhp =
      (struct allnet_app_media_header *) ((char *)pak + ahsize);
  writeb32u ((unsigned char *)(&amhp->app), ALLNET_MEDIA_APP_VOA);
  writeb32u ((unsigned char *)(&amhp->media), ALLNET_VOA_HANDSHAKE_SYN);

  /* copy hs header into packet */
  void * enc_payload = ((void *)amhp) + amhpsize;
  memcpy (enc_payload, encbuf, encbufsize);
  free (encbuf);

  /* sign media+hs headers */
  int sigsize = 0;
  if (prvkey != NULL) {
    char * sig_payload = (char *)amhp;
    int sig_psize = amhpsize + encbufsize;
    char * sig;
    sigsize = allnet_sign (sig_payload, sig_psize, prvkey, &sig);
    if (sigsize != 0) {
      memcpy (enc_payload + encbufsize, sig, sigsize);
      free (sig);
      assert (ahsize + sig_psize + sigsize == *paksize -2); /* last 2 bytes */
      writeb16 (sig_payload + sig_psize + sigsize, sigsize);
    }
  }
  if (sigsize == 0) {
    printf ("voa: ERROR: could not sign request\n");
    return NULL;
  }

  assert (ahsize + amhpsize + encbufsize + sigsize + 2 == *paksize);
  return pak;
}

/**
 * Receive and handle allnet messages in a loop until global term is set
 * @param timeout timeout in ms. If timeout != 0, only listen until a stream was
 *                accepted or the timeout is reached (encoder)
 * @return 0 on error or term (or timeout reached when timeout is set),
 *         1 on success (only when timeout is set)
 */
static int voa_receive (int timeout)
{
  struct timeval now;
  struct timeval timeout_end;
  if (timeout) {
    gettimeofday (&now, NULL);
    timeout_end = now;
    add_us (&timeout_end, timeout * 1000ULL);
  } else {
    timeout = PIPE_MESSAGE_WAIT_FOREVER;
  }

  int ret = 0;
  while (!term) {
    int pipe;
    int priority;
    char * message;
    int size = receive_pipe_message_any (timeout, &message, &pipe, &priority);
    if (size > 0) {
      ret = handle_packet ((const char *)message, size, timeout != PIPE_MESSAGE_WAIT_FOREVER);
      free (message);
    }

    if (timeout != PIPE_MESSAGE_WAIT_FOREVER) {
      if (ret)
        return 1;
      gettimeofday (&now, NULL);
      if ((timeout = delta_us (&timeout_end, &now) / 1000ULL) == 0)
        return 0;
    }
    if (size < 0) {
      printf ("voa: pipe closed, exiting\n");
      return 0;
    }
  }
  return 0;
}

/**
 * Initiate VoA handshake by sending the request
 * The key and secret are chosen the first time the function is called
 * @return 1 on success, 0 on failure
 */
static int send_voa_request ()
{
  static int init_key = 1;
  static char key [ALLNET_STREAM_KEY_SIZE];
  static char secret [ALLNET_STREAM_SECRET_SIZE];
  if (init_key) {
    stream_cipher_init (key, secret, init_key);
    init_key = 0;
  }
  int paksize;
  struct allnet_header * pak = create_voa_hs_packet (key, secret,
      (const char *)data.stream_id, &paksize);
  if (pak == NULL) {
    fprintf (stderr, "voa: failed to create request packet");
    return 0;
  }
  if (!send_pipe_message (data.allnet_socket, (const char *)pak, paksize,
                          ALLNET_PRIORITY_DEFAULT)) {
    fprintf (stderr, "voa: error sending stream packet\n");
    return 0;
  }
  return 1;
}

/**
 * Creates a stream packet for an ongoing stream
 * The returned packet must be free'd by caller.
 * @param buf buffer to be sent (will be copied and encrypted)
 * @param buf bufsize size of buf
 * @param stream_id ptr to STREAM_ID_SIZE bytes
 * @param [out] paksize size of returned packet.
 */
static struct allnet_header * create_voa_stream_packet (
              const unsigned char * buf, int bufsize,
              const unsigned char * stream_id, int * paksize)
{
  unsigned int sigsize = ALLNET_VOA_COUNTER_SIZE + ALLNET_VOA_HMAC_SIZE;
  int psize = bufsize + sigsize;
  struct allnet_header * pak = create_packet (psize,
         ALLNET_TYPE_DATA, 3 /*max hops*/, ALLNET_SIGTYPE_NONE,
         data.my_address, data.my_addr_bits,
         data.dest_address, data.dest_addr_bits,
         stream_id, NULL /*ack*/, paksize);
  pak->transport |= ALLNET_TRANSPORT_DO_NOT_CACHE;

  /* fill data */
  char * payload = (char *)pak + ALLNET_SIZE_HEADER (pak);
  assert (psize == *paksize - (payload - (char *)pak));

#if DEBUG > 1
  printf ("raw audio (%db):\n", bufsize);
  int i=0;
  for (; i < bufsize; ++i)
    printf ("%02x ", *((const unsigned char *)buf+i));
  printf (".\n");
#endif /* DEBUG */

  /* encrypt and copy into packet */
  if (!allnet_stream_encrypt_buffer (&data.enc_state, (const char *)buf, bufsize, payload, psize))
    return NULL;

#if DEBUG > 2
  printf ("-\n");
  for (i=0; i < ALLNET_SIZE_HEADER(pak); ++i)
    printf ("%02x ", *((const unsigned char *)pak+i));
  printf (".\n");
  for (; i-ALLNET_SIZE_HEADER(pak) < bufsize; ++i)
    printf ("%02x ", *((const unsigned char *)pak+i));
  printf (".\n");
  for (; i < *paksize; ++i)
    printf ("%02x ", *((const unsigned char *)pak+i));
  printf ("\n\n");
#endif /* DEBUG */
  return pak;
}

/**
 * Callback on gstreamer bus events
 * Sets global term to -1 on error, to 0 on end of stream
 * @param bus GStreamer bus
 * @param msg GStreamer message
 * @param data VoA struct
 */
static void cb_message (GstBus * bus, GstMessage * msg, VOAData * data)
{
  switch (GST_MESSAGE_TYPE (msg)) {
    case GST_MESSAGE_ERROR: {
      GError * err;
      gchar * debug;

      gst_message_parse_error (msg, &err, &debug);
      fprintf (stderr, "Error: %s\n", err->message);
      g_error_free (err);
      g_free (debug);

      gst_element_set_state (data->pipeline, GST_STATE_READY);
      term = -1;
      break;
    }
    case GST_MESSAGE_EOS:
      /* end-of-stream */
      printf ("EOS Msg\n");
      gst_element_set_state (data->pipeline, GST_STATE_READY);
      term = 1;
      break;
    case GST_MESSAGE_BUFFERING: {
      /* CHECK: not sure we really need this, since live streams don't buffer */
      gint percent = 0;
      gst_message_parse_buffering (msg, &percent);
      printf ("Buffering (%3d%%)\r", percent);
      /* Wait until buffering is complete before start/resume playing */
      if (percent < 100)
        gst_element_set_state (data->pipeline, GST_STATE_PAUSED);
      else
        gst_element_set_state (data->pipeline, GST_STATE_PLAYING);
      break;
    }
    case GST_MESSAGE_CLOCK_LOST:
      /* Get a new clock */
      printf ("lost clock\n");
      gst_element_set_state (data->pipeline, GST_STATE_PAUSED);
      gst_element_set_state (data->pipeline, GST_STATE_PLAYING);
      break;
    default:
      /* Unhandled message */
      break;
  }
}

/**
 * Main loop for the encoder after the stream has been initialized.
 * Terminates when global term is set. Sets term = -1 on error.
 */
static void enc_main_loop ()
{
  /* poll samples (blocking) */
  GstAppSink * voa_sink = GST_APP_SINK (data.enc.voa_sink);
  while (!term && !gst_app_sink_is_eos (voa_sink)) {
    GstSample * sample = gst_app_sink_pull_sample (voa_sink);
    if (sample) {
      GstBuffer * buffer = gst_sample_get_buffer (sample);
      gsize bufsiz = gst_buffer_get_size (buffer);
#if DEBUG > 1
      printf ("voa: offset: %lu, duration: %lums, size: %lu\n", buffer->offset, (unsigned long)buffer->duration / 1000000, (size_t)bufsiz);
#endif /* DEBUG */
      GstMapInfo info;
      if (!gst_buffer_map (buffer, &info, GST_MAP_READ))
        printf ("voa: error mapping buffer\n");
      int pak_size;
      struct allnet_header * pak = create_voa_stream_packet (info.data, info.size, data.stream_id, &pak_size);
      if (pak) {
        if (!send_pipe_message (data.allnet_socket, (const char *)pak, pak_size, ALLNET_PRIORITY_DEFAULT_HIGH))
          fprintf (stderr, "voa: error sending stream packet\n");
#if DEBUG > 1
        printf ("voa: size: %d (%lu)\n", pak_size, info.size);
#endif /* DEBUG */
      } else {
        fprintf (stderr, "voa: failed to create packet");
        term = -1;
      }

      gst_buffer_unmap (buffer, &info);
      gst_sample_unref (sample);
    } else {
      printf ("NULL sample\n");
    }
  }
}

/**
 * Init the audio system.
 * Caller is responsible to call cleanup_audio () when done
 * @param is_encoder initialize for encoding if set, for decoding otherwise
 */
static int init_audio (int is_encoder)
{
  GstMessage * msg;
  GstStateChangeReturn ret;

  /* Initialize GStreamer */
  int argc = 0;
  char * argv[] = { "" };
  gst_init (&argc, (char ***)&argv);
  GstCaps * appcaps = gst_caps_from_string (AUDIO_CAPS);

  /* Create the empty pipeline */
  data.pipeline = gst_pipeline_new ("pipeline");
  if (!data.pipeline) {
    fprintf (stderr, "Couldn't create pipeline.\n");
    return 0;
  }

  /* Create the elements */
  if (is_encoder) {
    data.enc.source = gst_element_factory_make ("audiotestsrc", "source");
    //data.enc.source = gst_element_factory_make ("autoaudiosrc", "source");
    data.enc.convert = gst_element_factory_make ("audioconvert", "convert");
    data.enc.resample = gst_element_factory_make ("audioresample", "resample");
    data.enc.encoder = gst_element_factory_make ("opusenc", "encoder");
#ifdef RTP
    data.enc.rtp = gst_element_factory_make ("rtpopuspay", "rtp");
#endif /* RTP */
    data.enc.voa_sink = gst_element_factory_make ("appsink", "voa_sink");

    if (!data.enc.source || !data.enc.convert || !data.enc.resample ||
        !data.enc.encoder ||
#ifdef RTP
        !data.enc.rtp ||
#endif /* RTP */
        !data.enc.voa_sink) {
      fprintf (stderr, "Not all elements could be created.\n");
      return 0;
    }

    GstCaps * rawcaps = gst_caps_from_string ("audio/x-raw,clockrate=(int)48000,channels=(int)1");
    GstPad * srcpad = gst_element_get_static_pad (data.enc.source, "src");
    gst_pad_set_caps (srcpad, rawcaps);
    gst_caps_unref (rawcaps);

    /* Configure encoder appsink */
    // g_object_set (data.enc.voa_sink, /*"caps", appcaps,*/ NULL);

    /* Modify the source's properties */
    g_object_set (data.enc.encoder, "bandwidth", 1101, /* narrowband */
                                    "bitrate", 4000,
                                    "cbr", FALSE, /* constant bit rate */
                                    NULL);

    gst_bin_add_many (GST_BIN (data.pipeline), data.enc.source,
            data.enc.convert, data.enc.resample, data.enc.encoder,
#ifdef RTP
            data.enc.rtp,
#endif /* RTP */
           data.enc.voa_sink, NULL);

    if (! gst_element_link_many (data.enc.source,
            data.enc.convert, data.enc.resample, data.enc.encoder,
#ifdef RTP
            data.enc.rtp,
#endif /* RTP */
            data.enc.voa_sink, NULL)) {
      fprintf (stderr, "Elements could not be linked.\n");
      gst_object_unref (data.pipeline);
      return 0;
    }

  } else {
    /* decoder */
    bzero (data.stream_id, STREAM_ID_SIZE);
    data.dec.stream_id_set = 0;
    data.dec.voa_source = gst_element_factory_make ("appsrc", "voa_source");
#ifdef RTP
    data.dec.jitterbuffer = gst_element_factory_make ("rtpjitterbuffer", "jitterbuffer");
    data.dec.rtpdepay = gst_element_factory_make ("rtpopusdepay", "rtpdepay");
#endif /* RTP */
    data.dec.decoder = gst_element_factory_make ("opusdec", "decoder");
    if (!data.dec.decoder)
      fprintf (stderr, "Couldn't create opus decoder, make sure gstreamer1.0-plugins-bad is installed\n");
    data.dec.sink = gst_element_factory_make ("autoaudiosink", "sink");
    if (!data.dec.voa_source ||
#ifdef RTP
        !data.dec.jitterbuffer || !data.dec.rtpdepay ||
#endif /* RTP */
        !data.dec.decoder || !data.dec.sink) {
      fprintf (stderr, "Not all elements could be created.\n");
      return 0;
    }
    /* Configure decoder source */
    g_object_set (data.dec.voa_source,
      "stream-type", GST_APP_STREAM_TYPE_STREAM,
      "format", GST_FORMAT_TIME /*_BYTES?*/,
      "caps", appcaps,
      NULL);
#ifdef RTP
    g_object_set (data.dec.jitterbuffer, "latency", 100, "do-lost", TRUE, NULL); /* opus: 20ms of data per packet */
#endif /* RTP */
    g_object_set (data.dec.decoder, "plc", TRUE, NULL); /* packet loss concealment */
    /* play as soon as possible and continue playing after packet loss by
     * disabling sync */
    g_object_set (data.dec.sink, "sync", FALSE, NULL);

    gst_bin_add_many (GST_BIN (data.pipeline), data.dec.voa_source,
#ifdef RTP
            data.dec.jitterbuffer, data.dec.rtpdepay,
#endif /* RTP */
            data.dec.decoder,
            data.dec.sink, NULL);
    if (! gst_element_link_many (data.dec.voa_source,
#ifdef RTP
            data.dec.jitterbuffer, data.dec.rtpdepay,
#endif /* RTP */
            data.dec.decoder, data.dec.sink, NULL)) {
      fprintf (stderr, "Elements could not be linked.\n");
      gst_object_unref (data.pipeline);
      return 0;
    }
  }
  gst_caps_unref (appcaps);

  /* Wait until error or EOS */
  data.bus = gst_element_get_bus (data.pipeline);
  g_signal_connect (data.bus, "message", G_CALLBACK (cb_message), &data);

  /* Start playing the pipeline */
  ret = gst_element_set_state (data.pipeline, GST_STATE_PAUSED);
  if (ret == GST_STATE_CHANGE_FAILURE) {
    fprintf (stderr, "Unable to change pipeline state.\n");
    gst_object_unref (data.pipeline);
    return 0;
  }

  if (is_encoder)
    gst_element_set_state (data.pipeline, GST_STATE_PLAYING);
  return 1;
}

/** Cleanup function for audio system */
static void cleanup_audio ()
{
  /* Free resources */
  gst_object_unref (data.bus);
  gst_element_set_state (data.pipeline, GST_STATE_NULL);
  gst_object_unref (data.pipeline);
}

/**
 * Mask (zero) out unused parts of the last byte of addr.
 * @param addr ADDRESS_SIZE bytes of address with last unused whole bytes already zeroed out.
 * @param nbits number of relevant address bits
 */
static void mask_unused_addr_bits (unsigned char * addr, int nbits)
{
  int nbytes = (nbits >> 3) + 1;
  if (nbits % 8)
    /* signed shift */
    addr [nbytes-1] &= (unsigned char)(((char)0x80) >> ((nbits % 8) - 1));
  else if (nbytes < ADDRESS_SIZE)
    addr [nbytes-1] = 0;
}

int allnet_global_debugging = 0;
int main (int argc, char ** argv)
{
  if (argc == 2 && strcmp (argv [1], "-h") == 0) {
    printf ("usage: %s [-c contact] [dest-addr [dest-bits]]\n", argv [0]);
    return 0;
  }
  int socket = connect_to_local (argv [0], argv [0]);
  if (socket < 0) {
    fprintf (stderr, "Could not connect to AllNet\n");
    return 1;
  }
  init_data ();
  data.allnet_socket = socket;

  data.my_addr_bits = ADDRESS_BITS;
  int nbytes = (data.my_addr_bits >> 3) + 1;
  if (nbytes > ADDRESS_SIZE)
    nbytes = ADDRESS_SIZE;
  random_bytes ((char *)data.my_address, nbytes);
  mask_unused_addr_bits (data.my_address, data.my_addr_bits);
  if (argc > 1) {
    int a = 0;
    while (a < argc) {
      if (strcmp (argv [a], "-c") == 0) {
        if (++a < argc)
          data.dest_contact = argv [a];
        ++a;

      } else {
        nbytes = strnlen (argv [a], ADDRESS_SIZE);
        data.dest_addr_bits = 8 * nbytes;
        memcpy (data.dest_address, argv [a], nbytes);
        ++a;
        if (a < argc) {
          int b = atoi (argv [a]);
          data.dest_addr_bits = b > ADDRESS_BITS ? ADDRESS_BITS : b;
          mask_unused_addr_bits (data.dest_address, data.dest_addr_bits);
        }
      }
    }
  }

  int len = strlen (argv [0]);
  int is_encoder = (strcmp (argv [0] + len - 4, "voas") == 0);

  if (is_encoder && data.dest_contact == NULL) {
    fprintf (stderr, "Contact required\n");
    return 1;
  }

  printf ("is_encoder: %d\n", is_encoder);
  printf ("My address:   ");
  int i;
  for (i = 0; i < ADDRESS_SIZE; ++i)
    printf ("%02x ", data.my_address [i]);
  printf (" (%d bits)\n", data.my_addr_bits);
  if (data.dest_contact)
    printf ("Contact: %s\n", data.dest_contact);
  if (is_encoder) {
    printf ("Dest address: ");
    for (i = 0; i < ADDRESS_SIZE; ++i)
      printf ("%02x ", data.dest_address [i]);
    printf (" (%d bits)\n", data.dest_addr_bits);
  }

  if (!init_audio (is_encoder))
    return 1;

  if (is_encoder) {
    random_bytes ((char *)data.stream_id, STREAM_ID_SIZE);
    int i = 0;
    /* retry 10x every 2s */
    do {
      printf (".");
      fflush (stdout);
      if (send_voa_request () && voa_receive (2000)) {
        printf ("\n");
        enc_main_loop ();
      }
    } while (++i < 10);
  } else {
    voa_receive (0);
  }

  cleanup_audio ();
  if (term != 1)
    return term;
  return 0;
}

/* vim: set ts=2 sw=2 sts=2 et : */
