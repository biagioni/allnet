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

#include <stdio.h>
#include <glib.h>         /* g_*, ... */
#include <gst/gst.h>
#include <gst/app/gstappsrc.h>
#include <gst/app/gstappsink.h>
#include <stdlib.h>       /* atoi */
#include <string.h>       /* memcpy */

#include "lib/app_util.h" /* connect_to_local */
#include "lib/cipher.h"   /* allnet_verify */
#include "lib/keys.h"     /* struct bc_key_info, get_other_keys */
#include "lib/media.h"    /* ALLNET_MEDIA_AUDIO_OPUS */
#include "lib/packet.h"
#include "lib/pipemsg.h"  /* send_pipe_message */
#include "lib/priority.h"
#include "lib/util.h"     /* create_packet, random_bytes */

#include "voa.h"

typedef struct _DecoderData {
  GstElement * voa_source; /* Voice-over-allnet source */
#ifdef RTP
  GstElement * jitterbuffer;
  GstElement * rtpdepay;
#endif /* RTP */
  GstElement * decoder;
  GstElement * sink; /* playback device */
  int sourceid;
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
  int is_encoder;
  int allnet_socket;
  unsigned char stream_id [STREAM_ID_SIZE];
  union {
    EncoderData enc;
    DecoderData dec;
  };
} VOAData;

static VOAData data;
static int term = 0; /* exit main loop when set */

static int dec_handle_data (const char * buf, int bufsize) {
  gchar * buffer = g_new (gchar, bufsize);
  memcpy (buffer, buf, bufsize);
  GstFlowReturn ret;

  printf ("read %d bytes\n", bufsize);
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
  printf ("state: %d, pending: %d\n", st, pst);
  if (st != GST_STATE_PLAYING && pst != GST_STATE_PLAYING && pst != GST_STATE_PLAYING)
    gst_element_set_state (data.pipeline, GST_STATE_PLAYING);

  return 1;
}

static int check_signature (const struct allnet_header * hp, const char * payload, int * msize) {
  int psize = *msize - (payload - ((const char *)hp));
  int vsize = 0; // TODO: size of block to verify
  int ssize = 0;
  const char * sig = NULL;
  #define SIG_LENGHT_SIZE 2
  if ((psize > SIG_LENGHT_SIZE) && (hp->sig_algo == ALLNET_SIGTYPE_RSA_PKCS1)) {
/* RSA_PKCS1 is the only type of signature supported for now */
    ssize = readb16 (payload + (psize - SIG_LENGHT_SIZE));
    if (ssize + SIG_LENGHT_SIZE < psize) {
      sig = payload + (psize - (ssize + SIG_LENGHT_SIZE));
      *msize -= ssize + SIG_LENGHT_SIZE;
      vsize -= ssize + SIG_LENGHT_SIZE;
    }
  }

  if (sig == NULL)  /* ignore */
    return 0;

  const char * from = NULL;
  struct bc_key_info * keys;
  int nkeys = get_other_keys (&keys);
  if ((nkeys > 0) && (ssize > 0) && (sig != NULL)) {
    int i;
    for (i = 0; i < nkeys; i++) {
      if (allnet_verify (payload, vsize, sig, ssize, keys [i].pub_key)) {
        from = keys [i].identifier;
        return 1;
      }
    }
  }
  return 0;
}

static int handle_packet (const char * message, int msize) {
/* TODO: remove DEBUG: print packets
  printf ("-\n");
  int i=0;
  for (; i < sizeof(struct allnet_header); ++i)
    printf ("%02x ", *((const unsigned char *)message+i));
  printf (".\n");
  for (; i-sizeof (struct allnet_header) < sizeof(struct allnet_app_media_header); ++i)
    printf ("%02x ", *((const unsigned char *)message+i));
  printf (".\n");
  for (; i-sizeof (struct allnet_header)-sizeof (struct allnet_app_media_header) < sizeof(struct allnet_voa_header); ++i)
    printf ("%02x ", *((const unsigned char *)message+i));
  printf (".\n");
  for (; i < msize; ++i)
    printf ("%02x ", *((const unsigned char *)message+i));
  printf ("\n\n");
*/
  int headersizes = sizeof (struct allnet_header) +
                    sizeof (struct allnet_app_media_header) +
                    sizeof (struct allnet_voa_header);
  printf ("got message of size %d (%d data)\n", msize, msize - headersizes);
  if (! is_valid_message (message, msize)) {
    printf ("got invalid message of size %d\n", msize);
    return 0;
  }
  const struct allnet_header * hp = (const struct allnet_header *) message;
  int hsize = ALLNET_SIZE_HEADER (hp);
  int amhsize = sizeof (struct allnet_app_media_header);
  int voahsize = sizeof (struct allnet_voa_header);
  if (msize <= headersizes)
    return 0;
  if (hp->message_type != ALLNET_TYPE_DATA)
    return 0;

  const char * payload = ((const char *)hp) + headersizes;
  check_signature (hp, payload, &msize);
  const struct allnet_app_media_header * amhp =
    (const struct allnet_app_media_header *) ((const char *)message + hsize);
  if (readb32u ((const unsigned char *)(&amhp->app)) != ALLNET_MEDIA_APP_VOA)
    return 0;
  if (readb32u ((const unsigned char *)(&amhp->media)) != ALLNET_MEDIA_AUDIO_OPUS) {
    printf ("voa: unsupported media type\n");
    return 0;
  }

  const struct allnet_voa_header * avhp =
    (const struct allnet_voa_header *) ((const char *)amhp + amhsize);

  /* handle valid packet */
  int bufsize = msize - headersizes;
  const char * buf = ((const char *)avhp) + voahsize;
  return dec_handle_data (buf, bufsize);
}

static struct allnet_header * create_voa_packet (
              const unsigned char * buf, int bufsize,
              const unsigned char * stream_id, int * paksize)
{
  unsigned int headersizes = sizeof (struct allnet_app_media_header) + sizeof (struct allnet_voa_header);
  struct allnet_header * pak = create_packet (bufsize + headersizes,
         ALLNET_TYPE_DATA, 3 /*max hops*/, ALLNET_SIGTYPE_HMAC_SHA512,
         NULL/*src addr*/, 0 /*src bits*/, NULL, 0 /*dst*/, stream_id, NULL /*ack*/, paksize);
  pak->transport = ALLNET_TRANSPORT_STREAM | ALLNET_TRANSPORT_DO_NOT_CACHE;

  /* allnet media headers */
  struct allnet_app_media_header * amhp =
      (struct allnet_app_media_header *) ((char *)pak + sizeof (struct allnet_header));
  writeb32u ((unsigned char *)(&amhp->app), ALLNET_MEDIA_APP_VOA);
  writeb32u ((unsigned char *)(&amhp->media), ALLNET_MEDIA_AUDIO_OPUS);

  /* allnet voa headers */
  struct allnet_voa_header * avhp =
      (struct allnet_voa_header *) ((char *)amhp + sizeof (struct allnet_app_media_header));

  /* fill data */
  memcpy ((void *)avhp + sizeof (struct allnet_voa_header), buf, bufsize);

  /* TODO: remove */
/* TODO: remove DEBUG: print packets
  printf ("-\n");
  int i=0;
  for (; i < sizeof(struct allnet_header); ++i)
    printf ("%02x ", *((const unsigned char *)pak+i));
  printf (".\n");
  for (; i-sizeof (struct allnet_header) < sizeof(struct allnet_app_media_header); ++i)
    printf ("%02x ", *((const unsigned char *)pak+i));
  printf (".\n");
  for (; i-sizeof (struct allnet_header)-sizeof (struct allnet_app_media_header) < sizeof(struct allnet_voa_header); ++i)
    printf ("%02x ", *((const unsigned char *)pak+i));
  printf (".\n");
  for (; i < *paksize; ++i)
    printf ("%02x ", *((const unsigned char *)pak+i));
  printf ("\n\n");
*/
  return pak;
}

static void cb_message (GstBus * bus, GstMessage * msg, VOAData * data) {

  switch (GST_MESSAGE_TYPE (msg)) {
    case GST_MESSAGE_ERROR: {
      GError * err;
      gchar * debug;

      gst_message_parse_error (msg, &err, &debug);
      fprintf (stderr, "Error: %s\n", err->message);
      g_error_free (err);
      g_free (debug);

      gst_element_set_state (data->pipeline, GST_STATE_READY);
      term = 1;
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

static void enc_main_loop () {
  /* poll samples (blocking) */
  GstAppSink * voa_sink = GST_APP_SINK (data.enc.voa_sink);
  while (!term && !gst_app_sink_is_eos (voa_sink)) {
    GstSample * sample = gst_app_sink_pull_sample (voa_sink);
    if (sample) {
      GstBuffer * buffer = gst_sample_get_buffer (sample);
      gsize bufsiz = gst_buffer_get_size (buffer);
      printf ("offset: %lu, duration: %lums, size: %lu\n", buffer->offset, (unsigned long)buffer->duration / 1000000, (size_t)bufsiz);
      GstMapInfo info;
      if (!gst_buffer_map (buffer, &info, GST_MAP_READ))
        printf ("error mapping buffer\n");
      int pak_size;
      struct allnet_header * pak = create_voa_packet (info.data, info.size, data.stream_id, &pak_size);
      if (!send_pipe_message (data.allnet_socket, (const char *)pak, pak_size, ALLNET_PRIORITY_DEFAULT_HIGH))
        fprintf (stderr, "error sending\n");
      printf ("size: %d (%lu)\n", pak_size, info.size);

      gst_buffer_unmap (buffer, &info);
      gst_sample_unref (sample);
    } else {
      printf ("NULL sample\n");
    }
  }
}

static void dec_main_loop ()
{
  while (!term) {
    int pipe;
    int priority;
    char * message;
    int size = receive_pipe_message_fd (PIPE_MESSAGE_WAIT_FOREVER, &message,
                                        data.allnet_socket, NULL, NULL, &pipe,
                                        &priority);
    if (size <= 0) {
      printf ("voa: pipe closed, exiting\n");
      return;
    }
    (void) handle_packet ((const char *)message, size);
    free (message);
  }
}

static int init_audio (int is_encoder)
{
  GstBus * bus;
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
    return -1;
  }

  /* Create the elements */
  if (is_encoder) {
    random_bytes ((char *)data.stream_id, STREAM_ID_SIZE);
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
      return -1;
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
      return -1;
    }

  } else {
    /* decoder */
    data.dec.sourceid = 0;
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
      return -1;
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
      return -1;
    }
  }
  gst_caps_unref (appcaps);

  /* Wait until error or EOS */
  bus = gst_element_get_bus (data.pipeline);
  g_signal_connect (bus, "message", G_CALLBACK (cb_message), &data);

  /* Start playing the pipeline */
  ret = gst_element_set_state (data.pipeline, GST_STATE_PAUSED);
  if (ret == GST_STATE_CHANGE_FAILURE) {
    fprintf (stderr, "Unable to change pipeline state.\n");
    gst_object_unref (data.pipeline);
    return -1;
  }

  if (is_encoder) {
    gst_element_set_state (data.pipeline, GST_STATE_PLAYING);
    enc_main_loop ();
  } else {
    dec_main_loop ();
  }

  /* Free resources */
  gst_object_unref (bus);
  gst_element_set_state (data.pipeline, GST_STATE_NULL);
  gst_object_unref (data.pipeline);
  return 0;
}

int allnet_global_debugging = 0;
int main (int argc, char ** argv)
{
  int socket = connect_to_local (argv [0], argv [0]);
  if (socket < 0)
    return 1;
  data.allnet_socket = socket;

  char my_address [ADDRESS_SIZE];
  char dest_address [ADDRESS_SIZE];
  int my_addr_bits = ADDRESS_BITS;
  int dest_addr_bits = 0;
  bzero (my_address, sizeof (my_address));  /* set any unused part to all zeros */
  bzero (dest_address, sizeof (dest_address));
  int nbytes = (my_addr_bits >> 3) + 1;
  random_bytes (my_address, nbytes);
  if (my_addr_bits % 8)
    my_address[nbytes-1] &=
      ((char)0x80) >> ((my_addr_bits % 8) - 1); /* signed shift */
  else
    my_address[nbytes-1] = 0;

  if (argc > 1) {
    dest_addr_bits = argc > 2 ? atoi (argv[2]) : strnlen (argv[1], ADDRESS_SIZE);
    if (dest_addr_bits > ADDRESS_BITS)
      dest_addr_bits = ADDRESS_BITS;
    memcpy (dest_address, argv[1], dest_addr_bits);
  }

  int is_encoder = (strcmp (argv [0], "./voas") == 0);
  printf ("is_encoder: %d\n", is_encoder);
  init_audio (is_encoder);
  return 0;
}

/* vim: set ts=2 sw=2 sts=2 et : */
