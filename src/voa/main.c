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

#ifdef ALLNET
#include <lib/app_util.h> /* connect_to_local */
#include <lib/packet.h>
#include <lib/util.h>     /* random_bytes */
#endif /* ALLNET */
#ifdef SOCKET
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#endif /* SOCKET */
#include <gio/gio.h>
#include <gst/gst.h>
#include <gst/app/gstappsrc.h>
#include <gst/app/gstappsink.h>
#include <stdlib.h>       /* atoi */
#include <string.h>       /* memcpy */

#ifdef RTP
#define AUDIO_CAPS "application/x-rtp,media=(string)audio,payload=(int)96,clock-rate=(int)48000,encoding-name=(string)X-GST-OPUS-DRAFT-SPITTKA-00"
#else
#define AUDIO_CAPS "audio/x-opus,media=(string)audio,clockrate=(int)48000,channels=(int)1"
#endif /* RTP */
#define IFACE_PORT 12534

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
#ifdef SOCKET
  GSocket * gsocket;
  int socket;
  struct sockaddr_in dest;
#endif /* SOCKET */
  GMainLoop * loop;
  GstElement * pipeline;
  gboolean is_encoder;
  union {
    EncoderData enc;
    DecoderData dec;
  };
} VOAData;

static void dec_handle_data_free_buffer (gpointer data) {
  g_free (data);
}

static gboolean dec_handle_data (GIOChannel * source, GIOCondition condition, gpointer data) {
  gchar * buffer = g_new (gchar, 1024);
  gsize length;
  GError * err = NULL;
  GstFlowReturn ret;

  GIOStatus iostat;
  iostat = g_io_channel_read_chars (source, buffer, 1024, &length, &err);
  if (iostat != G_IO_STATUS_NORMAL)
    g_printerr ("couldn't read packets %s\n", iostat == G_IO_STATUS_AGAIN ? "interface busy" : "unknown issue");
  if (err)
    g_printerr ("Error in dec_handle_data: %s", err->message);
  if (iostat != G_IO_STATUS_NORMAL)
    return TRUE;
  g_print ("read %lu bytes\n", length);
  if (length == 0)
    return TRUE;

  GstBuffer * gstbuf = gst_buffer_new_wrapped (buffer, length);

  /* Push the buffer into the appsrc */
  VOAData * d = (VOAData *)data;
  g_signal_emit_by_name (d->dec.voa_source, "push-buffer", gstbuf, &ret);
#ifdef RTP
  GValue val = G_VALUE_INIT;
  g_value_init (&val, G_TYPE_INT);
  g_object_get_property (G_OBJECT (d->dec.jitterbuffer), "percent", &val);
  gint percent = g_value_get_int (&val);
  g_print ("Jitterbuffer %d\n", percent);
#endif /* RTP */
  gst_buffer_unref (gstbuf);
  if (ret != GST_FLOW_OK) {
    g_printerr ("error inserting packets into gst pipeline\n");
    return FALSE; /* We got some error, stop sending data */
  }
  GstState st, pst;
  gst_element_get_state (d->pipeline, &st, &pst, 0);
  g_print ("state: %d, pending: %d\n", st, pst);
  if (st != GST_STATE_PLAYING && pst != GST_STATE_PLAYING && pst != GST_STATE_PLAYING)
    gst_element_set_state (d->pipeline, GST_STATE_PLAYING);

  return TRUE;
}

static void enc_eos (GstAppSink * sink, gpointer data) {
  g_print ("EOS received\n");
}

static GstFlowReturn enc_new_preroll (GstAppSink * sink, gpointer p) {
  g_print ("preroll received\n");
  return GST_FLOW_OK;
}

/* voa_sink has received a sample */
static GstFlowReturn enc_new_sample (GstAppSink * sink, gpointer p) {
  GstSample * sample;

  VOAData * data = (VOAData *)p;

  /* Retrieve the sample */
  g_signal_emit_by_name (sink, "pull-sample", &sample);
  if (sample) {
    GstBuffer * buffer = gst_sample_get_buffer (sample);
    gsize bufsiz = gst_buffer_get_size (buffer);
    g_print ("offset: %lu, duration: %lums, size: %lu\n", buffer->offset, buffer->duration / 1000000, bufsiz);
    GstMapInfo info;
    if (!gst_buffer_map (buffer, &info, GST_MAP_READ))
      g_print ("error mapping buffer\n");
#ifdef ALLNET
    /* TODO: create message */
    // int pak_size;
    // struct allnet_header * pak = create_packet (info.size, ALLNET_TYPE_DATA, 3 /*max hops*/, NULL/*src addr*/, 0 /*src bits*/, NULL, 0 /*dst*/, NULL /*ack*/);
    // pak->transport = ALLNET_TRANSPORT_STREAM;
    // char * sid = new_msg_id ();
    // pak->stream_id = sid;
    // send_pipe_message (sock, msg, pak_size, ALLNET_PRIORITY_HIGH);
#endif /* ALLNET */
#ifdef SOCKET
    if (sendto (data->socket, info.data, info.size, 0, (const struct sockaddr *)&data->dest, sizeof (data->dest)) == -1)
      g_printerr ("error sending\n");
    g_print ("size: %lu\n", info.size);
#endif /* SOCKET */
    g_print (".");

    gst_buffer_unmap (buffer, &info);
    gst_sample_unref (sample);
  } else {
    g_print ("NULL sample\n");
  }

  return GST_FLOW_OK;
}

static void cb_message (GstBus * bus, GstMessage * msg, VOAData * data) {

  switch (GST_MESSAGE_TYPE (msg)) {
    case GST_MESSAGE_ERROR: {
      GError * err;
      gchar * debug;

      gst_message_parse_error (msg, &err, &debug);
      g_printerr ("Error: %s\n", err->message);
      g_error_free (err);
      g_free (debug);

      gst_element_set_state (data->pipeline, GST_STATE_READY);
      g_main_loop_quit (data->loop);
      break;
    }
    case GST_MESSAGE_EOS:
      /* end-of-stream */
      g_print ("EOS Msg\n");
      gst_element_set_state (data->pipeline, GST_STATE_READY);
      g_main_loop_quit (data->loop);
      break;
    case GST_MESSAGE_BUFFERING: {
      /* CHECK: not sure we really need this, since live streams don't buffer */
      gint percent = 0;
      gst_message_parse_buffering (msg, &percent);
      g_print ("Buffering (%3d%%)\r", percent);
      /* Wait until buffering is complete before start/resume playing */
      if (percent < 100)
        gst_element_set_state (data->pipeline, GST_STATE_PAUSED);
      else
        gst_element_set_state (data->pipeline, GST_STATE_PLAYING);
      break;
    }
    case GST_MESSAGE_CLOCK_LOST:
      /* Get a new clock */
      g_print ("lost clock\n");
      gst_element_set_state (data->pipeline, GST_STATE_PAUSED);
      gst_element_set_state (data->pipeline, GST_STATE_PLAYING);
      break;
    default:
      /* Unhandled message */
      break;
  }
}

static int init_audio (gboolean is_encoder)
{
  VOAData data;
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
    g_printerr ("Couldn't create pipeline.\n");
    return -1;
  }

  /* Create the elements */
  if (is_encoder) {
    //data.enc.source = gst_element_factory_make ("audiotestsrc", "source");
    data.enc.source = gst_element_factory_make ("autoaudiosrc", "source");
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
      g_printerr ("Not all elements could be created.\n");
      return -1;
    }

    GstCaps * rawcaps = gst_caps_from_string ("audio/x-raw,clockrate=(int)48000,channels=(int)1");
    GstPad * srcpad = gst_element_get_static_pad (data.enc.source, "src");
    gst_pad_set_caps (srcpad, rawcaps);
    gst_caps_unref (rawcaps);

    /* Configure encoder appsink */
    g_object_set (data.enc.voa_sink, "emit-signals", TRUE, /*"caps", appcaps,*/ NULL);
    GstAppSinkCallbacks cbs = {
      .eos = enc_eos,
      .new_preroll = NULL,
      .new_sample = enc_new_sample
    };
    gst_app_sink_set_callbacks (GST_APP_SINK (data.enc.voa_sink), &cbs, &data, NULL);

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
      g_printerr ("Elements could not be linked.\n");
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
    data.dec.sink = gst_element_factory_make ("autoaudiosink", "sink");
    if (!data.dec.voa_source ||
#ifdef RTP
        !data.dec.jitterbuffer || !data.dec.rtpdepay ||
#endif /* RTP */
        !data.dec.decoder || !data.dec.sink) {
      g_printerr ("Not all elements could be created.\n");
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
      g_printerr ("Elements could not be linked.\n");
      gst_object_unref (data.pipeline);
      return -1;
    }
  }
  gst_caps_unref (appcaps);

  /* Wait until error or EOS */
  bus = gst_element_get_bus (data.pipeline);
  g_signal_connect (bus, "message", G_CALLBACK (cb_message), &data);

#ifdef SOCKET
  guint source;
  if (is_encoder) {
    data.socket = socket (AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    /*
    // no binding needed when we're not receiving
    struct sockaddr_in sa;
    memset (&sa, 0, sizeof (struct sockaddr_in));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = inet_addr (INADDR_ANY);
    sa.sin_port = htons (12533);
    if (bind (data.socket, (struct sockaddr *)&sa, sizeof (struct sockaddr_in)) == -1)
      g_printerr ("couldn't bind socket\n");
    */
    memset (&data.dest, 0, sizeof (struct sockaddr_in));
    data.dest.sin_family = AF_INET;
    data.dest.sin_addr.s_addr = inet_addr ("127.0.0.1");
    data.dest.sin_port = htons (IFACE_PORT);

  } else {

    GError * err = NULL;
    data.gsocket = g_socket_new (G_SOCKET_FAMILY_IPV4,
                                  G_SOCKET_TYPE_DATAGRAM,
                                  G_SOCKET_PROTOCOL_UDP,
                                  &err);
    if (err != NULL) {
      g_printerr("%s\n", err->message);
      return -1;
    }
    g_socket_bind (data.gsocket,
      G_SOCKET_ADDRESS (g_inet_socket_address_new
        (g_inet_address_new_any (G_SOCKET_FAMILY_IPV4), IFACE_PORT)),
      FALSE, &err);
    if (err != NULL) {
      g_printerr("%s\n", err->message);
      return -1;
    }
    int fd = g_socket_get_fd (data.gsocket);
    GIOChannel * channel = g_io_channel_unix_new (fd);
    g_io_channel_set_encoding (channel, NULL, NULL);
    g_io_channel_set_buffered (channel, FALSE);
    source = g_io_add_watch (channel, G_IO_IN,
                              (GIOFunc) dec_handle_data, &data);
    g_print ("Listening for traffic on port %d..\n", IFACE_PORT);
    g_io_channel_unref (channel);
  }
#endif /* SOCKET */

  /* Start playing the pipeline */
  ret = gst_element_set_state (data.pipeline, GST_STATE_PAUSED);
  if (ret == GST_STATE_CHANGE_FAILURE) {
    g_printerr ("Unable to change pipeline state.\n");
    gst_object_unref (data.pipeline);
    return -1;
  }

  if (is_encoder) {
    gst_element_set_state (data.pipeline, GST_STATE_PLAYING);
    /* instead of using the main loop, use blocking reads:
     * while (TRUE) enc_new_sample (GST_APP_SINK (data.enc.voa_sink), &data);
     */
  }

  /* Create a GLib Main Loop and set it to run */
  data.loop = g_main_loop_new (NULL, FALSE);
  g_main_loop_run (data.loop);

  /* Free resources */
#ifdef SOCKET
  if (!is_encoder) {
    g_source_remove (source);
    g_object_unref (data.gsocket);
  }
#endif /* SOCKET */
  g_main_loop_unref (data.loop);
  gst_object_unref (bus);
  gst_element_set_state (data.pipeline, GST_STATE_NULL);
  gst_object_unref (data.pipeline);
  return 0;
}

int main (int argc, char ** argv)
{
#ifdef ALLNET
  int sock = connect_to_local (argv [0], argv [0]);
  if (sock < 0)
    return 1;

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

  if (argc > 0) {
    dest_addr_bits = argc > 1 ? atoi (argv[2]) : strnlen (argv[0], ADDRESS_SIZE);
    memcpy (dest_address, argv[1], dest_addr_bits);
  }
#endif /* ALLNET */

  gboolean is_encoder = (strcmp (argv [0], "./voas") == 0);
  g_print ("is_encoder: %d\n", is_encoder);
  init_audio (is_encoder);
  return 0;
}

/* vim: set ts=2 sw=2 sts=2 et : */
