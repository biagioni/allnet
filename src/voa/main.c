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

#include <lib/app_util.h> /* connect_to_local */
#include <lib/packet.h>
#include <lib/util.h>     /* random_bytes */
#include <gst/gst.h>
#include <stdlib.h>       /* atoi */
#include <string.h>       /* memcpy */

#define CHUNK_SIZE 1024   /* Amount of bytes we are sending in each buffer */
#define AUDIO_CAPS "audio/x-opus"

typedef struct _DecoderData {
  GstElement * voa_source; /* Voice-over-allnet source */
  GstElement * sink; /* playback device */
  int sourceid;
} DecoderData;

typedef struct _EncoderData {
  GstElement * source; /* recording device */
  GstElement * convert;
  GstElement * resample;
  GstElement * encoder;
  GstElement * voa_sink; /* Voice-over-allnet sink */

  guint sourceid;
} EncoderData;

typedef struct _VOAData {
  GMainLoop * loop;
  GstElement * pipeline;
  gboolean is_encoder;
  union {
    EncoderData enc;
    DecoderData dec;
  };
} VOAData;

/* voa_sink has received a buffer */
static void new_buffer (GstElement * sink, VOAData * data) {
  GstBuffer * buffer;

  /* Retrieve the buffer */
  g_signal_emit_by_name (sink, "pull-buffer", &buffer);
  if (buffer) {
    /* TODO: send buffer over allnet */
    /* TODO: create message */
    // int pak_size;
    // struct allnet_header * pak = create_packet (buf_siz, ALLNET_TYPE_DATA, 10 /*hops*/, NULL/*src addr*/, 0 /*src bits*/, NULL, 0 /*dst*/, NULL /*ack*/);
    // pak->transport = ALLNET_TRANSPORT_STREAM;
    // char * sid = new_msg_id ();
    // pak->stream_id = sid;
    // send_pipe_message (sock, msg, pak_size, ALLNET_PRIORITY_HIGH);

    gst_buffer_unref (buffer);
  }
}

static void cb_message (GstBus * bus, GstMessage * msg, VOAData * data) {

  switch (GST_MESSAGE_TYPE (msg)) {
    case GST_MESSAGE_ERROR: {
      GError * err;
      gchar * debug;

      gst_message_parse_error (msg, &err, &debug);
      g_print ("Error: %s\n", err->message);
      g_error_free (err);
      g_free (debug);

      gst_element_set_state (data->pipeline, GST_STATE_READY);
      g_main_loop_quit (data->loop);
      break;
    }
    case GST_MESSAGE_EOS:
      /* end-of-stream */
      gst_element_set_state (data->pipeline, GST_STATE_READY);
      g_main_loop_quit (data->loop);
      break;
    case GST_MESSAGE_BUFFERING: {
      gint percent = 0;

      /* If the stream is live, we do not care about buffering. */
      //if (data->is_live) break; // live streams don't pause

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
      gst_element_set_state (data->pipeline, GST_STATE_PAUSED);
      gst_element_set_state (data->pipeline, GST_STATE_PLAYING);
      break;
    default:
      /* Unhandled message */
      break;
  }
}

/* This method is called by the idle GSource in the mainloop, to feed CHUNK_SIZE bytes into voa_src.
 * The idle handler is added to the mainloop when appsrc requests us to start sending data (need-data signal)
 * and is removed when voa_src has enough data (enough-data signal).
 */
static gboolean push_data (VOAData *data) {
  GstBuffer *buffer;
  GstFlowReturn ret;
  int i;
  gint16 *raw;
  gint num_samples = CHUNK_SIZE / 2; /* Because each sample is 16 bits */
  gfloat freq;

  /* Create a new empty buffer for voa data */
  buffer = gst_buffer_new_and_alloc (CHUNK_SIZE);

  /* .. */

  /* Set its timestamp and duration */
  // GST_BUFFER_TIMESTAMP (buffer) = gst_util_uint64_scale (data->num_samples, GST_SECOND, SAMPLE_RATE);
  // GST_BUFFER_DURATION (buffer) = gst_util_uint64_scale (CHUNK_SIZE, GST_SECOND, SAMPLE_RATE);

  /* Push the buffer into the appsrc */
  g_signal_emit_by_name (data->dec.voa_source, "push-buffer", buffer, &ret);

  /* Free the buffer now that we are done with it */
  gst_buffer_unref (buffer);

  if (ret != GST_FLOW_OK) {
    /* We got some error, stop sending data */
    return FALSE;
  }
  return TRUE;
}

/* This signal callback triggers when appsrc needs data. Here, we add an idle handler
 * to the mainloop to start pushing data into the appsrc */
static void start_feed (GstElement *source, guint size, VOAData *data) {
  if (data->dec.sourceid == 0) {
    g_print ("Start feeding\n");
    data->dec.sourceid = g_idle_add ((GSourceFunc) push_data, data);
  }
}


/* This callback triggers when appsrc has enough data and we can stop sending.
* We remove the idle handler from the mainloop */
static void stop_feed (GstElement *source, VOAData *data) {
  if (data->dec.sourceid != 0) {
    g_print ("Stop feeding\n");
    g_source_remove (data->dec.sourceid);
    data->dec.sourceid = 0;
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

  /* Create the elements */
  if (is_encoder) {
    data.enc.source = gst_element_factory_make ("audiotestsrc", "source"); /* autoaudiosource */
    data.enc.convert = gst_element_factory_make ("audioconvert", "convert");
    data.enc.resample = gst_element_factory_make ("audioresample", "resample");
    data.enc.encoder = gst_element_factory_make ("opusenc", "encode");
    data.enc.voa_sink = gst_element_factory_make ("appsink", "voa_sink");
  } else {
    data.dec.voa_source = gst_element_factory_make ("appsource", "voa_source");
    data.dec.sink = gst_element_factory_make ("autoaudiosink", "sink");
  }

  GstCaps * appcaps = gst_caps_from_string (AUDIO_CAPS);
  if (is_encoder) {
    /* Configure encoder appsink */
    g_object_set (data.enc.voa_sink, "emit-signals", TRUE, "caps", appcaps, NULL);
    g_signal_connect (data.enc.voa_sink, "new-buffer", G_CALLBACK (new_buffer), &data);

    /* Modify the source's properties */
    g_object_set (data.enc.encoder, "bandwidth", 1101,
                                    "bitrate", 4000,
                                    "cbr", FALSE,
                                    NULL);

  } else {
    /* Configure decoder source */
    g_object_set (data.dec.voa_source, "caps", appcaps, NULL);
    g_signal_connect (data.dec.voa_source, "need-data", G_CALLBACK (start_feed), &data);
    g_signal_connect (data.dec.voa_source, "enough-data", G_CALLBACK (stop_feed), &data);
  }
  gst_caps_unref (appcaps);

  /* Create the empty pipeline and build it */
  data.pipeline = gst_pipeline_new ("pipeline");
  if (!data.pipeline) {
    g_printerr ("Couldn't create pipeline.\n");
    return -1;
  }

  if (is_encoder) {
    if (!data.enc.source || !data.enc.convert || !data.enc.voa_sink) {
      g_printerr ("Not all elements could be created.\n");
      return -1;
    }
    gst_bin_add_many (GST_BIN (data.pipeline), data.enc.source, data.enc.convert, data.enc.voa_sink, NULL);
    if (gst_element_link_many (data.enc.source, data.enc.convert, data.enc.voa_sink, NULL) != TRUE) {
      g_printerr ("Elements could not be linked.\n");
      gst_object_unref (data.pipeline);
      return -1;
    }

  } else {
    if (!data.dec.voa_source || !data.dec.sink) {
      g_printerr ("Not all elements could be created.\n");
      return -1;
    }
    gst_bin_add_many (GST_BIN (data.pipeline), data.dec.voa_source, data.dec.sink, NULL);
    if (gst_element_link_many (data.dec.voa_source, data.dec.sink, NULL) != TRUE) {
      g_printerr ("Elements could not be linked.\n");
      gst_object_unref (data.pipeline);
      return -1;
    }
  }

  /* Start playing */
  ret = gst_element_set_state (data.pipeline, GST_STATE_PLAYING);
  if (ret == GST_STATE_CHANGE_FAILURE) {
    g_printerr ("Unable to set the pipeline to the playing state.\n");
    gst_object_unref (data.pipeline);
    return -1;
  }

  data.loop = g_main_loop_new (NULL, FALSE);

  /* Wait until error or EOS */
  bus = gst_element_get_bus (data.pipeline);
  g_signal_connect (bus, "message", G_CALLBACK (cb_message), &data);

  /* Start playing the pipeline */
  gst_element_set_state (data.pipeline, GST_STATE_PLAYING);

  /* Create a GLib Main Loop and set it to run */
  data.loop = g_main_loop_new (NULL, FALSE);
  g_main_loop_run (data.loop);

  /* Free resources */
  g_main_loop_unref (data.loop);
  gst_object_unref (bus);
  gst_element_set_state (data.pipeline, GST_STATE_NULL);
  gst_object_unref (data.pipeline);
  return 0;
}

int main (int argc, char ** argv)
{
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

  gboolean is_encoder = (strcmp (argv [0], "./voas") == 0);
  g_print ("is_encoder: %d\n", is_encoder);
  init_audio (is_encoder);
  return 0;
}

/* vim: set ts=2 sw=2 sts=2 et : */
