/* allnet_radio.c: show all incoming broadcast messages to which we subscribe */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lib/app_util.h"
#include "lib/packet.h"
#include "lib/media.h"
#include "lib/pipemsg.h"
#include "lib/util.h"
#include "lib/app_util.h"
#include "lib/sha.h"
#include "lib/log.h"
#include "lib/priority.h"
#include "lib/cipher.h"
#include "lib/keys.h"

static int handle_packet (char * message, int msize, int * rcvd, int debug)
{
  *rcvd = 0;
  struct timeval receive_time;
  gettimeofday (&receive_time, NULL);

  if (! is_valid_message (message, msize)) {
    if (debug)
      printf ("got invalid message of size %d\n", msize);
    return 0;
  }
  if (debug)
    print_packet (message, msize, "handle_packet", 1);

  struct allnet_header * hp = (struct allnet_header *) message;
  int hsize = ALLNET_SIZE (hp->transport);
  int h2size = sizeof (struct allnet_app_media_header);
  if (msize <= hsize + h2size)  /* nothing to receive */
    return 0;
  if (hp->message_type != ALLNET_TYPE_CLEAR)
    return 0;
  char * verif = message + hsize;
  int vsize = msize - hsize;
  struct allnet_app_media_header * amhp =
    (struct allnet_app_media_header *) verif;
  if ((readb32u (amhp->media) != ALLNET_MEDIA_TEXT_PLAIN) &&
      (readb32u (amhp->media) != ALLNET_MEDIA_TIME_TEXT_BIN))
    return 0;

  char * payload = verif + h2size;
  int psize = vsize - h2size;

  int ssize = 0;
  char * sig = NULL;
  if ((psize > 2) && (hp->sig_algo == ALLNET_SIGTYPE_RSA_PKCS1)) {
/* RSA_PKCS1 is the only type of signature supported for now */
    ssize = readb16 (payload + (psize - 2));
    if (ssize + 2 < psize) {
      sig = payload + (psize - (ssize + 2));
      psize -= ssize + 2;
      vsize -= ssize + 2;
    }
  }
  if (sig == NULL)  /* ignore */
    return 0;
  char * from = "unknown sender";
  struct bc_key_info * keys;
  int nkeys = get_other_keys (&keys);
  if ((nkeys > 0) && (ssize > 0) && (sig != NULL)) {
    int i;
    for (i = 0; i < nkeys; i++) {
      if (allnet_verify (verif, vsize, sig, ssize,
                         keys [i].pub_key, keys [i].pub_klen))
        from = keys [i].identifier;
    }
  }
  if (strcmp (from, "unknown sender") == 0)
    printf ("got %d other keys, none matched %d %p\n", nkeys, ssize, sig);

  *sig = '\0';  /* null-terminate the string */
  printf ("from %s: %s\n", from, payload);
  if ((psize == strlen (payload) + 9) &&
      (readb32u (amhp->media) == ALLNET_MEDIA_TIME_TEXT_BIN)) {
  /* message from time server, see how long it took */
    char * bin_time = payload + strlen (payload) + 1;
    unsigned long long int packet_time = readb64 (bin_time);
    printf ("  sent at %lld seconds, ", packet_time);
    long long int delta =
       (receive_time.tv_sec - ALLNET_Y2K_SECONDS_IN_UNIX) - packet_time;
    if (delta >= 0)
      printf ("received after %lld.%06ld seconds\n", delta,
              receive_time.tv_usec);
    else
      printf ("clock skew detected (%lld.%06ld seconds before)\n",
              delta, receive_time.tv_usec);
    *rcvd = 1;
  } else {
    if (debug)
      printf ("psize %d, strlen %zd\n", psize, strlen (payload));
    printf ("received at %ld.%06ld\n", receive_time.tv_sec,
            receive_time.tv_usec);
    
  }

  return 0;  /* continue */
}

static void main_loop (int sock, int debug, int max)
{
  while (1) {
    int pipe;
    int pri;
    char * message;
    int found = receive_pipe_message_any (PIPE_MESSAGE_WAIT_FOREVER, &message,
                                          &pipe, &pri);
    if (found <= 0) {
      printf ("allnet-radio pipe closed, exiting\n");
      exit (1);
    }
    int received = 0;
    if (handle_packet (message, found, &received, debug))
      return;
    free (message);
    if ((max > 0) && (received)) {
      max--;
      if (max == 0)
        return;
    }
  }
}

static int debug_switch (int * argc, char ** argv)
{
  int i;
  int debug = 0;
  for (i = 1; i < *argc; i++) {
    if ((strcasecmp (argv [i], "debug") == 0) ||
        (strcasecmp (argv [i], "-debug") == 0)) {
      debug = 1;
      int j;
      for (j = i + 1; j < *argc; j++)
        argv [j - 1] = argv [j];
      (*argc)--;
    }
  }
  return debug;
}

/* global debugging variable -- if 1, expect more debugging output */
/* set in main */
int allnet_global_debugging = 0;

/* optional argument: quit after n messages */
int main (int argc, char ** argv)
{
  int verbose = get_option ('v', &argc, argv);
  if (verbose)
    allnet_global_debugging = verbose;

  int sock = connect_to_local (argv [0], argv [0]);
  if (sock < 0)
    return 1;

  int debug = debug_switch (&argc, argv);
  if (verbose && (! debug))
    debug = 1;

  int max = 0;
  if (argc > 1)
    max = atoi (argv [1]);

  main_loop (sock, debug, max);
  return 0;
}

