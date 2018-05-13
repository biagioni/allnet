/* allnet_radio.c: show all incoming broadcast messages to which we subscribe */
/*    special handling shows how early or late time messages are */
/*    if run as root and message is from an authenticated sender whose
 *    name is allnet_time, sets the system time to the received time */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "lib/app_util.h"
#include "lib/packet.h"
#include "lib/media.h"
#include "lib/sockets.h"
#include "lib/util.h"
#include "lib/app_util.h"
#include "lib/sha.h"
#include "lib/allnet_log.h"
#include "lib/priority.h"
#include "lib/cipher.h"
#include "lib/keys.h"

/* the sender(s) allowed to set this system's clock */
#define AUTH_SENDER	"allnet_time@"

/* if run as root and message is from an authenticated sender whose
 * name is allnet_time, sets the system time to the received time */
static void set_time (unsigned long long int packet_time)
{
  struct timeval t;
  t.tv_sec = packet_time + ALLNET_Y2K_SECONDS_IN_UNIX;
  t.tv_usec = 0;
  int res = settimeofday (&t, NULL);  /* fails if we are not root */
  if (res < 0) {
    if (errno == EPERM)               /* the result if we are not root */
      printf ("settimeofday failed (if wish to set time, run as root)\n");
    else
      perror ("settimeofday");
  } else {
    printf ("set time: success\n");
  }
}

static int handle_packet (char * message, int msize, int * rcvd, int debug)
{
  *rcvd = 0;
  struct timeval receive_time;
  gettimeofday (&receive_time, NULL);

  char * reason;
  if (! is_valid_message (message, msize, &reason)) {
    if (debug) {
      printf ("%s ", reason);
      print_buffer (message, msize, "got invalid message", 32, 1);
    }
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
      if (allnet_verify (verif, vsize, sig, ssize, keys [i].pub_key))
        from = keys [i].identifier;
    }
  }
  if (strcmp (from, "unknown sender") == 0)
    printf ("got %d other keys, none matched %d %p\n", nkeys, ssize, sig);

  *sig = '\0';  /* null-terminate the string */
  printf ("from %s: %s\n", from, payload);
  if ((psize == ((int) (strlen (payload) + 9))) &&
      (readb32u (amhp->media) == ALLNET_MEDIA_TIME_TEXT_BIN)) {
  /* message from time server, see how long it took */
    char * bin_time = payload + strlen (payload) + 1;
    unsigned long long int packet_time = readb64 (bin_time);
    printf ("  sent at %lld seconds, ", packet_time);
    long long int delta =
       (receive_time.tv_sec - ALLNET_Y2K_SECONDS_IN_UNIX) - packet_time;
    if (delta >= 0)
      printf ("received %lld.%06d seconds later\n", delta,
              (int) (receive_time.tv_usec));
    else  /* delta < 0 */
      printf ("received %lld.%06d seconds before sent\n", - (delta + 1),
              (int) (1000000 - receive_time.tv_usec));
    *rcvd = 1;
    if ((strncmp (from, AUTH_SENDER, strlen (AUTH_SENDER)) == 0) &&
/* to avoid too much instability, we set the time as follows:
 * if the packet time is earlier than our clock by 60s or less, we do
 * not change the local clock.  So we only set the local clock if
 * the packet time is (1) later than our clock (delta < 0), or (b)
 * more than 60s earlier than our clock. */
        ((delta < 0) || (delta > 60)))
      set_time (packet_time);
  } else {
    if (debug)
      printf ("psize %d, strlen %zd\n", psize, strlen (payload));
    printf ("received at %ld.%06ld\n", (long) (receive_time.tv_sec),
            (long) (receive_time.tv_usec));
  }

  return 0;  /* continue */
}

static void main_loop (int debug, int max)
{
  while (1) {
    unsigned int pri;
    char * message;
    int found = local_receive (SOCKETS_TIMEOUT_FOREVER, &message, &pri);
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

/* optional argument: quit after n messages */
int main (int argc, char ** argv)
{
  int verbose = get_option ('v', &argc, argv);
  log_to_output (verbose);

  /* pd p = init_pipe_descriptor (log); */
  if (connect_to_local (argv [0], argv [0], NULL, 1, 1) < 0)
    return 1;

  int debug = debug_switch (&argc, argv);
  if (verbose && (! debug))
    debug = 1;

  int max = 0;
  if (argc > 1)
    max = atoi (argv [1]);

  main_loop (debug, max);
  return 0;
}

