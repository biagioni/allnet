/* allnet_radio.c: show all incoming broadcast messages to which we subscribe */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../packet.h"
#include "../lib/pipemsg.h"
#include "../lib/util.h"
#include "../lib/sha.h"
#include "../lib/log.h"
#include "../lib/priority.h"
#include "../lib/cipher.h"
#include "../lib/keys.h"

static int handle_packet (char * message, int msize, int debug)
{
  struct timeval receive_time;
  gettimeofday (&receive_time, NULL);

  if (! is_valid_message (message, msize)) {
    printf ("got invalid message of size %d\n", msize);
    return 0;
  }
  if (debug)
    print_packet (message, msize, "handle_packet", 1);

  struct allnet_header * hp = (struct allnet_header *) message;
  int hsize = ALLNET_SIZE (hp->transport);
  if (hp->message_type != ALLNET_TYPE_CLEAR)
    return 0;
  if (msize <= hsize)  /* nothing to receive */
    return 0;

  char * payload = message + hsize;
  int psize = msize - hsize;

  int ssize = 0;
  char * sig = NULL;
  if ((psize > 2) && (hp->sig_algo == ALLNET_SIGTYPE_RSA_PKCS1)) {
/* RSA_PKCS1 is the only type of signature supported for now */
    ssize = readb16 (payload + (psize - 2));
    if (ssize + 2 < psize) {
      sig = payload + (psize - (ssize + 2));
      psize -= ssize + 2;
    }
  }
  char * from = "unknown sender";
  struct bc_key_info * keys;
  int nkeys = get_other_keys (&keys);
  if ((nkeys > 0) && (ssize > 0) && (sig != NULL)) {
    int i;
    for (i = 0; i < nkeys; i++) {
      if (verify (payload, psize, sig, ssize,
                  keys [i].pub_key, keys [i].pub_klen))
        from = keys [i].identifier;
    }
  }

  printf ("from %s: %s\n", from, payload);
  if (psize == strlen (payload) + 9) {  /* see how long it took */
    char * bin_time = payload + strlen (payload) + 1;
    unsigned long long int packet_time = readb64 (bin_time);
    printf ("  sent at %lld seconds, ", packet_time);
    unsigned long long int delta =
       (receive_time.tv_sec - Y2K_SECONDS_IN_UNIX) - packet_time;
    printf ("received after %lld.%06ld seconds\n", delta, receive_time.tv_usec);
  } else {
    if (debug)
      printf ("psize %d, strlen %zd\n", psize, strlen (payload));
    printf ("received at %ld.%06ld\n", receive_time.tv_sec,
            receive_time.tv_usec);
    
  }

  return 0;  /* continue */
}

static void main_loop (int sock, int debug)
{
  while (1) {
    int pipe;
    int pri;
    char * message;
    int found = receive_pipe_message_any (PIPE_MESSAGE_WAIT_FOREVER, &message,
                                          &pipe, &pri);
    if (found <= 0) {
      printf ("pipe closed, exiting\n");
      exit (1);
    }
    if (handle_packet (message, found, debug))
      return;
    free (message);
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

int main (int argc, char ** argv)
{
  int sock = connect_to_local (argv [0]);
  if (sock < 0)
    return 1;
  add_pipe (sock);

  int debug = debug_switch (&argc, argv);

  main_loop (sock, debug);
}

