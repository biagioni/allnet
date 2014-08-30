/* xchats.c: send xchat messages */
/* parameters are: name of contact and message */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "lib/packet.h"
#include "lib/pipemsg.h"
#include "lib/util.h"
#include "lib/priority.h"
#include "lib/log.h"
#include "chat.h"
#include "cutil.h"
#include "retransmit.h"
#include "xcommon.h"
#include "message.h"

/* returns the number of ms from now until the deadline, or 0 if the
 * deadline has passed */
static int until_deadline (struct timeval * deadline)
{
  struct timeval now;
  gettimeofday (&now, NULL);
  int result = (deadline->tv_sec  - now.tv_sec ) * 1000 +
               (deadline->tv_usec - now.tv_usec) / 1000;
/*  printf ("%2ld.%06ld, %4d until deadline %2ld.%06ld\n",
          now.tv_sec % 100, now.tv_usec, result,
          deadline->tv_sec % 100, deadline->tv_usec); */
  if (result < 0)
    return 0;
  return result;
}

static void add_time (struct timeval * time, int ms)
{
  time->tv_usec += ms * 1000;
  time->tv_sec += time->tv_usec / 1000000;
  time->tv_usec = time->tv_usec % 1000000;
}

/* global debugging variable -- if 1, expect more debugging output */
/* set in main */
int allnet_global_debugging = 0;

int main (int argc, char ** argv)
{
  int verbose = get_option ('v', &argc, argv);
  if (verbose)
    allnet_global_debugging = verbose;

  if (argc < 2) {
    printf ("usage: %s contact-name [message]\n", argv [0]);
    printf ("   or: %s -k contact-name [hops [secret]] (hops defaults to 1)\n",
            argv [0]);
    return 1;
  }

  int sock = xchat_init (argv [0]);
  if (sock < 0)
    return 1;

  int ack_expected = 0;
  long long int seq = 0;
  char * contact = argv [1];  /* contact we send to, peer we receive from */

  char * kcontact = NULL;
  char * my_secret = NULL;
  char * peer_secret = NULL;
#define MAX_SECRET	15  /* including a terminating null character */
  char my_secret_buf [MAX_SECRET];
  char peer_secret_buf [200];
  int kmax_hops = 0;
  int wait_time = 5000;   /* 5 seconds to wait for acks and such */

  if (strcmp (contact, "-k") == 0) {   /* send a key */
    if ((argc != 3) && (argc != 4) && (argc != 5)) {
      printf ("usage: %s -k contact-name [hops [secret]] (%d)\n",
              argv [0], argc);
      return 1;
    }
    kcontact = argv [2];
    int hops = 1;
    if (argc >= 4) {
      char * end;
      int n = strtol (argv [3], &end, 10);
      if (end != argv [3])
        hops = n;
    }
    random_string (my_secret_buf, MAX_SECRET);
    if (hops <= 1)
      my_secret_buf [6] = '\0';   /* for direct contacts, truncate to 6 chars */
    printf ("%d hops, my secret string is '%s'", hops, my_secret_buf);
    normalize_secret (my_secret_buf);
    printf (" (or %s)\n", my_secret_buf);
    my_secret = my_secret_buf;
    if (argc >= 5) {
      snprintf (peer_secret_buf, sizeof (peer_secret_buf), "%s", argv [4]);
      printf ("peer secret string is '%s'", peer_secret_buf);
      normalize_secret (peer_secret_buf);
      printf (" (or %s)\n", peer_secret_buf);
      peer_secret = peer_secret_buf;
    }
    kmax_hops = hops;
    wait_time = 10 * 60 * 1000;   /* wait up to 10 minutes for a key */
    char * send_secret = my_secret;
    if (! create_contact_send_key (sock, kcontact, send_secret,
                                   peer_secret, hops))
      return 1;
  } else { /* send the data packet */
    int i;
    keyset * keys;
    int nkeys = all_keys (contact, &keys);
    if ((argc > 2) && (nkeys > 0)) {
      int max_key = 0;
      for (i = 0; i < nkeys; i++) {
        char * key;
        int ksize = get_my_privkey (keys [i], &key);
        if (ksize > max_key)
          max_key = ksize;
      }
      static char text [ALLNET_MTU];
      int size = sizeof (text) - CHAT_DESCRIPTOR_SIZE -
                 ALLNET_SIZE (ALLNET_TRANSPORT_ACK_REQ) -
                 max_key; /* the maximum size of a signature */
      char * p = text;
      int printed = 0;
      for (i = 2; i < argc; i++) {
        int n = snprintf (p, size, "%s%s", argv [i], (i + 1 < argc) ? " " : "");
        printed += n;
        p += n;
        size -= n;
      }
  /*  printf ("sending %d chars: '%s'\n", printed, text); */
      seq = send_data_message (sock, contact, text, printed);
      ack_expected = 1;
    } else if (nkeys == 0) {
      printf ("error: no keys for contact '%s'\n", contact);
    } else if (nkeys < 0) {
      printf ("error: contact '%s' does not exist\n", contact);
    }
  }

  struct timeval start, deadline;
  gettimeofday (&start, NULL);
  gettimeofday (&deadline, NULL);
  add_time (&deadline, wait_time);
  int max_wait = until_deadline (&deadline);
  int ack_seen = 0;
  while (max_wait > 0) {
    char * packet;
    int pipe, pri;
    int found = receive_pipe_message_any (max_wait, &packet, &pipe, &pri);
    if (found < 0) {
      printf ("xchats pipe closed, exiting\n");
      exit (1);
    }
    int verified, duplicate, broadcast;
    char * desc;
    char * message;
    char * peer = NULL;
    keyset kset = -1;
    int mlen = handle_packet (sock, packet, found, &peer, &kset,
                              &message, &desc, &verified, NULL, &duplicate,
                              &broadcast, kcontact, my_secret, peer_secret,
                              kmax_hops, NULL, NULL, 0);
    if (mlen > 0) {
      char * ver_mess = "";
      if (! verified)
        ver_mess = " (not verified)";
      char * dup_mess = "";
      if (duplicate)
        dup_mess = "duplicate ";
      char * bc_mess = "";
      if (broadcast) {
        bc_mess = "broacast ";
        dup_mess = "";
        desc = "";
      }
      printf ("from '%s'%s got %s%s%s\n  %s\n", peer, ver_mess, dup_mess, 
              bc_mess, desc, message);
    } else if (mlen == -1) {  /* successful key exchange */
      printf ("success!  got remote key for %s\n", kcontact);
      gettimeofday (&deadline, NULL);
      add_time (&deadline, 5000);  /* wait 5 more seconds */
    }
  /* handle_packet may change what has been acked */
    if ((ack_expected) && (! ack_seen) && (is_acked (contact, seq))) {
      struct timeval finish;
      gettimeofday (&finish, NULL);   /* how long did the ack take? */
      long long int delta = (finish.tv_sec  - start.tv_sec ) * 1000000LL +
                            (finish.tv_usec - start.tv_usec);
      printf ("got ack from %s in %lld.%06llds\n", contact,
              delta / 1000000, delta % 1000000);

      gettimeofday (&deadline, NULL); /* wait another second from now */
      add_time (&deadline, 1000);     /* for additional messages */
      ack_seen = 1;
    }
    if (mlen > 0) {
      free (peer);
      free (message);
      if (! broadcast)
        free (desc);
    }
    max_wait = until_deadline (&deadline);
  }
  return 0;
}
