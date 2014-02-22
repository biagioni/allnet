/* xchats.c: send xchat messages */
/* parameters are: name of contact and message */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../packet.h"
#include "../lib/pipemsg.h"
#include "../lib/util.h"
#include "../lib/priority.h"
#include "chat.h"
#include "cutil.h"
#include "retransmit.h"
#include "xcommon.h"

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

int main (int argc, char ** argv)
{
  if (argc < 2) {
    printf ("usage: %s contact-name [message]\n", argv [0]);
    return 1;
  }

  /* allegedly, openSSL does this for us */
  /* srandom (time (NULL));/* RSA encryption uses the random number generator */

  int sock = xchat_init ();
  if (sock < 0)
    return 1;

  sleep (1);/* when measuring time, wait until server has accepted connection */

  char * contact = argv [1];  /* contact we send to, peer we receive from */
  request_and_resend (sock, contact);

  /* to do: subtract the size of the signature */
  static char text [ALLNET_MTU];
  char * p = text;
  int printed = 0;
  int i;
  long long int seq = 0;
  int ack_expected = 0;
  if (argc > 2) {
    int size = sizeof (text) - CHAT_DESCRIPTOR_SIZE -
               ALLNET_SIZE (ALLNET_TRANSPORT_ACK_REQ) -
               512; /* the likely size of a signature */
    for (i = 2; i < argc; i++) {
      int n = snprintf (p, size, "%s%s", argv [i], (i + 1 < argc) ? " " : "");
      printed += n;
      p += n;
      size -= n;
    }
/*  printf ("sending %d chars: '%s'\n", printed, text); */
    seq = send_data_message (sock, contact, text, printed);
    ack_expected = 1;
  }

  struct timeval start, deadline;
  gettimeofday (&start, NULL);
  gettimeofday (&deadline, NULL);
  add_time (&deadline, 5000);    /* deadline in 5 seconds */
  int max_wait = until_deadline (&deadline);
  int ack_seen = 0;
  while (max_wait > 0) {
    char * packet;
    int pipe, pri;
    int found = receive_pipe_message_any (max_wait, &packet, &pipe, &pri);
    if (found < 0) {
      printf ("pipe closed, exiting\n");
      exit (1);
    }
    int verified, duplicate;
    char * peer;
    char * desc;
    char * message;
    int mlen = handle_packet (sock, packet, found, &peer, &message, &desc,
                              &verified, NULL, &duplicate);
    int this_is_my_ack = 0;
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
      this_is_my_ack = 1;
    }
    if (mlen > 0) {
      printf ("from '%s' got %s\n  %s\n", peer, desc, message);
      if (this_is_my_ack) /* acked this packet, check for any outstanding */
        request_and_resend (sock, peer);
      free (peer); free (message); free (desc);
    }
    max_wait = until_deadline (&deadline);
  }
}
