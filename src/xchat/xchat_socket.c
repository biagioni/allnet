/* xchat_socket.c: send and receive xchat messages over a socket */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "packet.h"
#include "lib/pipemsg.h"
#include "lib/util.h"
#include "lib/priority.h"
#include "lib/log.h"
#include "chat.h"
#include "cutil.h"
#include "retransmit.h"
#include "xcommon.h"

/* messages have a length, time, code, peer name, and text of the message. */
/* length (4 bytes, big-endian order) includes everything.
 * time (4 bytes, big-endian order) is the time of original transmission
 * code is 1 byte, value 0 for a data message
 * the peer name and the message are null-terminated
 */

static void send_message (int sock, int code, time_t time, const char * peer,
                          const char * message)
{
  int plen = strlen (peer) + 1;     /* include the null character */
  int mlen = strlen (message) + 1;  /* include the null character */
  int length = 9 + plen + mlen;
  int n;
  char buf [ALLNET_MTU];
  if (length > ALLNET_MTU) {
    printf ("error: wanting to send 5 + %d + %d = %d, MTU is %d\n",
            plen, mlen, length, ALLNET_MTU);
    return;
  }
  buf [0] = (length >> 24) & 0xff;
  buf [1] = (length >> 16) & 0xff;
  buf [2] = (length >>  8) & 0xff;
  buf [3] = (length      ) & 0xff;
  buf [4] = (time >> 24) & 0xff;
  buf [5] = (time >> 16) & 0xff;
  buf [6] = (time >>  8) & 0xff;
  buf [7] = (time      ) & 0xff;
  buf [8] = code;
  strcpy (buf + 9, peer);
  strcpy (buf + 9 + plen, message);
  n = send (sock, buf, length, MSG_DONTWAIT);
  if ((n != length) && ((errno == EAGAIN) || (errno == EWOULDBLOCK)))
    return;  /* socket is busy -- should never be, but who knows */
  if (n != length) {
    perror ("send");
    printf ("error: tried to send %d, only sent %d bytes on unix socket\n",
            length, n);
    exit (1);   /* terminate the program */
  }
  /* print_buffer (buf, length, "sent", 20, 1); */
}

/* return the message length if a message was received, and 0 otherwise */
/* both peer and message must have length ALLNET_MTU or more */
static int recv_message (int sock, int * code, time_t * time,
                         char * peer, char * message)
{
  char buf [ALLNET_MTU * 10];
  int n = recv (sock, buf, sizeof (buf), MSG_DONTWAIT);
  int len, plen, mlen;
  time_t sent_time;
  char * msg;
  if ((n < 0) && ((errno == EAGAIN) || (errno == EWOULDBLOCK)))
    return 0;
  if (n == 0) {    /* peer closed the socket */
    /* printf ("xchat_socket: received peer shutdown, exiting\n"); */
    exit (0);
  }
  if (n < 9) {
    perror ("recv");
    printf ("error: received %d bytes on unix socket\n", n);
    exit (0);
  }
  len = ((buf [0] & 0xff) << 24) | ((buf [1] & 0xff) << 16) |
        ((buf [2] & 0xff) <<  8) | ((buf [3] & 0xff)      );
  if (len != n) {
    printf ("error: received %d bytes but length is %d\n", n, len);
    return 0;
  }
  sent_time = ((buf [4] & 0xff) << 24) | ((buf [5] & 0xff) << 16) |
              ((buf [6] & 0xff) <<  8) | ((buf [7] & 0xff)      );
  *time = sent_time;
  *code = buf [8] & 0xff;
  if (*code != 0) {
    printf ("error: received code %d but only code 0 is supported\n", *code);
    return 0;
  }
  plen = strlen (buf + 9);
  if (plen >= ALLNET_MTU) {
    printf ("error: received peer length %d but only %d is supported\n",
            plen, ALLNET_MTU - 1);
    return 0;
  }
  msg = buf + 9 + plen + 1;
  mlen = strlen (msg);
  if (mlen >= ALLNET_MTU) {
    printf ("error: received message length %d but only %d is supported\n",
            mlen, ALLNET_MTU - 1);
    return 0;
  }
  strcpy (peer, buf + 9);
  strcpy (message, msg);
  return mlen;
}

static void request_free_peer (char * peer, int sock)
{
  if (peer != NULL) {
    request_and_resend (sock, peer);
    free (peer);
  }
}

int main (int argc, char ** argv)
{
  /* allegedly, openSSL does this for us */
  /* srandom (time (NULL));/* RSA encryption uses the random number generator */

  if (argc < 2) {
    printf ("%s should have one socket arg, and never be called directly!\n",
            argv [0]);
    return 0;
  }
  int forwarding_socket = atoi (argv [1]);

/*
  printf ("would be good to request old messages, in 2 ways:\n");
  printf (" - by sending out a data_request message, and\n");
  printf (" - by sending out a chat request message when we get out-of-seq\n");
*/

  int sock = xchat_init ();
  if (sock < 0)
    return 1;

  int timeout = 100;      /* sleep up to 1/10 second */
  char * old_peer = NULL;
  long long int seq = 0;
  while (1) {
    char to_send [ALLNET_MTU];
    char peer [ALLNET_MTU];
    int code;
    time_t time;
    int len = recv_message (forwarding_socket, &code, &time, peer, to_send);
    if (len > 0) {
      seq = send_data_message (sock, peer, to_send, strlen (to_send));
    }
    char * packet;
    int pipe, pri;
    int found = receive_pipe_message_any (timeout, &packet, &pipe, &pri);
    if (found < 0) {
      printf ("pipe closed, exiting\n");
      exit (1);
    }
    if (found == 0) {  /* timed out, request/resend any missing */
      request_free_peer (old_peer, sock);
      old_peer = NULL;
    } else {    /* found > 0, got a packet */
      int verified, duplicate;
      char * peer;
      char * desc;
      char * message;
      time_t time = 0;
      int mlen = handle_packet (sock, packet, found, &peer, &message, &desc,
                                &verified, &time, &duplicate);
      if (mlen > 0) {
        if (! duplicate)
          send_message (forwarding_socket, 0, time, peer, message);
        if ((old_peer == NULL) || (strcmp (old_peer, peer) != 0)) {
          request_free_peer (old_peer, sock);
          old_peer = peer;
        } else { /* same peer, do nothing */
          free (peer);
        }
        free (message);
        free (desc);
      }
    }
  }
}
