/* xchatr.c: receive xchat messages */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../packet.h"
#include "../lib/pipemsg.h"
#include "../lib/util.h"
#include "../lib/priority.h"
#include "chat.h"
#include "cutil.h"
#include "retransmit.h"
#include "xcommon.h"

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

  int sock = xchat_init ();
  if (sock < 0)
    return 1;

  int timeout = PIPE_MESSAGE_WAIT_FOREVER;
  char * old_peer = NULL;
  while (1) {
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
      timeout = PIPE_MESSAGE_WAIT_FOREVER; /* cancel future timeouts */
    } else {    /* found > 0, got a packet */
      int verified, duplicate;
      char * peer;
      char * desc;
      char * message;
      int mlen = handle_packet (sock, packet, found, &peer, &message, &desc,
                                &verified, NULL, &duplicate);
      if (mlen > 0) {
        printf ("from '%s' got %s\n  %s\n", peer, desc, message);
        if ((old_peer == NULL) || (strcmp (old_peer, peer) != 0)) {
          request_free_peer (old_peer, sock);
          old_peer = peer;
          timeout = 100;   /* time before next request, 100ms == 0.1seconds */
        } else { /* same peer, do nothing */
          free (peer);
        }
        free (message);
        free (desc);
      }
    }
  }
}
