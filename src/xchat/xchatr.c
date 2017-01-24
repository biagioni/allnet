/* xchatr.c: receive xchat messages */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "lib/packet.h"
#include "lib/pipemsg.h"
#include "lib/util.h"
#include "lib/priority.h"
#include "lib/allnet_log.h"
#include "chat.h"
#include "cutil.h"
#include "retransmit.h"
#include "xcommon.h"

int main (int argc, char ** argv)
{
  log_to_output (get_option ('v', &argc, argv));
  struct allnet_log * log = init_log ("xchatr");
  pd p = init_pipe_descriptor (log);
  int sock = xchat_init (argv [0], p);
  if (sock < 0)
    return 1;

  int print_duplicates = 0;
  int i;
  for (i = 1; i < argc; i++) {
    if (strcmp (argv [i], "-a") == 0)
      print_duplicates = 1;
  }

  int timeout = PIPE_MESSAGE_WAIT_FOREVER;
  char * old_contact = NULL;
  keyset old_kset = -1;
  while (1) {
    char * packet;
    int pipe;
    unsigned int pri;
    int found = receive_pipe_message_any (p, timeout, &packet, &pipe, &pri);
    if (found < 0) {
      printf ("xchatr pipe closed, exiting\n");
      exit (1);
    }
    if (found == 0) {  /* timed out, request/resend any missing */
      if (old_contact != NULL) {
        request_and_resend (sock, old_contact, old_kset);
        old_contact = NULL;
        old_kset = -1;
      }
      timeout = PIPE_MESSAGE_WAIT_FOREVER; /* cancel future timeouts */
    } else {    /* found > 0, got a packet */
      int verified, duplicate, broadcast;
      char * peer;
      keyset kset;
      char * desc;
      char * message;
      int mlen = handle_packet (sock, packet, found, &peer, &kset, NULL,
                                &message, &desc, &verified, NULL, &duplicate,
                                &broadcast, NULL, NULL, NULL,
                                NULL, 0, 0, NULL, NULL, 0);
      if (mlen > 0) {
        /* time_t rtime = time (NULL); */
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
        if ((! duplicate) || (print_duplicates) || (broadcast))
          printf ("from '%s'%s got %s%s%s\n  %s\n",
                  peer, ver_mess, dup_mess, bc_mess, desc, message);
        if ((! broadcast) &&
            ((old_contact == NULL) ||
             (strcmp (old_contact, peer) != 0) || (old_kset != kset))) {
          request_and_resend (sock, peer, kset);
          if (old_contact != NULL)
            free (old_contact);
          old_contact = peer;
          old_kset = kset;
          timeout = 100;   /* time before next request, 100ms == 0.1seconds */
        } else {  /* same peer */
          free (peer);
        }
        free (message);
        if (! broadcast)
          free (desc);
      } 
    }
  }
}
