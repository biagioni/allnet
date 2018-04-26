/* xchatr.c: receive xchat messages */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "lib/packet.h"
#include "lib/util.h"
#include "lib/priority.h"
#include "lib/allnet_log.h"
#include "lib/app_util.h"
#include "lib/sockets.h"
#include "chat.h"
#include "cutil.h"
#include "retransmit.h"
#include "xcommon.h"

int main (int argc, char ** argv)
{
  log_to_output (get_option ('v', &argc, argv));
  int sock = xchat_init (argv [0], NULL);
  if (sock < 0)
    return 1;

  int print_duplicates = 0;
  int i;
  for (i = 1; i < argc; i++) {
    if (strcmp (argv [i], "-a") == 0)
      print_duplicates = 1;
  }

  int max_count = 0;
  int received_count = 0;
  for (i = 1; i + 1 < argc; i++) {
    if (strcmp (argv [i], "-m") == 0) {
      int n = atoi (argv [i + 1]);
      if (n > 0)
        max_count = n;
      printf ("will quit after %d packets\n", n);
    }
  }

  int timeout = SOCKETS_TIMEOUT_FOREVER;
  char * old_contact = NULL;
  keyset old_kset = -1;
  while (1) {
    char * packet;
    unsigned int pri;
    int found = local_receive (timeout, &packet, &pri);
    if (found < 0) {
      printf ("xchatr pipe closed, exiting\n");
      exit (1);
    }
    if (found == 0) {  /* timed out, request/resend any missing */
      if (old_contact != NULL) {
        request_and_resend (sock, old_contact, old_kset, 0);
        old_contact = NULL;
        old_kset = -1;
      }
      timeout = SOCKETS_TIMEOUT_FOREVER; /* cancel future timeouts */
    } else {    /* found > 0, got a packet */
      int verified = 0, duplicate = -1, broadcast = -2;
      uint64_t seq = 0;
      char * peer = NULL;
      keyset kset = 0;
      char * desc = NULL;
      char * message = NULL;
      int mlen = handle_packet (sock, packet, found, pri, &peer, &kset,
                                &message, &desc, &verified, &seq, NULL,
                                &duplicate, &broadcast, NULL, NULL);
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
        if ((! duplicate) || (print_duplicates)) {
          printf ("from '%s'%s got %s%s%s\n  %s\n",
                  peer, ver_mess, dup_mess, bc_mess, desc, message);
          if ((max_count != 0) && (++received_count >= max_count))
            return 0;
        }
        if ((! broadcast) &&
            ((old_contact == NULL) ||
             (strcmp (old_contact, peer) != 0) || (old_kset != kset))) {
          request_and_resend (sock, peer, kset, 1);
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
