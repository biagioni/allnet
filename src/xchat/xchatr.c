/* xchatr.c: receive xchat messages */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lib/packet.h"
#include "lib/pipemsg.h"
#include "lib/util.h"
#include "lib/priority.h"
#include "lib/log.h"
#include "chat.h"
#include "cutil.h"
#include "retransmit.h"
#include "xcommon.h"

/* global debugging variable -- if 1, expect more debugging output */
/* set in main */
int allnet_global_debugging = 0;

int main (int argc, char ** argv)
{
  int verbose = get_option ('v', &argc, argv);
  if (verbose)
    allnet_global_debugging = verbose;

  int sock = xchat_init (argv [0]);
  if (sock < 0)
    return 1;

  char * contact = NULL;
  char * secret = NULL;
#define MAX_SECRET	15  /* including a terminating null character */
  char secret_buf [MAX_SECRET];
  int key_hops = 0;
  int print_duplicates = 0;
  int seeking_key = 0;
  int i;
  for (i = 1; i < argc; i++) {
    if (strcmp (argv [i], "-a") == 0)
      print_duplicates = 1;
    if ((i + 1 < argc) && (strcmp (argv [i], "-k") == 0)) {
      seeking_key = 1;
      /* -k contact-name [max-hops]: exchange keys for this new contact */
      contact = argv [i + 1];
      if (i + 2 < argc) {
        char * end;
        int n = strtol (argv [i + 2], &end, 10);
        if (end != argv [i + 2])
          key_hops = n;
      }
      if (key_hops <= 0)
        key_hops = 1;
      int secret_len = sizeof (secret_buf);
      if (key_hops <= 1)
        secret_len = 7;  /* including null byte, so only 6 actual chars */
      random_string (secret_buf, secret_len);
      secret = secret_buf;
      printf ("%d hops, my secret string is '%s'", key_hops, secret);
      normalize_secret (secret);
      printf (" (or %s)\n", secret);
      create_contact_send_key (sock, contact, secret, NULL, key_hops);
    }
  }

  int timeout = PIPE_MESSAGE_WAIT_FOREVER;
  char * old_contact = NULL;
  keyset old_kset = -1;
  while (1) {
    char * packet;
    int pipe, pri;
    int found = receive_pipe_message_any (timeout, &packet, &pipe, &pri);
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
      int mlen = handle_packet (sock, packet, found, &peer, &kset,
                                &message, &desc, &verified, NULL, &duplicate,
                                &broadcast, contact, secret, NULL, key_hops,
                                NULL, NULL, 0);
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
        if ((! duplicate) || (print_duplicates) || (broadcast))
          printf ("from '%s'%s got %s%s%s\n  %s\n", peer, ver_mess, dup_mess,
                  bc_mess, desc, message);
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
      } else if ((mlen == -1) && (seeking_key)) {
        printf ("success!  got remote key for %s\n", contact);
      }
    }
  }
}
