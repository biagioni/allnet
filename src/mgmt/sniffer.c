/* sniffer.c: show all incoming messages */

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

static int handle_packet (char * message, int msize, int * rcvd, int debug,
                          int verify)
{
  *rcvd = 0;
  struct timeval receive_time;
  gettimeofday (&receive_time, NULL);

  if (! is_valid_message (message, msize)) {
    printf ("got invalid message of size %d\n", msize);
    return 0;
  }
  *rcvd = 1;
  print_packet (message, msize, "received: ", 1);
  struct allnet_header * hp = (struct allnet_header *) message;
  char * data = ALLNET_DATA_START (hp, hp->transport, msize); 
  int dsize = msize - (data - message);
  print_buffer (data, dsize, "   payload:", 16, 1);
  if (verify && (hp->message_type == ALLNET_TYPE_DATA)) {
    char * contact;
    char * text;
    keyset k;
    int tsize = decrypt_verify (hp->sig_algo, data, dsize, &contact, &k, &text,
                                NULL, 0, NULL, 0, 0);
    if (tsize > 0)
      print_buffer (text, tsize, " decrypted:", 16, 1);
  }
  return 0;
}

static void main_loop (int sock, int debug, int max, int verify)
{
  while (1) {
    int pipe;
    int pri;
    char * message;
    int found = receive_pipe_message_any (PIPE_MESSAGE_WAIT_FOREVER, &message,
                                          &pipe, &pri);
    if (found <= 0) {
      printf ("packet sniffer pipe closed, exiting\n");
      exit (1);
    }
    int received = 0;
    if (handle_packet (message, found, &received, debug, verify))
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
/* option -y: see if can verify each message */
int main (int argc, char ** argv)
{
  int verbose = get_option ('v', &argc, argv);
  log_to_output (verbose);
  int verify = get_option ('y', &argc, argv);

  int sock = connect_to_local (argv [0], argv [0]);
  if (sock < 0)
    return 1;

  int debug = debug_switch (&argc, argv);
  if (verbose && (! debug))
    debug = 1;

  int max = 0;
  if (argc > 1)
    max = atoi (argv [1]);

  main_loop (sock, debug, max, verify);
  return 0;
}

