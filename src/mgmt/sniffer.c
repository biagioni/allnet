/* sniffer.c: show all incoming messages */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
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

static char * hms (char * time_string)
{
  /* format is "Tue Mar  3 20:28:06 2015 HST" */
  char * space = rindex (time_string, ' ');
  if (space != NULL) {
    *space = '\0';  /* get rid of timezone */
    space = rindex (time_string, ' ');
    if (space != NULL) {
      *space = '\0';  /* get rid of year */
      space = rindex (time_string, ' ');
      if (space != NULL)
        return space + 1; /* get rid of day-of-week, month, and day-of-month */
    }
  }
  return "";
}

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
  char time_string [ALLNET_TIME_STRING_SIZE];
  allnet_localtime_string (allnet_time (), time_string);
  printf ("%s ", hms (time_string));
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

static int received_before (char * message, int mlen)
{
#define MAX_MESSAGES	1000
#define MESSAGE_STORAGE	(ALLNET_MTU + 2)
  static char * received_before = NULL;
  static int latest_received = 0;
  if (received_before == NULL) {
    received_before = malloc_or_fail (MESSAGE_STORAGE * MAX_MESSAGES,
                                      "storage of unique packets");
    memset (received_before, 0, MESSAGE_STORAGE * MAX_MESSAGES);
  }
  char * ptr;
  int i;
  for (i = 0; i < MAX_MESSAGES; i++) {
    ptr = received_before + (MESSAGE_STORAGE * i); 
    int len = readb16 (ptr);
    ptr += 2;  /* point to the message itself */
    if ((len > ALLNET_HEADER_SIZE) && (len == mlen) &&
        /* separately compare all but the byte at position 2 (hop count) */
        (memcmp (ptr, message, 2) == 0) &&
        (memcmp (ptr + 3, message, mlen - 3) == 0))
      return 1;
  }
  latest_received = (latest_received + 1) % MAX_MESSAGES;
  ptr = received_before + (MESSAGE_STORAGE * latest_received);
  writeb16 (ptr, mlen);
  memcpy (ptr + 2, message, mlen);
  return 0;
#undef MAX_MESSAGES
#undef MESSAGE_STORAGE
}

static void main_loop (int sock, int debug, int max, int verify, int unique)
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
    if ((! unique) || (! received_before (message, found))) {
      int received = 0;
      if (handle_packet (message, found, &received, debug, verify))
        return;
      if ((max > 0) && (received)) {
        max--;
        if (max == 0)
          return;
      }
    }
    free (message);
  }
}

#if 0
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
#endif /* 0 */

/* global debugging variable -- if 1, expect more debugging output */
/* set in main */
int allnet_global_debugging = 0;

/* optional argument: quit after n messages */
/* option -y: see if can verify each message */
int main (int argc, char ** argv)
{
  /* even if using gnu getopt, behave in a standard manner */
  setenv ("POSIXLY_CORRECT", "", 0);
  int verbose = 0;
  int debug = 0;
  int verify = 0;
  int unique = 0;
  int opt;
  while ((opt = getopt (argc, argv, "vdyu")) != -1) {
    switch (opt) {
    case 'd': debug = 1; break;
    case 'v': verbose = 1; break;
    case 'y': verify = 1; break;
    case 'u': unique = 1; break;
    default:
      printf ("usage: %s [-v] [-d] [-y] [-u] [number-of-messages]\n", argv [0]);
      printf ("       -v: verbose, -d: debug, -y: verify sig, -u: unique only");
      exit (1);
    }
  }
  if (verbose)
    debug = 1;
  log_to_output (verbose);

  int sock = connect_to_local (argv [0], argv [0]);
  if (sock < 0)
    return 1;

  int max = 0;
  if (argc > optind)
    max = atoi (argv [optind]);

  main_loop (sock, debug, max, verify, unique);
  return 0;
}

