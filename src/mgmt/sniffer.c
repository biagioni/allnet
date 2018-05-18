/* sniffer.c: show all incoming messages */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "lib/app_util.h"
#include "lib/packet.h"
#include "lib/mgmt.h"
#include "lib/media.h"
#include "lib/sockets.h"
#include "lib/util.h"
#include "lib/app_util.h"
#include "lib/sha.h"
#include "lib/allnet_log.h"
#include "lib/priority.h"
#include "lib/cipher.h"
#include "lib/keys.h"

/* whenever we set the types variable, the low bit will be 0 because 0 is
 * not a valid packet type.  So we can distinguish ALL_PACKET_TYPES from
 * anything the user may set. */
/* we really only need the bits set up to the maximum packet type, setting
 * all the bits is an attempt at future-proofing.  But if the last packet
 * type is no longer ALLNET_TYPE_MGMT, must replace the value below. */
#define ALL_PACKET_TYPES	0x7fffffff
#define MAX_PACKET_TYPE		ALLNET_TYPE_MGMT

static char * hms (char * time_string)
{
  /* format is "Tue Mar  3 20:28:06 2015 HST" */
  char * space = strrchr (time_string, ' ');
  if (space != NULL) {
    *space = '\0';  /* get rid of timezone */
    space = strrchr (time_string, ' ');
    if (space != NULL) {
      *space = '\0';  /* get rid of year */
      space = strrchr (time_string, ' ');
      if (space != NULL)
        return space + 1; /* get rid of day-of-week, month, and day-of-month */
    }
  }
  return "";
}

static int handle_packet (char * message, unsigned int msize, int * rcvd,
                          int debug, int verify, int types, int subtypes,
                          int full_payloads,
                          unsigned char * src, unsigned int src_bits,
                          unsigned char * dst, unsigned int dst_bits)
{
  *rcvd = 0;
  struct timeval receive_time;
  gettimeofday (&receive_time, NULL);
  int max = (full_payloads ? msize : 100);

  struct allnet_header * hp = (struct allnet_header *) message;
  char * reason = NULL;
  if (! is_valid_message (message, msize, &reason)) {
    int saved_hops = -1;
    int print_msg = 0;
    if ((msize > ALLNET_HEADER_SIZE) && (hp->hops > hp->max_hops)) {
      /* if a packet is valid but has invalid hop count, show anyway */
      saved_hops = hp->hops;
      hp->hops = hp->max_hops;
      print_msg = (! is_valid_message (message, msize, &reason));
      hp->hops = saved_hops;
    }
    if (print_msg) {
      printf ("sniffer got invalid message (%s): ", reason);
      print_buffer (message, msize, "", max, 1);
    }
    return 0;
  }
  int type = hp->message_type;
  if ((type >= 0) && (type <= MAX_PACKET_TYPE) && (! ((1 << type) & types)))
    return 0;  /* do not print this type of packet */
  if ((type == ALLNET_TYPE_MGMT) && (subtypes != ~0) &&
      (msize >= ALLNET_MGMT_HEADER_SIZE (hp->transport))) {
    struct allnet_mgmt_header * ah = (struct allnet_mgmt_header *)
      (ALLNET_DATA_START (hp, hp->transport, msize));
    int subtype = ah->mgmt_type;
    if ((subtype >= 0) && (subtype <= 32) && (! ((1 << subtype) & subtypes)))
      return 0;
  }
  if (((src_bits > 0) &&
       (matching_bits (src, src_bits, hp->source, hp->src_nbits) < src_bits)) ||
      ((dst_bits > 0) &&
       (matching_bits (dst, dst_bits,
                       hp->destination, hp->dst_nbits) < dst_bits))) {
    return 0;  /* does not match the source or destination address */
  }
  *rcvd = 1;
  char time_string [ALLNET_TIME_STRING_SIZE];
  allnet_localtime_string (allnet_time (), time_string);
  printf ("%s ", hms (time_string));
  print_packet (message, msize, "received: ", 1);
  char * data = ALLNET_DATA_START (hp, hp->transport, msize); 
  int dsize = msize - (data - message);
  print_buffer (data, dsize, "   payload:", max, 1);
  if (verify) {
    if (hp->message_type == ALLNET_TYPE_DATA) {
      char * contact;
      char * text;
      keyset k;
      int tsize = decrypt_verify (hp->sig_algo, data, dsize, &contact, &k,
                                  &text, NULL, 0, NULL, 0, 0);
      if (tsize > 0) {
        print_buffer (text, tsize, " decrypted:", 100, 0);
        if (tsize > 40) {
          int len = tsize - 40;
          char * copy = malloc_or_fail (len + 1, "sniffer/handle_packet");
          memcpy (copy, text + 40, len);
          copy [len] = '\0';
          printf (" (%s)", copy);
          free (copy);
        }
        printf ("\n");
        free (text);
      }
    } else if ((hp->message_type == ALLNET_TYPE_CLEAR) && 
               (hp->sig_algo != ALLNET_SIGTYPE_NONE)) {
      int verified = 0;
      int ssize = readb16 (data + dsize - 2) + 2;
      if ((ssize > 2) && (ssize < dsize)) {
        int msize = dsize - ssize;  /* size of text message */
        char * likely_start = data + sizeof (struct allnet_app_media_header);
        char * likely_end = data + msize;
        char * sig = data + msize;
        struct bc_key_info * keys;
        int nkeys = get_other_keys (&keys);
        int i;
        for (i = 0; i < nkeys; i++) {
printf (" %d: attempting to verify with %s\n", i, keys [i].identifier);
          if (allnet_verify (data, dsize - ssize, sig, ssize - 2,
                             keys [i].pub_key)) {
            *likely_end = '\0';
            printf (" verified with %s: %s\n",
                    keys [i].identifier, likely_start);
            verified = 1;
            break;
          }
        }
        nkeys = get_own_keys (&keys);
        for (i = 0; i < nkeys; i++) {
printf (" %d: attempting to verify with own key %s\n", i, keys [i].identifier);
          if (allnet_verify (data, dsize - ssize, sig, ssize - 2,
                             keys [i].pub_key)) {
            *likely_end = '\0';
            printf (" verified (own %s): %s\n",
                    keys [i].identifier, likely_start);
            verified = 1;
            break;
          }
        }
      }
      if (! verified) {
        if ((ssize > 2) && (ssize < dsize)) {
          data [dsize - ssize] = '\0';
          printf (" (not verified %s)\n",
                  data + sizeof (struct allnet_app_media_header));
        } else {
          char c = data [dsize - 1];  /* so we can null terminate */
          data [dsize - 1] = '\0';  
          printf (" (not verified, no sig: %s%c)\n",
                  data + sizeof (struct allnet_app_media_header), c);
        }
      }
    }
  }
  return 0;
}

static int received_before (char * message, unsigned int mlen)
{
#define MAX_MESSAGES	1000
#define MESSAGE_STORAGE	(ALLNET_MTU + 2)
  static char * received_before = NULL;
  static int latest_received = 0;
  if (received_before == NULL) {  /* only true on the first call */
    received_before = malloc_or_fail (MESSAGE_STORAGE * MAX_MESSAGES,
                                      "storage of unique packets");
    memset (received_before, 0, MESSAGE_STORAGE * MAX_MESSAGES);
  }
  char * ptr;
  int i;
  for (i = 0; i < MAX_MESSAGES; i++) {
    ptr = received_before + (MESSAGE_STORAGE * i); 
    unsigned int len = readb16 (ptr);
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

static void main_loop (int debug, int max, int verify, int unique,
                       int types, int subtypes, int full,
                       unsigned char * src, unsigned int src_bits,
                       unsigned char * dst, unsigned int dst_bits)
{
  while (1) {
    unsigned int pri;
    char * message;
    int found = local_receive (SOCKETS_TIMEOUT_FOREVER, &message, &pri);
    if (found <= 0) {
      printf ("packet sniffer pipe closed, exiting\n");
      exit (1);
    }  /* found > 0 */
    if ((! unique) || (! received_before (message, found))) {
      int received = 0;
      if (handle_packet (message, found, &received, debug, verify,
                         types, subtypes, full, src, src_bits, dst, dst_bits))
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

static void usage (const char * command)
{
  printf ("usage: %s [-v] [-d] [-y] [-u] [-f] [-t type]* "
          " [-a destination address] [-s source] [number-of-messages]\n",
          command);
  printf ("       -v: verbose, -d: debug, -y: verify sig, -u: unique only");
  printf ("       -f: print full message payloads, not abbreviated");
  printf ("       -t n: only show messages of type n -- may be repeated\n");
  printf ("       -a x, -s x: only show messages with source/dest x\n");
  printf ("       (repeating the SAME type, toggles it)\n");
  exit (1);
}

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
  int full_payloads = 0;
  int types = ALL_PACKET_TYPES;
  int type = -1;
  int subtype = -1;  /* for mgmt packets can specify subtype */
  int subtypes = ~0; /* all subtypes */
  int opt;
  unsigned long long int addr_int = 0;
  unsigned char dst [ADDRESS_SIZE];
  unsigned char src [ADDRESS_SIZE];
  memset (dst, 0, ADDRESS_SIZE);
  memset (src, 0, ADDRESS_SIZE);
  unsigned int dst_bits = 0;
  unsigned int src_bits = 0;
  char * end = NULL;
  while ((opt = getopt (argc, argv, "vdyufa:s:t:")) != -1) {
    switch (opt) {
    case 'd': debug = 1; break;
    case 'v': verbose = 1; break;
    case 'y': verify = 1; break;
    case 'u': unique = 1; break;
    case 'f': full_payloads = 1; break;
    case 's': /* source address */
      addr_int = strtoll (optarg, &end, 16);
      src_bits = (end - optarg) * 4;
      addr_int = addr_int << (64 - src_bits);  /* shift all the way left */
      writeb64u (src, addr_int);
      break;
    case 'a': /* destination address */
      addr_int = strtoll (optarg, &end, 16);
      dst_bits = (end - optarg) * 4;
      addr_int = addr_int << (64 - dst_bits);  /* shift all the way left */
      writeb64u (dst, addr_int);
      break;
    case 't': /* packet type */
      subtype = -1;   /* needs to be reset on each loop */
      if ((strncmp (optarg, "7.", 2) == 0) &&
          (strlen (optarg) > 2)) {
        type = 7;
        subtype = atoi (optarg + 2);
        int mask = 1 << subtype;
        if (subtypes == ~0)
          subtypes = mask;
        else if (subtypes & mask)  /* already set, clear */
          subtypes &= ~mask;
        else
          subtypes |= mask;
      } else {
        type = atoi (optarg);
      }
      if ((type != 0) && (type <= MAX_PACKET_TYPE)) {  /* valid parameter */
        int mask = 1 << type;
        if (types == ALL_PACKET_TYPES)  /* never set before */
          types = mask;
        else if ((types & mask) && (subtype == -1))  /* already set, clear */
          types &= ~mask;
        else
          types |= mask;
#ifdef DEBUG_PRINT
        printf ("type %d, mask %x, types %x\n", type, mask, types);
#endif /* DEBUG_PRINT */
        break;
      }  /* else print usage */
    default:
      usage (argv [0]);
      exit (1);
    }
  }
  if (verbose)
    debug = 1;
  log_to_output (verbose);

  if (connect_to_local (argv [0], argv [0], NULL, 1, 1) < 0)
    return 1;

  int max = 0;
  if (argc > optind)
    max = atoi (argv [optind]);

  main_loop (debug, max, verify, unique, types, subtypes, full_payloads,
             src, src_bits, dst, dst_bits);
  return 0;
}

