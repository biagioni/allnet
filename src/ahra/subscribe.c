/* subscribe.c: request a key for a given Allnet Human Readable Address, AHRA */
/* parameter: an AHRA, such as "a personal phrase"@word_pairs.word_pairs */
/* if it obtains the key, it saves it and returns */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lib/packet.h"
#include "lib/media.h"
#include "lib/util.h"
#include "lib/app_util.h"
#include "lib/sha.h"
#include "lib/priority.h"
#include "lib/cipher.h"
#include "lib/keys.h"
#include "lib/mapchar.h"
#include "lib/allnet_log.h"

/* source must be ADDRESS_SIZE, and here will be filled in with random data */
static int send_key_request (int sock, char * phrase, char * source, int slen,
                             struct allnet_log * alog)
{
  /* compute the destination address from the phrase */
  unsigned char destination [ADDRESS_SIZE];
  char * mapped;
  int mlen = map_string (phrase, &mapped);
  sha512_bytes (mapped, mlen, (char *) destination, 1);
  free (mapped);

#define EMPTY_FINGERPRINT_SIZE	1  /* nbits_fingerprint plus the fingerprint */
  unsigned int dsize = EMPTY_FINGERPRINT_SIZE + KEY_RANDOM_PAD_SIZE;
  unsigned int psize;
  struct allnet_header * hp =
    create_packet (dsize, ALLNET_TYPE_KEY_REQ, 10, ALLNET_SIGTYPE_NONE,
                   (unsigned char *) source, slen * 8, destination, 8,
                   NULL, NULL, &psize);
  
  if (hp == NULL)
    return 0;
  unsigned int hsize = ALLNET_SIZE(hp->transport);
  if (psize != hsize + dsize) {
    printf ("send_key_request error: psize %d != %d = %d + %d\n", psize,
            hsize + dsize, hsize, dsize);
    return 0;
  }
  char * packet = (char *) hp;

  struct allnet_key_request * kp =
    (struct allnet_key_request *) (packet + hsize);
  kp->nbits_fingerprint = 0;
  char * r = ((char *) kp) + EMPTY_FINGERPRINT_SIZE;
  random_bytes (r, KEY_RANDOM_PAD_SIZE);

/* printf ("sending %d-byte key request\n", psize); */
  int ret = (local_send (packet, psize, ALLNET_PRIORITY_LOCAL));
  if (! ret)
    printf ("unable to send key request message\n");
  return ret;
}

static int handle_packet (char * message, int msize,
                          char * ahra, char * address, int alen, int debug)
{
  char * reason = NULL;
  if (! is_valid_message (message, msize, &reason)) {
    if (debug) {
      printf ("got invalid message: %s ", reason);
      print_buffer (message, msize, NULL, 32, 1);
    }
    return 0;
  }
  if (debug)
    print_packet (message, msize, "handle_packet", 1);
  struct allnet_header * hp = (struct allnet_header *) message;
  int hsize = ALLNET_SIZE (hp->transport);
  int h2size = sizeof (struct allnet_app_media_header);
  if (hp->message_type != ALLNET_TYPE_CLEAR)
    return 0;
  if (msize <= hsize + h2size + KEY_RANDOM_PAD_SIZE)  /* nothing */
    return 0;
  if (memcmp (address, hp->destination, alen) != 0)  /* not for me */
    return 0;
  int ksize = msize - (hsize + h2size) - KEY_RANDOM_PAD_SIZE;

  char * amp = message + hsize;
  struct allnet_app_media_header * amhp =
    (struct allnet_app_media_header *) amp;
  if (readb32u (amhp->media) != ALLNET_MEDIA_PUBLIC_KEY)
    return 0;
  char * key = amp + h2size;
  print_buffer (key, ksize, "subscribe received key", 10, 1);

  int correct = verify_bc_key (ahra, key, ksize, "en", 16, 1);
  if (correct)
    printf ("received key %s does verify, saved\n", ahra);
  else
    printf ("received key does not verify\n");
  return correct;  /* we are done */
}

static void wait_for_response (char * phrase, char * ahra,
                               char * address, int alen, int debug)
{
  while (1) {
    unsigned int pri;
    char * message;
    int found = local_receive (-1, &message, &pri);
    if (found <= 0) {
      printf ("allnet-subscribe pipe closed, exiting\n");
      exit (1);
    }
    if (handle_packet (message, found, ahra, address, alen, debug))
      return;
    free (message);
  }
}

static void usage (char * pname, char * reason)
{
  printf ("usage: %s 'Allnet Human Readable Address' (AHRA)\n", pname);
  printf ("an AHRA has two parts, usually separated by '@'\n");
  printf ("1. a personal phrase (often enclosed in matching quotes)\n");
  printf ("2. a sequence of word pairs identifying the public key\n");
  printf ("optionally, these may be followed by:\n");
  printf ("   a language, such as ',en' and/or\n");
  printf ("   a number of bits to match such as ',16'\n");
  printf ("your command %s\n", reason);
  exit (1);
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

int main (int argc, char ** argv)
{
  int verbose = get_option ('v', &argc, argv);
  log_to_output (verbose);
  int debug = debug_switch (&argc, argv);
   if ((verbose) && (debug <= 0))
     debug = 1;
  if (argc < 2)
    usage (argv [0], "did not provide the AHRA");
  if (argc > 2)
    usage (argv [0], "had more than one argument (maybe you forgot quotes?)");
  char * phrase;
  char * reason = "did not parse";
  if (! parse_ahra (argv [1], &phrase, NULL, NULL, NULL, NULL, &reason))
    usage (argv [0], reason);

  struct allnet_log * alog = init_log ("subscribe");
  /* pd p = init_pipe_descriptor (alog); */
  int sock = connect_to_local (argv [0], argv [0], NULL, 1);
  if (sock < 0)
    return 1;

  /* create a random source address */
  char source [ADDRESS_SIZE];
  random_bytes (source, sizeof (source));
  if (send_key_request (sock, phrase, source, sizeof (source), alog)) 
    wait_for_response (phrase, argv [1], source, sizeof (source), debug);
  return 0;
}

