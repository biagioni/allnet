/* subscribe.c: request a key for a given Allnet Human Readable Address, AHRA */
/* parameter: an AHRA, such as "a personal phrase"@word_pairs.word_pairs */
/* if it obtains the key, it saves it and returns */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lib/packet.h"
#include "lib/pipemsg.h"
#include "lib/util.h"
#include "lib/sha.h"
#include "lib/priority.h"
#include "lib/cipher.h"
#include "lib/keys.h"

static int send_key_request (int sock, char * phrase,
                             char * pubkey, int ksize) 
{
  /* compute the destination address from the phrase */
  char destination [ADDRESS_SIZE];
  char * mapped;
  int mlen = map_string (phrase, &mapped);
  sha512_bytes (mapped, mlen, destination, 1);
  free (mapped);

  int dsize = 1 + ksize;  /* nbits_fingerprint plust the key */
  int psize;
  struct allnet_header * hp =
    create_packet (dsize, ALLNET_TYPE_KEY_REQ, 10, ALLNET_SIGTYPE_NONE,
                   NULL, 0, destination, 8, NULL, &psize);
  
  if (hp == NULL)
    return 0;
  int hsize = ALLNET_SIZE(hp->transport);
  if (psize != hsize + dsize) {
    printf ("send_key_request error: psize %d != %d = %d + %d\n", psize,
            hsize + dsize, hsize, dsize);
    return 0;
  }
  char * packet = (char *) hp;

  struct allnet_key_request * kp =
    (struct allnet_key_request *) (packet + hsize);
  kp->nbits_fingerprint = 0;
  char * reply_key = packet + hsize + 1;
  memcpy (reply_key, pubkey, ksize);

/* printf ("sending %d-byte key request\n", psize); */
  if (! send_pipe_message_free (sock, packet, psize, ALLNET_PRIORITY_LOCAL)) {
    printf ("unable to send key request message\n");
    return 0;
  }
  return 1;
}

static int handle_packet (char * message, int msize,
                          char * privkey, int ksize, char * ahra, int debug)
{
  if (! is_valid_message (message, msize)) {
    printf ("got invalid message of size %d\n", msize);
    return 0;
  }
  if (debug)
    print_packet (message, msize, "handle_packet", 1);
  struct allnet_header * hp = (struct allnet_header *) message;
  int hsize = ALLNET_SIZE (hp->transport);
  if (hp->message_type != ALLNET_TYPE_DATA)
    return 0;
  if (msize <= hsize)  /* nothing to decrypt */
    return 0;

  char * after_header = message + hsize;
  /* print_buffer (after_header, msize - hsize, "payload", 900, 1); */
  char * text;
  int tsize = decrypt (after_header, msize - hsize, privkey, ksize, &text);
  if (tsize <= 0) {
    printf ("decryption of %d bytes with %d-byte key failed\n",
            msize - hsize, ksize);
    return 0;
  }

  int correct = verify_bc_key (ahra, text, tsize, "en", 16, 1);
  if (correct)
    printf ("received key %s does verify, saved\n", ahra);
  else
    printf ("received key does not verify\n");
  free (text);
  return correct;  /* we are done */
}

static void wait_for_response (int sock, char * phrase,
                               char * privkey, int privsize, char * ahra,
                               int debug)
{
  while (1) {
    int pipe;
    int pri;
    char * message;
    int found = receive_pipe_message_any (PIPE_MESSAGE_WAIT_FOREVER, &message,
                                          &pipe, &pri);
    if (found <= 0) {
      printf ("pipe closed, exiting\n");
      exit (1);
    }
    if (handle_packet (message, found, privkey, privsize, ahra, debug))
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
  int debug = debug_switch (&argc, argv);
  if (argc < 2)
    usage (argv [0], "did not provide the AHRA");
  if (argc > 2)
    usage (argv [0], "had more than one argument (maybe you forgot quotes?)");
  char * phrase;
  char * reason = "did not parse";
  if (! parse_ahra (argv [1], &phrase, NULL, NULL, NULL, NULL, &reason))
    usage (argv [0], reason);

  int sock = connect_to_local (argv [0]);
  if (sock < 0)
    return 1;
  add_pipe (sock);

  char * pubkey;
  char * privkey;
  int privsize;
  int ksize = get_temporary_key (&pubkey, &privkey, &privsize);
  /* print_buffer (pubkey, ksize, "public key", ksize, 1); */
  if (send_key_request (sock, phrase, pubkey, ksize)) 
    wait_for_response (sock, phrase, privkey, privsize, argv [1], debug);
  free (pubkey);   /* not very useful, just pro forma */
  free (privkey);
}

