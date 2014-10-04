/* xkeys.c: create public key and send public key message */
/* parameters are: contact name, secret string, and number of hops */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "lib/app_util.h"
#include "lib/packet.h"
#include "lib/pipemsg.h"
#include "lib/util.h"
#include "lib/priority.h"
#include "lib/sha.h"
#include "lib/cipher.h"
#include "lib/keys.h"
#include "lib/log.h"
#include "chat.h"
#include "cutil.h"

static void send_ack (int s, char * packet, char * address, int nbits,
                      char * message_ack)
{
  struct allnet_header * hp = (struct allnet_header *) packet;
  int asize;
  struct allnet_header * ackp =
    create_ack (hp, message_ack, address, nbits, &asize);
  char * ack = (char *) ackp;
  if (! send_pipe_message_free (s, ack, asize, ALLNET_PRIORITY_LOCAL))
    printf ("unable to send key ack\n");
}

static int delta_ms (struct timeval * finish, struct timeval * start)
{
  int result = (finish->tv_usec - start->tv_usec) / 1000;
  result += (finish->tv_sec - start->tv_sec) * 1000;
  return result;
}

static int handle_packet (int sock, char * message, int msize,
                          char * my_key, int ksize,
                          char * contact, keyset keys,
                          char * secret, char * address, int nbits,
                          struct timeval * start, struct timeval * finish)
{
#ifdef DEBUG_PRINT
  print_packet (message, msize, "received", 1);
#endif /* DEBUG_PRINT */
  struct allnet_header * hp = (struct allnet_header *) message;
  if (msize < ALLNET_SIZE(hp->transport)) {
    printf ("got %d < %zd bytes, dropping message\n", msize,
            ALLNET_SIZE(hp->transport));
    return 0;
  }
  if (hp->message_type != ALLNET_TYPE_DATA) {
    printf ("got a message of type %d, dropping\n", hp->message_type);
    return 0;
  }
  if (! bitstring_matches (hp->destination, 0, address, 0, nbits)) {
    printf ("destination bitstring %02x.%02x not matching %02x.%02x (%d/%d)\n",
            hp->destination [0] & 0xff, hp->destination [1] & 0xff,
            address [0] & 0xff, address [1] & 0xff, hp->dst_nbits, nbits);
    return 0;
  }
  gettimeofday (finish, NULL);
  unsigned long long int delta = delta_us (finish, start);
  int usec = delta % 1000000;
  int sec = delta / 1000000;
  printf ("got tentative reply in %d.%06ds\n", sec, usec);

  char * cipher = message + ALLNET_SIZE(hp->transport);
  int csize = msize - ALLNET_SIZE(hp->transport);

  char * text;   /* plaintext, if all goes well */
  int tsize = allnet_decrypt (cipher, csize, my_key, ksize, &text);
  if (tsize <= 0) {
    print_buffer (cipher, csize, "unable to decrypt", 14, 1);
    return 0;
  }
  printf ("decryption successful!\n");
  char * contact_pubkey = text + MESSAGE_ID_SIZE;
  int computed_ksize = tsize - MESSAGE_ID_SIZE - strlen (secret);
  /* expected key size is 4096 bits or 512 bytes, plus one header byte */
  int contact_ksize = 4096 / 8 + 1;
  if ((*contact_pubkey != KEY_RSA4096_E65537) ||
      (computed_ksize != contact_ksize)) {
    printf ("computed key size %d, but received key type/size %d/%d\n",
            computed_ksize, (*contact_pubkey) & 0xff, contact_ksize);
    print_buffer (contact_pubkey, tsize, "public key", 16, 1);
    free (text);
    return 0;
  }
  char * received_secret = contact_pubkey + contact_ksize;
  int secret_len = tsize - MESSAGE_ID_SIZE - computed_ksize;
  if (secret_len != strlen (secret)) {
    printf ("received secret of length %d, our secret (%s) has length %zd\n",
            secret_len, secret, strlen (secret));
    free (text);
    return 0;
  }
  if (memcmp (received_secret, secret, secret_len) != 0) {
    char * copy = malloc_or_fail (secret_len + 1, "secret copy");
    memcpy (copy, received_secret, secret_len);
    copy [secret_len] = '\0';
    printf ("received secret %s, expected %s\n", copy, secret);
    free (copy);
    free (text);
    return 0;
  }
  printf ("received valid public key for %s\n", contact);
  set_contact_pubkey (keys, contact_pubkey, contact_ksize);
  set_contact_remote_addr (keys, hp->src_nbits, hp->source);
  send_ack (sock, message, address, nbits, text);
  free (text);
  return 1;
}

/* wait for a key for a limited time */
static void wait_for_key (int sock, char * secret, char * contact,
                          keyset keys, char * address, int nbits,
                          unsigned long long int ms, struct timeval * start)
{
#ifdef DEBUG_PRINT
  printf ("wait_for_key, nbits %d\n", nbits);
#endif /* DEBUG_PRINT */
  char * my_key;
  int ksize = get_my_privkey (keys, &my_key);
  if (ksize <= 0) {
    printf ("error: unable to get my own private key\n");
    exit (1);
  }
  struct timeval finish;
  finish = *start;
  int done = 0;
  while ((! done) && (delta_us (&finish, start) <= ms)) {
    int pipe;
    int pri;
    char * message;
    int found = receive_pipe_message_any (ms, &message, &pipe, &pri);
    if (found <= 0) {
      printf ("xkeys pipe closed, exiting\n");
      exit (1);
    }
    if (is_valid_message (message, found))
      done = handle_packet (sock, message, found, my_key, ksize, contact, keys,
                            secret, address, nbits, start, &finish);
    free (message);
    gettimeofday (&finish, NULL);
  }
}

/* send the public key, followed by the hmac of the public key using
 * the secret as the key for the hmac */
static void send_key_message (char * contact, char * secret, int hops, int sock)
{
  char address [ADDRESS_SIZE];
  random_bytes (address, sizeof (address));
  int nbits = 16;
  keyset keys = create_contact (contact, 4096, 1, NULL, 0,
                                address, nbits, NULL, 0);
  if (keys < 0) {
    printf ("contact %s already exists\n", contact);
    return;
  }
  char * my_public_key;
  int public_key_size = get_my_pubkey (keys, &my_public_key);
  if (public_key_size <= 0) {
    printf ("unable to create a public key for contact %s (pks %d)\n",
            contact, public_key_size);
    return;
  }
  int dsize = public_key_size + SHA512_SIZE;
  int size;
  struct allnet_header * hp =
    create_packet (dsize, ALLNET_TYPE_KEY_XCHG, hops, ALLNET_SIGTYPE_NONE,
                   address, nbits, NULL, 0, NULL, &size);
  char * message = (char *) hp;

  char * data = message + ALLNET_SIZE(hp->transport);
  memcpy (data, my_public_key, public_key_size);
  sha512hmac (my_public_key, public_key_size, secret, strlen (secret),
              /* hmac is written directly into the packet */
              data + public_key_size);

  struct timeval start;
  gettimeofday (&start, NULL);
  if (! send_pipe_message_free (sock, message, size, ALLNET_PRIORITY_LOCAL)) {
    printf ("unable to send key exchange packet to %s\n", contact);
    return;
  }
  /* see if an response comes back within a day or so */
  wait_for_key (sock, secret, contact, keys, address, nbits, 86400000, &start);
}

/* global debugging variable -- if 1, expect more debugging output */
/* set in main */
int allnet_global_debugging = 0;

int main (int argc, char ** argv)
{
  int verbose = get_option ('v', &argc, argv);
  if (verbose)
    allnet_global_debugging = verbose;

  if (argc != 4) {
    printf ("usage: %s contact-name secret-string num-hops\n", argv [0]);
    print_usage (argc, argv, 1, 1);
    return 1;
  }

  int sock = connect_to_local ("xkeys", argv [0]);
  if (sock < 0)
    return 1;

  char * contact = argv [1];
  char * secret = argv [2];
  int hops = atoi (argv [3]);

  normalize_secret (secret);
  if (hops < 1)
    hops = 1;
  if (hops > 255)
    hops = 255;
  printf ("sending key for '%s' with (normalized) secret '%s', ",
          contact, secret);
  if (hops != 1)
    printf ("%d hops\n", hops);
  else
    printf ("1 hop\n");
  send_key_message (contact, secret, hops, sock);
  return 0;
}
