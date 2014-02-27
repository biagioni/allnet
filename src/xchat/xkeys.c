/* xkeys.c: create public key and send public key message */
/* parameters are: contact name, secret string, and number of hops */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "packet.h"
#include "lib/pipemsg.h"
#include "lib/util.h"
#include "lib/priority.h"
#include "lib/sha.h"
#include "lib/cipher.h"
#include "lib/keys.h"
#include "lib/log.h"
#include "chat.h"
#include "cutil.h"

static void send_ack (int s, char * packet, char * address, char * message_ack)
{
  struct allnet_header * hp = (struct allnet_header *) packet;
  char ack [ALLNET_HEADER_SIZE + MESSAGE_ID_SIZE];
  int asize = sizeof (ack);
  bzero (ack, asize);
  struct allnet_header * ackp = (struct allnet_header *) ack;
  ackp->version = ALLNET_VERSION;
  ackp->message_type = ALLNET_TYPE_ACK;
  ackp->hops = 0;
  ackp->max_hops = hp->max_hops;
  ackp->src_nbits = ADDRESS_SIZE;
  ackp->dst_nbits = hp->src_nbits;
  ackp->sig_algo = ALLNET_SIGTYPE_NONE;
  ackp->transport = ALLNET_TRANSPORT_NONE;
  memcpy (ackp->source, address, ADDRESS_SIZE);
  memcpy (ackp->destination, hp->source, (hp->src_nbits + 7) / 8);
  memcpy (ack + ALLNET_HEADER_SIZE, message_ack, MESSAGE_ID_SIZE);
  if (! send_pipe_message (s, ack, asize, ALLNET_PRIORITY_LOCAL)) {
    printf ("unable to send key ack\n");
    return;
  }
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
print_packet (message, msize, "received", 1);
  if (msize < ALLNET_HEADER_SIZE) {
    printf ("got %d bytes, dropping message\n", msize);
    return 0;
  }
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
    printf ("destination bitstring %02x.%02x does not match %02x.%02x (%d)\n",
            hp->destination [0] & 0xff, hp->destination [1] & 0xff,
            address [0] & 0xff, address [1] & 0xff, hp->dst_nbits);
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
  int tsize = decrypt (cipher, csize, my_key, ksize, &text);
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
  send_ack (sock, message, address, text);
  free (text);
  return 1;
}

/* wait for a key for a limited time */
static void wait_for_key (int sock, char * secret, char * contact,
                          keyset keys, char * address, int nbits,
                          unsigned long long int ms, struct timeval * start)
{
  char * my_key;
  int ksize = get_my_privkey (keys, &my_key);
  if (ksize <= 0) {
    printf ("error: unable to get my own private key\n");
    exit (1);
  }
  add_pipe (sock);
  struct timeval finish;
  finish = *start;
  int done = 0;
  while ((! done) && (delta_us (&finish, start) <= ms)) {
    int pipe;
    int pri;
    char * message;
    int found = receive_pipe_message_any (ms, &message, &pipe, &pri);
    if (found <= 0) {
      printf ("pipe closed, exiting\n");
      exit (1);
    }
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
  keyset keys = create_contact (contact, 4096, 1, NULL, 0,
                                address, 16, NULL, 0);
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
  char message [ALLNET_MTU];
  bzero (message, sizeof (message));
  struct allnet_header * hp = (struct allnet_header *) message;
  hp->version = ALLNET_VERSION;
  hp->message_type = ALLNET_TYPE_KEY_XCHG;
  hp->hops = 0;
  hp->max_hops = hops;
  hp->src_nbits = 16;
  hp->dst_nbits = 0;
  hp->sig_algo = ALLNET_SIGTYPE_NONE;
  hp->transport = ALLNET_TRANSPORT_NONE;
  memcpy (hp->source, address, hp->src_nbits / 8);

  char * data = message + ALLNET_SIZE (hp->transport);
  memcpy (data, my_public_key, public_key_size);
  sha512hmac (my_public_key, public_key_size, secret, strlen (secret),
              /* hmac is written directly into the packet */
              data + public_key_size);
  int size = ALLNET_SIZE (hp->transport) + public_key_size + SHA512_SIZE;

  struct timeval start;
  gettimeofday (&start, NULL);
  if (! send_pipe_message (sock, message, size, ALLNET_PRIORITY_LOCAL)) {
    printf ("unable to send key exchange packet to %s\n", contact);
    return;
  }
  /* see if an response comes back within a day or so */
  wait_for_key (sock, secret, contact, keys, address, hp->src_nbits,
                86400000, &start);
}

int main (int argc, char ** argv)
{
  if (argc != 4) {
    printf ("usage: %s contact-name secret-string num-hops\n", argv [0]);
    return 1;
  }

  /* allegedly, openSSL does this for us */
  /* srandom (time (NULL));/* RSA encryption uses the random number generator */

  int sock = connect_to_local ("xkeys");
  if (sock < 0)
    return 1;

  /*sleep (1); when measuring time, wait until server has accepted connection */

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
}
