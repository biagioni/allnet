/* xkeys.c: create public key and send public key message */
/* parameters are: contact name, secret string, and number of hops */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "packet.h"
#include "pipemsg.h"
#include "util.h"
#include "priority.h"
#include "sha.h"
#include "chat.h"
#include "cutil.h"

static void send_ack (int s, char * packet, char * address, char * packet_id)
{
  struct allnet_header * hp = (struct allnet_header *) packet;
  struct allnet_header_data ack;
  int asize = sizeof (ack);
  bzero (&ack, asize);
  ack.version = ALLNET_VERSION;
  ack.packet_type = ALLNET_TYPE_DATA_ACK;
  ack.hops = 0;
  ack.max_hops = hp->max_hops;
  ack.src_nbits = ADDRESS_SIZE * 8;
  ack.dst_nbits = hp->src_nbits;
  ack.sig_algo = ALLNET_SIGTYPE_NONE;
  memcpy (ack.source, address, ADDRESS_SIZE);
  memcpy (ack.destination, hp->source, (hp->src_nbits + 7) / 8);
  memcpy (ack.packet_id, packet_id, PACKET_ID_SIZE);
  if (! send_pipe_message (s, (char *) (&ack), asize, SEVEN_EIGHTS)) {
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

/* wait for a key for a limited time */
static void wait_for_key (int sock, char * secret,
                          char * contact, char * address,
                          unsigned long long int ms, struct timeval * start)
{
  char * my_key;
  int ksize = get_my_privkey (contact, &my_key);
  if (ksize <= 0) {
    printf ("error: unable to get my own private key\n");
    exit (1);
  }
  add_pipe (sock);
  struct timeval finish;
  finish = *start;
  while (delta_us (&finish, start) <= ms) {
    int pipe;
    int pri;
    char * packet;
    int found = receive_pipe_message_any (ms, &packet, &pipe, &pri);
    if (found <= 0) {
      printf ("pipe closed, exiting\n");
      exit (1);
    }
    if (found >= ALLNET_HEADER_DATA_SIZE) {
      struct allnet_header_data * hp = (struct allnet_header_data *) packet;
      if ((hp->packet_type == ALLNET_TYPE_DATA) &&
          (hp->dst_nbits == 8 * ADDRESS_SIZE) &&
          (memcmp (hp->destination, address, ADDRESS_SIZE) == 0)) {
        gettimeofday (&finish, NULL);
        int usec = finish.tv_usec - start->tv_usec;
        int sec = finish.tv_sec - start->tv_sec;
        while (usec < 0) {
          usec += US_PER_S;
          sec--;
        }
        printf ("got tentative reply in %d.%06ds\n", sec, usec);

        char * cipher = packet + ALLNET_HEADER_DATA_SIZE;
        int csize = found - ALLNET_HEADER_DATA_SIZE;

        char * text;   /* plaintext, if all goes well */
        int tsize = decrypt (cipher, csize, my_key, ksize, &text);
        if (tsize <= 0) {
          print_buffer (cipher, csize, "unable to decrypt", 14, 1);
        } else {
          printf ("decryption successful!\n");
          char * contact_pubkey = text + PACKET_ID_SIZE;
          int contact_ksize = public_key_length (contact_pubkey);
          int computed_ksize = tsize - PACKET_ID_SIZE - strlen (secret);
          if ((computed_ksize == contact_ksize) && (contact_ksize > 0)) {
            char * received_secret = contact_pubkey + contact_ksize;
            int secret_len = tsize - PACKET_ID_SIZE - computed_ksize;
            if (memcmp (received_secret, secret, secret_len) == 0) {
              printf ("received valid public key for %s\n", contact);
              save_contact_pubkey (contact, contact_pubkey, contact_ksize,
                                   NULL /* do not need my own public key */ );
              send_ack (sock, packet, address, text);
              free (text);
              free (packet);
              return;
            } else {
              static char copy [1000];
              memcpy (copy, received_secret, secret_len);
              copy [secret_len] = '\0';
              printf ("received secret %s, expected %s\n", copy, secret);
            }
          } else {
            printf ("computed key size %d, but received key size %d\n",
                    computed_ksize, contact_ksize);
            print_buffer (contact_pubkey, tsize, "public key", 16, 1);
          }
          free (text);
        }
      }
    } else {
      printf ("got %d bytes, dropping packet\n", found);
    }
    if (found > 0)
      free (packet);
    gettimeofday (&finish, NULL);
  }
}

/* send the public key, followed by the hmac of the public key using
 * the secret as the key for the hmac */
static void send_key_message (char * contact, char * secret, int hops, int sock)
{
  char * my_public_key;
  int public_key_size = new_contact (contact, &my_public_key);
  if (public_key_size <= 0) {
    printf ("unable to create new contact '%s', not sending key\n", contact);
    return;
  }
  int size = ALLNET_HEADER_SIZE + public_key_size + SHA512_SIZE;
  char * packet = calloc (size, 1);
  if (packet == NULL) {
    perror ("malloc");
    printf ("unable to allocate %d bytes, not sending key\n", size);
    return;
  }
  struct allnet_header * hp = (struct allnet_header *) packet;
  hp->version = ALLNET_VERSION;
  hp->packet_type = ALLNET_TYPE_KEY_XCHG;
  hp->hops = 0;
  hp->max_hops = hops;
  hp->src_nbits = 8 * ADDRESS_SIZE;
  hp->dst_nbits = 0;
  hp->sig_algo = ALLNET_SIGTYPE_NONE;
  memcpy (packet + ALLNET_HEADER_SIZE, my_public_key, public_key_size);
  sha512hmac (my_public_key, public_key_size, secret, strlen (secret),
              /* hmac is written directly into the packet */
              packet + ALLNET_HEADER_SIZE + public_key_size);
  free (my_public_key);

  struct timeval start;
  gettimeofday (&start, NULL);
  if (! send_pipe_message (sock, packet, size, SEVEN_EIGHTS)) {
    printf ("unable to send key exchange packet to %s\n", contact);
    return;
  }
  /* see if an response comes back within a day or so */
  wait_for_key (sock, secret, contact, hp->source, 86400000, &start);
}

int main (int argc, char ** argv)
{
  if (argc != 4) {
    printf ("usage: %s contact-name secret-string num-hops\n", argv [0]);
    return 1;
  }

  /* allegedly, openSSL does this for us */
  /* srandom (time (NULL));/* RSA encryption uses the random number generator */

  int sock = connect_to_local ();
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
