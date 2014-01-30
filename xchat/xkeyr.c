/* xkeyr.c: receive key exchange messages and respond to them. */
/* parameters are: contact name, secret string */

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
#include "cipher.h"

static void wait_for_ack (char * contact, char * packet_id,
                          struct timeval * start)
{
  /* wait a short while for an ack */
  printf ("to do: eventually, might respond to retransmissions or requests\n");
  struct timeval now;
  do {
    char * ack;
    int pipe;
    int prio;
    int asize = receive_pipe_message_any (1000, &ack, &pipe, &prio);
    printf ("received %d bytes\n", asize);
    if (asize <= 0) {
      printf ("pipe closed, exiting\n");
      exit (1);
    }
    if (asize >= ALLNET_HEADER_DATA_SIZE) {
      struct allnet_header_data * hp = (struct allnet_header_data *) ack;
      if ((hp->packet_type == ALLNET_TYPE_DATA_ACK) &&
          (memcmp (hp->packet_id, packet_id, PACKET_ID_SIZE) == 0)) {
        printf ("key exchange is complete with contact %s\n", contact);
        free (ack);
        return;
      }
    }
    if (asize > 0)
      free (ack);
    gettimeofday (&now, NULL);
  } while (delta_us (&now, start) < 3 * 1000 * 1000);
}

/* send the public key, followed by the hmac of the public key using
 * the secret as the key for the hmac */
static void send_key_message (int sock, char * contact, int nbits, char * addr,
                              char * my_addr, char * secret,
                              char * contact_key, int contact_ksize,
                              char * my_pubkey, int my_ksize, int hops)
{
  int length = PACKET_ID_SIZE + my_ksize + strlen (secret);
  char * text = malloc_or_fail (length, "send_key_message text");
  random_bytes (text, PACKET_ID_SIZE);
  memcpy (text + PACKET_ID_SIZE, my_pubkey, my_ksize);
  /* do not copy secret's terminating null byte */
  memcpy (text + PACKET_ID_SIZE + my_ksize, secret, strlen (secret));
  char * cipher;
  int csize = encrypt (text, length, contact_key, contact_ksize, &cipher);

  int psize = ALLNET_HEADER_DATA_SIZE + csize;
  char * packet = malloc_or_fail (psize, "send_key_message packet");
  bzero (packet, psize);

  struct allnet_header_data * hp = (struct allnet_header_data *) packet;
  hp->version = ALLNET_VERSION;
  hp->packet_type = ALLNET_TYPE_DATA;
  hp->hops = 0;
  hp->max_hops = hops;
  hp->src_nbits = 8 * ADDRESS_SIZE;
  hp->dst_nbits = nbits;
  hp->sig_algo = ALLNET_SIGTYPE_NONE;
  memcpy (hp->source, my_addr, ADDRESS_SIZE);
  memcpy (hp->destination, addr, (nbits + 7) / 8);
  sha512_bytes (text, PACKET_ID_SIZE, hp->packet_id, PACKET_ID_SIZE);
  memcpy (packet + ALLNET_HEADER_DATA_SIZE, cipher, csize);
  free (cipher);

  struct timeval start;
  gettimeofday (&start, NULL);
  if (! send_pipe_message (sock, packet, psize, SEVEN_EIGHTS)) {
    printf ("unable to send key exchange reply packet to %s\n", contact);
    return;
  }
  /* wait a short while for an ack */
  wait_for_ack (contact, text, &start);
}

/* wait for a key for a limited time */
static void wait_for_key (int sock, char * secret, char * contact,
                          unsigned long long int ms)
{
  struct timeval start;
  gettimeofday (&start, NULL);
  add_pipe (sock);
  char * packet;
  int pipe;
  int pri;
  unsigned long long int timeout = ms * 1000LL;
  struct timeval finish;
  finish = start;
  char my_addr [ADDRESS_SIZE];
  random_bytes (my_addr, ADDRESS_SIZE);
  while (delta_us (&finish, &start) <= timeout) {
    int found = receive_pipe_message_any (ms, &packet, &pipe, &pri);
    gettimeofday (&finish, NULL);
    if (found <= 0) {
      printf ("pipe closed (timeout %lld), exiting\n", ms);
      exit (1);
    }
    if (found > ALLNET_HEADER_SIZE + SHA512_SIZE) {
      struct allnet_header * hp = (struct allnet_header *) packet;
      if (hp->packet_type == ALLNET_TYPE_KEY_XCHG) {  /* look at it */
        int usec = finish.tv_usec - start.tv_usec;
        int sec = finish.tv_sec - start.tv_sec;
        while (usec < 0) {
          usec += US_PER_S;
          sec--;
        }
        printf ("got key message in %d.%06ds\n", sec, usec);

        char * contact_key = packet + ALLNET_HEADER_SIZE;
        int contact_ksize = found - ALLNET_HEADER_SIZE - SHA512_SIZE;
        char * received_hmac = contact_key + contact_ksize;
        char hmac [SHA512_SIZE];
        sha512hmac (contact_key, contact_ksize, secret, strlen (secret), hmac);
        if (memcmp (hmac, received_hmac, SHA512_SIZE) == 0) {
          printf ("received valid public key for '%s'\n", contact);
          char * my_pubkey;
          int my_ksize = save_contact_pubkey (contact, contact_key,
                                              contact_ksize, &my_pubkey);
          int sending_hops = hp->hops + 2;
          if (sending_hops < hp->max_hops)
            sending_hops = hp->max_hops;
          /* get the public key so it is in a format we can use */
          char * pubkey;
          int pubksize = get_contact_pubkey (contact, &pubkey);
          if (pubksize <= 0) {
            printf ("error: unable to get saved public key\n");
            exit (1);
          }
          send_key_message (pipe, contact, hp->src_nbits, hp->source, my_addr,
                            secret, pubkey, pubksize, my_pubkey, my_ksize,
                            sending_hops);
          free (pubkey);
          free (packet);
          return;
        } else {
          printf ("received key with hmac other than expected\n");
          /* for now, print for debugging purposes */
          print_buffer (contact_key, contact_ksize, "received key ", 15, 1);
          print_buffer (received_hmac, SHA512_SIZE, "received hmac", 15, 1);
          print_buffer (hmac, SHA512_SIZE, "computed hmac", 15, 1);
        }
      }
    } else {
#ifdef DEBUG_PRINT
      printf ("got %d bytes, dropping packet\n", found);
#endif /* DEBUG_PRINT */
    }
    if (found > 0)
      free (packet);
  }
}

int main (int argc, char ** argv)
{
  if (argc != 3) {
    printf ("usage: %s contact-name secret-string\n", argv [0]);
    return 1;
  }

  char * contact = argv [1];
  char * secret = argv [2];
  normalize_secret (secret);

  if (get_counter (contact) != 0) {
    printf ("error: contact %s already exists\n", contact);
    return 1;
  }

  /* allegedly, openSSL does this for us */
  /* srandom (time (NULL));/* RSA encryption uses the random number generator */

  int sock = connect_to_local ();
  if (sock < 0)
    return 1;

  /*sleep (1); when measuring time, wait until server has accepted connection */

  printf ("waiting for key message from '%s' with (normalized) secret '%s'\n",
          contact, secret);
  wait_for_key (sock, secret, contact, 600 * 1000);
  /* send_key_message (contact, secret, hops, sock); */
}
