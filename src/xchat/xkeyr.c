/* xkeyr.c: receive key exchange messages and respond to them. */
/* parameters are: contact name, secret string */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

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

static void wait_for_ack (char * contact, char * message_ack,
                          struct timeval * start, int timeout_us)
{
  /* wait a short while for an ack */
  printf ("to do: eventually, might respond to retransmissions or requests\n");
  struct timeval now;
  do {
    char * ack;
    int pipe;
    int prio;
    int asize = receive_pipe_message_any (1000, &ack, &pipe, &prio);
#ifdef DEBUG_PRINT
    printf ("received %d bytes\n", asize);
#endif /* DEBUG_PRINT */
    if (asize <= 0) {
      printf ("xkeyr pipe closed, exiting\n");
      exit (1);
    }
    if (is_valid_message (ack, asize)) {
      struct allnet_header * hp = (struct allnet_header *) ack;
      int hsize = ALLNET_SIZE (hp->transport);
      char * data = ack + hsize;
      if ((asize >= hsize + MESSAGE_ID_SIZE) &&
          (hp->message_type == ALLNET_TYPE_ACK) &&
          (memcmp (data, message_ack, MESSAGE_ID_SIZE) == 0)) {
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
static void send_key_message (int sock, char * contact, keyset keys,
                              char * secret, int hops, int timeout_us)
{
  char * contact_key;
  int contact_ksize = get_contact_pubkey (keys, &contact_key);
  char * my_pubkey;
  int my_ksize = get_my_pubkey (keys, &my_pubkey);
#ifdef DEBUG_PRINT
  printf ("send_key_message: my key %p/%d, contact key %p/%d\n",
          my_pubkey, my_ksize, contact_key, contact_ksize);
#endif /* DEBUG_PRINT */
  char addr [ADDRESS_SIZE];
  int nbits = get_remote (keys, addr);
  char my_addr [ADDRESS_SIZE];
  int my_bits = get_local (keys, my_addr);
  if (my_bits > 16)
    my_bits = 16;   /* in 2014, 16 bits is plenty */

  int length = MESSAGE_ID_SIZE + my_ksize + strlen (secret);
  char * text = malloc_or_fail (length, "send_key_message text");
  random_bytes (text, MESSAGE_ID_SIZE);
  memcpy (text + MESSAGE_ID_SIZE, my_pubkey, my_ksize);
  /* do not copy secret's terminating null byte */
  memcpy (text + MESSAGE_ID_SIZE + my_ksize, secret, strlen (secret));
  char * cipher;
  int csize = allnet_encrypt (text, length, contact_key, contact_ksize, &cipher);

#ifdef DEBUG_PRINT
  printf ("encrypted %d bytes, result is %d bytes long\n", length, csize);
#endif /* DEBUG_PRINT */

  int psize;
  struct allnet_header * hp =
    create_packet (csize - MESSAGE_ID_SIZE, ALLNET_TYPE_DATA, hops,
                   ALLNET_SIGTYPE_NONE, my_addr, my_bits, addr, nbits,
                   text, &psize);
  char * packet = (char *) hp;
#ifdef DEBUG_PRINT
  printf ("packet size is %d bytes\n", psize);
#endif /* DEBUG_PRINT */

  memcpy (packet + ALLNET_SIZE(hp->transport), cipher, csize);
  free (cipher);

  struct timeval start;
  gettimeofday (&start, NULL);
  if (! send_pipe_message (sock, packet, psize, ALLNET_PRIORITY_LOCAL)) {
    printf ("unable to send key exchange reply packet to %s\n", contact);
    return;
  }
  /* wait a short while for an ack */
  wait_for_ack (contact, text, &start, timeout_us);
}

/* wait for a key for a limited time */
static void wait_for_key (int sock, char * secret, char * contact,
                          unsigned long long int ms)
{
  struct timeval start;
  gettimeofday (&start, NULL);
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
    struct allnet_header * hp = (struct allnet_header *) packet;
    if ((is_valid_message (packet, found)) &&
        (found > (ALLNET_SIZE (hp->transport) + SHA512_SIZE))) {
      if (hp->message_type == ALLNET_TYPE_KEY_XCHG) {  /* look at it */
        int usec = finish.tv_usec - start.tv_usec;
        int sec = finish.tv_sec - start.tv_sec;
        while (usec < 0) {
          usec += ALLNET_US_PER_S;
          sec--;
        }
        printf ("got key message in %d.%06ds\n", sec, usec);

        char * contact_key = packet + ALLNET_HEADER_SIZE;
        int contact_ksize = found - ALLNET_HEADER_SIZE - SHA512_SIZE;
        char * received_hmac = contact_key + contact_ksize;
        char hmac [SHA512_SIZE];
        sha512hmac (contact_key, contact_ksize, secret, strlen (secret), hmac);
        if (memcmp (hmac, received_hmac, SHA512_SIZE) == 0) {
          printf ("received valid public key %p/%d for '%s'\n", contact_key,
                  contact_ksize, contact);
          print_buffer (contact_key, contact_ksize, "key", 10, 1);
          keyset keys = create_contact (contact, 4096, 1,
                                        contact_key, contact_ksize,
                                        my_addr, 16,
                                        hp->source, hp->src_nbits);

          int sending_hops = hp->hops + 2;
          if (sending_hops < hp->max_hops)
            sending_hops = hp->max_hops;
          send_key_message (pipe, contact, keys, secret, sending_hops,
                            timeout + 1000000 - delta_us (&finish, &start));
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

/* global debugging variable -- if 1, expect more debugging output */
/* set in main */
int allnet_global_debugging = 0;

int main (int argc, char ** argv)
{
  int verbose = get_option ('v', &argc, argv);
  if (verbose)
    allnet_global_debugging = verbose;

  if (argc != 3) {
    printf ("usage: %s contact-name secret-string\n", argv [0]);
    print_usage (argc, argv, 1, 1);
    return 1;
  }

  char * contact = argv [1];
  char * secret = argv [2];
  normalize_secret (secret);

  if (get_counter (contact) != 0) {
    printf ("error: contact %s already exists\n", contact);
    return 1;
  }

  int sock = connect_to_local ("xkeyr", argv [0]);
  if (sock < 0)
    return 1;

  printf ("waiting for key message from '%s' with (normalized) secret '%s'\n",
          contact, secret);
  wait_for_key (sock, secret, contact, 600 * 1000);
  return 0;
}
