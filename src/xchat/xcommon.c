/* xcommon.c: send and receive messages for xchat */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <inttypes.h>

#include "chat.h"
#include "xcommon.h"
#include "message.h"
#include "cutil.h"
#include "retransmit.h"
#include "lib/media.h"
#include "lib/util.h"
#include "lib/app_util.h"
#include "lib/pipemsg.h"
#include "lib/cipher.h"
#include "lib/priority.h"
#include "lib/log.h"
#include "lib/sha.h"
#include "lib/mapchar.h"

/* #define DEBUG_PRINT */

static void request_cached_data (int sock, int hops)
{
  int size;
  struct allnet_header * hp =
    create_packet (0, ALLNET_TYPE_DATA_REQ, hops, ALLNET_SIGTYPE_NONE,
                   NULL, 0, NULL, 0, NULL, &size);
  if (! send_pipe_message_free (sock, (char *) (hp), size,
                                ALLNET_PRIORITY_LOCAL_LOW))
    printf ("unable to request cached data\n");
}

/* returns the socket if successful, -1 otherwise */
int xchat_init (char * arg0)
{
  int sock = connect_to_local ("xcommon", arg0);
  if (sock < 0)
    return -1;
  request_cached_data (sock, 10);
  return sock;
}

/* optional... */
void xchat_end (int sock)
{
  close (sock);
}

#define NUM_ACKS	100
/* initial contents should not matter, accidental match is unlikely */
static char recently_sent_acks [NUM_ACKS] [MESSAGE_ID_SIZE];
static int currently_sent_ack = 0;

static int is_recently_sent_ack (char * message_ack)
{
  int i;
  for (i = 0; i < NUM_ACKS; i++)
    if (memcmp (message_ack, recently_sent_acks [i], MESSAGE_ID_SIZE) == 0)
      return 1;
  return 0;
}

/* send an ack for the given message and message ID */
static void send_ack (int sock, struct allnet_header * hp,
                      unsigned char * message_ack,
                      int send_resend_request, char * contact, keyset kset)
{
  if ((hp->transport & ALLNET_TRANSPORT_ACK_REQ) == 0) {
printf ("packet not requesting an ack, no ack sent\n");
    return;
  }
  int size;
  struct allnet_header * ackp =
    create_ack (hp, message_ack, NULL, ADDRESS_BITS, &size);
  if (ackp == NULL)
    return;
  /* also save in the (very likely) event that we receive our own ack */
  currently_sent_ack = (currently_sent_ack + 1) % NUM_ACKS;
  memcpy (recently_sent_acks [currently_sent_ack], message_ack,
          MESSAGE_ID_SIZE);
#ifdef DEBUG_PRINT
  print_packet ((char *) ackp, size, "sending ack", 1);
#endif /* DEBUG_PRINT */
  send_pipe_message_free (sock, (char *) ackp, size, ALLNET_PRIORITY_LOCAL);
/* after sending the ack, see if we can get any outstanding
 * messages from the peer */
  if (send_resend_request)
    request_and_resend (sock, contact, kset);
}

static void handle_ack (int sock, char * packet, int psize, int hsize)
{
  struct allnet_header * hp = (struct allnet_header *) packet;
  /* save the acks */
  char * ack = packet + ALLNET_SIZE (hp->transport);
  int count = (psize - hsize) / MESSAGE_ID_SIZE; 
  int i;
  for (i = 0; i < count; i++) {
    char * peer;
    keyset kset;
    long long int ack_number = ack_received (ack, &peer, &kset);
    if (ack_number > 0) {
#ifdef DEBUG_PRINT
      printf ("sequence number %lld acked\n", ack_number);
#endif /* DEBUG_PRINT */
      request_and_resend (sock, peer, kset);
/*    } else if (ack_number == -2) {
      printf ("packet acked again\n"); */
    } else if (is_recently_sent_ack (ack)) {
      /* printf ("received my own ack\n"); */
    } else {
      /* print_buffer (ack, MESSAGE_ID_SIZE, "unknown ack rcvd",
                    MESSAGE_ID_SIZE, 1); */
    }
    fflush (NULL);
/* */
    ack += MESSAGE_ID_SIZE;
  }
}

static int handle_clear (struct allnet_header * hp, char * data, int dsize,
                         char ** contact, char ** message,
                         int * verified, int * broadcast)
{
  if (hp->sig_algo == ALLNET_SIGTYPE_NONE) {
#ifdef DEBUG_PRINT
    printf ("ignoring unsigned clear packet of size %d\n", dsize);
#endif /* DEBUG_PRINT */
    return 0;
  }
  struct allnet_app_media_header * amhp =
    (struct allnet_app_media_header *) data;
  char * verif = data;
  int media = 0;
  if (dsize >= sizeof (struct allnet_app_media_header) + 2)
    media = readb32u (amhp->media);
  if ((media != ALLNET_MEDIA_TEXT_PLAIN) &&
      (media != ALLNET_MEDIA_TIME_TEXT_BIN)) {
#ifdef DEBUG_PRINT
    printf ("handle_clear ignoring unknown media type %08x, dsize %d\n",
            media, dsize);
#endif /* DEBUG_PRINT */
    return 0;
  }
  int ssize = readb16 (data + (dsize - 2)) + 2;  /* size of the signature */
  if ((ssize <= 2) || (dsize <= ssize)) {
    printf ("data packet size %d less than sig %d, dropping\n", dsize, ssize);
    return 0;
  }
  data += sizeof (struct allnet_app_media_header);
  int text_size = dsize - sizeof (struct allnet_app_media_header) - ssize;
  char * sig = data + text_size;
#ifdef DEBUG_PRINT
  printf ("data size %d, text %d + sig %d\n", dsize, text_size, ssize);
#endif /* DEBUG_PRINT */
  struct bc_key_info * keys;
  int nkeys = get_other_keys (&keys);
  int i;
/* print_buffer (verif, dsize - ssize, "verifying BC message", dsize, 1); */
  for (i = 0; i < nkeys; i++) {
    if ((matches ((unsigned char *) (keys [i].address), ADDRESS_BITS,
                  hp->source, hp->src_nbits) > 0) &&
        (allnet_verify (verif, dsize - ssize, sig, ssize - 2,
                        keys [i].pub_key, keys [i].pub_klen))) {
      *contact = strcpy_malloc (keys [i].identifier,
                                "handle_message broadcast contact");
      *message = malloc_or_fail (text_size + 1, "handle_clear message");
      memcpy (*message, data, text_size);
      (*message) [text_size] = '\0';   /* null-terminate the message */
      *broadcast = 1;
      *verified = 1;
#ifdef DEBUG_PRINT
      printf ("verified bc message, contact %s, %d bytes\n",
              keys [i].identifier, text_size);
#endif /* DEBUG_PRINT */
      return text_size;
    } 
#ifdef DEBUG_PRINT
      else {
      printf ("matches (%02x%02x, %02x%02x/%d) == %d\n",
              keys [i].address [0] & 0xff, keys [i].address [1] & 0xff,
              hp->source [0] & 0xff, hp->source [1] & 0xff, hp->src_nbits,
              matches (keys [i].address, ADDRESS_BITS,
                       hp->source, hp->src_nbits));
      printf ("verify (%p/%d, %p/%d, %p/%d) == %d\n",
              data, dsize - ssize, sig, ssize - 2,
              keys [i].pub_key, keys [i].pub_klen,
              verify (data, dsize - ssize, sig, ssize - 2,
                      keys [i].pub_key, keys [i].pub_klen));
    }
#endif /* DEBUG_PRINT */
  }
  printf ("unable to verify bc message\n");
  return 0;   /* did not match */
}

static int handle_data (int sock, struct allnet_header * hp,
                        char * data, int dsize, char ** contact, keyset * kset,
                        char ** message, char ** desc, int * verified,
                        time_t * sent, int * duplicate, int * broadcast)
{
  int verif = 0;
  char * text = NULL;
  int tsize = decrypt_verify (hp->sig_algo, data, dsize, contact, kset, &text,
                              (char *) (hp->source), hp->src_nbits,
                              (char *) (hp->destination), hp->dst_nbits, 0);
  if (tsize < 0) {
    printf ("no signature to verify, but decrypted from %s\n", *contact);
    tsize = -tsize;
  } else if (tsize > 0) {
    verif = 1;
  }
  if (tsize < CHAT_DESCRIPTOR_SIZE) {
#ifdef DEBUG_PRINT
    printf ("decrypted packet has size %d, min is %zd, dropping\n",
            tsize, CHAT_DESCRIPTOR_SIZE);
#endif /* DEBUG_PRINT */
    return 0;
  }
  if (*contact == NULL) {
#ifdef DEBUG_PRINT
    printf ("contact not known\n");
#endif /* DEBUG_PRINT */
    if (text != NULL) free (text);
    return 0;
  }
#ifdef DEBUG_PRINT
  printf ("got packet from contact %s\n", *contact);
#endif /* DEBUG_PRINT */
  struct chat_descriptor * cdp = (struct chat_descriptor *) text;
  int app = readb32u (cdp->app_media.app);
  int media = readb32u (cdp->app_media.media);
  if ((app != XCHAT_ALLNET_APP_ID) || (media != ALLNET_MEDIA_TEXT_PLAIN)) {
#ifdef DEBUG_PRINT
    printf ("handle_data ignoring unknown app %08x, media type %08x\n",
            app, media);
    print_buffer (text, CHAT_DESCRIPTOR_SIZE, "chat descriptor", 100, 1);
#endif /* DEBUG_PRINT */
    return 0;
  }
  char * cleartext = text + CHAT_DESCRIPTOR_SIZE;
  int msize = tsize - CHAT_DESCRIPTOR_SIZE;

  long long int seq = readb64u (cdp->counter);
  if (seq == COUNTER_FLAG) {
    do_chat_control (*contact, *kset, text, tsize, sock, hp->hops + 4);
    send_ack (sock, hp, cdp->message_ack, verif, *contact, *kset);
    if (*contact != NULL) { free (*contact); *contact = NULL; }
    if (text != NULL) free (text);
    return 0;
  }

  *broadcast = 0;
  *duplicate = 0;
  if (was_received (*contact, *kset, seq))
    *duplicate = 1;

  save_incoming (*contact, *kset, cdp, cleartext, msize);

  *message = malloc_or_fail (msize + 1, "handle_data message");
  memcpy (*message, cleartext, msize);
  (*message) [msize] = '\0';   /* null-terminate the message */
  *desc = chat_descriptor_to_string (cdp, 0, 0);
  *verified = verif;
  if (sent != NULL)
    *sent = (readb64u (cdp->timestamp) >> 16) & 0xffffffff;

  /* printf ("hp->hops = %d\n", hp->hops); */

  send_ack (sock, hp, cdp->message_ack, verif, *contact, *kset);

  free (text);

  return msize;
}

static int handle_sub (int sock, struct allnet_header * hp,
                       char * data, int dsize,
                       char * subscription,
                       const unsigned char * addr, int nbits)
{
  if ((nbits == 0) ||
      ((hp->dst_nbits == nbits) && 
       (matches (hp->destination, nbits, addr, nbits)))) {
#ifdef DEBUG_PRINT
    printf ("handle_sub calling verify_bc_key\n");
#endif /* DEBUG_PRINT */
    struct allnet_app_media_header * amhp =
      (struct allnet_app_media_header *) data;
    int media = 0;
    if (dsize >= sizeof (struct allnet_app_media_header) + 2)
      media = readb32u (amhp->media);
    if (media != ALLNET_MEDIA_PUBLIC_KEY) {
#ifdef DEBUG_PRINT
      printf ("handle_sub ignoring unknown media type %08x, dsize %d\n",
              media, dsize);
#endif /* DEBUG_PRINT */
      return 0;
    }
    data += sizeof (struct allnet_app_media_header);
    dsize -= sizeof (struct allnet_app_media_header);
    int correct = verify_bc_key (subscription, data, dsize, "en", 16, 1);
    if (correct)
      printf ("received key does verify %s, saved\n", subscription);
    else
      printf ("received key does not verify\n");
    return correct;
  }
#ifdef DEBUG_PRINT
  printf ("handle_sub did not call verify_bc_key\n");
#endif /* DEBUG_PRINT */
  return 0;
}

static int send_key (int sock, char * contact, keyset kset, char * secret,
                     unsigned char * address, int abits, int max_hops)
{
  char * my_public_key;
  int pub_ksize = get_my_pubkey (kset, &my_public_key);
  if (pub_ksize <= 0) {
    printf ("unable to send key, no public key found for contact %s (%d/%d)\n",
            contact, kset, pub_ksize);
    return 0;
  }
  int dsize = pub_ksize + SHA512_SIZE;
  int size;
  struct allnet_header * hp =
    create_packet (dsize, ALLNET_TYPE_KEY_XCHG, max_hops, ALLNET_SIGTYPE_NONE,
                   address, abits, NULL, 0, NULL, &size);
  char * message = (char *) hp;

  char * data = message + ALLNET_SIZE (hp->transport);
  memcpy (data, my_public_key, pub_ksize);
  sha512hmac (my_public_key, pub_ksize, secret, strlen (secret),
              /* hmac is written directly into the packet */
              data + pub_ksize);

  if (! send_pipe_message_free (sock, message, size, ALLNET_PRIORITY_LOCAL)) {
    printf ("unable to send %d-byte key exchange packet to %s\n",
            size, contact);
    return 0;
  }
  return 1;
}

static int handle_key (int sock, struct allnet_header * hp,
                       char * data, int dsize, char * contact,
                       char * secret1, char * secret2, int max_hops)
{
#ifdef DEBUG_PRINT
  printf ("in handle_key (%s, %s, %s)\n", contact, secret1, secret2);
#endif /* DEBUG_PRINT */
  if ((contact == NULL) || (secret1 == NULL))
    return 0;
  if (hp->hops > max_hops)
    return 0;
  keyset * keys;
  int nkeys = all_keys (contact, &keys);
  if (nkeys < 1) {
    printf ("error '%s'/%d: create own key before calling handle_packet\n",
            contact, nkeys);
    return 0;
  }
#ifdef DEBUG_PRINT
  printf ("handle_key received key\n");
#endif /* DEBUG_PRINT */
  unsigned char peer_addr [ADDRESS_SIZE];
  int peer_bits;
  int key_index = -1;
  int i;
  for (i = 0; i < nkeys; i++) {
    char * key;
    int klen = get_contact_pubkey (keys [i], &key);
    peer_bits = get_remote (keys [i], peer_addr);
    if ((klen <= 0) &&
        ((peer_bits <= 0) ||
         (matches (peer_addr, peer_bits, hp->source, hp->src_nbits) > 0))) {
#ifdef DEBUG_PRINT
      printf ("handle_key matches at index %d/%d\n", i, nkeys);
#endif /* DEBUG_PRINT */
      key_index = i;
      break;
    }
  }
  if (key_index < 0) {
    if (nkeys <= 0)
      printf ("handle_key error: contact '%s' has %d keys\n", contact, nkeys);
/* it is fairly normal to get multiple copies of the key.  Ignore.
    else
      printf ("handle_key: contact '%s' has %d keys, no unmatched key found\n",
              contact, nkeys);
*/
    return 0;
  }

  char * received_key = data;
  int ksize = dsize - SHA512_SIZE;
  /* check to see if it is my own key */
  for (i = 0; i < nkeys; i++) {
    char * test_key;
    int test_klen = get_my_pubkey (keys [i], &test_key);
    if ((test_klen == ksize) && (memcmp (received_key, test_key, ksize) == 0)) {
/* it is fairly normal to get my own key back.  Ignore.
*/
      printf ("handle_key: got my own key\n");
      return 0;
    }
  }
  char * received_hmac = data + ksize;
  char hmac [SHA512_SIZE];
  sha512hmac (received_key, ksize, secret1, strlen (secret1), hmac);
  int found1 = (memcmp (hmac, received_hmac, SHA512_SIZE) == 0);
  int found2 = 0;
  if ((! found1) && (secret2 != NULL)) {
    sha512hmac (received_key, ksize, secret2, strlen (secret2), hmac);
    found2 = (memcmp (hmac, received_hmac, SHA512_SIZE) == 0);
  }
#ifdef DEBUG_PRINT
  printf ("hmac gives %d/%d\n", found1, found2);
#endif /* DEBUG_PRINT */
  if ((found1) || (found2)) {
#ifdef DEBUG_PRINT
    printf ("received valid public key %p/%d for '%s'/%d\n", received_key,
            ksize, contact, key_index);
    print_buffer (received_key, ksize, "key", 10, 1);
#endif /* DEBUG_PRINT */
    if (set_contact_pubkey (keys [key_index], received_key, ksize)) {
      if (hp->src_nbits > 0)
        set_contact_remote_addr (keys [key_index], hp->src_nbits, hp->source);
      /* send the key to the peer -- may be redundant, but may be useful */
      char * secret = secret1;
      if (found2)   /* use peer's secret */
        secret = secret2;
      /* else peer sent us a valid key, must know our secret1 */
printf ("sending back key with secret %s\n", secret);
      if (! send_key (sock, contact, keys [key_index], secret,
                      hp->source, hp->src_nbits, max_hops))
        printf ("send_key failed for key index %d/%d\n", key_index, nkeys);
      return -1;  /* successful key exchange */
    }
    printf ("handle_key error: set_contact_pubkey returned 0\n");
    return 0;
  }
#ifdef DEBUG_PRINT
  printf ("public key does not check with secrets %s %s\n", secret1, secret2);
#endif /* DEBUG_PRINT */
  return 0;
}

/* handle an incoming packet, acking it if it is a data packet for us
 * returns the message length > 0 if this was a valid data message from a peer.
 * if it gets a valid key, returns -1 (details below)
 * Otherwise returns 0 and does not fill in any of the following results.
 *
 * if it is a data or ack, it is saved in the xchat log
 * if it is a valid data message from a peer or a broadcaster,
 * fills in verified and broadcast
 * fills in contact, message (to point to malloc'd buffers, must be freed)
 * if not broadcast, fills in desc (also malloc'd), sent (if not null)
 * and duplicate.
 * if verified and not broadcast, fills in kset.
 * the data message (if any) is null-terminated
 *
 * if kcontact and ksecret1 are not NULL, assumes we are also looking
 * for key exchange messages sent to us matching either of ksecret1 or
 * (if not NULL) ksecret2.  If such a key is found, returns -1.
 * there are two ways of calling this:
 * - if the user specified the peer's secret, first send initial key,
 *   then call handle_packet with our secret in ksecret1 and our
 *   peer's secret in ksecret2.
 * - otherwise, put our secret in ksecret1, make ksecret2 and kaddr NULL,
 *   and handle_packet is ready to receive a key.
 * In either case, if a matching key is received, it is saved and a
 * response is sent (if a response is a duplicate, it does no harm).
 * kmax_hops specifies the maximum hop count of incoming acceptable keys,
 * and the hop count used in sending the key.
 *
 * if subscription is not null, listens for a reply containing a key
 * matching the subscription, returning -2 if a match is found.
 */
int handle_packet (int sock, char * packet, int psize,
                   char ** contact, keyset * kset,
                   char ** message, char ** desc,
                   int * verified, time_t * sent,
                   int * duplicate, int * broadcast,
                   char * kcontact, char * ksecret1, char * ksecret2,
                   int kmax_hops,
                   char * subscription, 
                   unsigned char * addr, int nbits)
{
  if (! is_valid_message (packet, psize))
    return 0;

  struct allnet_header * hp = (struct allnet_header *) packet;
  int hsize = ALLNET_SIZE (hp->transport);
  if (psize < hsize)
    return 0;

#ifdef DEBUG_PRINT
  if (hp->hops > 0)  /* not my own packet */
    print_packet (packet, psize, "xcommon received", 1);
#endif /* DEBUG_PRINT */

  if (hp->message_type == ALLNET_TYPE_ACK) {
    handle_ack (sock, packet, psize, hsize);
    return 0;
  }

  if (hp->message_type == ALLNET_TYPE_CLEAR) { /* a broadcast packet */
    if ((subscription != NULL) && (addr != NULL)) {
      int sub = handle_sub (sock, hp, packet + hsize, psize - hsize,
                            subscription, addr, nbits);
#ifdef DEBUG_PRINT
      printf ("handle_sub (%d, %p, %p, %d, %s, %p, %d) ==> %d\n",
              sock, hp, packet + hsize, psize - hsize, subscription,
              addr, nbits, sub);
#endif /* DEBUG_PRINT */
      if (sub > 0)   /* received a key in response to our subscription */
        return sub;
    }
#ifdef DEBUG_PRINT
    else
      printf ("subscription %p, addr %p, did not call handle_sub\n",
              subscription, addr);
#endif /* DEBUG_PRINT */
    return handle_clear (hp, packet + hsize, psize - hsize,
                         contact, message, verified, broadcast);
  }

  if (hp->message_type == ALLNET_TYPE_DATA) /* an encrypted data packet */
    return handle_data (sock, hp, packet + hsize, psize - hsize,
                        contact, kset, message, desc, verified, sent,
                        duplicate, broadcast);

  if (hp->message_type == ALLNET_TYPE_KEY_XCHG)
    return handle_key (sock, hp, packet + hsize, psize - hsize,
                       kcontact, ksecret1, ksecret2, kmax_hops);

  return 0;
}

/* send this message and save it in the xchat log. */
/* returns the sequence number of this message, or 0 for errors */
long long int send_data_message (int sock, char * peer,
                                 char * message, int mlen)
{
  if (mlen <= 0) {
    printf ("unable to send a data message of size %d\n", mlen);
    return 0;
  }

  int dsize = mlen + CHAT_DESCRIPTOR_SIZE;
  char * data_with_cd = malloc_or_fail (dsize, "xcommon.c send_data_message");
  struct chat_descriptor * cp = (struct chat_descriptor *) data_with_cd;
  if (! init_chat_descriptor (cp, peer)) {
    printf ("unknown contact %s\n", peer);
    free (data_with_cd);
    return 0;
  }
  uint64_t seq = readb64u (cp->counter);
  memcpy (data_with_cd + CHAT_DESCRIPTOR_SIZE, message, mlen);
  /* send_to_contact initializes the message ack in data_with_cd/cp */
#ifdef DEBUG_PRINT
  printf ("sending seq %" PRIu64 ":\n", seq);
#endif /* DEBUG_PRINT */
  send_to_contact (data_with_cd, dsize, peer, sock,
                   NULL, 16, NULL, 16, 4, ALLNET_PRIORITY_LOCAL, 1);
  free (data_with_cd);
  return seq;
}

/* if there is anyting unacked, resends it.  If any sequence number is known
 * to be missing, requests it */
/* but not too often */
void request_and_resend (int sock, char * contact, keyset kset)
{
  if (get_counter (contact) <= 0) {
    printf ("unable to request and resend for %s, peer not found\n", contact);
    return;
  }
/*  printf ("request_and_resend (socket %d, peer %s)\n", sock, peer); */
  static char * old_contact = NULL;

  /* if it is the same peer as on the last call, we do nothing */
  if ((old_contact != NULL) && (strcmp (contact, old_contact) == 0)) {
/*    printf ("request_and_resend (%s), same as old peer\n", peer); */
    return;
  }

  if (old_contact != NULL)
    free (old_contact);
  old_contact = strcpy_malloc (contact, "request_and_resend contact");

  /* request retransmission of any missing messages */
  int hops = 10;
  send_retransmit_request (contact, kset, sock, hops,
                           ALLNET_PRIORITY_LOCAL_LOW);

  /* resend any unacked messages, but no more than once every hour */
  static time_t last_resend = 0;
  time_t now = time (NULL);
  if (now - last_resend > 3600) {
    last_resend = now;
    resend_unacked (contact, kset, sock, hops, ALLNET_PRIORITY_LOCAL_LOW, 10);
  }
}

/* send the public key, followed by the hmac of the public key using
 * the secret as the key for the hmac, and return 1.
 * secret2 may be NULL, secret1 should not be.
 * or fail and returns 0 if the contact already exists (or other errors) */
int create_contact_send_key (int sock, char * contact, char * secret1,
                             char * secret2, int hops)
{
  unsigned char address [ADDRESS_SIZE];
  random_bytes ((char *) address, sizeof (address));
  int abits = 16;
  keyset kset = create_contact (contact, 4096, 1, NULL, 0,
                                address, abits, NULL, 0);
  if (kset < 0) {
    printf ("contact %s already exists\n", contact);
    return 0;
  }
  if (send_key (sock, contact, kset, secret1, address, abits, hops)) {
    printf ("send_key sent key to contact %s, %d hops, secret %s\n",
            contact, hops, secret1);
    if ((secret2 != NULL) && (strlen (secret2) > 0) &&
        (send_key (sock, contact, kset, secret2, address, abits, hops)))
      printf ("send_key also sent key to contact %s, %d hops, secret %s\n",
              contact, hops, secret2);
    return 1;
  }
  printf ("send_key failed for create_contact_send_key\n");
  return 0;
}

static int send_key_request (int sock, char * phrase,
                             unsigned char * addr, int * nbits)
{
  /* compute the destination address from the phrase */
  unsigned char destination [ADDRESS_SIZE];
  char * mapped;
  int mlen = map_string (phrase, &mapped);
  sha512_bytes (mapped, mlen, (char *) destination, 1);
  free (mapped);

  random_bytes ((char *) addr, ADDRESS_SIZE);
  *nbits = 8;
  int dsize = 1;  /* nbits_fingerprint with no key */
  int psize = -1;
  struct allnet_header * hp =
    create_packet (dsize, ALLNET_TYPE_KEY_REQ, 10, ALLNET_SIGTYPE_NONE,
                   addr, *nbits, destination, *nbits, NULL, &psize);
  
  if (hp == NULL) {
    printf ("send_key_request: unable to create packet of size %d/%d\n",
            dsize, psize);
    return 0;
  }
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

#ifdef DEBUG_PRINT
  printf ("sending %d-byte key request\n", psize);
#endif /* DEBUG_PRINT */
  if (! send_pipe_message_free (sock, packet, psize, ALLNET_PRIORITY_LOCAL)) {
    printf ("unable to send key request message\n");
    return 0;
  }
  return 1;
}

/* sends out a request for a key matching the subscription.
 * returns 1 for success (and fills in my_addr and nbits), 0 for failure */
int subscribe_broadcast (int sock, char * ahra,
                         unsigned char * my_addr, int * nbits)
{
  char * phrase;
  char * reason;
  if (! parse_ahra (ahra, &phrase, NULL, NULL, NULL, NULL, &reason)) {
    printf ("subcribe_broadcast unable to parse '%s': %s\n", ahra, reason);
    return 0;
  }
  if (! send_key_request (sock, phrase, my_addr, nbits))
    return 0;
  return 1;
}

