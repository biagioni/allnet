/* xcommon.c: send and receive messages for xchat */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <inttypes.h>

#include "chat.h"
#include "xcommon.h"
#include "message.h"
#include "cutil.h"
#include "retransmit.h"
#include "lib/priority.h"
#include "lib/util.h"
#include "lib/log.h"

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
  add_pipe (sock);
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
static void send_ack (int sock, struct allnet_header * hp, char * message_ack,
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
print_packet ((char *) ackp, size, "sending ack", 1);
  send_pipe_message_free (sock, (char *) ackp, size, ALLNET_PRIORITY_LOCAL);
/* after sending the ack, see if we can get any outstanding
 * messages from the peer */
  if (send_resend_request)
    request_and_resend (sock, contact, kset);
}

/* handle an incoming message, acking it if it is a data message for us */
/* if it is a data or ack, it is saved in the xchat log */
/* fills in peer, message, desc (all to point to statically-allocated
 * buffers) and verified, and returns the message length > 0 if this was
 * a valid data message from a peer.  Otherwise returns 0 */
/* the data message (if any) is null-terminated */
int handle_packet (int sock, char * packet, int psize,
                   char ** contact, keyset * kset,
                   char ** message, char ** desc,
                   int * verified, time_t * sent, int * duplicate)
{
/*  print_timestamp ("received packet"); */
  struct timeval tv;
  gettimeofday (&tv, NULL);
  printf ("%ld.%06ld: got %d-byte packet from socket %d\n",
          tv.tv_sec, tv.tv_usec, psize, sock);
/*  print_buffer (packet, psize, "handle_packet", 24, 1); */
  if (! is_valid_message (packet, psize)) {
/*
    printf ("packet size %d less than data header size %zd, dropping\n",
            psize, ALLNET_HEADER_DATA_SIZE);
*/
    return 0;
  }

  struct allnet_header * hp = (struct allnet_header *) packet;
  int hsize = ALLNET_SIZE (hp->transport);
  if ((psize < hsize) || ((hp->message_type != ALLNET_TYPE_DATA) &&
                          (hp->message_type != ALLNET_TYPE_ACK))) {
    return 0;
  }

  if (hp->hops > 0)  /* not my own packet */
    print_packet (packet, psize, "xcommon received", 1);

  if (hp->message_type == ALLNET_TYPE_ACK) {
    /* save the acks */
    char * ack = packet + ALLNET_SIZE (hp->transport);
    int count = (psize - hsize) / MESSAGE_ID_SIZE; 
    int i;
    for (i = 0; i < count; i++) {
      long long int ack_number = ack_received (ack, contact, kset);
      if (ack_number > 0) {
        printf ("sequence number %lld acked\n", ack_number);
        request_and_resend (sock, *contact, *kset);
/*    } else if (ack_number == -2) {
        printf ("packet acked again\n"); */
      } else if (is_recently_sent_ack (ack)) {
        printf ("received my own ack\n");
      } else {
        print_buffer (ack, MESSAGE_ID_SIZE, "unknown ack rcvd",
                      MESSAGE_ID_SIZE, 1);
      }
      fflush (NULL);
/* */
      ack += MESSAGE_ID_SIZE;
    }
    return 0;
  }

  /* we now know it is a data packet */
  int verif = 0;
  int ssize = 0;  /* size of the signature */
  char * sig = NULL;
  if (hp->sig_algo != ALLNET_SIGTYPE_NONE)
    ssize = readb16 (packet + (psize - 2));
/*  print_buffer (packet + psize - 2, 2, "sigsize", 16, 1); */
  /* size needed for the unencrypted part of the packet (header+trailer)*/
  unsigned int htsize = hsize + ssize;
  if (psize <= htsize) {
    printf ("data packet size %d less than header and trailer %d, dropping\n",
            psize, htsize);
    return 0;
  }
/*printf ("header and trailer size %d, signature size %d\n", htsize, ssize); */
  char * text = NULL;
  int tsize = decrypt_verify (hp->sig_algo, packet + hsize, psize - hsize,
                              contact, kset, &text,
                              hp->source, hp->src_nbits, hp->destination,
                              hp->dst_nbits, 0);
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
  char * cleartext = text + CHAT_DESCRIPTOR_SIZE;
  int msize = tsize - CHAT_DESCRIPTOR_SIZE;

  long long int seq = readb64 (cdp->counter);
  if (seq == COUNTER_FLAG) {
    do_chat_control (*contact, *kset, text, tsize, sock, hp->hops + 4);
    send_ack (sock, hp, cdp->message_ack, verif, *contact, *kset);
    if (*contact != NULL) { free (*contact); *contact = NULL; }
    if (text != NULL) free (text);
    return 0;
  }

  *duplicate = 0;
  if (was_received (*contact, *kset, seq))
    *duplicate = 1;

  save_incoming (*contact, *kset, cdp, cleartext, msize);

  *message = malloc_or_fail (msize + 1, "handle_packet message");
  memcpy (*message, cleartext, msize);
  (*message) [msize] = '\0';   /* null-terminate the message */
  *desc = chat_descriptor_to_string (cdp, 0, 0);
  *verified = verif;
  if (sent != NULL)
    *sent = (readb64 (cdp->timestamp) >> 16) & 0xffffffff;

  /* printf ("hp->hops = %d\n", hp->hops); */

  send_ack (sock, hp, cdp->message_ack, verif, *contact, *kset);

  free (text);

  return msize;
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

  int transport = ALLNET_TRANSPORT_ACK_REQ;
  int dsize = mlen + CHAT_DESCRIPTOR_SIZE;
  char * data_with_cd = malloc_or_fail (dsize, "xcommon.c send_data_message");
  struct chat_descriptor * cp = (struct chat_descriptor *) data_with_cd;
  if (! init_chat_descriptor (cp, peer)) {
    printf ("unknown contact %s\n", peer);
    free (data_with_cd);
    return 0;
  }
  uint64_t seq = readb64 (cp->counter);
  memcpy (data_with_cd + CHAT_DESCRIPTOR_SIZE, message, mlen);
  /* send_to_contact initializes the message ack in data_with_cd/cp */
printf ("sending seq %" PRIu64 ":\n", seq);
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

