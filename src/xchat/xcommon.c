/* xcommon.c: send and receive messages for xchat */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>

#include "chat.h"
#include "xcommon.h"
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
int xchat_init ()
{
  /* apparently openssh does all this for us */
#if 0
  /* RSA encryption uses the random number generator */
  unsigned int seed = time (NULL);
  int rfd = open ("/dev/random", O_RDONLY);
  if (rfd < 0) {
    printf ("using weak random number generator, may be insecure\n");
  } else {
    /* wish I could initialize the whole rstate!!! */
    read (rfd, ((char *) (&seed)), sizeof (unsigned int));
    close (rfd);
  }
  static char rstate [256]; 
  initstate (seed, rstate, sizeof (rstate));
#endif /* 0 */

  int sock = connect_to_local ("xcommon");
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

#define NUM_ACKS	10
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
static void send_ack (int sock, struct allnet_header * hp, char * message_ack)
{
  char buffer [ALLNET_MTU];
  struct allnet_header * ackp = (struct allnet_header *) buffer;
  ackp->version = hp->version;
  ackp->message_type = ALLNET_TYPE_ACK;
  ackp->hops = 0;
  ackp->max_hops = hp->hops + 2;/* for margin, send 2 more hops than received */
  ackp->src_nbits = hp->dst_nbits;
  ackp->dst_nbits = hp->src_nbits;
  ackp->sig_algo = ALLNET_SIGTYPE_NONE;
  ackp->transport = ALLNET_TRANSPORT_NONE;
  *((long long int *)ackp->source) = *((long long int *)(hp->destination));
  *((long long int *)ackp->destination) = *((long long int *)(hp->source));

  int hsize = ALLNET_SIZE (ackp->transport);
  memcpy (buffer + hsize, message_ack, MESSAGE_ID_SIZE);
  /* also save in the (very likely) event that we receive our own ack */
  currently_sent_ack = (currently_sent_ack + 1) % NUM_ACKS;
  memcpy (recently_sent_acks [currently_sent_ack], message_ack,
          MESSAGE_ID_SIZE);
  send_pipe_message (sock, buffer, sizeof (buffer), ALLNET_PRIORITY_LOCAL);
  /* printf ("ack sent\n"); */
}

/* handle an incoming message, acking it if it is a data message for us */
/* if it is a data or ack, it is saved in the xchat log */
/* fills in peer, message, desc (all to point to statically-allocated
 * buffers) and verified, and returns the message length > 0 if this was
 * a valid data message from a peer.  Otherwise returns 0 */
/* the data message (if any) is null-terminated */
int handle_packet (int sock, char * packet, int psize,
                   char ** peer, char ** message, char ** desc,
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
  print_packet (packet, psize, "xcommon received", 1);

  struct allnet_header * hp = (struct allnet_header *) packet;
  int hsize = ALLNET_SIZE (hp->transport);
  if ((psize < hsize) || ((hp->message_type != ALLNET_TYPE_DATA) &&
                          (hp->message_type != ALLNET_TYPE_ACK))) {
    return 0;
  }

  if (hp->message_type == ALLNET_TYPE_ACK) {
    /* save the acks */
    char * ack = packet + ALLNET_SIZE (hp->transport);
    int count = (psize - hsize) / MESSAGE_ID_SIZE; 
    int i;
    for (i = 0; i < count; i++) {
      long long int ack_number = ack_received (ack, NULL);
/* */
      if (ack_number > 0)
        printf ("sequence number %lld acked\n", ack_number);
      else if (ack_number == -2)
        printf ("packet acked again\n");
      else if (is_recently_sent_ack (ack))
        printf ("received my own ack\n");
      else
        print_buffer (ack, MESSAGE_ID_SIZE, "unknown ack rcvd",
                      MESSAGE_ID_SIZE, 1);
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
  char * contact = NULL;
  char * text = NULL;
  int tsize = decrypt_verify (hp->sig_algo, packet + hsize,
                              psize - hsize, &contact, &text,
                              hp->source, hp->src_nbits, hp->destination,
                              hp->dst_nbits, 0);
  if (tsize < 0) {
    printf ("no signature to verify, but decrypted from %s\n", contact);
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
  if (contact == NULL) {
#ifdef DEBUG_PRINT
    printf ("contact not known\n");
#endif /* DEBUG_PRINT */
    if (text != NULL) free (text);
    return 0;
  }
#ifdef DEBUG_PRINT
  printf ("got packet from contact %s\n", contact);
#endif /* DEBUG_PRINT */
  struct chat_descriptor * cdp = (struct chat_descriptor *) text;
  char * cleartext = text + CHAT_DESCRIPTOR_SIZE;
  int msize = tsize - CHAT_DESCRIPTOR_SIZE;

  long long int seq = readb64 (cdp->counter);
  if (seq == COUNTER_FLAG) {
    do_chat_control (contact, text, tsize, sock, hp->hops + 4);
    send_ack (sock, hp, cdp->message_ack);
    if (contact != NULL) free (contact);
    if (text != NULL) free (text);
    return 0;
  }

  *duplicate = 0;
  if (was_received (contact, seq))
    *duplicate = 1;

  save_incoming (contact, cdp, cleartext, msize);

  *peer = contact;
  *message = malloc_or_fail (msize + 1, "handle_packet message");
  memcpy (*message, cleartext, msize);
  (*message) [msize] = '\0';   /* null-terminate the message */
  *desc = chat_descriptor_to_string (cdp, 0, 0);
  *verified = verif;
  if (sent != NULL)
    *sent = (readb64 (cdp->timestamp) >> 16) & 0xffffffff;

  free (text);

  /* printf ("hp->hops = %d\n", hp->hops); */

  send_ack (sock, hp, cdp->message_ack);

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
    return;
  }
  memcpy (data_with_cd + CHAT_DESCRIPTOR_SIZE, message, mlen);
  /* send_to_contact initializes the message ack in data_with_cd/cp */
  send_to_contact (data_with_cd, dsize, peer, sock,
                   NULL, 16, NULL, 16, 4, ALLNET_PRIORITY_LOCAL);
  save_outgoing (peer, cp, message, mlen);
  free (data_with_cd);
}

/* if there is anyting unacked, resends it.  If any sequence number is known
 * to be missing, requests it */
void request_and_resend (int sock, char * peer)
{
  if (get_counter (peer) <= 0) {
    printf ("unable to request and resend for %s, peer not found\n", peer);
    return;
  }
/*  printf ("request_and_resend (socket %d, peer %s)\n", sock, peer); */
  static char * old_peer = NULL;

  /* if it is the same peer as on the last call, we do nothing */
  if ((old_peer != NULL) && (strcmp (peer, old_peer) == 0)) {
/*    printf ("request_and_resend (%s), same as old peer\n", peer); */
    return;
  }

  if (old_peer != NULL)
    free (old_peer);
  old_peer = strcpy_malloc (peer, "request_and_resend peer");

  /* request retransmission of any missing messages */
  int hops = 10;
  send_retransmit_request (peer, sock, hops, ALLNET_PRIORITY_LOCAL_LOW);

  /* resend any unacked messages, but no more than once every hour */
  static time_t last_resend = 0;
  time_t now = time (NULL);
  if (now - last_resend > 3600) {
    last_resend = now;
    resend_unacked (peer, sock, hops, ALLNET_PRIORITY_LOCAL_LOW);
  }
}

