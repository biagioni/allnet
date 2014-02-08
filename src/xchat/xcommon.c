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
#include "priority.h"
#include "util.h"

static void request_cached_data (int sock)
{
  struct allnet_header_data ah;
  memset (&ah, 0, sizeof (ah));
  ah.version = ALLNET_VERSION;
  ah.packet_type = ALLNET_TYPE_DATA_REQ;
  ah.hops = 0;
  ah.max_hops = 5;
  ah.src_nbits = 0;  /* for now, later maybe put our address */
  ah.dst_nbits = 0;
  ah.sig_algo = ALLNET_SIGTYPE_NONE;
  ah.pad = 0;
  /* a bit of randomness to make it clear this packet is not the same
   * as any other packet we might have sent before */
  struct timeval now;
  gettimeofday (&now, NULL);
  sha512_bytes (&now, sizeof (now), ah.packet_id, PACKET_ID_SIZE);
  if (! send_pipe_message (sock, (char *) (&ah),
                           ALLNET_HEADER_DATA_SIZE, THREE_QUARTERS))
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

  int sock = connect_to_local ();
  if (sock < 0)
    return -1;
  add_pipe (sock);
  request_cached_data (sock);
  return sock;
}

/* optional... */
void xchat_end (int sock)
{
  close (sock);
}

#define NUM_ACKS	10
/* initial contents should not matter, accidental match is unlikely */
static char recently_sent_acks [NUM_ACKS] [PACKET_ID_SIZE];
static int currently_sent_ack = 0;

static int is_recently_sent_ack (char * packet_id)
{
  int i;
  for (i = 0; i < NUM_ACKS; i++)
    if (memcmp (packet_id, recently_sent_acks [i], PACKET_ID_SIZE) == 0)
      return 1;
  return 0;
}

/* send an ack for the given packet and packet ID */
static void send_ack (int sock, struct allnet_header_data * hp, char * packet_id)
{
  static int ack_number = 0;
  char buffer [ALLNET_HEADER_DATA_SIZE + 1];
  buffer [ALLNET_HEADER_DATA_SIZE] = (ack_number++) % 256;
  struct allnet_header_data * ack = (struct allnet_header_data *) buffer;
  ack->version = hp->version;
  ack->packet_type = ALLNET_TYPE_DATA_ACK;
  ack->hops = 0;
  ack->max_hops = hp->hops + 2;  /* for margin, send 2 more hops than received */
  ack->src_nbits = hp->dst_nbits;
  ack->dst_nbits = hp->src_nbits;
  ack->sig_algo = ALLNET_SIGTYPE_NONE;
  *((long long int *)ack->source) = *((long long int *)(hp->destination));
  *((long long int *)ack->destination) = *((long long int *)(hp->source));
  memcpy (ack->packet_id, packet_id, PACKET_ID_SIZE);
  /* also save in the (very likely) event that we receive our own ack */
  currently_sent_ack = (currently_sent_ack + 1) % NUM_ACKS;
  memcpy (recently_sent_acks [currently_sent_ack], packet_id, PACKET_ID_SIZE);
  send_pipe_message (sock, buffer, sizeof (buffer), SEVEN_EIGHTS);
  /* printf ("ack sent\n"); */
}

/* handle an incoming packet, acking it if it is a data packet for us */
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
  if (psize < ALLNET_HEADER_DATA_SIZE) {
/*
    printf ("packet size %d less than data header size %zd, dropping\n",
            psize, ALLNET_HEADER_DATA_SIZE);
*/
    return 0;
  }

  struct allnet_header_data * hp = (struct allnet_header_data *) packet;
  if (hp->packet_type == ALLNET_TYPE_DATA_ACK) {
    /* save the ack */
    char * contact;
    long long int ack_number = ack_received (hp->packet_id, &contact);
/*
    if (ack_number > 0)
      printf ("sequence number %lld acked\n", ack_number);
    else if (ack_number == -2)
      printf ("packet acked again\n");
    else if (is_recently_sent_ack (hp->packet_id))
      printf ("received my own ack\n");
    else
      print_buffer (hp->packet_id, PACKET_ID_SIZE, "unknown ack rcvd",
                    PACKET_ID_SIZE, 1);
*/
    fflush (NULL);
    if (contact != NULL)
      free (contact);
    return 0;
  }

  if (hp->packet_type != ALLNET_TYPE_DATA) {
#ifdef DEBUG_PRINT
    printf ("not a data packet, dropping\n");
#endif /* DEBUG_PRINT */
    return 0;
  }

  /* we know it is a data packet */
  int verif = 0;
  int ssize = 0;  /* size of the signature */
  char * sig = NULL;
  if (hp->sig_algo != ALLNET_SIGTYPE_NONE)
    ssize = ((packet [psize - 2] & 0xff) << 8) +
             (packet [psize - 1] & 0xff) + 2;
/*  print_buffer (packet + psize - 2, 2, "sigsize", 16, 1); */
  /* size needed for the unencrypted part of the packet (Header and Trailer) */
  unsigned int htsize = ALLNET_HEADER_DATA_SIZE + ssize;
  if (psize <= htsize) {
    printf ("data packet size %d less than header and trailer %d, dropping\n",
            psize, htsize);
    return 0;
  }
/*printf ("header and trailer size %d, signature size %d\n", htsize, ssize); */
  char * contact = NULL;
  char * text = NULL;
  int tsize = decrypt_verify (hp->sig_algo, packet + ALLNET_HEADER_DATA_SIZE,
                              psize - ALLNET_HEADER_DATA_SIZE,
                              &contact, &text,
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

  long long int seq = read_big_endian64 (cdp->counter);
  if (seq == COUNTER_FLAG) {
    do_chat_control (sock, contact, text, tsize, 9);
    send_ack (sock, hp, cdp->packet_id);
    if (contact != NULL) free (contact);
    if (text != NULL) free (text);
    return 0;
  }

  *duplicate = 0;
  if (was_received (contact, seq))
    *duplicate = 1;

  save_incoming (contact, cdp, cleartext, msize);

  *peer = contact;
  *message = malloc (msize + 1);
  if (*message == NULL) {
    perror ("malloc new message");
    exit (1);
  }
  memcpy (*message, cleartext, msize);
  (*message) [msize] = '\0';   /* null-terminate the message */
  *desc = chat_descriptor_to_string (cdp, 0, 0);
  *verified = verif;
  if (sent != NULL)
    *sent = (read_big_endian64 (cdp->timestamp) >> 16) & 0xffffffff;

  free (text);

  /* printf ("hp->hops = %d\n", hp->hops); */

  send_ack (sock, hp, cdp->packet_id);
#if 0
  /* send ack */
#ifdef DEBUG_PRINT
  printf ("acking packet with sequence %lld\n", seq);
#endif /* DEBUG_PRINT */
  struct allnet_header_data ack;
  ack.version = hp->version;
  ack.packet_type = ALLNET_TYPE_DATA_ACK;
  ack.hops = 0;
  ack.max_hops = hp->hops + 2;  /* for margin, send 2 more hops than received */
  ack.src_nbits = hp->dst_nbits;
  ack.dst_nbits = hp->src_nbits;
  ack.sig_algo = ALLNET_SIGTYPE_NONE;
  *((long long int *)ack.source) = *((long long int *)(hp->destination));
  *((long long int *)ack.destination) = *((long long int *)(hp->source));
  memcpy (ack.packet_id, cdp->packet_id, PACKET_ID_SIZE);
  /* also save in the (very likely) event that we receive our own ack */
  memcpy (recently_sent_ack, cdp->packet_id, PACKET_ID_SIZE);
  send_pipe_message (sock, (char *)&ack, ALLNET_HEADER_DATA_SIZE, SEVEN_EIGHTS);
  /* printf ("ack sent\n"); */
#endif /* 0 */

  return msize;
}

/* send this packet and save it in the xchat log. */
/* returns the sequence number of this packet, or 0 for errors */
long long int send_data_packet (int sock, char * peer,
                                char * message, int mlen)
{
  if (mlen <= 0) {
    printf ("unable to send a data packet of size %d\n", mlen);
    return 0;
  }

  static char clear [ALLNET_MTU - ALLNET_HEADER_DATA_SIZE];
  struct chat_descriptor * cp = (struct chat_descriptor *) clear;
  bzero (cp->packet_id, PACKET_ID_SIZE);
  static char packet [ALLNET_MTU];
  struct allnet_header_data * hp = (struct allnet_header_data *) packet;
  bzero (packet, sizeof (packet));

  if (! init_chat_descriptor (cp, peer, hp->packet_id)) {
    printf ("unknown contact %s\n", peer);
    return;
  }
  if (sizeof (clear) < CHAT_DESCRIPTOR_SIZE + mlen) {
    printf ("message too long: %d chars, max is %zd, truncating\n",
            mlen, sizeof (clear) - CHAT_DESCRIPTOR_SIZE);
    mlen = sizeof (clear) - CHAT_DESCRIPTOR_SIZE;
  }
  memcpy (clear + CHAT_DESCRIPTOR_SIZE, message, mlen);

  /* encrypt */
  char * key;
  int ksize = get_contact_pubkey (peer, &key);
  if (ksize <= 0) {
    printf ("error (%d): unable to get public key for %s\n", ksize, peer);
    return;
  }
  char * encr;
  int esize = encrypt (clear, CHAT_DESCRIPTOR_SIZE + mlen, key, ksize, &encr);
  if (esize == 0) {
    printf ("error: unable to encrypt packet\n");
    return;
  }
  free (key);

  ksize = get_my_privkey (peer, &key);
  char * sig;
  int ssize = sign (encr, esize, key, ksize, &sig);
  free (key);

  hp->version = ALLNET_VERSION;
  hp->packet_type = ALLNET_TYPE_DATA;
  hp->hops = 0;
  hp->max_hops = 9;
  hp->src_nbits = 0;   /* to do: set addresses */
  hp->dst_nbits = 0;
  hp->sig_algo = ALLNET_SIGTYPE_RSA_PKCS1;
  memcpy (packet + ALLNET_HEADER_DATA_SIZE, encr, esize);
  memcpy (packet + ALLNET_HEADER_DATA_SIZE + esize, sig, ssize);
  int index = ALLNET_HEADER_DATA_SIZE + esize + ssize;
  packet [index] = (ssize >> 8) & 0xff;
  packet [index + 1] = ssize & 0xff;
  int size = ALLNET_HEADER_DATA_SIZE + esize + ssize + 2;
  free (encr);
  free (sig);

  if (send_pipe_message (sock, packet, size, SEVEN_EIGHTS))
    save_outgoing (peer, cp, message, mlen);
}

/* if there is anyting unacked, resends it.  If any sequence number is known
 * to be missing, requests it */
void request_and_resend (int sock, char * peer)
{
/*  printf ("request_and_resend (socket %d, peer %s)\n", sock, peer); */
  static char * old_peer = NULL;

  /* if it is the same peer as on the last call, we do nothing */
  if ((old_peer != NULL) && (strcmp (peer, old_peer) == 0)) {
/*    printf ("request_and_resend (%s), same as old peer\n", peer); */
    return;
  }

  /* request retransmission of any missing packets */
  int msize;
  char src [ADDRESS_SIZE];
  char dst [ADDRESS_SIZE];
  int sbits = 0;
  int dbits = 0;
  int hops = 10;
  char * message = retransmit_request (peer, 0, src, sbits, dst, dbits,
                                       hops, &msize);
  if (message == NULL) {
    /* printf ("nothing to request from %s\n", peer); */
  } else {
    if (! send_pipe_message (sock, message, msize, THREE_QUARTERS))
      printf ("unable to request retransmission from %s\n", peer);
    else
      /* printf ("requested retransmission from %s\n", peer); */
  
    free (message);
  }
  if (old_peer != NULL)
    free (old_peer);
  old_peer = strcpy_malloc (peer, "request_and_resend peer");

  /* resend any unacked messages, but no more than once every 30s */
  static time_t last_resend = 0;
  time_t now = time (NULL);
  if (now - last_resend > 30) {
    last_resend = now;
    struct retransmit_messages msgs = retransmit_unacked (peer, 9);
    int i;
    for (i = 0; i < msgs.num_messages; i++) {
      if (! send_pipe_message (sock, msgs.messages [i],
                               msgs.message_lengths [i], THREE_QUARTERS))
        /* note priority is slightly less than for regular messages */
        printf ("unable to retransmit message %d of size %d\n", i,
                msgs.message_lengths [i]);
    }
    free_retransmit (msgs);
  }
}

