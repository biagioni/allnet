/* retransmit.c: support requesting and resending chat messages */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "util.h"
#include "priority.h"
#include "chat.h"
#include "store.h"
#include "cutil.h"
#include "retransmit.h"

#define DEBUG_PRINT

/* allocates and returns a buffer containing a chat_control message that
 * may be sent to request retransmission.
 * The buffer includes the allnet header.
 * if always_generate is 1, always returns such a buffer (except in
 * case of errors, when NULL is returned.
 * if always_generate is 0, only returns the buffer if there are known
 * gaps in the sequence numbers received from this contact.
 * returns NULL in case of error or if no buffer is returned..
 */
unsigned char * retransmit_request (char * contact, int alway_generate,
                                    char * src, int sbits,
                                    char * dst, int dbits, int hops,
                                    int * msize)
{
  /* get the keys, make sure all that is fine */
  char * key;
  int ksize = get_contact_pubkey (contact, &key);
  if (ksize == 0) {
    printf ("unable to locate key for contact %s (%d)\n", contact, ksize);
    return NULL;
  }
  unsigned long long int rcvd_sequence = get_last_received (contact);
  if (rcvd_sequence <= 0) {
    printf ("never received for contact %s\n", contact);
    return NULL;
  }
  char * priv_key;
  int priv_ksize = get_my_privkey (contact, &priv_key);
  if (priv_ksize == 0) {
    printf ("unable to locate pkey for contact %s (%d)\n", contact, priv_ksize);
    free (key);
    return NULL;
  }
  int num_singles;
  int num_ranges;
  char * missing = get_missing (contact, &num_singles, &num_ranges);

/*
int d;
printf ("generating %d singles, %d ranges:\n", num_singles, num_ranges);
for (d = 0; d < num_singles; d++)
  printf ("%lld, ", read_big_endian64 (missing + d * COUNTER_SIZE));
for (d = 0; d < num_ranges; d++)
printf ("%lld-%lld, ",
read_big_endian64 (missing + ((2 * d     + num_singles) * COUNTER_SIZE)),
read_big_endian64 (missing + ((2 * d + 1 + num_singles) * COUNTER_SIZE)));
*/

  if ((missing == NULL) || ((num_singles == 0) && (num_ranges == 0))) {
    /* printf ("no messages missing from contact %s\n", contact); */
    if (missing != NULL)
      free (missing);
    free (key);
    free (priv_key);
    return NULL;
  }

  /* compute number of counters in request */
  int counters_size = (num_singles + 2 * num_ranges) * COUNTER_SIZE;
  int size = sizeof (struct chat_control_request) + counters_size;
  unsigned char * request = malloc_or_fail (size, "retransmit_request");
  /* set to all zeros the packet ID and other fields we don't use */
  memset (request, 0, size);
  struct chat_control_request * ccrp = (struct chat_control_request *) request;
  random_bytes (ccrp->packet_id, PACKET_ID_SIZE);
  char packet_id_hash [PACKET_ID_SIZE];
  sha512_bytes (ccrp->packet_id, PACKET_ID_SIZE, packet_id_hash, PACKET_ID_SIZE);
  write_big_endian64 (ccrp->counter, COUNTER_FLAG);
  ccrp->type = CHAT_CONTROL_TYPE_REQUEST;
  ccrp->num_singles = num_singles;
  ccrp->num_ranges = num_ranges;
  write_big_endian64 (ccrp->last_received, rcvd_sequence);
  int i;
  char * ptr = ccrp->counters;

  for (i = 0; i < num_singles; i++) {
#ifdef DEBUG_PRINT
    print_buffer (missing + i * COUNTER_SIZE, COUNTER_SIZE,
                  "single retransmit", 15, 1);
#endif /* DEBUG_PRINT */
    memcpy (ptr, missing + i * COUNTER_SIZE, COUNTER_SIZE);
    ptr += COUNTER_SIZE;
  }
  for (i = 0; i < num_ranges; i++) {
    int index = num_singles + i * 2;
#ifdef DEBUG_PRINT
    print_buffer (missing + (index    ) * COUNTER_SIZE, COUNTER_SIZE,
                  "range from", 15, 1);
#endif /* DEBUG_PRINT */
    memcpy (ptr,  missing + (index    ) * COUNTER_SIZE, COUNTER_SIZE);
    ptr += COUNTER_SIZE;
#ifdef DEBUG_PRINT
    print_buffer (missing + (index + 1) * COUNTER_SIZE, COUNTER_SIZE,
                  "        to", 15, 1);
#endif /* DEBUG_PRINT */
    memcpy (ptr,  missing + (index + 1) * COUNTER_SIZE, COUNTER_SIZE);
    ptr += COUNTER_SIZE;
  }
  free (missing);
#ifdef DEBUG_PRINT
  printf ("retransmit request for %s includes %d singles, %d ranges\n",
          contact, num_singles, num_ranges);
#endif /* DEBUG_PRINT */

  /* encrypt */
  char * encrypted;
  int esize = encrypt (request, size, key, ksize, &encrypted);
  free (request);
  if (esize == 0) {
    printf ("unable to encrypt retransmit request\n");
    free (key);
    free (priv_key);
    return NULL;
  }

  /* sign */
  char * signature;
  int ssize = sign (encrypted, esize, priv_key, priv_ksize, &signature);
  if (ssize == 0) {
    printf ("unable to sign retransmit request\n");
    free (encrypted);
    free (key);
    free (priv_key);
    return NULL;
  }
  free (key);
  free (priv_key);

  size = ALLNET_HEADER_DATA_SIZE + esize + ssize + 2;
  request = malloc_or_fail (size, "retransmit_request packet");

  memcpy (request + ALLNET_HEADER_DATA_SIZE, encrypted, esize);
  free (encrypted);
  memcpy (request + ALLNET_HEADER_DATA_SIZE + esize, signature, ssize);
  free (signature);
  write_big_endian16 (request + ALLNET_HEADER_DATA_SIZE + esize + ssize, ssize);

  /* initialize request header */
  /* set to zero unused fields, including the packet ID */
  memset (request, 0, ALLNET_HEADER_DATA_SIZE);
  struct allnet_header_data * hp = (struct allnet_header_data *) request;
  hp->version = ALLNET_VERSION;
  hp->packet_type = ALLNET_TYPE_DATA;
  hp->hops = 0;
  hp->max_hops = hops + 2;  /* for margin, send 2 more hops than received */
  hp->src_nbits = sbits;
  hp->dst_nbits = dbits;
  hp->sig_algo = ALLNET_SIGTYPE_RSA_PKCS1;
  memcpy (hp->source, src, ADDRESS_SIZE);
  memcpy (hp->destination, dst, ADDRESS_SIZE);
  memcpy (hp->packet_id, packet_id_hash, PACKET_ID_SIZE);

  *msize = size;
#ifdef DEBUG_PRINT
  print_buffer (request, size, "request", 50, 1); 
#endif /* DEBUG_PRINT */
  return request;
}
#undef DEBUG_PRINT

#define MAXLL	(-1LL)
/* return -1 (MAXLL) if no previous, or the previous otherwise */
static unsigned long long int get_prev (unsigned long long int last,
                                        unsigned char * singles,
                                        unsigned int num_singles,
                                        unsigned char * ranges,
                                        unsigned int num_ranges)
{
  /* printf ("maxLL is %llx\n", MAXLL); */
  unsigned long long int result = MAXLL;
  if (last <= 0)
    return result;
  /* in what follows, last > 0, so last-1 is a valid expression >= 0 */
  int i;
  for (i = 0; i < num_ranges; i++) {
    int index = 2 * i * COUNTER_SIZE;
    unsigned long long int start = read_big_endian64 (ranges + index);
    index += COUNTER_SIZE;
    unsigned long long int finish = read_big_endian64 (ranges + index);
    if (start <= finish) {        /* a reasonable range */
      if (start <= last - 1) {    /* range may have the prev */
        unsigned long long int candidate = last - 1;
        if (finish < candidate)
          candidate = finish;
        if ((result == MAXLL) || (result < candidate))
          result = candidate;
      }
    }
  }
  for (i = 0; i < num_singles; i++) {
    unsigned long long int n = read_big_endian64 (singles + i * COUNTER_SIZE);
    if ((n < last) && ((result == MAXLL) || (result < n)))
      result = n;
  }
#ifdef DEBUG_PRINT
  printf ("get_prev (%lld, %p/%d, %p/%d) ==> %lld\n",
          last, singles, num_singles, ranges, num_ranges, result);
#endif /* DEBUG_PRINT */
  return result;
}

/* code adapted from send_packet in xchats.c (now in xcommon.c) */
static char * buffer_to_data_message (char * text, int tsize,
                                      char * contact,
                                      unsigned long long int seq,
                                      unsigned long long int time,
                                      int hops, char * packet_id, int * rsize)
{
  static char clear [ALLNET_MTU - ALLNET_HEADER_DATA_SIZE];
  struct chat_descriptor * cp = (struct chat_descriptor *) clear;

  memcpy (cp->packet_id, packet_id, PACKET_ID_SIZE);
  write_big_endian64 (cp->counter, seq);
  write_big_endian64 (cp->timestamp, time);

  if (sizeof (clear) < CHAT_DESCRIPTOR_SIZE + tsize) {
    printf ("resend message too long: %d chars, max is %zd, truncating\n",
            tsize, sizeof (clear) - CHAT_DESCRIPTOR_SIZE);
    tsize = sizeof (clear) - CHAT_DESCRIPTOR_SIZE;
  }
  memcpy (clear + CHAT_DESCRIPTOR_SIZE, text, tsize);

  /* encrypt */
  char * key;
  int ksize = get_contact_pubkey (contact, &key);
  if (ksize <= 0) {
    printf ("error (%d): unable to get public key for\n", ksize, contact);
    return NULL;
  }
  char * encr;
  int esize = encrypt (clear, CHAT_DESCRIPTOR_SIZE + tsize, key, ksize, &encr);
  if (esize == 0) {
    printf ("error: unable to encrypt packet\n");
    return NULL;
  }

  ksize = get_my_privkey (contact, &key);
  char * sig;
  int ssize = sign (encr, esize, key, ksize, &sig);
  free (key);

  int size = ALLNET_HEADER_DATA_SIZE + esize + ssize + 2;
  char * packet = calloc (size, 1);
  if (packet == NULL) {
    printf ("unable to allocate %d bytes for retransmit packet\n", size);
    return NULL;
  }
  struct allnet_header_data * hp = (struct allnet_header_data *) packet;

  hp->version = ALLNET_VERSION;
  hp->packet_type = ALLNET_TYPE_DATA;
  hp->hops = 0;
  hp->max_hops = hops;
  hp->src_nbits = 0;   /* to do: set addresses */
  hp->dst_nbits = 0;
  hp->sig_algo = ALLNET_SIGTYPE_RSA_PKCS1;
  sha512_bytes (packet_id, PACKET_ID_SIZE, hp->packet_id, PACKET_ID_SIZE);
  memcpy (packet + ALLNET_HEADER_DATA_SIZE, encr, esize);
  memcpy (packet + ALLNET_HEADER_DATA_SIZE + esize, sig, ssize);
  int index = ALLNET_HEADER_DATA_SIZE + esize + ssize;
  packet [index] = (ssize >> 8) & 0xff;
  packet [index + 1] = ssize & 0xff;
  free (encr);
  free (sig);

  *rsize = size;
  return packet;
}

static char * get_resend_message (char * contact, unsigned long long int seq,
                                  int hops, int * mlen)
{
  int size;
  unsigned long long int time;
  char packet_id [PACKET_ID_SIZE];
  char * text = get_outgoing (contact, seq, &size, &time, packet_id);
  if ((text == NULL) || (size <= 0))
    return 0;
#ifdef DEBUG_PRINT
  printf ("retransmitting outgoing, seq %lld, time %lld/0x%llx\n",
          seq, time, time);
#endif /* DEBUG_PRINT */
  /* convert the text to something we can send. */
  int msize;
  char * message = buffer_to_data_message (text, size, contact, seq, time,
                                           hops, packet_id, &msize);
  free (text);
  if ((message == NULL) || (msize <= 0)) {
    *mlen = 0;
    return NULL;
  }
  *mlen = msize;
  return message;
}

/* returns 1 for success, 0 for error */
static int get_resend (struct retransmit_messages * result, int index,
                       char * contact, unsigned long long int seq, int hops)
{
  printf ("get_resend storing resend seq %lld at index %d\n", seq, index);
  result->messages [index] =
     get_resend_message (contact, seq, hops, result->message_lengths + index);
  if ((result->messages [index] == NULL) ||
      (result->message_lengths [index] <= 0))
    printf ("  (failed)\n");
  if ((result->messages [index] == NULL) ||
      (result->message_lengths [index] <= 0))
    return 0;
  return 1;
}

/*
struct retransmit_messages {
  int num_messages;
  char * * messages;
  int * message_lengths;
};
*/

/* analyzes the retransmit message and the last sequence number sent for
 * the contact, and fills in result (up to result.num_messages) to give
 * the messages that can be resent.
 * returns the number of messages that can be sent (<= result.num_messages),
 * returns 0 in case of errors.
 */
static int get_resends (char * contact, char * message, int mlen, int hops,
                        struct retransmit_messages * result)
{
  int available = result->num_messages;
#ifdef DEBUG_PRINT
  printf ("in get_resends (%s, %p, %d)\n", contact, message, mlen);
#endif /* DEBUG_PRINT */
  if (mlen < sizeof (struct chat_control_request)) {
    printf ("message size %d less than %zd, cannot be retransmit\n",
            mlen, sizeof (struct chat_control_request));
    return 0;
  }
  struct chat_control_request * hp = (struct chat_control_request *) message;
  if (hp->type != CHAT_CONTROL_TYPE_REQUEST) {
    printf ("message type %d != %d, not a retransmit request\n",
            hp->type, CHAT_CONTROL_TYPE_REQUEST);
    return 0;
  }
  int expected_size = COUNTER_SIZE * (hp->num_singles + 2 * hp->num_ranges)
                      + sizeof (struct chat_control_request);
  if (mlen < expected_size) {
    printf ("message size %d less than %d, invalid retransmit\n",
            mlen, expected_size);
    return 0;
  }
  unsigned long long int counter = get_counter (contact);
  if (counter == 0LL) {
    printf ("contact %s not found, cannot retransmit\n", contact);
    return 0;
  }

  /* add all the sequence numbers from hp->last_received+1 to counter */
  unsigned long long int last = read_big_endian64 (hp->last_received);
  if (last + available < counter)
    last = counter - available;
  int index = 0;
  unsigned long long int seq;
  for (seq = last + 1; seq < counter; seq++) {
    if (get_resend (result, index, contact, seq, hops))
      index++;
    else {
      printf ("1: unable to get retransmit sequence %lld for %s, skipping\n",
              seq, contact);
#ifdef DEBUG_PRINT
#endif /* DEBUG_PRINT */
      break;
    }
  }
  while (index < available) {
    unsigned long long int prev =
      get_prev (last, hp->counters, hp->num_singles,
                hp->counters + (hp->num_singles * COUNTER_SIZE),
                hp->num_ranges);
    if (prev == MAXLL)   /* no more found before this */
      break;
    if (get_resend (result, index, contact, prev, hops)) { /* add to results */
      last = prev;                   /* next should be before this one */
      index++;                       /* at the next index */
    } else {
      printf ("2: unable to get retransmit sequence %lld for %s, skipping\n",
              prev, contact);
#ifdef DEBUG_PRINT
#endif /* DEBUG_PRINT */
      break;
    }
  }
  result->num_messages = index;
  return index;
}

/* returns a collection of messages that may be sent to the contact that
 * sent us the retransmit message.  The number of messages may be 0 or more.
 * After it has been used, the pointers in the retransmit_messages should
 * be freed by calling free_retransmit.
 */
struct retransmit_messages
    retransmit_received (char * contact, char * message, int mlen, int hops)
{
#ifdef DEBUG_PRINT
  printf ("in retransmit_received (%p, %p, %d)\n", contact, message, mlen);
#endif /* DEBUG_PRINT */
  struct retransmit_messages result;
  result.num_messages = 0;
  result.messages = NULL;
  result.message_lengths = NULL;

#define MAX_RESENDS_AT_ONCE	5
  int size = MAX_RESENDS_AT_ONCE * (sizeof (char *) + sizeof (int));
  char * buffer = malloc (size);
  if (buffer == NULL) {
    printf ("retransmit_received, unable to allocate %d bytes for %d\n",
            size, MAX_RESENDS_AT_ONCE);
    return result;
  }
  result.num_messages = MAX_RESENDS_AT_ONCE;
  result.messages = (char * *) buffer;
  result.message_lengths = 
        (int *) (buffer + (result.num_messages * sizeof (char *)));
  int i;
  for (i = 0; i < result.num_messages; i++) {
    result.messages [i] = NULL;
    result.message_lengths [i] = 0;
  }
  result.num_messages = get_resends (contact, message, mlen, hops, &result);
  return result;
}

/* returns 0 or more of the messages that were sent, but not acked */
struct retransmit_messages retransmit_unacked (char * contact, int hops)
{
  struct retransmit_messages result;
  result.num_messages = 0;
  result.messages = NULL;
  result.message_lengths = NULL;

  int singles;
  int ranges;
  char * unacked = get_unacked (contact, &singles, &ranges);
  if (unacked == NULL)
    return result;

  int total = singles;
  char * rangep = unacked + (COUNTER_SIZE * total);
  
  int i;
  for (i = 0; i < ranges; i++) {
    unsigned long long int start =
       read_big_endian64 (rangep +  i * 2      * COUNTER_SIZE);
    unsigned long long int finish =
       read_big_endian64 (rangep + (i * 2 + 1) * COUNTER_SIZE);
    total += (finish + 1 - start);
  }
  if (total > MAX_RESENDS_AT_ONCE) {
    printf ("total resends %d, sending %d\n", total, MAX_RESENDS_AT_ONCE);
#ifdef DEBUG_PRINT
#endif /* DEBUG_PRINT */
    total = MAX_RESENDS_AT_ONCE;
  }
  int size = total * (sizeof (char *) + sizeof (int));
  char * buffer = malloc (size);
  if (buffer == NULL) {
    printf ("retransmit_unacked, unable to allocate %d bytes for %d\n",
            size, total);
    return result;
  }
  result.num_messages = total;
  result.messages = (char * *) buffer;
  result.message_lengths = 
        (int *) (buffer + (result.num_messages * sizeof (char *)));
  int count = 0;  /* how many messages we have */
  for (i = 0; count < total && i < singles; i++) {
    unsigned long long int seq = 
       read_big_endian64 (unacked + i * COUNTER_SIZE);
    result.messages [count] =
       get_resend_message (contact, seq, hops, result.message_lengths + count);
    /* printf ("single unacked %d is %lld, count %d\n", i, seq, count); */
    count++;
  }
  for (i = 0; count < total && i < ranges; i++) {
    unsigned long long int start =
       read_big_endian64 (rangep + (i * 2    ) * COUNTER_SIZE);
    unsigned long long int finish =
       read_big_endian64 (rangep + (i * 2 + 1) * COUNTER_SIZE);
    printf ("range unacked %d is %lld-%lld, count %d\n",
            i, start, finish, count);
    unsigned long long int j;
    for (j = start; count < total && j <= finish; j++) {
      result.messages [count] =
         get_resend_message (contact, j, hops, result.message_lengths + count);
      count++;
    }
  }
  free (unacked);
/*
  printf ("retransmit_unacked returning %d singles, %d ranges, total %d/%d\n",
          singles, ranges, count, result.num_messages); */
  return result;
}

void free_retransmit (struct retransmit_messages msg_info)
{
  if (msg_info.num_messages > 0) {
    int i;
    for (i = 0; i < msg_info.num_messages; i++)
      if (msg_info.messages [i] != NULL)
        free (msg_info.messages [i]);
    /* it is enough to free messages, since message_lengths is allocated by
     * the same malloc operation */
    free (msg_info.messages);
  }
}

/* retransmit any requested messages */
void do_chat_control (int sock, char * contact, char * msg, int msize,
                      int hops)
{
  struct chat_control * cc = (struct chat_control *) msg;
  if (cc->type == CHAT_CONTROL_TYPE_REQUEST) {
    struct retransmit_messages rxt =
            retransmit_received (contact, msg, msize, hops);
    printf ("retransmitting %d messages:\n", rxt.num_messages);
    int i;
    for (i = 0; i < rxt.num_messages; i++) {
      int rsize = rxt.message_lengths [i];
#ifdef DEBUG_PRINT
      printf ("  retransmitting %d bytes\n", rsize);
#endif /* DEBUG_PRINT */
      send_pipe_message (sock, rxt.messages [i], rsize, THREE_QUARTERS);
    }
    free_retransmit (rxt);
  } else {
    printf ("chat control type %d, not implemented\n", cc->type);
  }
}


