/* retransmit.c: support requesting and resending chat messages */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lib/util.h"
#include "lib/priority.h"
#include "lib/keys.h"
#include "chat.h"
#include "store.h"
#include "cutil.h"
#include "retransmit.h"

#define DEBUG_PRINT

/* figures out the number of singles and the number of ranges. */
/* returns a dynamically allocated array (must be free'd) of
 *    (COUNTER_SIZE) bytes * (singles + 2 * ranges);
 * or NULL for failure
 */
static char * gather_missing_info (char * contact, int * singles, int * ranges,
                                   unsigned long long int * rcvd_sequence)
{
  *rcvd_sequence = get_last_received (contact);
  if (*rcvd_sequence <= 0) {
    printf ("never received for contact %s\n", contact);
    return NULL;
  }
  char * missing = get_missing (contact, singles, ranges);
  if ((missing == NULL) || ((*singles == 0) && (*ranges == 0))) {
#ifdef DEBUG_PRINT
    printf ("no messages missing from contact %s\n", contact);
#endif /* DEBUG_PRINT */
    if (missing != NULL)
      free (missing);
    return NULL;
  }
#ifdef DEBUG_PRINT
  int d;
  printf ("generating %d singles, %d ranges:\n", *singles, *ranges);
  for (d = 0; d < *singles; d++)
    printf ("%lld, ", readb64 (missing + d * COUNTER_SIZE));
  for (d = 0; d < *ranges; d++)
  printf ("%lld-%lld, ",
  readb64 (missing + ((2 * d     + *singles) * COUNTER_SIZE)),
  readb64 (missing + ((2 * d + 1 + *singles) * COUNTER_SIZE)));
#endif /* DEBUG_PRINT */
  return missing;
}

/* allocates and fills in in the chat control request header, except for
 * the message_ack */
/* returns the request (*rsize bytes) for success, NULL for failure */
static char * create_chat_control_request (char * contact, char * missing,
                                           int num_singles, int num_ranges,
                                           unsigned long long int rcvd_sequence,
                                           int * rsize)
{
  *rsize = 0;
  /* compute number of counters in request */
  int counters_size = (num_singles + 2 * num_ranges) * COUNTER_SIZE;
  int size = sizeof (struct chat_control_request) + counters_size;
  unsigned char * request = malloc_or_fail (size, "retransmit_request");
  if (request == NULL)
    return NULL;

  bzero (request, size);
  struct chat_control_request * ccrp = (struct chat_control_request *) request;
  writeb64 (ccrp->counter, COUNTER_FLAG);
  ccrp->type = CHAT_CONTROL_TYPE_REQUEST;
  ccrp->num_singles = num_singles;
  ccrp->num_ranges = num_ranges;
  writeb64 (ccrp->last_received, rcvd_sequence);
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
#ifdef DEBUG_PRINT
  printf ("retransmit request for %s includes %d singles, %d ranges\n",
          contact, num_singles, num_ranges);
#endif /* DEBUG_PRINT */
  *rsize = size;
  return request;
}

#if 0 /* now in cutil */
static int send_to_contact (char * data, int dsize, char * contact, int sock,
                            char * src, int sbits, char * dst, int dbits,
                            int hops, int priority)
{
  /* get the keys */
  keyset * keys;
  int nkeys = all_keys (contact, &keys);
  if (nkeys <= 0) {
    printf ("unable to locate key for contact %s (%d)\n", contact, nkeys);
    return 0;
  }

  int result = 1;
  int k;
  for (k = 0; k < nkeys; k++) {
    char * priv_key;
    char * key;
    int priv_ksize = get_my_privkey (keys [k], &priv_key);
    int ksize = get_contact_pubkey (keys [k], &key);
    if ((priv_ksize == 0) || (ksize == 0)) {
      printf ("unable to locate key %d for contact %s (%d, %d)\n",
              k, contact, priv_ksize, ksize);
      continue;  /* skip to the next key */
    }
    /* set the message ack */
    struct chat_descriptor * cdp = (struct chat_descriptor *) data;
    random_bytes (cdp->message_ack, MESSAGE_ID_SIZE);
    char message_ack_hash [MESSAGE_ID_SIZE];
    sha512_bytes (cdp->message_ack, MESSAGE_ID_SIZE,
                  message_ack_hash, MESSAGE_ID_SIZE);
    /* encrypt */
    char * encrypted;
    int esize = encrypt (data, dsize, key, ksize, &encrypted);
    if (esize == 0) {  /* some serious problem */
      printf ("unable to encrypt retransmit request for key %d of %s\n",
              k, contact);
      result = 0;
      break;  /* exit the loop */
    }
    /* sign */
    char * signature;
    int ssize = sign (encrypted, esize, priv_key, priv_ksize, &signature);
    if (ssize == 0) {
      printf ("unable to sign retransmit request\n");
      free (encrypted);
      result = 0;
      break;  /* exit the loop */
    }

    int transport = ALLNET_TRANSPORT_ACK_REQ;

    int hsize = ALLNET_SIZE (transport);
    int msize = hsize + esize + ssize + 2;
    char * message = malloc_or_fail (msize, "retransmit_request message");
    bzero (message, msize);
    struct allnet_header * hp = (struct allnet_header *) message;
    hp->version = ALLNET_VERSION;
    hp->message_type = ALLNET_TYPE_DATA;
    hp->hops = 0;
    hp->max_hops = hops;
    hp->src_nbits = sbits;
    hp->dst_nbits = dbits;
    hp->sig_algo = ALLNET_SIGTYPE_RSA_PKCS1;
    hp->transport = transport;
    memcpy (hp->source, src, ADDRESS_SIZE);
    memcpy (hp->destination, dst, ADDRESS_SIZE);
    memcpy (ALLNET_MESSAGE_ID(hp, transport, msize),
            message_ack_hash, MESSAGE_ID_SIZE);

    memcpy (message + hsize, encrypted, esize);
    free (encrypted);
    memcpy (message + hsize + esize, signature, ssize);
    free (signature);
    writeb16 (message + hsize + esize + ssize, ssize);

    if (! send_pipe_message (sock, message, msize, priority))
      printf ("unable to request retransmission from %s\n", contact);
    /* else
        printf ("requested retransmission from %s\n", peer); */
    free (message);
  }
  return result;
}
#endif /* 0 -- now in cutil */

/* sends a chat_control message to request retransmission.
 * returns 1 for success, 0 in case of error.
 */ 
int send_retransmit_request (char * contact, int sock,
                             char * src, int sbits, char * dst, int dbits,
                             int hops, int priority)
{
  int num_singles;
  int num_ranges;
  unsigned long long int rcvd_sequence;
  char * missing = gather_missing_info (contact, &num_singles, &num_ranges,
                                        &rcvd_sequence);
  if (missing == NULL)
    return 0;

  int size = 0;
  char * request =
    create_chat_control_request (contact, missing, num_singles, num_ranges,
                                 rcvd_sequence, &size);
  free (missing);
  if (request == NULL)
    return 0;

  int result = send_to_contact (request, size, contact, sock, src, sbits,
                                dst, dbits, hops, priority);
  free (request);
  return result;
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
    unsigned long long int start = readb64 (ranges + index);
    index += COUNTER_SIZE;
    unsigned long long int finish = readb64 (ranges + index);
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
    unsigned long long int n = readb64 (singles + i * COUNTER_SIZE);
    if ((n < last) && ((result == MAXLL) || (result < n)))
      result = n;
  }
#ifdef DEBUG_PRINT
  printf ("get_prev (%lld, %p/%d, %p/%d) ==> %lld\n",
          last, singles, num_singles, ranges, num_ranges, result);
#endif /* DEBUG_PRINT */
  return result;
}

static void resend_message (unsigned long long int seq, char * contact,
                            int sock, char * src, int sbits,
                            char * dst, int dbits, int hops, int priority)
{
  int size;
  unsigned long long int time;
  char message_ack [MESSAGE_ID_SIZE];
  char * text = get_outgoing (contact, seq, &size, &time, message_ack);
  if ((text == NULL) || (size <= 0))
    return;
  char * message = malloc_or_fail (size + CHAT_DESCRIPTOR_SIZE, "resend_msg");
  bzero (message, CHAT_DESCRIPTOR_SIZE);
  struct chat_descriptor * cdp = (struct chat_descriptor *) message;
  writeb64 (cdp->counter, seq);
  writeb64 (cdp->timestamp, time);
  memcpy (message + CHAT_DESCRIPTOR_SIZE, text, size);
  free (text);
#ifdef DEBUG_PRINT
  printf ("retransmitting outgoing to %s, seq %lld, time %lld/0x%llx\n",
          contact, seq, time, time);
#endif /* DEBUG_PRINT */
  send_to_contact (message, size + CHAT_DESCRIPTOR_SIZE, contact, sock,
                   src, sbits, dst, dbits, hops, priority);
  free (text);
}

/* resends the messages requested by the retransmit message */
void resend_messages (char * retransmit_message, int mlen, char * contact,
                      int sock, char * src, int sbits, char * dst, int dbits,
                      int hops, int top_priority)
{
#ifdef DEBUG_PRINT
  printf ("in resend_messages (%p, %d, %s, %d, %d)\n", message, mlen, contact,
          sock, hops);
#endif /* DEBUG_PRINT */
  if (mlen < sizeof (struct chat_control_request)) {
    printf ("message size %d less than %zd, cannot be retransmit\n",
            mlen, sizeof (struct chat_control_request));
    return;
  }
  struct chat_control_request * hp =
    (struct chat_control_request *) retransmit_message;
  if (hp->type != CHAT_CONTROL_TYPE_REQUEST) {
    printf ("message type %d != %d, not a retransmit request\n",
            hp->type, CHAT_CONTROL_TYPE_REQUEST);
    return;
  }
  int expected_size = COUNTER_SIZE * (hp->num_singles + 2 * hp->num_ranges)
                      + sizeof (struct chat_control_request);
  if (mlen != expected_size) {
    printf ("message size %d was not the expected %d, invalid retransmit\n",
            mlen, expected_size);
    return;
  }

  unsigned long long int counter = get_counter (contact);
  if (counter == 0LL) {
    printf ("contact %s not found, cannot retransmit\n", contact);
    return;
  }

  /* priority decreases gradually from 5/8, which is less than for
   * fresh messages. */
  int priority = top_priority;
  /* assume the more recent messages are more important, so send them first */
  unsigned long long int last = readb64 (hp->last_received);
  while (counter > last) {
    resend_message (counter, contact, sock, src, sbits, dst, dbits, hops,
                    priority);
    counter--;
    priority -= EPSILON;
  }
  /* now send any prior messages */
  while (1) {
    unsigned long long int prev =
      get_prev (last, hp->counters, hp->num_singles,
                hp->counters + (hp->num_singles * COUNTER_SIZE),
                hp->num_ranges);
    if (prev == MAXLL)   /* no more found before this */
      break;
    resend_message (prev, contact, sock, src, sbits, dst, dbits, hops,
                    priority);
    last = prev;
    priority -= EPSILON;
  }
}

void resend_unacked (char * contact, int sock, 
                     char * src, int sbits, char * dst, int dbits,
                     int hops, int priority)
{
  int singles;
  int ranges;
  char * unacked = get_unacked (contact, &singles, &ranges);
  if (unacked == NULL)
    return;

  int i;
  for (i = 0; i < singles; i++) {
    unsigned long long int seq = readb64 (unacked);
    unacked += COUNTER_SIZE;
    resend_message (seq, contact, sock, src, sbits, dst, dbits, hops, priority);
  }
  for (i = 0; i < ranges; i++) {
    unsigned long long int start = readb64 (unacked);
    unacked += COUNTER_SIZE;
    unsigned long long int finish = readb64 (unacked);
    unacked += COUNTER_SIZE;
    while (start <= finish) {
      resend_message (start, contact, sock, src, sbits, dst, dbits, hops,
                      priority);
      start++;
    }
  }
}

/* retransmit any requested messages */
void do_chat_control (char * contact, char * msg, int msize, int sock,
                      char * src, int sbits, char * dst, int dbits, int hops)
{
  struct chat_control * cc = (struct chat_control *) msg;
  if (cc->type == CHAT_CONTROL_TYPE_REQUEST) {
    resend_messages (msg, msize, contact, sock,
                     src, sbits, dst, dbits, hops, FIVE_EIGHTS);
  } else {
    printf ("chat control type %d, not implemented\n", cc->type);
  }
}


