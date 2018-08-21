/* retransmit.c: support requesting and resending chat messages */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include "lib/packet.h"
#include "lib/media.h"
#include "lib/util.h"
#include "lib/priority.h"
#include "lib/keys.h"
#include "chat.h"
#include "message.h"
#include "cutil.h"
#include "store.h"
#include "retransmit.h"

/* #define DEBUG_PRINT */

/* figures out the number of singles and the number of ranges. */
/* returns a dynamically allocated array (must be free'd) of
 *    (COUNTER_SIZE) bytes * (singles + 2 * ranges);
 * or NULL for failure
 */
static char * gather_missing_info (const char * contact, keyset k,
                                   int * singles, int * ranges,
                                   uint64_t * rcvd_sequence)
{
  *rcvd_sequence = get_last_received (contact, k);
  if (*rcvd_sequence <= 0) {
#ifdef DEBUG_PRINT
    printf ("never received for contact %s\n", contact);
#endif /* DEBUG_PRINT */
    return NULL;
  }
  char * missing = get_missing (contact, k, singles, ranges);
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
  printf ("for contact %s keyset %d generating %d singles, %d ranges:\n",
          contact, k, *singles, *ranges);
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
/* if num_singles == 0 == num_ranges, missing may be NULL */
static char * create_chat_control_request (const char * contact, char * missing,
                                           int num_singles, int num_ranges,
                                           uint64_t rcvd_sequence,
                                           int * rsize)
{
  *rsize = 0;
  /* compute number of counters in request */
  int counters_size = (num_singles + 2 * num_ranges) * COUNTER_SIZE;
  int size = sizeof (struct chat_control_request) + counters_size;
  char * request = malloc_or_fail (size, "retransmit_request");
  if (request == NULL)
    return NULL;

  memset (request, 0, size);
  struct chat_control_request * ccrp = (struct chat_control_request *) request;
  writeb32u (ccrp->app_media.app, XCHAT_ALLNET_APP_ID);
  writeb32u (ccrp->app_media.media, ALLNET_MEDIA_DATA);
  writeb64u (ccrp->counter, COUNTER_FLAG);
  ccrp->type = CHAT_CONTROL_TYPE_REQUEST;
  ccrp->num_singles = num_singles;
  ccrp->num_ranges = num_ranges;
  writeb64u (ccrp->last_received, rcvd_sequence);
  int i;
  unsigned char * ptr = ccrp->counters;
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
  printf ("retransmit request for %s has %d singles, %d ranges, last %lld\n",
          contact, ccrp->num_singles, ccrp->num_ranges,
          readb64u (ccrp->last_received));
  ptr = ccrp->counters;
  for (i = 0; i < num_singles; i++)
    print_buffer ((char *)(ptr + i * COUNTER_SIZE), COUNTER_SIZE,
                  "single retransmit", 15, 1);
  ptr = ccrp->counters + (num_singles * COUNTER_SIZE);
  for (i = 0; i < num_ranges; i++) {
    print_buffer ((char *)(ptr + i * COUNTER_SIZE * 2),
                  COUNTER_SIZE, "range from", 15, 1);
    print_buffer ((char *)(ptr + i * COUNTER_SIZE * 2 + COUNTER_SIZE),
                  COUNTER_SIZE, "        to", 15, 1);
  }
#endif /* DEBUG_PRINT */
  *rsize = size;
  return request;
}

/* sends a chat_control message to request retransmission.
 * returns 1 for success, 0 in case of error or if there is nothing to send */
int send_retransmit_request (const char * contact, keyset k, int sock,
                             int hops, int priority, const char * expiration)
{
  int num_singles;
  int num_ranges;
  uint64_t rcvd_sequence;
  char * missing = gather_missing_info (contact, k, &num_singles, &num_ranges,
                                        &rcvd_sequence);
  if ((missing == NULL) &&
      ((rcvd_sequence == 0) || (random_int (1, 100) <= 95)))
    return 0;
  /* either we know we are missing some messages (num_singles > 0 and/or
   * num_ranges > 0) or, with 5% chance, we request anyway, in case
   * messages have been sent that are after the last one we've received */

  int size = 0;
  char * request =
    create_chat_control_request (contact, missing, num_singles, num_ranges,
                                 rcvd_sequence, &size);
  free (missing);
  if (request == NULL)
    return 0;
  int result = send_to_key (request, size, contact, k, sock,
                            hops, priority, expiration, 1, 0);
  free (request);
  return result;
}

/* sanity check: if the last_received value is greater than
 * our get_counter, change our sequence number to match, otherwise
 * our messages will be ignored as duplicates. */
static void sanity_check_sequence_number (const char * contact, keyset k,
                                          struct chat_control_request * hp,
                                          int sock, int hops)
{
  uint64_t counter = get_counter (contact);
  uint64_t last = readb64u (hp->last_received);
  if (counter >= last)
    return;
  printf ("error: counter %ju < last_received %ju\n",
          (uintmax_t)counter, (uintmax_t)last);
  /* send an empty message, using the last missing sequence number */
  size_t cd_size = sizeof (struct chat_descriptor);
  size_t dsize = 1;  /* message is a single space, " " */
  char * message = malloc_or_fail (cd_size + dsize, "sanity_check_seq");
  char * data = message + cd_size;
  memcpy (data, " ", dsize);
  size_t msize = cd_size + dsize;
  struct chat_descriptor * cdp = (struct chat_descriptor *) message;
  if (! init_chat_descriptor (cdp, contact))
    return;
  writeb64u (cdp->counter, last);  /* final sequence number */
  save_outgoing (contact, k, cdp, data, 0);
  /* since this is sort of a housekeeping message, send with minimum priority */
  send_to_key (message, (int)msize, contact, k, sock,
               hops, ALLNET_PRIORITY_EPSILON, NULL, 1, 1);
  free (message);
}

#define MAXLL	((uint64_t) (-1LL))
/* return -1 (MAXLL) if no previous, otherwise the previous sequence number */
static uint64_t get_prev (uint64_t last,
                          unsigned char * singles, unsigned int num_singles,
                          unsigned char * ranges, unsigned int num_ranges)
{
  /* printf ("maxLL is %jx\n", (uintmax_t)MAXLL); */
  uint64_t result = MAXLL;
  if (last <= 0)
    return result;
  /* in what follows, last > 0, so last-1 is a valid expression >= 0 */
  unsigned int i;
  for (i = 0; i < num_ranges; i++) {
    unsigned int index = 2 * i * COUNTER_SIZE;
    uint64_t start = readb64u (ranges + index);
    index += COUNTER_SIZE;
    uint64_t finish = readb64u (ranges + index);
    if (start <= finish) {        /* a reasonable range */
      if (start <= last - 1) {    /* range may have the prev */
        uint64_t candidate = last - 1;
        if (finish < candidate)
          candidate = finish;
        if ((result == MAXLL) || (result < candidate))
          result = candidate;
      }
    }
  }
  for (i = 0; i < num_singles; i++) {
    uint64_t n = readb64u (singles + i * COUNTER_SIZE);
    if ((n < last) && ((result == MAXLL) || (result < n)))
      result = n;
  }
#ifdef DEBUG_PRINT
  printf ("get_prev (%ju, %p/%d, %p/%d) ==> %ju\n",
          (uintmax_t)last, singles, num_singles, ranges, num_ranges,
          (uintmax_t)result);
#endif /* DEBUG_PRINT */
  return result;
}

#define LIMIT_RETRANSMIT_RATE  /* 2017/03/10: still experimenting, for now
                                  keep it enabled */
#ifdef LIMIT_RETRANSMIT_RATE
/* the allnet xchat protocol has two mechanisms for retransmitting:
 * - pull: a receiver that knows it is lacking some message will
 *   request them, sending a chat_control_request
 * - push: a sender with unacked message will retransmit them
 * both are done when a message from the peer indicates the peer may
 * be reachable.
 *
 * This redundancy is good, leading perhaps to greater packet delivery.
 * However, it can also lead to unnecessary (duplicate) packet
 * retransmission, which is not particularly useful.
 *
 * To avoid duplicate retransmission, we remember the last few
 * retransmitted packets, and do not retransmit them again if they
 * were sent within the most recent TIME_BEFORE_RESEND.
 */
/* #define TIME_BEFORE_RESEND	600    * 600 seconds, 10 min */
#define TIME_BEFORE_RESEND	27    /* 27 seconds, ~1/2 min */
#define NUM_RECENTLY_RESENT	100
struct resend_info {
  uint64_t seq;
  char * contact;
  keyset k;
  time_t resend_time;
};
static struct resend_info recently_resent [NUM_RECENTLY_RESENT];
static int latest_resent = 0;

static void init_resent ()
{
  static int initialized = 0;
  if (! initialized) {
    initialized = 1;
    int i;
    for (i = 0; i < NUM_RECENTLY_RESENT; i++) {
      recently_resent [i].seq = 0;
      recently_resent [i].contact = NULL;
      recently_resent [i].k = -1;
    }
    latest_resent = 0;
  }
}

static int was_recently_resent (uint64_t seq, const char * contact, keyset k)
{
  int i;
  for (i = 0; i < NUM_RECENTLY_RESENT; i++) {
    if ((recently_resent [i].contact != NULL) &&
        (recently_resent [i].seq == seq) &&
        (recently_resent [i].k == k) &&
        (strcmp (recently_resent [i].contact, contact) == 0) &&
        (allnet_time () <
         (unsigned long long int) (recently_resent [i].resend_time) +
                                  TIME_BEFORE_RESEND))
      return 1;
  }
  return 0;
}

static void record_resend (uint64_t seq, const char * contact, keyset k)
{
  latest_resent = (latest_resent + 1) % NUM_RECENTLY_RESENT;
  if (recently_resent [latest_resent].contact != NULL)
    free (recently_resent [latest_resent].contact);
  recently_resent [latest_resent].seq = seq;
  recently_resent [latest_resent].k = k;
  recently_resent [latest_resent].contact =
      strcpy_malloc (contact, "record_resend");
  recently_resent [latest_resent].resend_time = (time_t) (allnet_time ());
}
#endif /* LIMIT_RETRANSMIT_RATE */

static void resend_message (uint64_t seq, const char * contact,
                            keyset k, int sock,
                            unsigned int hops, unsigned int priority)
{
#ifdef DEBUG_PRINT
  printf ("resending message with sequence %ju to %s/%d\n",
          (uintmax_t)seq, contact, k);
#endif /* DEBUG_PRINT */
#ifdef LIMIT_RETRANSMIT_RATE
  init_resent ();
  if (was_recently_resent (seq, contact, k)) {
#ifdef DEBUG_PRINT
    printf ("recently resent seq %ju %s/%d, not sending again\n",
            (uintmax_t)seq, contact, k);
#endif /* DEBUG_PRINT */
    return;
  }
#endif /* LIMIT_RETRANSMIT_RATE */
  int size;
  uint64_t time;
  char message_ack [MESSAGE_ID_SIZE];
  char * text = get_outgoing (contact, k, seq, &size, &time, message_ack);
  if ((text == NULL) || (size <= 0)) {
#ifdef DEBUG_PRINT
    printf ("  resend_message %s %d: no outgoing %ju, %p %d\n",
            contact, k, (uintmax_t)seq, text, size);
#endif /* DEBUG_PRINT */
    return;
  }
#ifdef DEBUG_PRINT
  printf ("  resending message with sequence %ju to %s: %s\n",
          (uintmax_t)seq, contact, text);
#endif /* DEBUG_PRINT */
#ifdef LIMIT_RETRANSMIT_RATE
  record_resend (seq, contact, k);
#endif /* LIMIT_RETRANSMIT_RATE */
  char * message = malloc_or_fail (size + CHAT_DESCRIPTOR_SIZE, "resend_msg");
  memset (message, 0, CHAT_DESCRIPTOR_SIZE);
  struct chat_descriptor * cdp = (struct chat_descriptor *) message;
  memcpy (cdp->message_ack, message_ack, MESSAGE_ID_SIZE);
  writeb64u (cdp->counter, seq);
  writeb64u (cdp->timestamp, time);
  /* the fixed part of the header */
  writeb32 ((char *) (cdp->app_media.app), XCHAT_ALLNET_APP_ID);
  writeb32 ((char *) (cdp->app_media.media), ALLNET_MEDIA_TEXT_PLAIN);
  memcpy (message + CHAT_DESCRIPTOR_SIZE, text, size);
#ifdef DEBUG_PRINT
  printf ("  rexmit outgoing %s, seq %ju, t %ju/0x%jx\n",
          contact, (uintmax_t)seq, (uintmax_t)time, (uintmax_t)time);
  print_buffer ((char *) cdp->message_ack, MESSAGE_ID_SIZE, "rexmit ack", 5, 1);
#endif /* DEBUG_PRINT */
  resend_packet (message, size + CHAT_DESCRIPTOR_SIZE, contact, k, sock,
                 hops, priority);
#ifdef DEBUG_PRINT
  printf ("  resent message with sequence ");
  if (seq != readb64 ((char *)cdp->counter))
    printf ("%ju =? %ju ", (uintmax_t)seq,
            (uintmax_t)readb64 ((char *)cdp->counter));
  else
    printf ("%ju ", (uintmax_t)seq);
  printf ("to %s: '%s'\n", contact, text);
#endif /* DEBUG_PRINT */
  free (text);
  free (message);
}

/* resends the messages requested by the retransmit message */
static void resend_messages (const char * retransmit_message, int mlen,
                             const char * contact, keyset k, int sock,
                             unsigned int hops, unsigned int top_priority,
                             unsigned int max)
{
#ifdef DEBUG_PRINT
  printf ("in resend_messages (%p, %d, %s, %d, %d, %d)\n",
          retransmit_message, mlen, contact, k, sock, hops);
#endif /* DEBUG_PRINT */
  if (mlen < (int) (sizeof (struct chat_control_request))) {
    printf ("message size %d less than %zd, cannot be retransmitted\n",
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
  if (readb32u (hp->app_media.app) != XCHAT_ALLNET_APP_ID) {
    printf ("message app %08lx != %08x, not an xchat message\n",
            readb32u (hp->app_media.app), XCHAT_ALLNET_APP_ID);
    return;
  }
  int expected_size = COUNTER_SIZE * (hp->num_singles + 2 * hp->num_ranges)
                      + sizeof (struct chat_control_request);
  if (mlen != expected_size) {
    printf ("message size %d was not the expected %d, invalid retransmit\n",
            mlen, expected_size);
    return;
  }

  uint64_t counter = get_counter (contact);
  if (counter == 0LL) {
    printf ("contact %s not found, cannot retransmit\n", contact);
    return;
  }
  counter--;   /* the last counter sent, which is one less than get_counter */
#ifdef DEBUG_PRINT
  printf ("rcvd rexmit request for %s, %d singles, %d ranges, last %lld\n",
          contact, hp->num_singles, hp->num_ranges,
          readb64u (hp->last_received));
  char * ptr = (char *)(hp->counters);
  int i;
  for (i = 0; i < hp->num_singles; i++)
    print_buffer (ptr + i * COUNTER_SIZE, COUNTER_SIZE,
                  "single retransmit", 15, 1);
  ptr = (char *)(hp->counters + (hp->num_singles * COUNTER_SIZE));
  for (i = 0; i < hp->num_ranges; i++) {
    print_buffer (ptr + i * COUNTER_SIZE * 2,                COUNTER_SIZE,
                  "range from", 15, 1);
    print_buffer (ptr + i * COUNTER_SIZE * 2 + COUNTER_SIZE, COUNTER_SIZE,
                  "        to", 15, 1);
  }
#endif /* DEBUG_PRINT */

  unsigned int send_count = 0;
  /* priority decreases gradually from 5/8, which is less than for
   * fresh messages. */
  unsigned int priority = top_priority;
  /* assume the more recent messages are more important, so send them first */
  /* and with slightly higher priority */
  uint64_t last = readb64u (hp->last_received);
  while ((counter > last) && (send_count < max)) {
    resend_message (counter, contact, k, sock, hops, priority);
    counter--;
    send_count++;
    priority -= ALLNET_PRIORITY_EPSILON;
  }
  /* now send any prior messages */
  while (1) {
    uint64_t prev =
      get_prev (last, hp->counters, hp->num_singles,
                hp->counters + (hp->num_singles * COUNTER_SIZE),
                hp->num_ranges);
    if (prev == MAXLL)   /* no more found before this */
      break;
    if (send_count++ >= max)
      break;
    resend_message (prev, contact, k, sock, hops, priority);
    last = prev;
    priority -= ALLNET_PRIORITY_EPSILON;
  }
  sanity_check_sequence_number (contact, k, hp, sock, hops);
}

/* returns the number of messages sent, or 0 */
int resend_unacked (const char * contact, keyset k, int sock, 
                    int hops, int priority, int max)
{
  int singles;
  int ranges;
  char * unacked = get_unacked (contact, k, &singles, &ranges);
#ifdef DEBUG_PRINT
  printf ("get_unacked returned %d singles, %d ranges, %p\n",
          singles, ranges, unacked);
#endif /* DEBUG_PRINT */
  if (unacked == NULL)
    return 0;

  int max_send = 8;
  int send_count = 0;
  char * p = unacked;
  int i;
  for (i = 0; (i < singles) && (send_count < max_send); i++) {
    uint64_t seq = readb64 (p);
#ifdef DEBUG_PRINT
    printf ("seq %ju at %p\n", (uintmax_t)seq, p);
#endif /* DEBUG_PRINT */
    p += sizeof (uint64_t);
    resend_message (seq, contact, k, sock, hops, priority);
    send_count++;
  }
  for (i = 0; (i < ranges) && (send_count < max_send); i++) {
    uint64_t start = readb64 (p);
    p += COUNTER_SIZE;
    uint64_t finish = readb64 (p);
    p += COUNTER_SIZE;
    while ((send_count < max_send) && (start <= finish)) {
      resend_message (start, contact, k, sock, hops, priority);
      start++;
      send_count++;
    }
  }
  free (unacked);
  return send_count;
}

/* retransmit any requested messages */
void do_chat_control (const char * contact, keyset k, char * msg, int msize,
                      int sock, int hops)
{
  struct chat_control * cc = (struct chat_control *) msg;
  if (cc->type == CHAT_CONTROL_TYPE_REQUEST) {
    resend_messages (msg, msize, contact, k, sock, hops,
                     ALLNET_PRIORITY_LOCAL_LOW, 16);
  } else {
    printf ("chat control type %d, not implemented\n", cc->type);
  }
}


