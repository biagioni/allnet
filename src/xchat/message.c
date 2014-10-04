/* message.c: use store.c to provide non-volatile storage of chat messages */

/* messages are stored in each contact's directory under a day file, e.g.
 * ~/.allnet/xchat/20130101174522/20140302
 * group messages are stored in that group's directory (not yet implemented).
 *
 * each contact may have multiple keys, and thus multiple directories.
 * Directories are indirectly identified by keys.
 * keys.c/key_dir returns a directory x as ~/.allnet/contacts/x,
 * in which case the chat information is stored under ~/.allnet/xchat/x
 *
 * note that:
 * - messages we send are sent to all instances of a given contact,
 *   so sequence numbers (and messages) we send are the same across
 *   all directories of a contact
 * - messages we receive are sent independently by each of the instances
 *   of a contact, so their sequence numbers are independent.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include "chat.h"
#include "message.h"
#include "store.h"
#include "cutil.h"
#include "lib/util.h"
#include "lib/keys.h"

/* return the lowest unused counter, used as sequence number when sending
 * messages to this contact.  returns 0 if the contact cannot be found */
uint64_t get_counter (char * contact)
{
  keyset * kset;
  int nkeys = all_keys (contact, &kset);
  if (nkeys < 0)
    return 0;
  uint64_t max = 0;
  int i;
  for (i = 0; i < nkeys; i++) {
    uint64_t seq;
    int type = highest_seq_record (contact, kset [i], MSG_TYPE_SENT,
                                   &seq, NULL, NULL, NULL, NULL, NULL);
    if ((type != MSG_TYPE_DONE) && (seq > max))
      max = seq;
  }
  return max + 1;
}

/* return the largest received counter, or 0 if the contact cannot be found
 * or the keyset is not valid. */
uint64_t get_last_received (char * contact, keyset k)
{
  uint64_t seq;
  int type = highest_seq_record (contact, k, MSG_TYPE_RCVD,
                                 &seq, NULL, NULL, NULL, NULL, NULL);
  if (type == MSG_TYPE_RCVD)
    return seq;
  return 0;
}

/* search for a message with a message ack matching "wanted", and of wtype.
 * if not found, return 0
 * if found, and:
 *   if wtype is MSG_TYPE_ACK, return 1
 *   otherwise, return the sequence number of the matching message
 */
static uint64_t find_ack (char * contact, keyset k, char * wanted, int wtype)
{
  struct msg_iter * iter = start_iter (contact, k);
  if (iter == NULL)
    return 0;
  int type;
  uint64_t seq = 0;
  char ack [MESSAGE_ID_SIZE];
  while ((type = prev_message (iter, &seq, NULL, NULL, ack, NULL, NULL))
         != MSG_TYPE_DONE) {
    if ((type == wtype) &&
        (memcmp (wanted, ack, MESSAGE_ID_SIZE) == 0)) {
      free_iter (iter);
      if (wtype == MSG_TYPE_ACK)  /* seq is not set */
        return 1;
      else
        return seq;
    }
  }
  free_iter (iter);
  return 0;  /* not found */
}

/* save an outgoing message to a specific directory for this contact.
 * the directory is specific because the message ack is different for
 * each copy of the message */
void save_outgoing (char * contact, keyset k, struct chat_descriptor * cp,
                    char * text, int tsize)
{
  uint64_t time;
  int tz;
  get_time_tz (readb64u (cp->timestamp), &time, &tz);
  save_record (contact, k, MSG_TYPE_SENT, readb64u (cp->counter), time, tz,
               (char *) (cp->message_ack), text, tsize);
}

/* return the (malloc'd) outgoing message with the given sequence number,
 * or NULL if there is no such message.
 * if there is more than one such message, returns the latest.
 * Also fills in the size, time and message_ack -- message_ack must have
 * at least MESSAGE_ID_SIZE bytes */
char * get_outgoing (char * contact, keyset k, uint64_t seq,
                     int * size, uint64_t * time, char * message_ack)
{
  struct msg_iter * iter = start_iter (contact, k);
  int type;
  uint64_t mseq;
  uint64_t mtime;
  int msize;
  int tz;
  char * result;
  while ((type = prev_message (iter, &mseq, &mtime, &tz, message_ack,
          &result, &msize)) != MSG_TYPE_DONE) {
    if ((type == MSG_TYPE_SENT) && (mseq == seq)) { /* found */
      if (time != NULL)
        *time = make_time_tz (mtime, tz);
      if (size != NULL)
        *size = msize;
      free_iter (iter);
      return result;
    }
    free (result);   /* not found, try again */
  }
  free_iter (iter);
  return NULL;
}

/* save a received message */
void save_incoming (char * contact, keyset k,
                    struct chat_descriptor * cp, char * text, int tsize)
{
  uint64_t time;
  int tz;
  get_time_tz (readb64 ((char *) (cp->timestamp)), &time, &tz);
  if (find_ack (contact, k, (char *) (cp->message_ack), MSG_TYPE_RCVD) == 0)
    save_record (contact, k, MSG_TYPE_RCVD, readb64u (cp->counter),
                 time, tz, (char *) (cp->message_ack), text, tsize);
}

/* mark a previously sent message as acknowledged
 * return the sequence number > 0 if this is an ack for a known contact,
 * return 0 if this ack is not recognized
 * if result > 0:
 * if contact is not NULL, the contact is set to point to the
 * contact name (statically allocated, do not modify in any way) and
 * if kset is not null, the location it points to is set to the keyset
 */
uint64_t ack_received (char * message_ack, char ** contact, keyset * kset)
{
  char ** contacts;
  int nc = all_contacts (&contacts);
  int c;
  for (c = 0; c < nc; c++) {
    keyset * ksets;
    int nk = all_keys (contacts [c], &ksets);
    int k;
    for (k = 0; k < nk; k++) {
      uint64_t seq = find_ack (contacts [c], ksets [k], message_ack,
                               MSG_TYPE_SENT);
      if (seq > 0) {
        if (! find_ack (contacts [c], ksets [k], message_ack, MSG_TYPE_ACK))
          save_record (contacts [c], ksets [k], MSG_TYPE_ACK, seq,
                       0, 0, message_ack, NULL, 0);
        if (contact != NULL)
          *contact = contacts [c];
        if (kset != NULL)
          *kset = ksets [k];
        return seq;
      }
    }
  }
  return 0;
}

static uint64_t max_seq (char * contact, keyset k, int wanted)
{
  uint64_t seq;
  int type = highest_seq_record (contact, k, wanted, &seq, NULL, NULL, NULL,
                                 NULL, NULL);
  if (type == MSG_TYPE_DONE)
    return 0;
  return seq;
}

/* returns a new (malloc'd) array, or NULL in case of error
 * the new array has (singles + 2 * ranges) * COUNTER_SIZE bytes.
 * the first *singles sequence numbers are individual sequence numbers
 * that we never received.
 * the next *ranges * 2 sequence numbers are pairs a, b such that we have
 * not received any of the sequence numbers a <= seq <= b */
char * get_missing (char * contact, keyset k, int * singles, int * ranges)
{
  uint64_t last = max_seq (contact, k, MSG_TYPE_RCVD);
  *singles = 0;
  *ranges = 0;
  if (last < 1)
    return NULL;
/* the current implementation is quite simple and only returns singles */
#define MAX_MISSING	20
  char * result = malloc_or_fail (MAX_MISSING * COUNTER_SIZE, "get_missing");
  int missing = 0;
  uint64_t i;
  for (i = last - 1; i > 0; i--) {
    if (! was_received (contact, k, i)) {
      writeb64 (result + (missing * COUNTER_SIZE), i);
      missing++;
      if (missing >= MAX_MISSING) {
        *singles = missing;
        return result;
      }
    }
  }
  if (missing == 0) {
    free (result);
    return NULL;
  }
  *singles = missing;
  return result;
}

/* returns a new (malloc'd) array, or NULL in case of error
 * the new array has (singles + 2 * ranges) * COUNTER_SIZE bytes.
 * the first *singles sequence numbers are individual sequence numbers
 * for which we never received an ack.
 * the next *ranges * 2 sequence numbers are pairs a, b such that we have
 * not received acks for the sequence numbers a <= seq <= b */
char * get_unacked (char * contact, keyset k, int * singles, int * ranges)
{
  uint64_t last = max_seq (contact, k, MSG_TYPE_SENT);
  *singles = 0;
  *ranges = 0;
  if (last < 1)
    return NULL;
/* the current implementation is quite simple and only returns singles */
#define MAX_UNACKED	MAX_MISSING
  char * result = malloc_or_fail (MAX_UNACKED * COUNTER_SIZE, "get_unacked");
  int unacked = 0;
  uint64_t i;
  for (i = last; i > 0; i--) {
    if (! is_acked_one (contact, k, i)) {
      writeb64 (result + unacked * COUNTER_SIZE, i);
      unacked++;
      if (unacked >= MAX_UNACKED) {
        *singles = unacked;
        return result;
      }
    }
  }
  if (unacked == 0) {
    free (result);
    return NULL;
  }
  *singles = unacked;
  return result;
}

/* returns 1 if this sequence number has been acked by all the recipients,
 * 0 otherwise */
int is_acked (char * contact, uint64_t seq)
{
  keyset * kset;
  int nkeys = all_keys (contact, &kset);
  if (nkeys < 0)
    return 0;
  int k;
  for (k = 0; k < nkeys; k++)
    if (! is_acked_one (contact, kset [k], seq))
      return 0;
  return 1;
}

/* returns 1 if this sequence number has been acked by this specific recipient,
 * 0 otherwise */
int is_acked_one (char * contact, keyset k, uint64_t wanted)
{
  struct msg_iter * iter = start_iter (contact, k);
  if (iter == NULL)
    return 0;
  int type;
  uint64_t seq;
  char ack [MESSAGE_ID_SIZE];
  while ((type = prev_message (iter, &seq, NULL, NULL, ack, NULL, NULL))
         != MSG_TYPE_DONE) {
    if ((type == MSG_TYPE_SENT) && (seq == wanted)) {
/* this is the first (most recent) message sent with this sequence number.
 * we simply report whether this one has been acked -- the others are not
 * so important */
      uint64_t seq = find_ack (contact, k, ack, MSG_TYPE_ACK);
      free_iter (iter);
      return (seq > 0);
    }
  }
  free_iter (iter);
  return 0;
}

/* returns 1 if this sequence number has been received, 0 otherwise */
int was_received (char * contact, keyset k, uint64_t wanted)
{
  struct msg_iter * iter = start_iter (contact, k);
  if (iter == NULL)
    return 0;
  int type;
  uint64_t seq;
  while ((type = prev_message (iter, &seq, NULL, NULL, NULL, NULL, NULL))
         != MSG_TYPE_DONE) {
    if ((type == MSG_TYPE_RCVD) && (seq == wanted)) {
      free_iter (iter);
      return 1;
    }
  }
  free_iter (iter);
  return 0;
}
