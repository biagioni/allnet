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
#include <pthread.h>
#ifdef CHECK_ASSERTIONS
#include <assert.h>
#endif /* CHECK_ASSERTIONS */

#include "chat.h"
#include "message.h"
#include "store.h"
#include "cutil.h"
#include "lib/util.h"
#include "lib/keys.h"
#include "lib/sha.h"

/* return the lowest unused counter, used as sequence number when sending
 * messages to this contact.  returns 0 if the contact cannot be found */
uint64_t get_counter (const char * contact)
{
  keyset * kset = NULL;
  int nkeys = all_keys (contact, &kset);
  if (nkeys < 0)
    return 0;
  uint64_t max = 0;
  int i;
  for (i = 0; i < nkeys; i++) {
    uint64_t seq = highest_seq_value (contact, kset [i], MSG_TYPE_SENT);
    if (seq > max)
      max = seq;
  }
  free (kset);
  return max + 1;
}

/* return the largest received counter, or 0 if the contact cannot be found
 * or the keyset is not valid. */
uint64_t get_last_received (const char * contact, keyset k)
{
  return highest_seq_value (contact, k, MSG_TYPE_RCVD);
}

/* returns 1 if they are the same, 0 if different */
static inline int same_message_id (const char * id1, const char * id2)
{
#ifdef CHECK_ASSERTIONS
  assert (sizeof (uint64_t) * 2 == MESSAGE_ID_SIZE);
#endif /* CHECK_ASSERTIONS */
  const uint64_t * i1 = (uint64_t *) id1;
  const uint64_t * i2 = (uint64_t *) id2;
  return ((i1 [0] == i2 [0]) && (i1 [1] == i2 [1]));
}

/* search for a message with a message ack matching "wanted", and of wtype.
 * if not found, return 0
 * if found, and:
 *   if wtype is MSG_TYPE_ACK, return 1
 *   otherwise, return the sequence number of the matching message
 */
static uint64_t find_ack (const char * contact, keyset k, const char * wanted,
                          int wtype, int * report_ack_found)
{
  if (report_ack_found != NULL)
    *report_ack_found = 0;
  struct msg_iter * iter = start_iter (contact, k);
  if (iter == NULL)
    return 0;
  int type;
  uint64_t seq = 0;
  char ack [MESSAGE_ID_SIZE];
  int ack_found = 0;
  while ((type = prev_message (iter, &seq, NULL, NULL, NULL, ack, NULL, NULL))
         != MSG_TYPE_DONE) {
    if ((type == wtype) && (same_message_id (wanted, ack))) {
      free_iter (iter);
      if (wtype == MSG_TYPE_ACK) { /* seq is not set */
        return 1;
      } else {
        if (report_ack_found != NULL)
          *report_ack_found = ack_found;
        return seq;
      }
    } else if ((wtype != MSG_TYPE_ACK) && (type == MSG_TYPE_ACK) &&
               (same_message_id (wanted, ack))) {
      ack_found = 1;
    }
  }
  free_iter (iter);
  return 0;  /* not found */
}

/* putting null characters in files makes it hard for Java to read the file. */
static void eliminate_nulls (char * text, int tsize)
{
int replaced = 0;
  int i;
  for (i = 0; i < tsize; i++) {
    if (text [i] == '\0')
      replaced = 1;
    if (text [i] == '\0')
      text [i] = '_';
  }
if (replaced)
print_buffer (text, tsize, "found null characters in message", tsize, 1);
}

/* save an outgoing message to a specific directory for this contact.
 * the directory is specific because the message ack is different for
 * each copy of the message */
void save_outgoing (const char * contact, keyset k, struct chat_descriptor * cp,
                    char * text, int tsize)
{
  uint64_t time;
  int tz;
  get_time_tz (readb64u (cp->timestamp), &time, &tz);
  eliminate_nulls (text, tsize);
  save_record (contact, k, MSG_TYPE_SENT, readb64u (cp->counter), time, tz,
               allnet_time (), (char *) (cp->message_ack), text, tsize);
}

/* return the (malloc'd) outgoing message with the given sequence number,
 * or NULL if there is no such message.
 * if there is more than one such message, returns the latest.
 * Also fills in the size, time and message_ack -- message_ack must have
 * at least MESSAGE_ID_SIZE bytes */
extern int get_outgoing_show_debug;
int get_outgoing_show_debug = 0;
char * get_outgoing (const char * contact, keyset k, uint64_t seq,
                     int * size, uint64_t * time, char * message_ack)
{
  struct msg_iter * iter = start_iter (contact, k);
  if (iter == NULL)  /* non-existent contact or no messages */
    return NULL;
  int type;
  uint64_t mseq;
  uint64_t mtime;
  int msize;
  int tz;
  char * result = NULL;
  while ((type = prev_message (iter, &mseq, &mtime, &tz, NULL, message_ack,
          &result, &msize)) != MSG_TYPE_DONE) {
if ((get_outgoing_show_debug) && (type == MSG_TYPE_SENT) && (strcmp (contact, "edo-on-celine") == 0))
printf ("get_outgoing (%" PRIu64 "): type %d, seq %" PRIu64 ", message '%s'\n",
seq, MSG_TYPE_SENT, mseq, result);
    if ((type == MSG_TYPE_SENT) && (mseq == seq)) { /* found */
      if (time != NULL)
        *time = make_time_tz (mtime, tz);
      if (size != NULL)
        *size = msize;
      free_iter (iter);
      return result;
    }
    if (result != NULL)
      free (result);   /* not found, try again */
    result = NULL;
  }
  free_iter (iter);
  return NULL;
}

/* forward declaration, implemented below */
static void add_to_message_id_cache (char * ack);

/* save a received message */
void save_incoming (const char * contact, keyset k,
                    struct chat_descriptor * cp, char * text, int tsize)
{
  uint64_t time;
  int tz;
  get_time_tz (readb64 ((char *) (cp->timestamp)), &time, &tz);
  char * ack = (char *) (cp->message_ack);
  if (find_ack (contact, k, ack, MSG_TYPE_RCVD, NULL) == 0) {
    eliminate_nulls (text, tsize);
    save_record (contact, k, MSG_TYPE_RCVD, readb64u (cp->counter),
                 time, tz, allnet_time (), ack, text, tsize);
    add_to_message_id_cache (ack);
  }
}

/* mark a previously sent message as acknowledged
 * return the sequence number > 0 if this is an ack for a known contact,
 * return 0 if this ack is not recognized
 * if result > 0:
 * if contact is not NULL, the contact is set to point to the
 * contact name (dynamically allocated, must be free'd) and
 * if kset is not null, the location it points to is set to the keyset
 * if new_ack is not null, the location it points to is set 1 if
 * this is an ack we have not seen before
 */
uint64_t ack_received (const char * message_ack, char ** contact, keyset * kset,
                       int * new_ack)
{
  char ** contacts = NULL;
  if (contact != NULL)
    *contact = NULL;
  if (kset != NULL)
    *kset = -1;
  if (new_ack != NULL)
    *new_ack = 0;
  int nc = all_contacts (&contacts);
  int c;
  for (c = 0; c < nc; c++) {
    keyset * ksets = NULL;
    int nk = all_keys (contacts [c], &ksets);
    int k;
    for (k = 0; k < nk; k++) {
      int found_ack = 0;
      uint64_t seq = find_ack (contacts [c], ksets [k], message_ack,
                               MSG_TYPE_SENT, &found_ack);
      if (seq > 0) {
#ifdef VERIFY_20170616_ACK_FINDER
        uint64_t a =
          find_ack (contacts [c], ksets [k], message_ack, MSG_TYPE_ACK, NULL);
        int x = (a != 0);  /* x is the boolean equivalent of a */
        if (x != found_ack) {
          printf ("find_ack %d (%ld), found_ack %d for %s, %d\n",
                  x, a, found_ack, contacts [c], ksets [k]);
          print_buffer (message_ack, MESSAGE_ID_SIZE, "ack",
                        MESSAGE_ID_SIZE, 1);
        }
#endif /* VERIFY_20170616_ACK_FINDER */
        if (! found_ack) {
          save_record (contacts [c], ksets [k], MSG_TYPE_ACK, seq,
                       0, 0, allnet_time (), message_ack, NULL, 0);
          if (new_ack != NULL)
            *new_ack = 1;
        }
        if (contact != NULL)
          *contact = strcpy_malloc (contacts [c], "ack_received");
        if (kset != NULL)
          *kset = ksets [k];
        free (ksets);
        free (contacts);
        return seq;
      }
    }
    if ((nk > 0) && (ksets != NULL))
      free (ksets);
  }
  if ((nc > 0) && (contacts != NULL))
    free (contacts);
  return 0;
}

static uint64_t max_seq (const char * contact, keyset k, int wanted)
{
  return highest_seq_value (contact, k, wanted);
}

#define MAX_MISSING	50
/* returns a new (malloc'd) array, or NULL in case of error
 * the new array has (singles + 2 * ranges) * COUNTER_SIZE bytes.
 * the first *singles sequence numbers are individual sequence numbers
 * that we never received.
 * the next *ranges * 2 sequence numbers are pairs a, b such that we have
 * not received any of the sequence numbers a <= seq <= b */
char * get_missing (const char * contact, keyset k, int * singles, int * ranges)
{
  uint64_t last = max_seq (contact, k, MSG_TYPE_RCVD);
  *singles = 0;
  *ranges = 0;
  if (last < 1)
    return NULL;
/* the current implementation is relatively simple, returning up to
 * MAX_MISSING singles and as many ranges. */
  char singles_values [MAX_MISSING] [COUNTER_SIZE];
  unsigned int singles_used = 0;
  char ranges_first [MAX_MISSING] [COUNTER_SIZE];
  char ranges_last [MAX_MISSING] [COUNTER_SIZE];
  unsigned int ranges_used = 0;
  uint64_t i;
  for (i = last - 1; i > 0; i--) {
    if (! was_received (contact, k, i)) {
      if ((ranges_used > 0) &&
          (i + 1 == readb64 (&(ranges_first [ranges_used - 1] [0])))) {
        /* i extends the latest range */
        writeb64 (&(ranges_first [ranges_used - 1] [0]), i);
      } else if ((singles_used > 0) && (ranges_used < MAX_MISSING) &&
                 (i + 1 == readb64 (singles_values [singles_used - 1]))) {
        /* replace a single with a range */
        memcpy (ranges_last [ranges_used], singles_values [singles_used - 1],
                COUNTER_SIZE);
        writeb64 (&(ranges_first [ranges_used] [0]), i);
        singles_used--;
        ranges_used++;
      } else if (singles_used < MAX_MISSING) {
        /* save as a single */
        writeb64 (&(singles_values [singles_used] [0]), i);
        singles_used++;
      } else {   /* singles_used >= MAX_MISSING, done */
/* note: could save a single as a range.  Not clear that this
 * is very useful, so just keeping the code simple here */
        break;
      }
    }
  }
  if ((singles_used == 0) && (ranges_used == 0))
    return NULL;
  *singles = singles_used;
  *ranges = ranges_used;
  char * result =
    malloc_or_fail ((singles_used + 2 * ranges_used) * COUNTER_SIZE,
                    "get_missing");
  memcpy (result, singles_values, singles_used * COUNTER_SIZE);
  char * p = result + singles_used * COUNTER_SIZE;
  for (i = 0; i < ranges_used; i++) {
    memcpy (p, ranges_first [i], COUNTER_SIZE);
    memcpy (p + COUNTER_SIZE, ranges_last [i], COUNTER_SIZE);
    p += 2 * COUNTER_SIZE;
  }
  return result;
}

#ifdef GET_MISSING_SINGLES_ONLY
/* old implementation, only returns singles */
char * get_missing (const char * contact, keyset k, int * singles, int * ranges)
{
  uint64_t last = max_seq (contact, k, MSG_TYPE_RCVD);
  *singles = 0;
  *ranges = 0;
  if (last < 1)
    return NULL;
/* the current implementation is quite simple and only returns singles */
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
#endif /* GET_MISSING_SINGLES_ONLY */

struct unacked_cache_record {
  keyset k;
  int singles;
  int ranges;
  char * result;
};

static struct unacked_cache_record * unacked_cache = NULL;
static unsigned int unacked_cache_num_entries = 0;
static pthread_mutex_t unacked_cache_mutex = PTHREAD_MUTEX_INITIALIZER;

/* called with unacked_cache_mutex held */
static void print_unacked_cache (int return_value, keyset k)
{
  printf ("%d unacked cache entries, cache %p",
          unacked_cache_num_entries, unacked_cache);
  if (return_value != -1)
    printf (", k %d, r %d", k, return_value);
  printf ("\n");
  if ((unacked_cache_num_entries > 0) && (unacked_cache != NULL)) {
    int i;
    for (i = 0; i < unacked_cache_num_entries; i++) {
      printf ("%d [%d]: %d, %d, %p\n", unacked_cache [i].k, i,
              unacked_cache [i].singles, unacked_cache [i].ranges,
              unacked_cache [i].result);
    }
  }
}

static void reset_unacked_cache ()
{
  pthread_mutex_lock (&unacked_cache_mutex);
  print_unacked_cache (-4, -2);
  if (unacked_cache != NULL) {
    int i;
    for (i = 0; i < unacked_cache_num_entries; i++) {
      if (unacked_cache [i].result != NULL)
        free (unacked_cache [i].result);
    }
    free (unacked_cache);
  }
  unacked_cache = NULL;
  unacked_cache_num_entries = 0;
  pthread_mutex_unlock (&unacked_cache_mutex);
printf ("reset unacked cache\n");
}

static int found_in_unacked_cache (const char * contact, keyset k,
                                   int * singles, int * ranges, char ** result)
{
  *singles = 0;
  *ranges = 0;
  *result = NULL;
  int return_value = 0;
  pthread_mutex_lock (&unacked_cache_mutex);
  int i;
  for (i = 0; i < unacked_cache_num_entries; i++) {
    if (k == unacked_cache [i].k) {
      *singles = unacked_cache [i].singles;
      *ranges = unacked_cache [i].ranges;
      size_t size = (*singles + 2 * (*ranges)) * COUNTER_SIZE;
      if ((size > 0) && (unacked_cache [i].result != NULL))
        *result = memcpy_malloc (unacked_cache [i].result, size,
                                 "message.c found_in_unacked_cache");
      return_value = 1;
      break;
    }
  }
#ifdef DEBUG_PRINT
  print_unacked_cache (return_value, k);
#endif /* DEBUG_PRINT */
  pthread_mutex_unlock (&unacked_cache_mutex);
  return return_value;
}

static void add_to_unacked_cache (const char * contact, keyset k,
                                  int singles, int ranges, const char * result)
{
  pthread_mutex_lock (&unacked_cache_mutex);
  int position = -1;  /* index where we will insert the new entry */
  int i;
  for (i = 0; i < unacked_cache_num_entries; i++) {
    if (unacked_cache [i].k == k) {
      position = i;
      if (unacked_cache [i].result != NULL)
        free (unacked_cache [i].result);
      unacked_cache [i].result = NULL;
      break;
    }
  }
  if (position == -1) {
    for (i = 0; i < unacked_cache_num_entries; i++) {
      if (unacked_cache [i].k == -1) {  /* free entry */
        position = i;
        if (unacked_cache [i].result != NULL)
          free (unacked_cache [i].result);
        unacked_cache [i].result = NULL;
        break;
      }
    }
  }
  struct unacked_cache_record * old_unacked_cache = NULL;
  if ((unacked_cache == NULL) || (position == -1)) {
    /* not found and none free, add a new entry to the end of the cache */
    old_unacked_cache = unacked_cache;
    position = unacked_cache_num_entries;
    unacked_cache_num_entries++;
    /* realloc works like malloc if unacked_cache is NULL */
    unacked_cache = realloc (unacked_cache,
                             sizeof (struct unacked_cache_record) *
                             unacked_cache_num_entries);
  }
  if (unacked_cache == NULL) { /* realloc failed, just discard the cache */
    unacked_cache = old_unacked_cache;  /* the one that might not be NULL */
    reset_unacked_cache ();
  } else {
    unacked_cache [position].k = k;
    unacked_cache [position].singles = singles;
    unacked_cache [position].ranges = ranges;
    size_t size = (singles + 2 * ranges) * COUNTER_SIZE;
    if ((size > 0) && (result != NULL))
      unacked_cache [position].result =
        memcpy_malloc (result, size, "message.c add_to_unacked_cache");
    else
      unacked_cache [position].result = NULL;
  }
#ifdef DEBUG_PRINT
  print_unacked_cache (1, k);
#endif /* DEBUG_PRINT */
  pthread_mutex_unlock (&unacked_cache_mutex);
}

/* returns a new (malloc'd) array, or NULL in case of error
 * the new array has (singles + 2 * ranges) * COUNTER_SIZE bytes.
 * the first *singles sequence numbers are individual sequence numbers
 * for which we never received an ack.
 * the next *ranges * 2 sequence numbers are pairs a, b such that we have
 * not received acks for the sequence numbers a <= seq <= b */
char * get_unacked (const char * contact, keyset k, int * singles, int * ranges)
{
  *singles = 0;
  *ranges = 0;
  char * result = NULL;
  if (found_in_unacked_cache (contact, k, singles, ranges, &result))
    return result;
  uint64_t last = max_seq (contact, k, MSG_TYPE_SENT);
  if (last < 1)
    return NULL;
/* the current implementation is quite simple and only returns singles */
#define MAX_UNACKED	MAX_MISSING
  result = malloc_or_fail (MAX_UNACKED * COUNTER_SIZE, "get_unacked");
  int unacked = 0;
  uint64_t i;
  unsigned long long int now = allnet_time ();
  for (i = last; i > 0; i--) {
    uint64_t mtime = 0;
    if (! is_acked_one (contact, k, i, &mtime)) {
      uint64_t age = ((now > mtime) ? (now - mtime) : 0);
      long long int selected = random_int (0, age);
#define ONE_WEEK_SECONDS	(60 * 60 * 24 * 7)
      /* if it's an old message make it less likely we will resend
       * if the message is less than a week old, always resend */
      if (selected < ONE_WEEK_SECONDS) {
         writeb64 (result + unacked * COUNTER_SIZE, i);
         unacked++;
         if (unacked >= MAX_UNACKED) {
           *singles = unacked;
           add_to_unacked_cache (contact, k, *singles, *ranges, result);
           return result;
        }
      }
    }
  }
  if (unacked == 0) {   /* everything has been acked for this contact and key */
    free (result);
    add_to_unacked_cache (contact, k, *singles, *ranges, NULL);
    return NULL;
  }
  *singles = unacked;
  add_to_unacked_cache (contact, k, *singles, *ranges, result);
  return result;
}

/* if there is a cache of unacked messages, reload.
 * call if you send a message to this contact
 * called internally by ack_received if the ack is new */
void reload_unacked_cache (const char * contact, keyset k)
{
  pthread_mutex_lock (&unacked_cache_mutex);
  int i;
  for (i = 0; i < unacked_cache_num_entries; i++) {
    if (k == unacked_cache [i].k) {
      unacked_cache [i].k = -1;  /* disable this entry for now */
      unacked_cache [i].singles = 0;
      unacked_cache [i].ranges = 0;
      if (unacked_cache [i].result != NULL)
        free (unacked_cache [i].result);
      unacked_cache [i].result = NULL;
      break;
    }
  }
#ifdef DEBUG_PRINT
  print_unacked_cache (2, k);
#endif /* DEBUG_PRINT */
  pthread_mutex_unlock (&unacked_cache_mutex);
  /* now refill the cache entry by calling get_unacked */
  int singles;
  int ranges;
  char * result = get_unacked (contact, k, &singles, &ranges);
  if (result != NULL)
    free (result);    /* never used */
#ifdef DEBUG_PRINT
  printf ("reloaded unacked cache for %s, %d\n", contact, k);
#endif /* DEBUG_PRINT */
}

/* returns 1 if this sequence number has been acked by all the recipients,
 * 0 otherwise */
int is_acked (const char * contact, uint64_t seq)
{
  keyset * kset = NULL;
  int nkeys = all_keys (contact, &kset);
  if (nkeys <= 0)
    return 0;
  int k;
  for (k = 0; k < nkeys; k++) {
    if (! is_acked_one (contact, kset [k], seq, NULL)) {
      free (kset);
      return 0;
    }
  }
  free (kset);
  return 1;
}

/* returns 1 if this sequence number has been acked by this specific recipient,
 * 0 otherwise */
/* if timep is not NULL, it is set to the time of the message with the wanted
 * sequence number, if any */
int is_acked_one (const char * contact, keyset k, uint64_t wanted,
                  uint64_t * timep)
{
  struct msg_iter * iter = start_iter (contact, k);
  if (iter == NULL)
    return 0;
  int type;
  uint64_t seq;
  char ack [MESSAGE_ID_SIZE];
  while ((type = prev_message (iter, &seq, timep, NULL, NULL, ack, NULL, NULL))
         != MSG_TYPE_DONE) {
    if ((type == MSG_TYPE_SENT) && (seq == wanted)) {
/* this is the first (most recent) message sent with this sequence number.
 * we simply report whether this one has been acked -- the others are not
 * so important */
      uint64_t result_seq = find_ack (contact, k, ack, MSG_TYPE_ACK, NULL);
      free_iter (iter);
      return (result_seq > 0);
    }
  }
  free_iter (iter);
  return 0;
}

/* if add != 0, and not found, it is added to the cache
 * returns 1 if found in the cache, 0 otherwise, and -1 if the cache is
 * for a different contact or keyset and add is 0. */
static int is_in_cache (const char * contact, keyset k, uint64_t seq, int add)
{
#ifdef DEBUG_PRINT
  if ((add) && (strcmp (contact, "edo-on-maru") == 0))
    printf ("for %s/%d adding %" PRIu64 "\n", contact, k, seq);
#endif /* DEBUG_PRINT */
/* this cache only supports one contact at a time.  That gives reasonable
 * performance at the beginning, when we are loading the list of contacts,
 * but has some cost when we switch contacts */
  static char * cached_contact = NULL;
  static keyset cached_k = -1;
/* a cache entry consists of the first and last sequence number known. */
  struct cache_entry {
    uint64_t first;
    uint64_t last;
  };
  static struct cache_entry * cache = NULL;
  static int cache_used = 0;
  static int cache_alloc = 0;
#ifdef DEBUG_PRINT
  if ((cache_used > 0) && (cached_contact != NULL)) {
    printf ("contact '%s'/'%s', seq %ju, add %d, used %d, k %d/%d",
            cached_contact, contact, (uintmax_t) seq, add, cache_used,
            cached_k, k);
    int x;
    for (x = 0; x < cache_used; x++)
      printf (", %ju..%ju", (uintmax_t) (cache [x].first),
              (uintmax_t) (cache [x].last));
    printf ("\n");
  }
#endif /* DEBUG_PRINT */
  if ((cached_contact == NULL) || (strcmp (contact, cached_contact) != 0) ||
      (k != cached_k)) {  /* not found */
    if (add) {  /* initialize or reinitialize */
#ifdef DEBUG_PRINT
      printf ("adding %s, keyset %d, seq %ju\n", contact, k, (uintmax_t) seq);
#endif /* DEBUG_PRINT */
      if (cached_contact != NULL)
        free (cached_contact);
      cached_contact = strcpy_malloc (contact, "message.c is_in_cache contact");
      cached_k = k;
      if ((cache_alloc < 1) || (cache == NULL)) {
        cache_alloc = 10;
        cache = malloc_or_fail (sizeof (struct cache_entry) * cache_alloc,
                                "message.c is_in_cache");
      }
      cache [0].first = seq;
      cache [0].last = seq;
      cache_used = 1;
      return 0;  /* was not in the cache, even though it is now */
    } else {
      return -1; /* different contact, do not add */
    }
  }
  int i;
  for (i = 0; i < cache_used; i++) {
    if ((seq >= cache [i].first) && (seq <= cache [i].last)) {
#ifdef DEBUG_PRINT
      printf ("returning found\n");
#endif /* DEBUG_PRINT */
      return 1;
    }
  }
/* not found, will return 0, perhaps after adding */
  if (add) {
    int merge = 0;
    for (i = 0; i < cache_used; i++) {
      if (seq + 1 == cache [i].first) {
        if (add)
          cache [i].first = seq;
        else
          merge = 1;
        add = 0;
      }
      if (cache [i].last + 1 == seq) {
        if (add)
          cache [i].last = seq;
        else
          merge = 1;
        add = 0;
      }
    }
    if (merge) {  /* the sequence number is adjacent to at least two entries */
      /* we may modify cache_used during the loop, so while instead of for */
      i = 0;
      while (i + 1 < cache_used) {
        int j;
        for (j = i + 1; j < cache_used; j++) {
          /* in the code that follows, i < j */
          int merged = 0;
          if (cache [j].last + 1 == cache [i].first) {
            cache [i].first = cache [j].first;
            merged = 1;
          } else if (cache [i].last + 1 == cache [j].first) {
            cache [i].last = cache [j].last;
            merged = 1;
          }
          if (merged) {
/* copy last entry to merged entry.  Harmless even if merged is last entry */
            cache [j] = cache [cache_used - 1];
            cache_used = cache_used - 1;
          }
        }
        i++;
      }
    } else if (add) {
      if ((cache_alloc < cache_used + 1) || (cache == NULL)) {
        cache_alloc = 10 + cache_alloc * 2;  /* cache size only grows */
        cache = realloc (cache, sizeof (struct cache_entry) * cache_alloc);
      }
      cache [cache_used].first = seq;
      cache [cache_used].last = seq;
      cache_used++;
    }
#ifdef DEBUG_PRINT
    if (cache_used > 0) {
      printf (" added '%s' %ju", contact, (uintmax_t)seq);
    int x;
    for (x = 0; x < cache_used; x++)
      printf (", %ju..%ju", (uintmax_t) (cache [x].first),
              (uintmax_t) (cache [x].last));
    printf ("\n");
    }
#endif /* DEBUG_PRINT */
  }
  return 0;  /* not found */
}

/* returns 1 if this sequence number has been received, 0 otherwise */
int was_received (const char * contact, keyset k, uint64_t wanted)
{
  int cached = is_in_cache (contact, k, wanted, 0);
  if (cached >= 0)   /* cache is authoritative */
    return cached;
  /* rebuild the cache */
  struct msg_iter * iter = start_iter (contact, k);
  if (iter == NULL)
    return 0;
  int type;
  uint64_t seq;
  while ((type = prev_message (iter, &seq, NULL, NULL, NULL, NULL,
                               NULL, NULL)) != MSG_TYPE_DONE) {
    if (type == MSG_TYPE_RCVD)
      is_in_cache (contact, k, seq, 1);  /* add to cache */
  }
  free_iter (iter);
  if (is_in_cache (contact, k, wanted, 0) > 0)
    return 1;
  return 0;
}

static char * message_id_cache = NULL;
static char * message_ack_cache = NULL;
static int current_cache_index = 0; /* must multiply by MESSAGE_ID_SIZE */
static int current_cache_size = 0;  /* in multiples of MESSAGE_ID_SIZE */

static void add_to_message_id_cache (char * ack)
{
  if (current_cache_index >= current_cache_size) {
    int total = ((current_cache_size > 0) ? (current_cache_size * 2) : 500);
    size_t size = total * MESSAGE_ID_SIZE;
    char * new_ids = realloc (message_id_cache, size);
    char * new_acks = realloc (message_ack_cache, size); 
    if ((new_ids == NULL) || (new_acks == NULL)) {
      printf ("allocation error in add_to_message_id: %zd %d %p/%p %p/%p\n",
              size, total, new_ids, message_id_cache,
              new_acks, message_ack_cache);
      return;  /* don't add */
    }
    message_id_cache = new_ids;
    message_ack_cache = new_acks;
    current_cache_size = total;
  }
  char * idp = message_id_cache + (current_cache_index * MESSAGE_ID_SIZE);
  char * ackp = message_ack_cache + (current_cache_index * MESSAGE_ID_SIZE);
  memcpy (ackp, ack, MESSAGE_ID_SIZE);
  sha512_bytes (ack, MESSAGE_ID_SIZE, idp, MESSAGE_ID_SIZE);
  current_cache_index++;
}

static void fill_message_id_cache ()
{
  static int initialized = 0;
  if (initialized)
    return;
  initialized = 1;
#ifdef DEBUG_PRINT
  unsigned long long int start = allnet_time_us ();
#endif /* DEBUG_PRINT */
  char ** contacts = NULL;
  int ncontacts = all_contacts (&contacts);
  int icontacts;
  for (icontacts = 0; icontacts < ncontacts; icontacts++) {
    keyset * keys = NULL;
    int nkeys = all_keys (contacts [icontacts], &keys);
    int ikeys;
    for (ikeys = 0; ikeys < nkeys; ikeys++) {
      struct msg_iter * iter = start_iter (contacts [icontacts], keys [ikeys]);
      if (iter != NULL) {
        int type;
        char ack [MESSAGE_ID_SIZE];
        while ((type = prev_message (iter, NULL, NULL, NULL, NULL, ack,
                                     NULL, NULL)) != MSG_TYPE_DONE) {
          if (type == MSG_TYPE_RCVD) {
            add_to_message_id_cache (ack);
          }
        }
        free_iter (iter);
      }
    }
    if ((nkeys > 0) && (keys != NULL))
      free (keys);
  }
  if ((ncontacts > 0) && (contacts != NULL))
    free (contacts);
#ifdef DEBUG_PRINT
  printf ("fill_message_id_cache took %lluus, %d/%d saved\n",
  allnet_time_us () - start, current_cache_index, current_cache_size);
#endif /* DEBUG_PRINT */
}

/* returns 1 if this message ID has been saved before, 0 otherwise
 * if it returns 1, also fills message_ack with the corresponding ack */
static int is_in_message_id_cache (const char * message_id, char * message_ack)
{
#ifdef DEBUG_PRINT
  unsigned long long int start = allnet_time_us ();
#endif /* DEBUG_PRINT */
  int i;
  for (i = 0; i < current_cache_index; i++) {
    if (same_message_id (message_id_cache + (i * MESSAGE_ID_SIZE),
                         message_id)) {
      memcpy (message_ack,  /* fill in the message ack */
              message_ack_cache + (i * MESSAGE_ID_SIZE), MESSAGE_ID_SIZE);
#ifdef DEBUG_PRINT
      printf ("is_in_message_id_cache found at %d: ", i);
      print_buffer (message_id, MESSAGE_ID_SIZE, "id", 100, 0);
      print_buffer (message_ack, MESSAGE_ID_SIZE, ", ack", 100, 1);
#endif /* DEBUG_PRINT */
#ifdef DEBUG_PRINT
      printf ("call to is_in_message_id_cache took %lluus, result 1/%d\n",
              allnet_time_us () - start, current_cache_index);
#endif /* DEBUG_PRINT */
      return 1;
    }
  }
#ifdef DEBUG_PRINT
  printf ("call to is_in_message_id_cache took %lluus, result 0/%d\n",
          allnet_time_us () - start, current_cache_index);
#endif /* DEBUG_PRINT */
  return 0;
}

/* returns 1 if this message ID is in the (limited size) saved cache,
 * 0 otherwise
 * in other words, may return 0 even though the message was saved,
 * just because it is not in the cache
 * if it returns 1, also fills message_ack with the corresponding ack */
int message_id_is_in_saved_cache (const char * message_id, char * message_ack)
{
  fill_message_id_cache ();
  return (is_in_message_id_cache (message_id, message_ack));
}

