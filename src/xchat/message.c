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
    uint64_t seq;
    int type = highest_seq_record (contact, kset [i], MSG_TYPE_SENT,
                                   &seq, NULL, NULL, NULL, NULL, NULL, NULL);
    if ((type != MSG_TYPE_DONE) && (seq > max))
      max = seq;
  }
  free (kset);
  return max + 1;
}

/* return the largest received counter, or 0 if the contact cannot be found
 * or the keyset is not valid. */
uint64_t get_last_received (const char * contact, keyset k)
{
  uint64_t seq;
  int type = highest_seq_record (contact, k, MSG_TYPE_RCVD,
                                 &seq, NULL, NULL, NULL, NULL, NULL, NULL);
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
static uint64_t find_ack (const char * contact, keyset k, const char * wanted,
                          int wtype)
{
  struct msg_iter * iter = start_iter (contact, k);
  if (iter == NULL)
    return 0;
  int type;
  uint64_t seq = 0;
  char ack [MESSAGE_ID_SIZE];
  while ((type = prev_message (iter, &seq, NULL, NULL, NULL, ack, NULL, NULL))
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
  if (find_ack (contact, k, ack, MSG_TYPE_RCVD) == 0) {
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
 */
uint64_t ack_received (const char * message_ack, char ** contact, keyset * kset)
{
  char ** contacts = NULL;
  if (contact != NULL)
    *contact = NULL;
  if (kset != NULL)
    *kset = -1;
  int nc = all_contacts (&contacts);
  int c;
  for (c = 0; c < nc; c++) {
    keyset * ksets = NULL;
    int nk = all_keys (contacts [c], &ksets);
    int k;
    for (k = 0; k < nk; k++) {
      uint64_t seq = find_ack (contacts [c], ksets [k], message_ack,
                               MSG_TYPE_SENT);
      if (seq > 0) {
        if (! find_ack (contacts [c], ksets [k], message_ack, MSG_TYPE_ACK)) {
          save_record (contacts [c], ksets [k], MSG_TYPE_ACK, seq,
                       0, 0, 0, message_ack, NULL, 0);
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
  uint64_t seq;
  int type = highest_seq_record (contact, k, wanted, &seq, NULL, NULL, NULL,
                                 NULL, NULL, NULL);
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
char * get_missing (const char * contact, keyset k, int * singles, int * ranges)
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
char * get_unacked (const char * contact, keyset k, int * singles, int * ranges)
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
           return result;
        }
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
      uint64_t result_seq = find_ack (contact, k, ack, MSG_TYPE_ACK);
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
    if (memcmp (message_id_cache + (i * MESSAGE_ID_SIZE),
                message_id, MESSAGE_ID_SIZE) == 0) {
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

