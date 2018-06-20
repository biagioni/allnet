/* pcache.c: central cache for messages and acks */

/* goal: we want to forward each message to each system at most once.
         However, this is impossible without infinite memory, so instead
         we forward messages at most once just until the table is full.

   There are two main data structures, one for most messages, and one for acks.
   An auxiliary data structure tracks the tokens we have seen, and maps
   them to small integers.  All three of these data structures are
   saved to disk.
   The messages data structure is a hash table indexed by message ID.
   The acks data structure is a hash table indexed by ack.

   When a message hash table entry is full, we do a gc to remove the
   lowest-priority messages from each entry, until at least half of
   that entry's storage is available.  After each g.c, we change our token.
   In contrast, throwing away acks does not change the token.
   */

/* command to compile it as a stand-alone program that prints the contents
   of the caches:
   gcc -Wall -g -o bin/allnet-print-caches -DPRINT_CACHE_FILES src/lib/pcache.c src/lib/configfiles.c src/lib/util.c src/lib/allnet_log.c src/lib/sha.c src/lib/ai.c src/lib/pipemsg.c src/lib/allnet_queue.c src/lib/pid_bloom.c -lpthread
*/

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <stdint.h>
#include <inttypes.h>
#include <pthread.h>  /* to be able to write files asynchronously */
#include <sys/mman.h>

#include "pcache.h"
#include "pid_bloom.h"
#include "packet.h"
#include "util.h"
#include "sha.h"
#include "configfiles.h"
#include "allnet_log.h"
#include "priority.h"

#ifdef COMPARE_SHA_TO_OPENSSL
#include <openssl/sha.h>  /* for debugging */
#endif /* COMPARE_SHA_TO_OPENSSL */

/* an ack whose ID hashes, e.g. to location 68 may be stored at any index
 * between 64 and 127 inclusive.  Unlike the messages table, this is the
 * only meaning of "slot" for the acks table. */
#define ACKS_PER_SLOT	64

#ifdef ALLNET_RESOURCE_CONSTRAINED     /* use fewer resources */
/* allow 4MiB of messages, 64Ki acks = 3MiB */
#define DEFAULT_MESSAGE_TABLE_SIZE	4194304
/* num_acks must be a multiple of ACKS_PER_SLOT. Each ack takes 48 bytes,
 * so this is about 3MB = 64K * 48 */
#define DEFAULT_NUM_ACKS	1024 * ACKS_PER_SLOT
#else /* ! ALLNET_RESOURCE_CONSTRAINED */ /*  use more disk and memory space */
/* allow 64MiB of messages, 1Mi acks = 48MiB */
#define DEFAULT_MESSAGE_TABLE_SIZE	67108864
/* num_acks must be a multiple of ACKS_PER_SLOT */
#define DEFAULT_NUM_ACKS	16384 * ACKS_PER_SLOT
#endif /* ALLNET_RESOURCE_CONSTRAINED */

#define MIN_SAVE_SECONDS		300  /* save at most once every 5min */
                                             /* (except at the beginning) */

#define MAX_TOKENS	64	/* external tokens.  The list of which tokens
                                   we have sent to can be saved in a uint64_t */

/* note: when message headers are in storage, they may not be aligned.
 * good practice is to copy the message out into a struct message_header
 * and then access that. */
struct message_header {
  char id [MESSAGE_ID_SIZE];
  uint32_t length;               /* length within storage */
  uint32_t priority;
  uint64_t sent_to_tokens;
};

#define MESSAGE_HEADER_SIZE	(sizeof (struct message_header))
/* space for the largest possible message, or multiple small ones */
#define MESSAGE_STORAGE_SIZE	(MESSAGE_HEADER_SIZE + ALLNET_MTU)
#define MAX_MESSAGES_PER_ENTRY	(MESSAGE_STORAGE_SIZE / MESSAGE_HEADER_SIZE)

/* num_messages are stored sequentially within the message_storage */
struct hash_table_entry {
  uint32_t num_messages;
  char storage [MESSAGE_STORAGE_SIZE];
};

struct hash_ack_entry {       /* indexed by id */
  char ack [MESSAGE_ID_SIZE]; /* the message ID corresponding to the ack */
  char id  [MESSAGE_ID_SIZE]; /* the message ID corresponding to the ack */
  uint8_t used;
  uint8_t max_hops;
  /* some padding here -- most likely 48 bits, otherwise 16 */
  uint64_t sent_to_tokens;
};

static struct hash_table_entry * message_table = NULL;
static struct hash_ack_entry * ack_table = NULL;
static unsigned int message_table_size = DEFAULT_MESSAGE_TABLE_SIZE;
static unsigned int num_message_table_entries =
    (DEFAULT_MESSAGE_TABLE_SIZE / sizeof (struct hash_table_entry));
static unsigned int num_acks = DEFAULT_NUM_ACKS;

static char local_token [PCACHE_TOKEN_SIZE];
static char token_list [MAX_TOKENS] [PCACHE_TOKEN_SIZE];
static int num_external_tokens = 0;

struct tokens_file {  /* format saved on file */
  uint64_t num_tokens;
  char local_token [PCACHE_TOKEN_SIZE];
  char tokens [MAX_TOKENS] [PCACHE_TOKEN_SIZE];
};

static struct allnet_log * alog = NULL;

static void debug_crash (const char * message)
{
  if ((message != NULL) && (strlen (message) > 0))
    printf ("error %s, now crashing\n", message);
  char * p = NULL;
  /* null pointer dereferencing generates a core dump, where supported */
  printf ("crashing %d\n", *p);  /* divide by zero, never printed */
}

static int bytes_used_for_entry (struct hash_table_entry * entry)
{
  int offset = 0;   /* offset is returned as the result */
  int i;
  for (i = 0; i < entry->num_messages; i++) {
    struct message_header mh;
    memcpy (&mh, entry->storage + offset, MESSAGE_HEADER_SIZE);
    offset += mh.length + MESSAGE_HEADER_SIZE;
  }
  return offset;
}

static void print_stats (const char * desc)
{
  char date [ALLNET_TIME_STRING_SIZE];
  long long int us = allnet_time_us ();
  long long int now = us / 1000000;
  us = us % 1000000;
  allnet_time_string (now, date);
  printf ("%s @ %s (%lld.%06lld):\n", desc, date, now, us);
  printf ("%s: %d/%d total tokens\n", desc,
          num_external_tokens, (int) MAX_TOKENS);
  int max_bytes = 0, max_bytes_index = 0, total_bytes = 0;
  int max_msgs  = 0, max_msgs_index  = 0, total_msgs  = 0;
  int max_acks  = 0, max_acks_index  = 0, total_acks  = 0;
  int i;
  for (i = 0; i < num_message_table_entries; i++) {
    int num_bytes = bytes_used_for_entry (message_table + i);
    int num_msgs  = message_table [i].num_messages;
    total_bytes += num_bytes;
    if ((i == 0) || (max_bytes < num_bytes)) {
      max_bytes = num_bytes;
      max_bytes_index = i;
    }
    total_msgs += num_msgs;
    if ((i == 0) || (max_msgs < num_msgs )) {
      max_msgs = num_msgs;
      max_msgs_index = i;
    }
#ifdef DEBUG_PRINT
    printf (" entry %d, %d bytes, %d messages\n", i, num_bytes, num_msgs);
#endif /* DEBUG_PRINT */
  }
  printf ("%s: max byte %d/%d @ %d, total %d/%d = avg %d bytes/entry\n", desc,
          max_bytes, (int) MESSAGE_STORAGE_SIZE, max_bytes_index,
          total_bytes, num_message_table_entries,
          total_bytes / num_message_table_entries);
  printf ("%s: max msgs %d @ %d, total %d/%d = avg %d msgs/entry, ",
          desc, max_msgs, max_msgs_index,
          total_msgs, num_message_table_entries,
          total_msgs / num_message_table_entries);
  if (total_msgs > 0)
    printf ("%d bytes/msg", total_bytes / total_msgs);
  printf ("\n");
  for (i = 0; i < num_acks; i += ACKS_PER_SLOT) {
    int acks_in_slot = 0;
    int j;
    for (j = 0; j < ACKS_PER_SLOT; j++)
      if (ack_table [i + j].used)
        acks_in_slot++;
    total_acks += acks_in_slot;
    if ((i == 0) || (max_acks < acks_in_slot)) {
      max_acks = acks_in_slot;
      max_acks_index = i;
    }
  }
  printf ("%s: total acks %d/%d = avg %g, max in slot %d/%d @ %d\n", desc,
          total_acks, num_acks, (total_acks * 1.0) / (num_acks * 1.0) ,
          max_acks, (int) ACKS_PER_SLOT, max_acks_index);
}

static void print_ack_table_entry (int aindex)
{
  int base = aindex - (aindex % ACKS_PER_SLOT);
  int i;
  for (i = 0; i < ACKS_PER_SLOT; i++) {
    if (ack_table [base + i].used) {
      char desc [1000];
      snprintf (desc, sizeof (desc), "%d: ", i);
      print_buffer (ack_table [base + i].id, MESSAGE_ID_SIZE, desc,
                    MESSAGE_ID_SIZE, 0);
      printf (", tokens %" PRIx64 "\n", ack_table [base + i].sent_to_tokens);
    }
/* else printf ("%d:\n", i); */
  }
}

static void reinit_local_token ()
{
  random_bytes (local_token, PCACHE_TOKEN_SIZE);
}

/* either read or create ~/.allnet/acache/sizes */
static void init_sizes ()
{
  const char * error = NULL;
  int error_n = -9999;
  int fd = open_read_config ("acache", "sizes", 1);
  if (fd < 0) {
  /* create ~/.allnet/acache/sizes */
    fd = open_write_config ("acache", "sizes", 1);
    if (fd < 0) {
      error = "unable to create ~/.allnet/acache/sizes";
      /* not a fatal error, continue */
    } else {
      char string [1000];
      snprintf (string, sizeof (string), "%d\n%d\n",
                DEFAULT_MESSAGE_TABLE_SIZE, DEFAULT_NUM_ACKS);
      int len = (int)strlen (string);
      if (write (fd, string, len) != len) {
        error = "unable to write ~/.allnet/acache/sizes";
        /* also not a fatal error */
      }
    }
  } else {     /* read input from ~/.allnet/acache/sizes */
    static char buffer [1000];
    ssize_t n = read (fd, buffer, sizeof (buffer));
    if ((n > 0) && (n < (ssize_t) (sizeof (buffer)))) {
      sscanf (buffer, "%d\n%d\n", &message_table_size, &num_acks);
      if (message_table_size < 100000) {
        error = "ignoring message table size < 100K";
        error_n = message_table_size;
        message_table_size = DEFAULT_MESSAGE_TABLE_SIZE;
      }
      if (num_acks < 100) {
        error = "ignoring ack table size < 100";
        error_n = num_acks;
        num_acks = DEFAULT_NUM_ACKS;
      }
      if ((num_acks % ACKS_PER_SLOT) != 0)
        num_acks -= (num_acks % ACKS_PER_SLOT);
    } else {
      error = "unable to read ~/.allnet/acache/sizes";
      error_n = (int)n;
    }
  }
  close (fd);
  if (error != NULL) {
    if (error_n != -9999)
      snprintf (alog->b, alog->s, "%s (%d)\n", error, error_n);
    else
      snprintf (alog->b, alog->s, "%s\n", error);
    printf ("%s", alog->b);
    log_error (alog, "operation on ~/.allnet/acache/sizes");
  }
  num_message_table_entries =
    message_table_size / sizeof (struct hash_table_entry);
#ifdef DEBUG_PRINT
  printf ("message table has %d entries (%d bytes), %d acks\n",
          num_message_table_entries, message_table_size, num_acks);
#endif /* DEBUG_PRINT */
}

static void initialize_acks_from_scratch ()
{
  if (num_acks < 100)
    num_acks = DEFAULT_NUM_ACKS;
  if ((num_acks % ACKS_PER_SLOT) != 0)
    num_acks -= (num_acks % ACKS_PER_SLOT);
  size_t asize = num_acks * sizeof (struct hash_ack_entry);
  assert (((asize / sizeof (struct hash_ack_entry)) % ACKS_PER_SLOT) == 0);
  ack_table = malloc_or_fail (asize, "pcache default ack");
  memset (ack_table, 0, asize);
}

/* called at the beginning, and in case of any initialization error */
static void initialize_from_scratch ()
{
  num_external_tokens = 0;
  memset (local_token, 0, sizeof (local_token));
  memset (token_list, 0, sizeof (token_list));
  message_table_size = DEFAULT_MESSAGE_TABLE_SIZE;
  num_message_table_entries =
    message_table_size / sizeof (struct hash_table_entry);
  if (message_table != NULL) free (message_table);
  message_table = malloc_or_fail (message_table_size, "pcache default message");
  memset (message_table, 0, message_table_size);
  initialize_acks_from_scratch ();
}

/* read the tokens file.
 * return 1 on success, 0 for failure */
static int initialize_tokens_from_file ()
{
  int result = 0;
  char * fname = NULL;
  if (config_file_name ("acache", "tokens", &fname)) {
    long long int fsize = file_size (fname);
    if (fsize == sizeof (struct tokens_file)) {  /* read the file */
      struct tokens_file * t;
      if (read_file_malloc (fname, (char **)(&t), 1)) {
        num_external_tokens = (int)t->num_tokens;
        if ((num_external_tokens > MAX_TOKENS) ||  /* sanity check */
            (num_external_tokens <= 0)) {
          printf ("error, read %d tokens, setting to %d\n",
                  num_external_tokens, MAX_TOKENS);
          num_external_tokens = MAX_TOKENS;
        }
        memcpy (local_token, t->local_token, PCACHE_TOKEN_SIZE);
        memcpy ((char *) token_list, (char *) t->tokens, sizeof (token_list));
        free (t);
        result = 1;   /* everything is OK */
      }
    }
    free (fname);
  }
  return result;
}

/* read the messages file.
 * return 1 on success, 0 for failure */
static int initialize_messages_from_file ()
{
  int result = 0;
  char * fname = NULL;
  size_t msize = num_message_table_entries * sizeof (struct hash_table_entry);
  int found_error = 0;
  if (config_file_name ("acache", "messages", &fname)) {
    long long int fsize = file_size (fname);
    if (fsize == msize) {  /* read the file */
      char * p;
      if (read_file_malloc (fname, &p, 1)) {
        struct hash_table_entry * mp = (struct hash_table_entry *)p;
        int i;
        for (i = 0; i < num_message_table_entries; i++) {  /* sanity check */
          int offset = 0;
          int m;
          for (m = 0; m < mp [i].num_messages; m++) {
            if (offset + MESSAGE_HEADER_SIZE >= MESSAGE_STORAGE_SIZE) {
              found_error = 1;
              break;
            }
            struct message_header mh;
            memcpy (&mh, mp [i].storage + offset, MESSAGE_HEADER_SIZE);
            offset += MESSAGE_HEADER_SIZE;
            if (offset + mh.length > MESSAGE_STORAGE_SIZE) {
              found_error = 1;
              break;
            }
            offset += mh.length;
          }
        }
        if (found_error) {
          if (p != NULL) free (p);
        } else {
          if (message_table != NULL) free (message_table);
          message_table = mp;
          result = 1;
        }
      }
    } else {
      found_error = 1;   /* unable to open the file */
    }
    if (found_error)
      unlink (fname);    /* delete the file (if it exists) */
    free (fname);
  } else {
    snprintf (alog->b, alog->s, "unable to access ~/.allnet/acache/messages"); 
    printf ("%s", alog->b);
    log_error (alog, "pcache message storage");
  }
  return result;
}

/* read the acks file
 * return 1 on success, 0 for failure */
static int initialize_acks_from_file ()
{
  int result = 0;
  char * fname = NULL;
  size_t asize = num_acks * sizeof (struct hash_ack_entry);
  if (config_file_name ("acache", "acks", &fname)) {
    char * p = NULL;
    int fsize = ((file_size (fname) == asize) ? read_file_malloc (fname, &p, 1)
                                              : 0);
    if (fsize == asize) {    /* all is well */
      assert (((asize / sizeof (struct hash_ack_entry)) % ACKS_PER_SLOT) == 0);
      ack_table = (struct hash_ack_entry *)p;   /* point to memory */
      result = 1;
      int i;
      for (i = 0; i < num_acks; i++) {
        if (ack_table [i].used) {
          int aindex = (readb64 (ack_table [i].id) % num_acks);
          if ((i / ACKS_PER_SLOT) != (aindex / ACKS_PER_SLOT)) {
printf ("verifying ~/.allnet/acache/acks file, no match at entry %d %d/%d, ",
i, aindex, ACKS_PER_SLOT);
print_buffer (ack_table [i].id , MESSAGE_ID_SIZE, "id", 16, 1);
            result = 0;
            break;
          }
        }
      }
    } else {    /* start over */
/* if (fsize != 0) printf ("ack table size %d, expecting %d for %d acks\n",
                        (int) fsize, (int) asize, num_acks); */
printf ("ack table size %d, expecting %d for %d acks\n",
                        (int) fsize, (int) asize, num_acks);
      if (p != NULL) {
        unlink (fname);   /* delete the file (if it exists) */
        free (p);   /* in case there was something */
      }
      if (fsize == 0) {    /* acks from scratch, but read other files */
        initialize_acks_from_scratch ();
        result = 1;
      }
    }
    free (fname);
  } else {
    snprintf (alog->b, alog->s, "unable to access ~/.allnet/acache/acks"); 
    printf ("%s", alog->b);
    log_error (alog, "pcache message storage");
  }
  return result;
}

/* load the three tables from files */
static void initialize_from_file ()
{
  initialize_from_scratch ();
  int tokens_ok = 0;
  int messages_ok = 0;
  int acks_ok = 0;
  tokens_ok = initialize_tokens_from_file ();
  if (tokens_ok)
    messages_ok = initialize_messages_from_file ();
  if (tokens_ok && messages_ok)
    acks_ok = initialize_acks_from_file ();
  if (tokens_ok && messages_ok && acks_ok) {
#ifdef VERBOSE_GC
    print_stats ("after init");
#endif /* VERBOSE_GC */
    return;   /* finished successfully */
  }
  printf ("error (%d/%d/%d) reading from files, starting with an empty cache\n",
          tokens_ok, messages_ok, acks_ok);
  initialize_from_scratch ();   /* some error, re-initialize */
}

/* return 1 if too soon, else update *time_var and state and return 0 */
/* if override is true, always update *time_var (not state) and return 0 */
static int too_soon (unsigned long long int * time_var, int * state,
                     int override)
{
  unsigned long long int now = allnet_time ();
#ifdef DEBUG_CACHE  /* if testing, always do whatever we're doing */
  override = 1;
#endif /* DEBUG_CACHE */
  if (override) {
    *time_var = now;
    return 0;
  }
  /* initially allow frequent saves, slowly transition to MIN_SAVE_SECONDS */
  unsigned long long int wait_time = 1;
  int i;
  for (i = 0; ((i < *state) && (wait_time < MIN_SAVE_SECONDS)); i++)
    wait_time = wait_time + wait_time;  /* double the wait time */
  if (wait_time > MIN_SAVE_SECONDS)
    wait_time = MIN_SAVE_SECONDS;
  if (now < *time_var + wait_time)
    return 1;
  *time_var = now;
  if (wait_time < MIN_SAVE_SECONDS)
    *state = *state + 1;
  return 0;
}

struct async_file_info {
  char * fname;     /* thread frees it when done */
  char * contents;  /* thread frees this when done */
  int csize;
};

static void * write_file_async_thread (void * arg)
{
  static pthread_mutex_t file_writing = PTHREAD_MUTEX_INITIALIZER;
  struct async_file_info * a = (struct async_file_info *) arg;
  pthread_mutex_lock (&file_writing);  /* serialize the writing */
  if (0 == write_file (a->fname, a->contents, a->csize, 1))
    printf ("unable to write file %s of size %d\n", a->fname, a->csize);
  free (a->fname);
  free (a->contents);
  free (arg);
  pthread_mutex_unlock (&file_writing);
  return NULL;
}

/* copies content, then after sending, frees fname */
static void write_file_async (char * fname, const char * contents, int csize)
{
  struct async_file_info * arg =
    malloc_or_fail (sizeof (struct async_file_info), "write_file_async arg");
  arg->fname = fname;
  arg->contents = memcpy_malloc (contents, csize, "write_file_async contents");
  arg->csize = csize;
  pthread_t t;
  pthread_create (&t, NULL, &write_file_async_thread, (void *) arg);
}

static void write_messages_file (int override)
{
  static unsigned long long int last_saved = 0;
  static int state = 0;
  if (too_soon (&last_saved, &state, override))
    return;
  char * fname;
  if (config_file_name ("acache", "messages", &fname)) {
    size_t msize = num_message_table_entries * sizeof (struct hash_table_entry);
    write_file_async (fname, (char *)message_table, (int)msize);
  } else {
    printf ("unable to save messages file\n");
  }
}

static void write_acks_file (int override)
{
  static unsigned long long int last_saved = 0;
  static int state = 0;
  if (too_soon (&last_saved, &state, override))
    return;
  char * fname;
  if (config_file_name ("acache", "acks", &fname)) {
    size_t asize = num_acks * sizeof (struct hash_ack_entry);
    write_file_async (fname, (char *)ack_table, (int)asize);
  } else {
    printf ("unable to save acks file\n");
  }
}

static void write_tokens_file (int override)
{
  static unsigned long long int last_saved = 0;
  static int state = 0;
  if (too_soon (&last_saved, &state, override))
    return;
  char * fname;
  if (config_file_name ("acache", "tokens", &fname)) {
    if (num_external_tokens > MAX_TOKENS) {  /* sanity check */
      printf ("error, %d tokens, reducing to %d\n",
              num_external_tokens, MAX_TOKENS);
      num_external_tokens = MAX_TOKENS;
    }
    struct tokens_file t;
    memset (&t, 0, sizeof (t));
    t.num_tokens = num_external_tokens;
    memcpy (t.local_token, local_token, PCACHE_TOKEN_SIZE);
    memcpy (t.tokens, token_list, sizeof (token_list));
    size_t asize = sizeof (t);
    write_file_async (fname, (char *)(&t), (int)asize);
  } else {
    printf ("unable to save tokens file\n");
  }
}

static void init_pcache ()
{
  if ((alog == NULL) || (num_message_table_entries <= 0)) {
    alog = init_log ("pcache.c");
    reinit_local_token ();
    memset (token_list, 0, sizeof (token_list));
    num_external_tokens = 0;
    init_sizes ();
    initialize_from_file ();   /* load the three tables from files */
  }
}

/* save cached information to disk */
void pcache_write ()
{
printf ("pcache_write called\n");
  if ((alog == NULL) || (num_message_table_entries <= 0))
    return;
  write_messages_file (1);
  write_acks_file (1);
  write_tokens_file (1);
  pid_save_bloom ();
}

/* fills in the first PCACHE_TOKEN_SIZE bytes of token with the current token */
void pcache_current_token (char * result_token)
{
  init_pcache ();
  memcpy (result_token, local_token, PCACHE_TOKEN_SIZE);
}

/* return 1 for success, 0 for failure.
 * look inside a message and fill in its ID (MESSAGE_ID_SIZE bytes). */
int pcache_message_id (const char * message, int msize, char * result_id)
{
  init_pcache ();
  if (msize < ALLNET_HEADER_SIZE)
    return 0;
  struct allnet_header * hp = (struct allnet_header *) message;
  ssize_t hsize = ALLNET_SIZE (hp->transport); 
  if (msize <= hsize)
    return 0;
  if (hp->transport & ALLNET_TRANSPORT_ACK_REQ) {
    /* the message has an explicit message ID, use that */
    char * message_id = ALLNET_MESSAGE_ID (hp, hp->transport, msize);
    memcpy (result_id, message_id, MESSAGE_ID_SIZE);
    return 1;
  }
  /* compute a message ID by hashing together the contents of the message */
  sha512_bytes (message + hsize, (int)(msize - hsize), result_id, MESSAGE_ID_SIZE);
#ifdef COMPARE_SHA_TO_OPENSSL
  unsigned char copy [SHA512_DIGEST_LENGTH];
  SHA512((unsigned char *) (message + hsize), msize - hsize, copy);
  if (memcmp (copy, result_id, MESSAGE_ID_SIZE) != 0) {
    print_buffer ((char *)copy, SHA512_DIGEST_LENGTH, "official SHA512",
                  MESSAGE_ID_SIZE, 1);
    print_buffer (result_id, MESSAGE_ID_SIZE, "my SHA512", MESSAGE_ID_SIZE, 1);
    char third [SHA512_SIZE];
    sha512(message + hsize, msize - hsize, third);
    if (memcmp (third, copy, SHA512_SIZE) != 0)
      print_buffer (result_id, SHA512_SIZE, "my complete SHA512",
                    MESSAGE_ID_SIZE, 1);
  }
#endif /* COMPARE_SHA_TO_OPENSSL */
  return 1;
}

static void shift_token (char * tokenp, int token_shift, const char * debug)
{
#ifdef DEBUG_PRINT
  printf ("shift_token (%p, %d, %s): %p..%p and %p..%p\n",
          tokenp, token_shift, debug, message_table,
          ((char *) message_table) + message_table_size, ack_table,
          ((char *) ack_table) + (num_acks * sizeof (struct hash_ack_entry)));
#endif /* DEBUG_PRINT */
  if (token_shift <= 0)
    return;
  if (token_shift > 32)
    printf ("error 1: %s token shift %d\n", debug, token_shift);
  /* now shift the tokens */
  uint64_t mask = ~(((uint64_t) -1) << (64 - token_shift));
static uint64_t tokens_shifted = 0;
if (! (tokens_shifted & (1 << token_shift))) {
printf ("%s, shift %d, mask %016" PRIx64 "\n", debug, token_shift, mask);
tokens_shifted = tokens_shifted | (1 << token_shift);
}
  uint64_t tokens = readb64 (tokenp);
  tokens = ((tokens >> token_shift) & mask);
  writeb64 (tokenp, tokens);
}

#define DEBUG_GC(test, err, crash) \
  if ((test)) {  \
    int x;  \
    char * s = ((crash) ? "error" : ""); \
    printf ("%s %d: %d/%d/%d, %d/%d msgs\n", s, err, current_message_offset,  \
            total_size, (int)MESSAGE_STORAGE_SIZE, num_messages, \
            hp->num_messages);  \
    for (x = 0; x < hp->num_messages; x++)  \
    printf ("%d/%d: message %p/%p (%d), length %d, keep %d\n", \
            x, hp->num_messages,  \
            msgs [x].message, hp->storage, \
            (int) (msgs [x].message - hp->storage), \
            msgs [x].mh.length, msgs [x].keep);  \
    if (crash) debug_crash (NULL); \
}

/* returns the new offset for the given index */
/* free up messages by priority (for same priority, free up earlier messages)
 * until at least half of the space + msize is available.
 * if msize >= half the space, removes all existing messages in the entry. */
static int gc_messages_entry (int eindex, int msize, int token_shift)
{
#ifdef DEBUG_PRINT
  printf ("gc_messages_entry (%d, %d)\n", eindex, msize);
#endif /* DEBUG_PRINT */
  struct hash_table_entry * hp = message_table + eindex;
  if (hp->num_messages <= 0)                   /* no messages, we are done */
    return 0;
  int wanted_space = MESSAGE_STORAGE_SIZE / 2 + msize + MESSAGE_HEADER_SIZE;
  if (wanted_space >= MESSAGE_STORAGE_SIZE) {  /* easy, free everything */
    hp->num_messages = 0;                      /* delete all messages */
    return 0;
  }
  struct message_info { /* temp data structure to make it easy to delete msgs */
    struct message_header mh;
    char * message;        /* points to hp->storage */
    int keep;              /* set unless we are willing to delete this msg */
  };
/* cannot have more than this many messages in an entry */
#define MAX_MESSAGE_INFO	(MESSAGE_STORAGE_SIZE / MESSAGE_HEADER_SIZE)
  struct message_info msgs [MAX_MESSAGE_INFO];
  assert (hp->num_messages <= MAX_MESSAGE_INFO);
#undef MAX_MESSAGE_INFO
int num_messages = -27;  /* for debugging */
  int i = 0;
  int current_message_offset = 0;
int total_size = -33;  /* for debugging */
  for (i = 0; i < hp->num_messages; i++) {
    memcpy (&(msgs [i].mh),
            hp->storage + current_message_offset, MESSAGE_HEADER_SIZE);
    current_message_offset += MESSAGE_HEADER_SIZE;
    msgs [i].message = hp->storage + current_message_offset;
    msgs [i].keep = 1;    /* change to mark message for deletion */
    current_message_offset += msgs [i].mh.length;
    DEBUG_GC ((current_message_offset > MESSAGE_STORAGE_SIZE), 1, 1); 
  }
  num_messages = hp->num_messages;
  total_size = current_message_offset;
  /* now delete any expired messages */
  for (i = 0; i < hp->num_messages; i++) {
    if ((msgs [i].keep) &&
        (is_expired_message (msgs [i].message, msgs [i].mh.length))) {
      msgs [i].keep = 0;    /* mark this message for deletion */
      total_size -= msgs [i].mh.length + MESSAGE_HEADER_SIZE;
      num_messages--;
      DEBUG_GC ((num_messages < 0), 2, 1); 
      DEBUG_GC ((total_size < 0), 3, 1); 
    }
  }
  while (total_size + wanted_space > MESSAGE_STORAGE_SIZE) {
  /* repeatedly delete the lowest-priority message until we have enough space */
    int lpindex = -1;  /* index of lowest-priority message */
    for (i = 0; i < hp->num_messages; i++)
      if ((msgs [i].keep) &&
          ((lpindex < 0) ||
           (msgs [i].mh.priority < msgs [lpindex].mh.priority)))
        lpindex = i;
    if ((lpindex < 0) || (! msgs [lpindex].keep)) {
      /* all messages have expired, delete them all */
      hp->num_messages = 0;
      return 0;
    }
    DEBUG_GC (((lpindex < 0) || (! msgs [lpindex].keep)), 4, 1);
    msgs [lpindex].keep = 0;    /* mark this message for deletion */
    total_size -= msgs [lpindex].mh.length + MESSAGE_HEADER_SIZE;
    num_messages--;
    DEBUG_GC ((num_messages < 0), 5, 1); 
  }
  DEBUG_GC ((current_message_offset > MESSAGE_STORAGE_SIZE), 6, 0); 
  /* finally, delete the messages we don't want to keep, and compact the rest */
  current_message_offset = 0;
  int check_size = 0;
  int check_num = 0;
  for (i = 0; i < hp->num_messages; i++) {
    if (msgs [i].keep) {
      shift_token ((char *) (&(msgs [i].mh.sent_to_tokens)), token_shift,
                   "gc_messages_entry"); 
      memcpy (hp->storage + current_message_offset,
              &(msgs [i].mh), MESSAGE_HEADER_SIZE);
      memmove (hp->storage + current_message_offset + MESSAGE_HEADER_SIZE,
               msgs [i].message, msgs [i].mh.length); 
      check_size += MESSAGE_HEADER_SIZE + msgs [i].mh.length; 
      check_num++;
      current_message_offset += MESSAGE_HEADER_SIZE + msgs [i].mh.length; 
    } else {
      if (! pid_is_in_bloom (msgs [i].mh.id, PID_MESSAGE_FILTER))
        pid_add_to_bloom (msgs [i].mh.id, PID_MESSAGE_FILTER);
    }
  }
if ((check_size != total_size) || (check_num != num_messages))
printf ("size %d =? %d, num = %d =? %d\n", check_size, total_size, check_num, num_messages);
  DEBUG_GC ((check_size != total_size), 7, 1); 
  DEBUG_GC ((check_num != num_messages), 8, 1); 
  assert (check_size == total_size);
  assert (check_num == num_messages);
  hp->num_messages = num_messages;
  return total_size;
}

/* free up acks at random, until at least half of the acks in
 * the slot are free */
static void gc_ack_slot (int aindex, int token_shift)
{
#ifdef DEBUG_PRINT
  printf ("gc_ack_slot (%d)\n", aindex);
#endif /* DEBUG_PRINT */
  int base = aindex - (aindex % ACKS_PER_SLOT);
  int i = 0;
  int used_count = 0;
  for (i = 0; i < ACKS_PER_SLOT; i++) {
    if (ack_table [base + i].used)
      used_count++;
  }
  while (used_count > ACKS_PER_SLOT / 2) {
    int sel = (int)random_int (0, ACKS_PER_SLOT - 1);  /* delete this entry */
    if (ack_table [base + sel].used) {            /* if it's in use */
      if (! pid_is_in_bloom (ack_table [base + sel].ack, PID_ACK_FILTER))
        pid_add_to_bloom (ack_table [base + sel].ack, PID_ACK_FILTER);
      if (! pid_is_in_bloom (ack_table [base + sel].id , PID_MESSAGE_FILTER))
        pid_add_to_bloom (ack_table [base + sel].id , PID_MESSAGE_FILTER);
      ack_table [base + sel].used = 0;
      used_count--;
    }
  }
  if (token_shift > 0) {
    for (i = 0; i < ACKS_PER_SLOT; i++)
      shift_token ((char *)&(ack_table [base + i].sent_to_tokens), token_shift,
                   "gc_acks_entry"); 
  }
}

/* does FIFO replacement -- just shifts tokens to the front of the
 * array, and returns the difference in positions. */
static int gc_tokens ()
{
  if (num_external_tokens < MAX_TOKENS)      /* no gc needed */
    return 0;
  int goal = ((3 * MAX_TOKENS) / 4);         /* keep 3/4 of existing tokens */
  int shift = (num_external_tokens - goal);  /* how many to shift */
  int shift_bytes = shift * PCACHE_TOKEN_SIZE;
  char * from = ((char *) token_list) + shift_bytes;
  int length = num_external_tokens - shift;
  int length_bytes = length * PCACHE_TOKEN_SIZE;
printf ("shifting %d tokens by %d: %d, %d, %d\n", num_external_tokens, shift,
shift_bytes, length, length_bytes);
#ifdef DEBUG_PRINT
print_buffer ((char *)token_list, sizeof (token_list), "before shift",
              sizeof (token_list), 1);
#endif /* DEBUG_PRINT */
  memmove (token_list, from, length_bytes);
  memset (((char *) token_list) + length_bytes, 0, /* clear the rest */
          sizeof (token_list) - length_bytes);
#ifdef DEBUG_PRINT
print_buffer ((char *)token_list, sizeof (token_list), "after  shift",
              sizeof (token_list), 1);
#endif /* DEBUG_PRINT */
  num_external_tokens -= shift;
#ifdef DEBUG_PRINT
printf ("num_external_tokens is now %d\n", num_external_tokens);
#endif /* DEBUG_PRINT */
  return shift;
}

#define PRINT_GC

/* Garbage collects both the messages and ack tables, guaranteeing
 * that at least half the bytes in each message table entry
 * and half the entries in each ack table slot are free. 
 * If eindex is in the range 0..num_message_table_entries,
 * also guarantees that the message table entry at that slot has
 * at least msize free bytes, and returns the offset for that entry.
 * otherwise returns 0.
 * Also updates the token. */
static int do_gc (int eindex, int msize,
                  int write_tok, int write_msg, int write_ack)
{
#ifdef PRINT_GC
  long long int start = allnet_time_us ();
#endif /* PRINT_GC */
#ifdef VERBOSE_GC
  static int gc_counter = 1;
  char desc [1000];
  snprintf (desc, sizeof (desc),
            "before gc (%d, %d, %d)", gc_counter, eindex, msize);
  print_stats (desc);
#endif /* VERBOSE_GC */
  int result = 0;
  int delta_tokens = gc_tokens ();
#ifdef VERBOSE_GC
  printf ("tokens shifted by %d\n", delta_tokens);
#endif /* VERBOSE_GC */
  int i;
  for (i = 0; i < num_acks; i += ACKS_PER_SLOT)
    gc_ack_slot (i, delta_tokens);
#ifdef VERBOSE_GC
  print_stats ("acks done, messages next");
#endif /* VERBOSE_GC */
  for (i = 0; i < num_message_table_entries; i++) {
    if (i == eindex)  /* use msize and set result */
      result = gc_messages_entry (i, msize, delta_tokens);
    else
      gc_messages_entry (i, 0, delta_tokens);
  }
  reinit_local_token ();
#ifdef VERBOSE_GC
  snprintf (desc, sizeof (desc),
            "gc (%d, %d, %d) => %d", gc_counter++, eindex, msize, result);
  print_stats (desc);
#endif /* VERBOSE_GC */
  long long int us = allnet_time_us () - start;
  printf ("gc %d/%d/%d took %lld.%06llds, shifted %d tokens\n",
          write_tok, write_msg, write_ack,
          us / 1000000, us % 1000000, delta_tokens);
#ifdef PRINT_GC
#endif /* PRINT_GC */
  if (write_tok) write_tokens_file (1);
  if (write_msg) write_messages_file (1);
  if (write_ack) write_acks_file (1);
  pid_advance_bloom ();
  pid_save_bloom ();
  return result;
}

/* save this (received) packet */
void pcache_save_packet (const char * message, int msize, int priority)
{
  init_pcache ();
  char id [MESSAGE_ID_SIZE];
  if (! pcache_message_id (message, msize, id)) {
    print_buffer (message, msize, "no message ID for packet: ", msize, 1);
    return;
  }
  if (pcache_id_found (id))   /* already here, nothing to do */
    return;
  int eindex = (readb64 (id) % num_message_table_entries);
  struct hash_table_entry * hp = message_table + eindex;
  int i;
  int offset = 0;
  for (i = 0; i < hp->num_messages; i++) {
    struct message_header mh;
    memcpy (&mh, hp->storage + offset, MESSAGE_HEADER_SIZE);
    offset += MESSAGE_HEADER_SIZE + mh.length;
  }
  int did_gc = 0;
  if (offset + MESSAGE_HEADER_SIZE + msize > MESSAGE_STORAGE_SIZE) {
    offset = do_gc (eindex, msize, 1, 0, 1);
    did_gc = 1;
  }
  if (offset + MESSAGE_HEADER_SIZE + msize <= MESSAGE_STORAGE_SIZE) {
    struct message_header mh;
    memcpy (mh.id, id, MESSAGE_ID_SIZE);
    mh.length = msize;
    mh.priority = priority;
    mh.sent_to_tokens = 0;
    memcpy (hp->storage + offset, &mh, MESSAGE_HEADER_SIZE);
    memcpy (hp->storage + offset + MESSAGE_HEADER_SIZE, message, msize);
    hp->num_messages = hp->num_messages + 1; 
  } else {
    printf ("gc error, @ %d offset %d + %d + %d > %d\n", eindex, offset,
            (int) MESSAGE_HEADER_SIZE, msize, (int) MESSAGE_STORAGE_SIZE);
    exit (1);
  }
  write_messages_file (did_gc);
}

/* record this packet ID, without actually saving it */
void pcache_record_packet (const char * message, int msize)
{
  init_pcache ();
  char id [MESSAGE_ID_SIZE];
  if (! pcache_message_id (message, msize, id)) {
    print_buffer (message, msize, "no message ID for packet: ", msize, 1);
    return;
  }
  /* only record it in the bloom filter */
  if (! pid_is_in_bloom (id, PID_MESSAGE_FILTER))
    pid_add_to_bloom (id, PID_MESSAGE_FILTER);
}

static void delete_message_entry (struct hash_table_entry * hp,
                                  struct message_header * mh, int offset)
{
  int length = MESSAGE_HEADER_SIZE + mh->length;
  int remaining = MESSAGE_STORAGE_SIZE - (offset + length);
  memmove (hp->storage + offset, hp->storage + offset + length, remaining);
  hp->num_messages--;
}

/* return 1 if the ID is in the cache, 0 otherwise
 * ID is MESSAGE_ID_SIZE bytes.
 * if found and delete is 1, deletes it */
static int pcache_id_found_delete (const char * id, int delete)
{
  int eindex = (readb64 (id) % num_message_table_entries);
  struct hash_table_entry * hp = message_table + eindex;
  int i;
  int offset = 0;
  for (i = 0; i < hp->num_messages; i++) {
    struct message_header mh;
    memcpy (&mh, hp->storage + offset, MESSAGE_HEADER_SIZE);
    if (memcmp (id, mh.id, MESSAGE_ID_SIZE) == 0) {  /* found */
      if (delete)
        delete_message_entry (hp, &mh, offset);
      return 1;   /* found */
    }
    offset += MESSAGE_HEADER_SIZE + mh.length;
  }
  return 0;       /* not found */
}

/* return 1 if the ID is in the cache, 0 otherwise
 * ID is MESSAGE_ID_SIZE bytes. */
int pcache_id_found (const char * id)
{
  init_pcache ();
  if (pid_is_in_bloom (id, PID_MESSAGE_FILTER))
    return 1;
  return pcache_id_found_delete (id, 0);  /* do not delete */
}

/* return the index of the ack in the ack hash table, or -1 if not found */
static int find_one_ack (const char * id)
{
  int aindex = (readb64 (id) % num_acks);
  int base = aindex - (aindex % ACKS_PER_SLOT);
  int i;
  for (i = 0; i < ACKS_PER_SLOT; i++) {
    if ((ack_table [base + i].used) &&
        (memcmp (ack_table [base + i].id, id, MESSAGE_ID_SIZE) == 0)) {
      return base + i;
    }
  }
  return -1;
}

/* return 1 if we have the ack for this ID, 0 if we do not
 * if we return 1, fill in the ack */
int pcache_id_acked (const char * id, char * ack)
{
  int aindex = find_one_ack (id);
  if (aindex >= 0) {
    memcpy (ack, ack_table [aindex].ack, MESSAGE_ID_SIZE);
    return 1;
  }
  return 0;
}

/* returns an index if there is one available, otherwise -1 */
static int find_free_ack_in_slot (int aindex)
{
  int base = aindex - (aindex % ACKS_PER_SLOT);
  int i;
  for (i = 0; i < ACKS_PER_SLOT; i++)
    if (! ack_table [base + i].used)    /* found a free entry */
      return base + i;                  /* use this as the index */
  return -1;
}

/* return the index of the ack in the ack hash table */
static int save_one_ack (const char * ack, int max_hops)
{
#ifdef DEBUG_PRINT
  static int received_count = 0;
  static int duplicate_count = 0;
  received_count++;
#endif /* DEBUG_PRINT */
  /* if it is in the bloom filter, no need to save */
  if (pid_is_in_bloom (ack, PID_ACK_FILTER))
    return 0;
  char id [MESSAGE_ID_SIZE];
  sha512_bytes (ack, MESSAGE_ID_SIZE, id, MESSAGE_ID_SIZE);
  int aindex = find_one_ack (id);
  if (aindex >= 0) {  /* found */
    if (ack_table [aindex].max_hops < max_hops)
      ack_table [aindex].max_hops = max_hops;
#ifdef DEBUG_PRINT
    duplicate_count++;
#endif /* DEBUG_PRINT */
    return aindex;
  }
  /* else, no existing entry, look for a free entry */
  int did_gc = 0;                     /* save file more aggressively if gc'd */
  aindex = (readb64 (id) % num_acks); /* index used if possible */
  if (ack_table [aindex].used) {      /* find another position in slot */
    int found = find_free_ack_in_slot (aindex);
    if (found < 0) {                  /* no free slot, must gc */
      do_gc (-1, 0, 1, 1, 0);
      did_gc = 1;
      if (ack_table [aindex].used) {   /* find another position in slot */
        found = find_free_ack_in_slot (aindex);  /* should always have space */
        if (found < 0) {              /* no free slot, error in gc */
          printf ("error 5: no space after gc in slot %d\n", aindex);
          print_stats ("error 6: no room for ack after gc");
          print_ack_table_entry (aindex);
          debug_crash ("no room for ack after gc");
        }
      } else {
        found = aindex;
      }
    }
    assert (found >= 0);
    aindex = found;
  }
  /* now aindex refers to the entry we will use.  It is in the
   * same slot as the original index, but may be a different entry */
  if (ack_table [aindex].used) {
    printf ("error 7: ack_table [%d] is used (%d)\n", aindex, did_gc);
    print_stats ("error 8: ack index after gc is still in use");
    print_ack_table_entry (aindex);
    debug_crash ("invalid index, ack entry still in use after gc");
  }
#ifdef DEBUG_PRINT
  static int replace_count = 0;
  if (ack_table [aindex].used) replace_count++;
  int occupied = 0;
  for (i = 0; i < num_acks; i++)
    if (ack_table [i].used)
      occupied++;
  printf ("replacing %d+%d/%d @ index %d/%d\n", replace_count, duplicate_count,
          received_count, aindex, occupied);
#endif /* DEBUG_PRINT */
  memcpy (ack_table [aindex].ack, ack, MESSAGE_ID_SIZE);
  memcpy (ack_table [aindex].id , id , MESSAGE_ID_SIZE);
  ack_table [aindex].used = 1;
  ack_table [aindex].max_hops = max_hops;
  ack_table [aindex].sent_to_tokens = 0;
  /* finally, delete the corresponding message if any */
  pcache_id_found_delete (id, 1);  /* delete if found */
  return aindex;
}

/* each ack has size MESSAGE_ID_SIZE */
/* record all these acks and delete (stop caching) corresponding messages */
void pcache_save_acks (const char * acks, int num, int max_hops)
{
  init_pcache ();
  int i;
  for (i = 0; i < num; i++)
    save_one_ack (acks + i * MESSAGE_ID_SIZE, max_hops);
  write_acks_file (0);
}

/* return -1 if already sent.
 * otherwise, return the index of the token in the token table */
static int token_to_send_to (const char * token, uint64_t bitmap)
{
  int i;
  for (i = 0; i < num_external_tokens; i++) {
    if (memcmp (token_list [i], token, MESSAGE_ID_SIZE) == 0) { /* found */
      if ((bitmap & (((uint64_t) 1) << i)) != 0)
        return -1;    /* already sent */
      else
        return i;     /* token index */
    }
  }  /* token not found, add it to the list */
  int did_gc = 0;
  if (num_external_tokens + 1 > MAX_TOKENS) {   /* gc the tokens */
    do_gc (-1, 0, 0, 1, 1);
    did_gc = 1;
  }
  if (num_external_tokens + 1 > MAX_TOKENS) {   /* error in GC tokeni*/
    printf ("error 9: no space after gc in tokens table, %d/%d\n",
            num_external_tokens, (int) MAX_TOKENS);
    print_stats ("error 10: no room for tokens after gc");
    debug_crash ("no room for tokens after gc");
  }
  memcpy (token_list [num_external_tokens], token, MESSAGE_ID_SIZE);
  int result = num_external_tokens;
  num_external_tokens++;
  write_tokens_file (did_gc);
  return result;
}

/* return 1 if the ack has not yet been sent to this token, 
 * and mark it as sent to this token. 
 * otherwise, return 0 */
int pcache_ack_for_token (const char * token, const char * ack)
{
  init_pcache ();
  /* assume that acks in the bloom filter have been sent to all tokens */
  /*   the assumption is not true, but it helps drop old acks */
  if (pid_is_in_bloom (ack, PID_ACK_FILTER))
    return 0;
  char id [MESSAGE_ID_SIZE];
  sha512_bytes (ack, MESSAGE_ID_SIZE, id, MESSAGE_ID_SIZE);
  int aindex = find_one_ack (id);
  int itoken = token_to_send_to (token, ack_table [aindex].sent_to_tokens);
  if (itoken == -1)  /* already sent */
    return 0;
  if (aindex >= 0)    /* found */
    ack_table [aindex].sent_to_tokens |= (((uint64_t) 1) << itoken);
  return 1;
}

/* call pcache_ack_for_token repeatedly for all these acks,
 * moving the new ones to the front of the array and returning the
 * number that are new (0 for none, -1 for errors) */
int pcache_acks_for_token (const char * token, char * acks, int num)
{
  init_pcache ();
  const char * ack = acks;
  char * offset = acks;
  int result = 0;
  int i;
  for (i = 0; i < num; i++) {
    if (pcache_ack_for_token (token, ack)) {  /* good one, keep it */
      if (offset != ack)
        memcpy (offset, ack, MESSAGE_ID_SIZE);
      offset += MESSAGE_ID_SIZE; /* increment offset only for new acks */
      result++;
    }
    ack += MESSAGE_ID_SIZE;      /* increment ack each time around the loop */
  }
  return result;
}

/* returns 0 if bits_power_two is 0, and 2^bits_power_two otherwise */
static int power_two (int bits_power_two)
{
  if (bits_power_two == 0)
    return 0;
  int result = 1;   /* first compute in bits */
  while ((bits_power_two-- > 0) && (result < ALLNET_MTU * 8))
    result += result;
  return result;
}

/* return the new size of free_ptr, or 0 for errors */
/* free_ptr points to n messages followed by the messages array.
 * the messages array is at the end so we can insert the new message
 * in front of it and grow the messages array at the end (or wherever). */
static size_t add_to_result (struct pcache_result * r, size_t size_old,
                             const char * message, int msize, int priority)
{
  size_t size_new = size_old + msize + sizeof (struct pcache_message);
  char * mem = realloc (r->free_ptr, size_new);
  if (mem == NULL) {
    printf ("add_to_result: unable to add, sizes %zd + %d + %zd = %zd\n",
            size_old, msize, sizeof (struct pcache_message), size_new);
    return 0;
  }
  size_t messages_size_old = sizeof (struct pcache_message) * r->n;
  size_t messages_size_new = sizeof (struct pcache_message) * (r->n + 1);
  assert (((messages_size_old == 0) && (size_old == 0)) ||
          (messages_size_old < size_old));
  char * src = mem + (size_old - messages_size_old); 
  assert (messages_size_new < size_new);
  char * dest = mem + (size_new - messages_size_new);
  memmove (dest, src, messages_size_old);
  struct pcache_message * messages_new = (struct pcache_message *) (dest);
  char * message_dest = src;
  memcpy (message_dest, message, msize);
  messages_new [r->n].message = message_dest;
  messages_new [r->n].msize = msize;
  messages_new [r->n].priority = priority;
  int i;
  char * start = mem;
  for (i = 0; i < r->n; i++) { /* have the messages point to the new memory */
    messages_new [i].message = start;
    start += messages_new [i].msize;
  }
  r->messages = messages_new;
  r->n++;
  r->free_ptr = mem;
  return size_new;
}

static void sort_result (struct pcache_result * r)
{
  /* bubble sort -- a simple quadratic sort */
  int swapped = 1;
  while (swapped) {
    swapped = 0;
    int i;
    for (i = 0; i + 1 < r->n; i++) {
      if (r->messages [i].priority < r->messages [i + 1].priority) {
        struct pcache_message swap = r->messages [i];
        r->messages [i] = r->messages [i + 1];
        r->messages [i + 1] = swap;
        swapped = 1;
      }
    }
  }
}

struct req_details {
  struct allnet_data_request req;
  int dst_bits;
  const unsigned char * dst_bitmap;
  int src_bits;
  const unsigned char * src_bitmap;
  int mid_bits;
  const unsigned char * mid_bitmap;
};

#if 0
static void print_rd (struct req_details *rd)
{
  printf ("%p %p %p %p %p %p %p\n",
          rd, &(rd->req), rd->req.dst_bitmap, rd->req.mid_bitmap,
          rd->dst_bitmap, rd->src_bitmap, rd->mid_bitmap);
  print_buffer ((char *) rd->dst_bitmap, rd->dst_bits, "dst", 32, 1);
  print_buffer ((char *) rd->src_bitmap, rd->src_bits, "src", 32, 1);
  print_buffer ((char *) rd->mid_bitmap, rd->mid_bits, "mid", 32, 1);
}
#endif /* 0 */

static struct req_details get_details (const struct allnet_data_request *req)
{
  struct req_details rd =
    { .req = *req,
      .dst_bits = power_two (req->dst_bits_power_two),
      .src_bits = power_two (req->src_bits_power_two),
      .mid_bits = power_two (req->mid_bits_power_two) };
  const unsigned char * ptr = req->dst_bitmap;
  if (rd.req.dst_bits_power_two == 0) {
    rd.dst_bitmap = NULL;
  } else {
    rd.dst_bitmap = ptr;
    ptr += (rd.dst_bits + 7) / 8;
  }
  if (rd.req.src_bits_power_two == 0) {
    rd.src_bitmap = NULL;
  } else {
    rd.src_bitmap = ptr;
    ptr += (rd.src_bits + 7) / 8;
  }
  if (rd.req.mid_bits_power_two == 0) {
    rd.mid_bitmap = NULL;
  } else {
    rd.mid_bitmap = ptr;
    ptr += (rd.mid_bits + 7) / 8;
  }
#if 0
print_rd (&rd);
printf ("allnet data request: since %lld, "
        "dst 2^%d, src 2^%d, mid 2^%d\n",
        readb64 ((char *) (req->since)), req->dst_bits_power_two,
        req->src_bits_power_two, req->mid_bits_power_two);
printf ("%d/%p, %d/%p, %d/%p:\n", rd.dst_bits, rd.dst_bitmap,
rd.src_bits, rd.src_bitmap, rd.mid_bits, rd.mid_bitmap);
print_buffer ((char *)rd.dst_bitmap, rd.dst_bits, "dst", ((rd.dst_bits + 7) / 8), 1);
print_buffer ((char *)rd.src_bitmap, rd.src_bits, "src", ((rd.src_bits + 7) / 8), 1);
print_buffer ((char *)rd.mid_bitmap, rd.mid_bits, "mid", ((rd.mid_bits + 7) / 8), 1);
#endif /* 0 */
  return rd;
}

static int matches_req (unsigned int nbits, uint64_t first64,
                        unsigned int power_two, int bitmap_bits,
                        const unsigned char * bitmap)
{
  if (bitmap == NULL)   /* matches */
    return 1;
  if (nbits < 1)        /* always matches */
    return 1;
  assert ((nbits < 64) || (power_two <= 16));
  assert (bitmap_bits < (ALLNET_MTU * 8));
  uint64_t mask = ((nbits == 0) ? 0 : ((int64_t) (-1)) << (64 - nbits));
  int bindex = (int)((first64 & mask) >> (64 - power_two));
#if 0
printf ("first64 %" PRIx64 " mask %" PRIx64 " => index %d/%x, ^2 %d nbits %d\n",
first64, mask, bindex, bindex, power_two, nbits);
#endif /* 0 */
  int loops = ((nbits >= power_two) ? 1 : (1 << (power_two - nbits)));
  int i;
  for (i = 0; i < loops; i++) {
    int byte_index = (bindex + i) / 8;
    int bit_index  = (bindex + i) % 8;
#if 0
printf ("[%d] %02x bit %d (%x) %s %016" PRIx64 "/%d >> %d = %x, %d loops\n",
byte_index, bitmap [byte_index], bit_index, (0x80 >> bit_index),
(((bitmap [byte_index] & (0x80 >> bit_index)) != 0) ? "matches"
                                                   : "does not match"),
first64, nbits, (64 - power_two), bindex, loops);
printf ("%p: ", bitmap);
print_buffer ((char *)bitmap, bitmap_bits, NULL, bitmap_bits / 8, 1);
#endif /* 0 */
    if (bitmap [byte_index] & (0x80 >> bit_index))
      return 1;
  }
  return 0;
}

static int matches_mid (const char * mid, int nbits,
                        int bitmap_bits, const unsigned char * bitmap)
{
  if ((mid == NULL) || (bitmap == NULL))   /* matches */
    return 1;
  assert (bitmap_bits < (ALLNET_MTU * 8));
  assert (bitmap_bits == power_two (nbits));
  uint64_t first64 = readb64 (mid);
  int bindex = (int)(first64 >> (64 - nbits));
  int byte_index = bindex / 8;
  int bit_index  = bindex % 8;
  return ((bitmap [byte_index] & (256 >> bit_index)) != 0);
}

static int matches_data_request (const struct req_details *rd,
                                 const char * message, int msize)
{
  const struct allnet_header * hp = (const struct allnet_header *) message;
  return ((matches_req (hp->dst_nbits, readb64 ((char *)hp->destination),
                        rd->req.dst_bits_power_two, rd->dst_bits,
                        rd->dst_bitmap)) &&
          (matches_req (hp->src_nbits, readb64 ((char *)hp->source),
                        rd->req.dst_bits_power_two, rd->src_bits,
                        rd->src_bitmap)) &&
          (matches_mid (ALLNET_MESSAGE_ID (hp, hp->transport, msize),
                        rd->req.mid_bits_power_two,
                        rd->mid_bits, rd->mid_bitmap)));
}

/* if successful, return the messages.
   return a result with n = 0 if there are no messages,
   and n = -1 in case of failure -- in both of these cases, free_ptr is NULL.
   messages are in order of descending priority. */
struct pcache_result pcache_request (const struct allnet_data_request *req)
{
  init_pcache ();
#ifdef TEST_ADD_TO_RESULT
  struct pcache_result test_result = {.n=0, .messages=NULL, .free_ptr=NULL};
  char test [100];
  size_t x = add_to_result (&test_result, 0, test, 16, 1234);
  size_t y = add_to_result (&test_result, x, test, 10, 5678);
  printf ("final size %zd\n", y);
  sort_result (&test_result);
  free (test_result.free_ptr);
#endif /* TEST_ADD_TO_RESULT */
  struct pcache_result result = {  .n = 0, .messages = NULL, .free_ptr = NULL };
  size_t result_size = 0;
  char zero_since [ALLNET_TIME_SIZE];
  memset (zero_since, 0, sizeof (zero_since));
  int match_all = ((req->dst_bits_power_two == 0) &&
                   (req->src_bits_power_two == 0) &&
                   (req->mid_bits_power_two == 0) &&
                   (memcmp (zero_since, req->since, sizeof (zero_since)) == 0));
  struct req_details rd = get_details (req);
int debug_count = 0;
  if (message_table != NULL) {
    int ie;
    for (ie = 0; ie < num_message_table_entries; ie++) {
      int offset = 0;
      int im;
      for (im = 0; im < message_table [ie].num_messages; im++) {
debug_count++;
        struct message_header * mh =
          (struct message_header *) (message_table [ie].storage + offset);
        char * msg = message_table [ie].storage + offset + MESSAGE_HEADER_SIZE;
        if (match_all || matches_data_request (&rd, msg, mh->length))
          result_size = add_to_result (&result, result_size,
                                       msg, mh->length, mh->priority);
        offset += mh->length + MESSAGE_HEADER_SIZE;
      }
    }
  }
  sort_result (&result);
/*
printf ("pcache_request returning %d/%d/%d/%d results\n",
        result.n, num_message_table_entries, debug_table_entries, debug_count);
*/
  return result;
}

/* return 1 if the trace request/reply has been seen before, or otherwise
 * return 0 and save the ID.  Trace ID should be MESSAGE_ID_SIZE bytes
 * implementation: add directly to the appropriate bloom filter */
int pcache_trace_request (const unsigned char * id)
{
  init_pcache ();
  if (pid_is_in_bloom ((const char *) id, PID_TRACE_REQ_FILTER))
    return 1;
  pid_add_to_bloom ((const char *) id, PID_TRACE_REQ_FILTER);
  return 0;
}

/* for replies, we look at the entire packet, without the header */
int pcache_trace_reply (const char * msg, int msize)
{
  init_pcache ();
  char id [MESSAGE_ID_SIZE];
  sha512_bytes (msg, msize, id, sizeof (id));
  if (pid_is_in_bloom (id, PID_TRACE_REPLY_FILTER))
    return 1;
  pid_add_to_bloom (id, PID_TRACE_REPLY_FILTER);
  return 0;
}

#ifdef IMPLEMENT_MGMT_ID_REQUEST  /* not used, so, not implemented */
/* similar to pcache_request.
   Modifies req to reflect any IDs (may be 0) that are not found */
struct pcache_result pcache_id_request (struct allnet_mgmt_id_request * req)
{
  printf ("pcache_id_request not implemented\n");
  exit (1);
  struct pcache_result res;
  return res;
}
#endif /* IMPLEMENT_MGMT_ID_REQUEST */

#if 0  /* not (yet) implemented */
/* similar to pcache_request. Tokens are PCACHE_TOKEN_SIZE bytes long. */
struct pcache_result pcache_token_request (const char * token);

/* mark that this message need never again be sent to this token */
void pcache_mark_token_sent (const char * token,  /* PCACHE_TOKEN_SIZE bytes */
                             const char * message, int msize);

/* return 1 if we have the ack, 0 if we do not */
int pcache_ack_found (const char * acks);

#endif /* 0 */

#ifdef PRINT_CACHE_FILES

static void print_message_table_entry (int eindex)
{
  int offset = 0;
  int i;
  for (i = 0; i < message_table [eindex].num_messages; i++) {
    struct message_header mh;
    memcpy (&mh, message_table [eindex].storage + offset, MESSAGE_HEADER_SIZE);
    char desc [1000];
    snprintf (desc, sizeof (desc), "message %d: offset %d, token %" PRIx64 "",
              i, offset, mh.sent_to_tokens);
    print_buffer (message_table [eindex].storage + offset + MESSAGE_HEADER_SIZE,
                  mh.length, desc, 26, 1);
    offset += mh.length + MESSAGE_HEADER_SIZE;
  }
}

int main (int argc, char ** argv)
{
  init_pcache ();
  if (argc > 1) {
    int i;
    for (i = 1; i < argc; i++) {
      if (strcasecmp (argv [i], "all") == 0) {
        int eindex;
        for (eindex = 0; eindex < num_message_table_entries; eindex++) {
          printf ("message table entry %d:\n", eindex);
          print_message_table_entry (eindex);
        }
        int aindex;
        for (aindex = 0; aindex < num_acks; aindex += ACKS_PER_SLOT) {
          printf ("ack table slot beginning with %d:\n", aindex);
          print_ack_table_entry (aindex);
        }
        break;   /* don't bother with any other arguments */
      }
      int eaindex = atoi (argv [i]);
      if ((eaindex >= 0) && (eaindex < num_message_table_entries))
        print_message_table_entry (eaindex);
      if ((eaindex >= 0) && (eaindex < num_acks))
        print_ack_table_entry (eaindex);
    }
  }
  print_stats ("saved cache");
}
#endif /* PRINT_CACHE_FILES */
