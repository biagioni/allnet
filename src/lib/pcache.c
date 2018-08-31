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

   command to compile it as a stand-alone program to test pcache_request:
   gcc -Wall -g -o bin/allnet-test-caches -DTEST_CACHE_FILES src/lib/pcache.c src/lib/configfiles.c src/lib/util.c src/lib/allnet_log.c src/lib/sha.c src/lib/ai.c src/lib/pipemsg.c src/lib/allnet_queue.c src/lib/pid_bloom.c -lpthread
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
 * good practice is to copy the header out into a struct message_header
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

static char local_token [ALLNET_TOKEN_SIZE];
static char token_list [MAX_TOKENS] [ALLNET_TOKEN_SIZE];
static int num_external_tokens = 0;

struct tokens_file {  /* format saved on file */
  uint64_t num_tokens;
  char local_token [ALLNET_TOKEN_SIZE];
  char tokens [MAX_TOKENS] [ALLNET_TOKEN_SIZE];
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
  random_bytes (local_token, ALLNET_TOKEN_SIZE);
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
  random_bytes (local_token, sizeof (local_token));
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
    struct tokens_file * t = NULL;
    long long int fsize = read_file_malloc (fname, (char **)(&t), 1);
    if (fsize == sizeof (struct tokens_file)) {  /* the file may be valid */
      result = 1;   /* success, unless we find something wrong below */
      num_external_tokens = (int)t->num_tokens;
      memcpy (local_token, t->local_token, ALLNET_TOKEN_SIZE);
      memcpy ((char *) token_list, (char *) t->tokens, sizeof (token_list));
      if ((num_external_tokens > MAX_TOKENS) ||  /* sanity check */
          (num_external_tokens < 0)) {
        result = 0;   /* something wrong with the number of tokens */
        printf ("error in %s, read %d tokens\n", fname, num_external_tokens);
      } else if (memget (local_token, 0, sizeof (local_token))) {
        result = 0;   /* something wrong with the local token */
        printf ("error in %s, local token is 0\n", fname);
      } else {
        int i;
        for (i = 0; i < num_external_tokens; i++) {
          if (memget (token_list [i], 0, ALLNET_TOKEN_SIZE)) {
            result = 0;       /* zero tokens are usually a sign of errors */
            printf ("error in file %s, token %d is zero\n", fname, i);
          }
        }
      }
      if (result == 0)
        num_external_tokens = 0;
    }
    if (t != NULL) free (t);
    if (fname != NULL) free (fname);
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

struct async_file_buffer {
  pthread_mutex_t busy;
  char fname [PATH_MAX];
  char * contents;
  int csize;    /* how many bytes of contents are meaningful */
  int alloc;    /* how many bytes contents points to, alloc >= csize */
};

/* 0 is for the messages file, 1 for the acks file, 2 for the tokens file */
#define FILE_BUFFER_MESSAGES	0
#define FILE_BUFFER_ACKS	1
#define FILE_BUFFER_TOKENS	2
#define FILE_BUFFER_MAX		FILE_BUFFER_TOKENS
struct async_file_buffer async_file_buffers [FILE_BUFFER_MAX + 1] =
 { { .busy = PTHREAD_MUTEX_INITIALIZER, .fname = "",
     .contents = NULL, .csize = 0, .alloc = 0 },
   { .busy = PTHREAD_MUTEX_INITIALIZER, .fname = "",
     .contents = NULL, .csize = 0, .alloc = 0 },
   { .busy = PTHREAD_MUTEX_INITIALIZER, .fname = "",
     .contents = NULL, .csize = 0, .alloc = 0 } };

/* called with the lock already held, unlocks */
static void * write_file_async_thread (void * arg)
{
  struct async_file_buffer * a = (struct async_file_buffer *) arg;
  if (0 == write_file (a->fname, a->contents, a->csize, 1))
    printf ("unable to write file %s of size %d\n", a->fname, a->csize);
  pthread_mutex_unlock (&a->busy);
  return NULL;
}

#define WRITE_FILE_ASYNC	1  /* write in the background */
#define WRITE_FILE_WAIT		0  /* wait for the write to complete */

/* if in_background is non-zero, copies the content and
 * starts a thread to write the file.
 * otherwise, writes the file before returning */
static void write_file_async (char * fname, const char * contents, int csize,
                              int file_buffer, int in_background)
{
  if ((! in_background) ||
      (file_buffer < 0) || (file_buffer > FILE_BUFFER_MAX)) {
    if (0 == write_file (fname, contents, csize, 1))
      printf ("unable to save file %s of size %d\n", fname, csize);
    return;
  }
  struct async_file_buffer * arg = async_file_buffers + file_buffer;
  if (pthread_mutex_trylock (&(arg->busy)) == 0) {  /* available */
    snprintf (arg->fname, sizeof (arg->fname), "%s", fname);
    if (arg->alloc < csize) {
      arg->contents = realloc (arg->contents, csize);
      arg->alloc = csize;
    }
    memcpy (arg->contents, contents, csize);
    arg->csize = csize;
    pthread_t t;
    pthread_create (&t, NULL, &write_file_async_thread, (void *) arg);
    pthread_detach (t);
  } else { /* already writing, don't write this time */
#ifdef DEBUG_FOR_DEVELOPER
    printf ("note: unable to save %s, operation already in progress\n", fname);
#endif /* DEBUG_FOR_DEVELOPER */
  }
}

/* if in_background is non-zero, starts a thread to write the file.
 * otherwise, writes the file before returning.
 * same for the other write_*_file functions */
static void write_messages_file (int override, int in_background)
{
  static unsigned long long int last_saved = 0;
  static int state = 0;
  if (too_soon (&last_saved, &state, override))
    return;
  char * fname;
  if (config_file_name ("acache", "messages", &fname)) {
    size_t msize = num_message_table_entries * sizeof (struct hash_table_entry);
    write_file_async (fname, (char *)message_table, (int)msize,
                      FILE_BUFFER_MESSAGES, in_background);
    free (fname);
  } else {
    printf ("unable to save messages file\n");
  }
}

static void write_acks_file (int override, int in_background)
{
  static unsigned long long int last_saved = 0;
  static int state = 0;
  if (too_soon (&last_saved, &state, override))
    return;
  char * fname;
  if (config_file_name ("acache", "acks", &fname)) {
    size_t asize = num_acks * sizeof (struct hash_ack_entry);
    write_file_async (fname, (char *)ack_table, (int) asize,
                      FILE_BUFFER_ACKS, in_background);
    free (fname);
  } else {
    printf ("unable to save acks file\n");
  }
}

static void write_tokens_file (int override, int in_background)
{
  static unsigned long long int last_saved = 0;
  static int state = 0;
  if (too_soon (&last_saved, &state, override))
    return;
  char * fname = NULL;
  if (config_file_name ("acache", "tokens", &fname)) {
    if (num_external_tokens > MAX_TOKENS) {  /* sanity check */
      printf ("error, %d tokens, reducing to %d\n",
              num_external_tokens, MAX_TOKENS);
      num_external_tokens = MAX_TOKENS;
    }
    struct tokens_file t;
    memset (&t, 0, sizeof (t));
    t.num_tokens = num_external_tokens;
    memcpy (t.local_token, local_token, ALLNET_TOKEN_SIZE);
    memcpy (t.tokens, token_list, sizeof (token_list));
    size_t tsize = sizeof (t);
    write_file_async (fname, (char *)(&t), (int)tsize,
                      FILE_BUFFER_TOKENS, in_background);
    free (fname);
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
  if ((alog == NULL) || (num_message_table_entries <= 0))
    return;
  write_messages_file (1, WRITE_FILE_WAIT);
  write_acks_file (1, WRITE_FILE_WAIT);
  write_tokens_file (1, WRITE_FILE_WAIT);
  pid_save_bloom ();
printf ("pcache_write completed\n");
}

/* fills in the first ALLNET_TOKEN_SIZE bytes of token with the current token */
void pcache_current_token (char * result_token)
{
  init_pcache ();
  memcpy (result_token, local_token, ALLNET_TOKEN_SIZE);
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
#ifdef DEBUG_FOR_DEVELOPER
static uint64_t tokens_shifted = 0;
if (! (tokens_shifted & (1 << token_shift))) {
printf ("%s, shift %d, mask %016" PRIx64 "\n", debug, token_shift, mask);
tokens_shifted = tokens_shifted | (1 << token_shift);
}
#endif /* DEBUG_FOR_DEVELOPER */
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
  if (hp->num_messages > MAX_MESSAGE_INFO) {
    printf ("error: num_messages %d > max %d\n",
            hp->num_messages, (int)MAX_MESSAGE_INFO);
    return 0;
  }
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
  int shift_bytes = shift * ALLNET_TOKEN_SIZE;
  char * from = ((char *) token_list) + shift_bytes;
  int length = num_external_tokens - shift;
  int length_bytes = length * ALLNET_TOKEN_SIZE;
#ifdef DEBUG_FOR_DEVELOPER
printf ("shifting %d tokens by %d: %d, %d, %d\n", num_external_tokens, shift,
shift_bytes, length, length_bytes);
#ifdef DEBUG_PRINT
print_buffer ((char *)token_list, sizeof (token_list), "before shift",
              sizeof (token_list), 1);
#endif /* DEBUG_PRINT */
#endif /* DEBUG_FOR_DEVELOPER */
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

#ifdef DEBUG_FOR_DEVELOPERS
#define PRINT_GC
#endif /* DEBUG_FOR_DEVELOPERS */

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
#ifdef PRINT_GC
  long long int us = allnet_time_us () - start;
  printf ("gc %d/%d/%d took %lld.%06llds, shifted %d tokens\n",
          write_tok, write_msg, write_ack,
          us / 1000000, us % 1000000, delta_tokens);
#endif /* PRINT_GC */
  if (write_tok) write_tokens_file (1, WRITE_FILE_ASYNC);
  if (write_msg) write_messages_file (1, WRITE_FILE_ASYNC);
  if (write_ack) write_acks_file (1, WRITE_FILE_ASYNC);
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
  write_messages_file (did_gc, WRITE_FILE_ASYNC);
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
 * if found and delete is 1, deletes it
 * if found and mhp is not NULL, points mhp to the message header */
static int pcache_id_found_delete (const char * id, int delete,
                                   char ** mhp)
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
      if (mhp != NULL)
        *mhp = hp->storage + offset;
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
  return pcache_id_found_delete (id, 0, NULL);  /* do not delete */
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
  pcache_id_found_delete (id, 1, NULL);  /* delete if found */
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
  write_acks_file (0, WRITE_FILE_ASYNC);
}

/* return -1 if already sent.
 * otherwise, return the index of the token in the token table */
static int token_to_send_to (const char * token, uint64_t bitmap,
                             const char * debug)
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
    static long long int last_gc = 0;
    static int printed = 0;
    if (last_gc + 60 > allnet_time ()) { /* gc'd in the last minute */
      if (! printed)
#ifdef DEBUG_FOR_DEVELOPER
        printf ("too many tokens causing too many gcs, ignoring\n")
#endif /* DEBUG_FOR_DEVELOPER */
        ;
      printed = 1;
      return -1;  /* pretend it was already sent */
    }
    printed = 0;  /* print again in the next minute */
#ifdef DEBUG_FOR_DEVELOPER
printf ("%s: ", debug);
print_buffer (token, MESSAGE_ID_SIZE, "new token", 8, 1);
for (i = 0; i < num_external_tokens; i++) {
printf ("%d: ", i);
print_buffer (token_list [i], MESSAGE_ID_SIZE, NULL, 8, 1);
}
#endif /* DEBUG_FOR_DEVELOPER */
    do_gc (-1, 0, 0, 1, 1);
    did_gc = 1;
    last_gc = allnet_time ();
#ifdef DEBUG_FOR_DEVELOPER
printf ("%s after gc\n", debug);
for (i = 0; i < num_external_tokens; i++) {
printf ("%d: ", i);
print_buffer (token_list [i], MESSAGE_ID_SIZE, NULL, 8, 1);
}
#endif /* DEBUG_FOR_DEVELOPER */
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
  write_tokens_file (did_gc, WRITE_FILE_ASYNC);
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
  int itoken = token_to_send_to (token, ack_table [aindex].sent_to_tokens, "1");
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

/* to reallocate less frequently, have a minimum size which is
 * sufficient to hold at least 10 maximum-sized packets, and never
 * realloc below that */
static void * pcache_realloc (void * ptr, int new_size)
{
#define LOCAL_MINIMUM	(11 * ALLNET_MTU)   /* never allocate less */
  if (new_size <= LOCAL_MINIMUM) {
    if (ptr == NULL)
      return malloc_or_fail (LOCAL_MINIMUM, "pcache_realloc 1");
    return ptr;  /* already allocated, no need to realloc */
  }
  /* now new_size > LOCAL_MINIMUM */
  if (ptr == NULL)
    return malloc_or_fail (new_size, "pcache_realloc 2");
  return realloc (ptr, new_size);
#undef LOCAL_MINIMUM
}

/* return the new size of free_ptr, or 0 for errors
 * free_ptr points to n messages.  The messages array is also resized.
 * the messages array is at the end so we can insert the new message
 * in front of it and grow the messages array at the end (or wherever). */
static size_t add_to_result (struct pcache_result * r, size_t size_old,
                             const char * message, int msize, int priority)
{
  size_t messages_size_new = (r->n + 1) * sizeof (struct pcache_message);
  struct pcache_message * new_messages =
    pcache_realloc (r->messages, (int) messages_size_new);
  size_t size_new = size_old + msize;
  char * orig = r->free_ptr;
  char * mem = pcache_realloc (r->free_ptr, (int) size_new);
  if ((mem == NULL) || (new_messages == NULL)) {
    printf ("add_to_result: unable to add, sizes %zd + %d + %zd = %zd, %p %p\n",
            size_old, msize, sizeof (struct pcache_message), size_new,
            mem, new_messages);
    return 0;
  }
  size_t move_size = 0;
  char * current = mem + size_old;
  int i;
  /* this loop continues as long as messages have priority < this priority
   * messages [i - 1].message points to the old storage, which may
   * not be the same as after realloc, so it has to be adjusted.
   * also, we will be shifting these messages out of the way to make room
   * for the msize of this message, so adjust the message pointer by msize.
   * finally, we shift messages up by one to make room for the new message */
  for (i = r->n; (i > 0) && (new_messages [i - 1].priority < priority); i--) {
    size_t offset = new_messages [i - 1].message - orig;
    new_messages [i] = new_messages [i - 1];
    current = mem + offset;
    new_messages [i].message = current + msize; /* will go there in memmove */
    move_size += new_messages [i].msize;
  }
  /* now move the messages themselves to make room for the new message */
  if (move_size > 0)
    memmove (current + msize, current, move_size);
  /* now insert the message */
  memcpy (current, message, msize);
  new_messages [i].message = current;
  new_messages [i].msize = msize;
  new_messages [i].priority = priority;
  /* this loop points the remaining message pointers to the new storage */
  while (i > 0) {
    i--;  /* now i >= 0 */
    current -= new_messages [i].msize;
    new_messages [i].message = current;  /* update the pointer */
  }
  r->messages = new_messages;
  r->n++;
  r->free_ptr = mem;
#ifdef DEBUG_PRINT
  char * error = NULL; for (int x = 0; x < r->n; x++)
  if ((! is_valid_message (r->messages [x].message, r->messages [x].msize,
                           &error)) &&
      (strcmp (error, "hops > max_hops") != 0)) {
    printf ("message %d, error %s ", x, error);
    print_buffer (r->messages [x].message, r->messages [x].msize, NULL, 100, 1);
  }
#endif /* DEBUG_PRINT */
  return size_new;
}

/* like add_to_result, but only adds if it can replace a lower-priority
 * element in the array */
static size_t cond_add_to_result (struct pcache_result * r, size_t size_old,
                                  const char * message, int msize, int priority)
{
  if (r->n <= 0) {
    printf ("cond_add_to_result: unable to add, r->n = %d <= 0\n", r->n);
    return 0;
  }
  if (r->messages [r->n - 1].priority >= priority)  /* drop this message */
    return size_old;
  /* will add.  Do it the easy way -- remove the last one, and add this one */
  size_old -= r->messages [r->n - 1].msize;
  r->n = r->n - 1;
  size_t result = add_to_result (r, size_old, message, msize, priority);
  return result;
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

#ifdef TEST_CACHE_FILES
static void print_rd (const struct req_details *rd)
{
  printf ("rd %p, req %p: dst %p src %p mid %p, rd dst %p src %p mid %p\n",
          rd, &(rd->req), rd->req.dst_bitmap, rd->req.src_bitmap,
          rd->req.mid_bitmap,
          rd->dst_bitmap, rd->src_bitmap, rd->mid_bitmap);
  print_buffer ((char *) rd->dst_bitmap, rd->dst_bits, "dst", 32, 1);
  print_buffer ((char *) rd->src_bitmap, rd->src_bits, "src", 32, 1);
  print_buffer ((char *) rd->mid_bitmap, rd->mid_bits, "mid", 32, 1);
}

static void print_pr (const struct pcache_result * res)
{
  printf ("result %p (free %p) has %d messages %p\n",
          res, res->free_ptr, res->n, res->messages);
  int i;
  for (i = 0; i < res->n; i++) {
    struct pcache_message * pm = &(res->messages [i]);
    printf ("[%d]: pri %8x, ", i, pm->priority);
    print_buffer (pm->message, pm->msize, NULL, 10, 0);
    printf (" %02x %02x..\n", pm->message [16] & 0xff, pm->message [17] & 0xff);
  }
}
#endif /* TEST_CACHE_FILES */

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
#ifdef TEST_CACHE_FILES
  print_rd (&rd);
  printf ("allnet data request: since %lld, "
          "dst 2^%d, src 2^%d, mid 2^%d\n",
          readb64 ((char *) (req->since)), req->dst_bits_power_two,
          req->src_bits_power_two, req->mid_bits_power_two);
  printf ("%d/%p, %d/%p, %d/%p:\n", rd.dst_bits, rd.dst_bitmap,
          rd.src_bits, rd.src_bitmap, rd.mid_bits, rd.mid_bitmap);
  print_buffer ((char *)rd.dst_bitmap, rd.dst_bits, "dst",
                ((rd.dst_bits + 7) / 8), 1);
  print_buffer ((char *)rd.src_bitmap, rd.src_bits, "src",
                ((rd.src_bits + 7) / 8), 1);
  print_buffer ((char *)rd.mid_bitmap, rd.mid_bits, "mid",
                ((rd.mid_bits + 7) / 8), 1);
#endif /* TEST_CACHE_FILES */
  return rd;
}

static int matches_req (unsigned int nbits, const char * address,
                        unsigned int power_two, int bitmap_bits,
                        const unsigned char * bitmap, int debug)
{
if (debug) printf ("entering match_request %04x, p2 %d, nb %d\n",
readb16 (address), power_two, nbits);
  if ((bitmap == NULL) || (power_two <= 0))   /* matches */
    return 1;
  if (nbits < 1)        /* always matches */
    return 1;
  if ((nbits > 64) || (power_two > 16) ||
      (bitmap_bits >= (ALLNET_MTU * 8))) {
    static int first_time = 1;
    if (first_time)
      printf ("matches_req error: %d bits, power_two %d, %d-bitmap, mtu %d\n",
              nbits, power_two, bitmap_bits, (int)ALLNET_MTU);
    first_time = 0;
    return 0;   /* no match */
  }
  int first16 = readb16 (address);
  int loops = ((nbits >= power_two) ? 1 : (1 << (power_two - nbits)));
  if (nbits < 16)   /* clear the low-order bits of the address */
    first16 = (first16 & (~ ((1 << (16 - nbits)) - 1)));
if (debug) printf ("matches_req: %d nbits, %d loops\n", nbits, loops);
  int i;
  for (i = 0; i < loops; i++) {
    int byte_index = allnet_bitmap_byte_index (power_two, first16 + i);
    int byte_mask  = allnet_bitmap_byte_mask  (power_two, first16 + i);
    if ((byte_index < 0) || (byte_mask < 0)) { /* something wrong */
      static int first_time = 1;
      if (first_time)
        printf ("matches_req2 error: %d bits of %04x (%04x) give %d %d\n",
                power_two, first16 + i, first16, byte_index, byte_mask);
      first_time = 0;
      return 0;   /* no match */
    }
    if (debug) {
      printf ("first16 %d/%d mask % index %d/%x byte %02x, ^2 %d nbits %d: ",
              first16 + i, first16, byte_mask, byte_index, byte_index,
              bitmap [byte_index], power_two, nbits);
      if (bitmap [byte_index] & byte_mask)
        printf ("matches\n");
      else
        printf ("no match\n");
      printf ("  %p: ", bitmap);
      print_buffer ((char *)bitmap, bitmap_bits, NULL, bitmap_bits / 8, 1);
    }
    if (debug)
      printf ("matching bitmap [%d] = %02x with %02x\n",
              byte_index, bitmap [byte_index], byte_mask);
    if (bitmap [byte_index] & byte_mask)
      return 1;
    if (debug)
      printf ("bitmap [%d] = %02x does not contain %02x\n",
              byte_index, bitmap [byte_index], byte_mask);
  }
  return 0;
}

static int matches_mid (const char * mid, int nbits,
                        const unsigned char * bitmap)
{
  if ((mid == NULL) || (bitmap == NULL))   /* matches */
    return 1;
  int first16 = readb16 (mid);
  int byte_index = allnet_bitmap_byte_index (nbits, first16);
  int byte_mask  = allnet_bitmap_byte_mask  (nbits, first16);
  if ((byte_index < 0) || (byte_mask < 0)) { /* something wrong */
    static int first_time = 1;
    if (first_time)
      printf ("matches_mid error: %d bits of %04x give %d %d\n",
              nbits, first16, byte_index, byte_mask);
    first_time = 0;
    return 0;   /* no match */
  }
  return ((bitmap [byte_index] & byte_mask) != 0);
}

static int matches_data_request (const struct req_details *rd,
                                 const char * message, int msize)
{
  const struct allnet_header * hp = (const struct allnet_header *) message;
  int debug = 0;
#ifdef DEBUG_PRINT
  debug = (message [1] == 1);  /* only debug data messages */
#endif /* DEBUG_PRINT */
  int r1 = matches_req (hp->dst_nbits, ((char *)hp->destination),
                        rd->req.dst_bits_power_two, rd->dst_bits,
                        rd->dst_bitmap, debug);
  int r2 = matches_req (hp->src_nbits, ((char *)hp->source),
                        rd->req.src_bits_power_two, rd->src_bits,
                        rd->src_bitmap, debug);
  int r3 = matches_mid (ALLNET_MESSAGE_ID (hp, hp->transport, msize),
                        rd->req.mid_bits_power_two,
                        rd->mid_bitmap);
#ifdef DEBUG_PRINT
  if (debug) {
    printf ("%d && %d && %d: ", r1, r2, r3);
    print_buffer (message, msize, NULL, 12, 0);
    printf (" %02x %02x ...\n", message [16] & 0xff, message [17] & 0xff); }
  }
#endif /* DEBUG_PRINT */
  return (r1 && r2 && r3);
}

/* if successful, return the messages.
   return a result with n = 0 if there are no messages,
   and n = -1 in case of failure -- in both of these cases, free_ptr is NULL.
   messages are in order of descending priority.
   If max > 0, at most max messages will be returned.  */
struct pcache_result pcache_request (const struct allnet_data_request *req,
                                     int max)
{
  init_pcache ();
  struct pcache_result result = {  .n = 0, .messages = NULL, .free_ptr = NULL };
  size_t result_size = 0;
  char zero_since [ALLNET_TIME_SIZE];
  memset (zero_since, 0, sizeof (zero_since));
  int match_all = ((req->dst_bits_power_two == 0) &&
                   (req->src_bits_power_two == 0) &&
                   (req->mid_bits_power_two == 0) &&
                   (memcmp (zero_since, req->since, sizeof (zero_since)) == 0));
  struct req_details rd = get_details (req);
#ifdef TEST_CACHE_FILES
  print_rd (&rd);
#endif /* TEST_CACHE_FILES */
int debug_count = 0;
int exp_count = 0;
int token_count = 0;
  if (message_table != NULL) {
    int ie;
    for (ie = 0; ie < num_message_table_entries; ie++) {
      int offset = 0;
      int im;
      for (im = 0; im < message_table [ie].num_messages; im++) {
debug_count++;
        char * p = message_table [ie].storage + offset;
        struct message_header mh;
        memcpy (&mh, p, sizeof (mh));
        char * msg = p + MESSAGE_HEADER_SIZE;
        char token [sizeof (rd.req.token)];
        memcpy (token, rd.req.token, sizeof (token));
#ifdef DEBUG_PRINT
static char debug_copy [sizeof (token)];
if (memcmp (token, debug_copy, sizeof (token)) != 0) {
print_buffer (token, sizeof (token), "pcache_request token", 4, 0);
print_buffer (req->token, sizeof (token), " =? ", 4, 1);
memcpy (debug_copy, token, sizeof (token)); }
#endif /* DEBUG_PRINT */
        if (match_all || matches_data_request (&rd, msg, mh.length)) {
          if (is_expired_message (msg, mh.length))
            exp_count++;
          else if ((! memget (token, 0, sizeof (token))) &&
                   (token_to_send_to (token, mh.sent_to_tokens, "pcache_request") == -1))
            /* token is not zero, and the corresponding bit is set */
            token_count++;
          else if ((max > 0) && (result.n >= max))
            result_size = cond_add_to_result (&result, result_size,
                                              msg, mh.length, mh.priority);
          else
            result_size = add_to_result (&result, result_size,
                                         msg, mh.length, mh.priority);
        }
        offset += mh.length + MESSAGE_HEADER_SIZE;
      }
    }
  }
/* printf ("pcache.c: %d results, %d expired, %d token\n",
result.n, exp_count, token_count); */
  if ((max > 0) && (result.n > max))
    result.n = max;
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

/* mark that this message need never again be sent to this token */
void pcache_mark_token_sent (const char * token,  /* ALLNET_TOKEN_SIZE bytes */
                             const char * message, int msize)
{
  init_pcache ();
  if ((token == NULL) || (message == NULL) || (msize < ALLNET_HEADER_SIZE))
    return;
  char id [MESSAGE_ID_SIZE];
  if (! pcache_message_id (message, msize, id)) {
    print_buffer (message, msize, "no message ID for packet: ", msize, 1);
    return;
  }
  int token_index = token_to_send_to (token, 0, "3");
  if (token_index >= 0) {
    char * hp = NULL;              /* 0: do not delete! -- hp points to mh */
    if ((pcache_id_found_delete (id, 0, &hp)) && (hp != NULL)) {
      struct message_header mh;
      memcpy (&mh, hp, sizeof (mh));
      mh.sent_to_tokens |= (((uint64_t) 1) << token_index);
      memcpy (hp, &mh, sizeof (mh));
    }
  }
}

#if 0  /* not (yet) implemented */

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
                  mh.length, desc, 36, 1);
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

#ifdef TEST_CACHE_FILES

int main (int argc, char ** argv)
{
  init_pcache ();
  if (argc <= 1) {  /* simple test, request everything */
    struct allnet_data_request req; /* null request, should return everything */
    memset (&req, 0, sizeof (struct allnet_data_request));
    struct pcache_result res = pcache_request (&req);
    print_pr (&res);
    return 0;
  }
/* code adapted from xcommon.c */
#define BITMAP_BITS_LOG 8  /* 11 or less to keep packet size below 1K */
#define BITMAP_BITS     (1 << BITMAP_BITS_LOG)
#define BITMAP_BYTES    (BITMAP_BITS / 8)
  /* adr is an allnet_data_request */
  /* adr_size has room for each of the bitmaps */
  unsigned int adr_size =
    sizeof (struct allnet_data_request) + BITMAP_BYTES * 3;
  struct allnet_data_request * adr = malloc_or_fail (adr_size,
                                                     "test_cache_files");
  memset (adr, 0, sizeof (adr_size));
  adr->dst_bits_power_two = BITMAP_BITS_LOG;
  adr->src_bits_power_two = BITMAP_BITS_LOG;
  adr->mid_bits_power_two = BITMAP_BITS_LOG;
  random_bytes ((char *) (adr->padding), sizeof (adr->padding));
  unsigned char * dst = adr->dst_bitmap;
  unsigned char * src = dst + BITMAP_BYTES;
  unsigned char * mid = src + BITMAP_BYTES;
/* end code adapted from xcommon.c */
  int dcount = 0;
  int scount = 0;
  int mcount = 0;
  int tcount = 0;
  int i;
  for (i = 1; i < argc; i++) {
    char * ep;
    int pos = strtol (&(argv [i] [1]), &ep, 16);
    if ((*ep != '\0') || (pos < 0) || (pos >= 256)) {
      printf ("unknown argument %s, %s\n", argv [i],
              "args should have a number 0 ... ff following d, s, or m");
      return 1;
    }
    if (argv [i] [0] == 'd')
      dcount++;
    else if (argv [i] [0] == 's')
      scount++;
    else if (argv [i] [0] == 'm')
      mcount++;
    else if (argv [i] [0] == 't')
      tcount++;
    else {
      printf ("unknown argument %s, args should begin with d, s, or m",
              argv [i]);
      return 1;
    }
  }
  if (dcount == 0) {
    adr->dst_bits_power_two = 0;
    mid = src;
    src = dst;
    dst = NULL;  /* crash if we try to access dst */
  }
  if (scount == 0) {
    adr->src_bits_power_two = 0;
    mid = src;
    src = NULL;  /* crash if we try to access src */
  }
  if (mcount == 0) {
    adr->mid_bits_power_two = 0;
    mid = NULL;  /* crash if we try to access mid */
  }
  int tokenpos = 0;
  for (i = 1; i < argc; i++) {
    char * ep;
    int pos = strtol (&(argv [i] [1]), &ep, 16);
    int byte_index = allnet_bitmap_byte_index (16, pos);
    int byte_mask  = allnet_bitmap_byte_mask  (16, pos);
    if (argv [i] [0] == 'd')
      dst [byte_index] |= byte_mask;
    else if (argv [i] [0] == 's')
      src [byte_index] |= byte_mask;
    else if (argv [i] [0] == 'm')
      mid [byte_index] |= byte_mask;
    else if (argv [i] [0] == 't')  /* token */
      adr->token [tokenpos++] = pos;
    else
      printf ("coding error on argument [%d] %s\n", i, argv [i]);
  }
  struct pcache_result res = pcache_request (adr);
  print_pr (&res);
}
#endif /* TEST_CACHE_FILES */
