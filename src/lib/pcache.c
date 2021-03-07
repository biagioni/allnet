/* pcache.c: central cache for messages */

/* a few principles:
   each message has an ID that is very likely distinct from other messages.
   each system  has an ID (token) that is very likely distinct
     from other systems.  The token can change whenever the system
     discards (part of) the cached messages
   we want to forward each message (and each ack) to each system at most once.
   if we get a data request, we want to forward based on that.

   since acks aren't acked, they are removed when they are replaced by
   a new ack that hashes to the same location
 */

#include <stdio.h>
#include <unistd.h>
#include <inttypes.h>
#include <string.h>
#include <signal.h>

#include "pcache.h"
#include "util.h"
#include "configfiles.h"
#include "sha.h"

/* implementation: acks are simple, a hash table, both on disk and in memory
 * the same for message IDs that we save (via pcache_record_packet),
 * and for trace requests and replies
 * likewise tokens are saved.  (the local token is handled separately)
 *
 * actual messages are stored sequentially in order of decreasing priority.
 * and their IDs are also stored in the mid_table.
 * every time we delete some messages, we decrease the priority
 * of the remaining messages */

struct message_header {  /* 32 bytes per message header */
  char id [MESSAGE_ID_SIZE];
  uint32_t length;               /* actual length of the message */
  uint32_t priority;             /* set to zero for deleted messages */
  uint64_t sent_to_tokens;
};  /* length bytes of data follow, padded to a multiple of 16 bytes */

static struct message_header * msg_table = NULL;
static size_t msg_table_size = 0;   /* size in bytes */

struct hash_entry {  /* 32 bytes per hash entry */
  char ida [MESSAGE_ID_SIZE]; /* for acks, this is the ack */
  uint64_t sent_to_tokens;    /* 8 bytes */
  uint8_t used;               /* 1 byte */
  uint8_t max_hops;           /* 1 byte -- only used for acks */
  uint8_t pad [6];            /* may be used in the future -- 6 bytes */
};

/* note the ack table is indexed by ID, but stores the ack */
static struct hash_entry * ack_table = NULL;
static int num_ack = 0;
static struct hash_entry * mid_table = NULL;  /* message IDs */
static int num_mid = 0;
static struct hash_entry * trc_table = NULL;  /* trace requests and replies */
static int num_trc = 0;

/* combine IDs with a random value to make it harder to guess how we hash */
static unsigned long long int ack_secret = 0;
static unsigned long long int mid_secret = 0;
static unsigned long long int trc_secret = 0;

#define MAX_TOKENS	64	/* external tokens.  The list of which tokens
                                   we have sent to can be saved in a uint64_t */
struct tokens {  /* format saved on file and in memory */
  char tokens [MAX_TOKENS] [ALLNET_TOKEN_SIZE];
  char num_tokens;
  char most_recent_token;  /* when we run out of space, we clear from here */
};

static struct tokens tokens = { .num_tokens = 0,
                                .most_recent_token = MAX_TOKENS - 1 };

static int save_tokens = 0;
static int save_ack_hashes = 0;
static int save_trc_hashes = 0;
static int save_messages = 0;

static const uint64_t one64 = 1;

static void crash (const char * reason)
{
  printf ("crashing %d (%s):\n", getpid (), reason);
  kill (getpid (), SIGABRT);
  printf ("exiting\n");
  exit (1);
}

static uint32_t msg_storage (uint32_t size)
{
  return (((size + 15) / 16) * 16);
}

static struct message_header * next_message (struct message_header * hp)
{
  const size_t mh_size = sizeof (struct message_header);
  struct message_header * result = NULL;   /* this is our result */
  if (hp == NULL) {   /* special case, check whether msg_table is empty */
    if ((msg_table_size < mh_size) || (msg_table->length == 0))
      return NULL;
    result = msg_table;   /* return the first message */
  } else {
    size_t msg_table_offset = ((char *) hp) - ((char *) msg_table);
    size_t current_size = mh_size + msg_storage (hp->length);
    /* do some checking, so we don't have to do it elsewhere */
    if ((hp->length == 0) || (hp->length > ALLNET_MTU) ||
        ((msg_table_offset % 16) != 0) ||
        (current_size + msg_table_offset > msg_table_size)) {
      printf ("next_message: hp %p/%d, offset %d, sizes %zd+%zd, table %p\n",
              hp, hp->length, (int)(((char *) hp) - ((char *) msg_table)),
              current_size, msg_table_offset, msg_table);
      return NULL;
    }
    result = (struct message_header *) (((char *) hp) + current_size);
  }
  if (result == NULL) { printf ("major error in next_message\n"); crash ("major error in next_message"); }
  char * p = (char *) result;
  size_t msg_table_offset = p - ((char *) msg_table);
  if ((msg_table_offset % 16) != 0) {
    printf ("next_message error: next %p, offset %zd, table %p\n",
            p, msg_table_offset, msg_table);
    crash ("next_message error");
    return NULL;
  }
  if (result->length == 0)  /* end of messages */
    return NULL;
  int result_size = mh_size + msg_storage (result->length);
  if (msg_table_offset + result_size > msg_table_size)
    return NULL;
  return result;
}

/* return -1 if not found, the token index otherwise */
static int token_find_index (const unsigned char * token)
{
  if ((token == NULL) || (memget (token, 0, ALLNET_TOKEN_SIZE)))
    return -1;   /* all-zeros token is never found */
  int i;
  for (i = 0; i < MAX_TOKENS; i++) {
    if (memcmp (tokens.tokens [i], token, ALLNET_TOKEN_SIZE) == 0) /* found */
      return i;
  }
  return -1; /* token not found */
}

static int add_token (const unsigned char * token)
{
  if ((token == NULL) || (memget (token, 0, ALLNET_TOKEN_SIZE))) {
    printf ("error in add_token: %p\n", token);
    crash ("error in add_token");
  }
  save_tokens = 1;
  int token_index = (tokens.most_recent_token + 1) % MAX_TOKENS;
  if ((tokens.num_tokens == MAX_TOKENS) && (token_index % 8 == 0)) {
    /* discard the next 8 tokens, clearing the corresponding byte
     * in all the records */
    printf ("clearing tokens %d..%d\n", token_index, token_index + 7);
    memset (tokens.tokens + token_index, 0, 8 * ALLNET_TOKEN_SIZE);
    /* adjust all the sent_to_tokens fields */
    int byte_index = token_index / 8;
    int i;
    for (i = 0; i < num_ack; i++)
      if (ack_table [i].used)
        ((char *)(&ack_table [i].sent_to_tokens)) [byte_index] = 0;
    for (i = 0; i < num_trc; i++)
      if (trc_table [i].used)
        ((char *)(&trc_table [i].sent_to_tokens)) [byte_index] = 0;
    for (i = 0; i + sizeof (struct message_header) <= msg_table_size; ) {
      char * p = (char *) msg_table;
      struct message_header * hp = (struct message_header *) (p + i);
      if (hp->length == 0)  /* last message, used as a sentinel */
        break;
      ((char *)(&hp->sent_to_tokens)) [byte_index] = 0;
      i += sizeof (struct message_header) + msg_storage (hp->length);
    }
    save_ack_hashes = 1;
    save_trc_hashes = 1;
    save_messages = 1;
  }
  memcpy (tokens.tokens [token_index], token, ALLNET_TOKEN_SIZE);
  if (tokens.num_tokens < MAX_TOKENS)
    tokens.num_tokens++;
  tokens.most_recent_token = token_index;
  return token_index;
}

/* returns a valid index, 0 <= i < hash_table_size.
 * id must have size 16, which is MESSAGE_ID_SIZE
 * we use sha512 hash so that even if an observer notices a collision,
 * they cannot guess the secret */
static int id_index (const char * id, unsigned long long int hash_table_size,
                     unsigned long long int secret)
{
  char source [MESSAGE_ID_SIZE + 8];
  memcpy (source, id, MESSAGE_ID_SIZE);
  writeb64 (source + MESSAGE_ID_SIZE, secret);
  char hash [SHA512_SIZE];
  sha512 (source, sizeof (source), hash);
  return (int) (readb64 (hash + SHA512_SIZE / 2) % hash_table_size);
}

/* the index for the ack is computed from the corresponding ID */
static int ack_index (const char * ack)
{
  char id [MESSAGE_ID_SIZE];
  sha512_bytes (ack, MESSAGE_ID_SIZE, id, MESSAGE_ID_SIZE);
  return id_index (id, num_ack, ack_secret);
}

/* is the ack for this ID in the ack table? */
static int id_is_acked (const char * id)
{
  int aindex = id_index (id, num_ack, ack_secret);
  char check_id [MESSAGE_ID_SIZE];
  sha512_bytes (ack_table [aindex].ida, MESSAGE_ID_SIZE,
                check_id, MESSAGE_ID_SIZE);
  return (memcmp (id, check_id, MESSAGE_ID_SIZE) == 0);
}

static void save_message (char * destination, const char * id,
                          const char * message, int msize, int priority)
{
  struct message_header * new = (struct message_header *) destination;
  size_t total_size = sizeof (struct message_header) + msg_storage (msize);
  memset (new, 0, total_size);
  memcpy (new->id, id, MESSAGE_ID_SIZE);
  new->length = msize;
  new->priority = priority;
  new->sent_to_tokens = 0;
  memcpy (destination + sizeof (struct message_header), message, msize);
  save_messages = 1;
}

/* if id != NULL and message != NULL and msize > 0 and priority > 0,
 * inserts the message while gc'ing */
static size_t gc_messages (const char * id, const char * message, int msize,
                           int priority)
{
  if ((id == NULL) || (message == NULL) || (msize <= 0) || (priority <= 0)) {
    id = NULL;
    message = NULL;
    msize = 0;
    priority = 0;
/* printf ("starting gc, length is %zd\n", msg_table_size); */
  }
  char * copy_to = (char *) msg_table;
  const size_t mh_size = sizeof (struct message_header);
  struct message_header * next = next_message (NULL);
  while (next != NULL) {
    struct message_header * current = next;
    /* update next *before* modifying the message table or anything else */
    next = next_message (current);
    const uint32_t eff_len = msg_storage (current->length);
    size_t hdr_msg_size = mh_size + eff_len;
    const char * current_message = ((char *) current) + mh_size;
    /* delete messages with priority 0, invalid (likely expired)
     * messages, and messages that have been acked.  We delete them by
     * only keeping messages that don't match any of these criteria */
    if ((current->priority != 0) &&
        (is_valid_message (current_message, current->length, NULL)) &&
        (! id_is_acked (current->id))) {
      if (((char *)current) != copy_to)
        memmove (copy_to, current, hdr_msg_size);
      save_messages = 1;          /* gc'd at least one message */
      copy_to += hdr_msg_size;
    } /* done with this message */
  }
  char * p = (char *) msg_table;
  if ((copy_to - p) + mh_size <= msg_table_size) { /* add a sentinel record */
    memset (copy_to, 0, mh_size);
    copy_to += mh_size; 
  }
/* printf ("finishing gc, length is %zd\n", copy_to - p); */
/* print_buffer (p, copy_to - p, "finished gc", 40, 1);  */
  return copy_to - p;
}

static int get_size_from_file (int line, int dflt)
{
  int fd = open_read_config ("acache", "sizes", 1);
  char * data = NULL;
  int size = read_fd_malloc (fd, &data, 0, 1, "~/.allnet/acache/sizes");
  if (size <= 0)
    return dflt;
  /* read_fd_malloc terminates the content with a null character,
   * so the content is a valid C string */
  int result = dflt;
  char * p = data;
  while (line-- > 0) {
    char * endp = NULL;
    result = (int) strtol (p, &endp, 10);
    if (endp == p) {
      result = dflt;
      break;
    }
    if (*endp == '\0') {
      if (line == 0)
        break;
      result = dflt;
      break;
    }
    if (*endp != '\n') {
      result = dflt;
      break;
    }  /* else, *endp is the newline character */
    p = endp + 1;
  }
  free (data);
  return result;
}

static void read_tokens_file ()
{
  int fd = open_read_config ("acache", "token", 1);
  if (fd >= 0) {
    ssize_t n = read (fd, &tokens, sizeof (tokens));
    close (fd);
    if ((n == sizeof (tokens)) && (tokens.num_tokens >= 0) &&
        (tokens.num_tokens <= MAX_TOKENS)) {
      int found_zero = 0;
      int i;
      for (i = 0; i < tokens.num_tokens; i++)
        if (memget (tokens.tokens [i], 0, ALLNET_TOKEN_SIZE))
          found_zero = 1;
      if (! found_zero)
        return;
    } else {  /* error */
      printf ("tokens file size %zd, expected %zd, ", n, sizeof (tokens));
      printf ("num_tokens not 0 <= %d <= %d\n", tokens.num_tokens, MAX_TOKENS);
    }
  }
  /* some error, initialize from scratch */
  printf ("error reading tokens file, initializing from scratch\n");
  memset (&tokens, 0, sizeof (tokens));
  /* initialize the local token */
  random_bytes (tokens.tokens [0], ALLNET_TOKEN_SIZE);
  tokens.num_tokens = 1;   /* record that we have a local token */
  save_tokens = 1;
}

static void write_tokens_file (int always)
{
#ifndef PRINT_CACHE_FILES
  if ((! always) && (! save_tokens))
    return;
  if (tokens.num_tokens <= 0) {
    printf ("saving tokens file, but only has %d tokens, setting to 1\n",
            tokens.num_tokens);
    tokens.num_tokens = 1;         /* at least the local token */
  }
  int fd = open_write_config ("acache", "token", 1);
  if (fd < 0)
    return;
  ssize_t n = write (fd, &tokens, sizeof (tokens));
  if (n != sizeof (tokens))
    perror ("error writing tokens file\n");
  close (fd);
  save_tokens = 0;
#endif /* PRINT_CACHE_FILES */
}

static void read_hash_file (const char * fname, int fsize,
                            struct hash_entry ** table, int * num,
                            unsigned long long int * secret)
{
  if ((*num > 0) && (*table != NULL))
    free (*table);
  *table = NULL;
  *num = 0;
  *secret = 0;
  int fd = open_read_config ("acache", fname, 1);
  if (fd >= 0) {
    char * file_contents = NULL;
    int actual_size = read_fd_malloc (fd, &file_contents, 1, 1, fname);
    int modulo = actual_size % sizeof (struct hash_entry);
    if ((file_contents != NULL) && (actual_size >= fsize) &&
        ((modulo == 0) || (modulo == 8))) {  /* valid */
      *table = (struct hash_entry *) file_contents;
      *num = actual_size / sizeof (struct hash_entry);
      if (modulo == 8) {
        *secret = readb64 (file_contents + (actual_size - 8));
      } else {   /* create a new secret and rehash.  Should only happen once */
        *secret = random_int (0, (unsigned long long int) (-1));
        struct hash_entry * old_hash = *table;
        struct hash_entry * new =
          malloc_or_fail (actual_size, "read_hash_file rehash");
        int i;
        for (i = 0; i < *num; i++)
          if (old_hash [i].used)
            new [id_index (old_hash [i].ida, *num, *secret)] = old_hash [i];
        free (old_hash);
        *table = new;
      }
      struct hash_entry * hash = *table;
      int i;
      if (save_tokens)  /* tokens have been reset */
        for (i = 0; i < *num; i++)
          hash [i].sent_to_tokens = 0;
      return;
    } /* else size is too small or bad, ignore contents */
    /* free the file contents if they were allocated */
    if ((actual_size > 0) && (file_contents != NULL))
      free (file_contents);
  }   /* else file does not exist, create an empty table set to all zeros */
  *num = fsize / sizeof (struct hash_entry);
  *table = malloc_or_fail (fsize, "read_hash_file");
  memset (*table, 0, fsize);
  *secret = random_int (0, (unsigned long long int) (-1));
}

static void write_hash_file (const char * fname, struct hash_entry * table,
                             int num, unsigned long long int secret)
{
#ifndef PRINT_CACHE_FILES
  int fd = open_write_config ("acache", fname, 1);
  if (fd >= 0) {
    size_t w = write (fd, table, num * sizeof (struct hash_entry));
    if (w != num * sizeof (struct hash_entry))
      perror ("write_hash_file error writing hash");
    char buffer [8];
    writeb64 (buffer, secret);
    size_t ws = write (fd, buffer, sizeof (buffer));
    if (ws != sizeof (buffer))
      perror ("write_hash_file error writing secret");
    close (fd);
  }
#endif /* PRINT_CACHE_FILES */
}

/* a hash table should have at least 64K ids */
static const int min_hash_file_size = 64 * 1024 * sizeof (struct hash_entry);

static void read_hash_files ()
{
  int default_file_size = get_size_from_file (2, min_hash_file_size);
  if (default_file_size < min_hash_file_size)
    default_file_size = min_hash_file_size;
  read_hash_file ("ack", default_file_size, &ack_table, &num_ack, &ack_secret);
  read_hash_file ("trace", default_file_size,
                  &trc_table, &num_trc, &trc_secret);
  save_ack_hashes = save_trc_hashes = 1;
}

static void write_hash_files (int always)
{
  if (always || save_ack_hashes) {
    write_hash_file ("ack", ack_table, num_ack, ack_secret);
    save_ack_hashes = 0;
  }
  if (always || save_trc_hashes) {
    write_hash_file ("trace", trc_table, num_trc, trc_secret);
    save_trc_hashes = 0;
  }
}

static void read_messages_file ()
{
  if (save_tokens)
    save_messages = 1;
  int fd = open_read_config ("acache", "message", 1);
  char * data = NULL;
  ssize_t size = read_fd_malloc (fd, &data, 1, 1, "~/.allnet/acache/message");
  close (fd);
  if ((size > 0) && (data != NULL)) {  /* check and create mid */
    ssize_t min_size = get_size_from_file (1, 8 * min_hash_file_size);
    if (size < min_size) {  /* extend to min size */
      char * new_data = realloc (data, min_size);
      if (new_data == NULL) {
        free (data);
        return;
      }
      data = new_data;
      memset (data + size, 0, min_size - size);
      size = min_size;
    }
    msg_table = (struct message_header *) data;
    msg_table_size = size;
    /* create the message ID table, and fill it in as we check the messages */
    ssize_t mid_size = get_size_from_file (2, min_hash_file_size);
    if (size > min_size * 2)  /* increase the mid table size in proportion */
      mid_size *= (size / min_size);
    if (mid_size < min_hash_file_size)
      mid_size = min_hash_file_size;
    num_mid = (int) (mid_size / sizeof (struct hash_entry));
    mid_table = malloc_or_fail (mid_size, "read_messages_file mid_table");
    /* now check each message and add it to the mid */
    struct message_header * current = NULL;
    while ((current = next_message (current)) != NULL) {
      if (current->priority > 0) { /* message has not been deleted */
        save_messages = 1;    /* found at least one good message */
        if (save_tokens)  /* tokens have been reset */
          current->sent_to_tokens = 0;
        /* add to mid table */
        int index = id_index (current->id, num_mid, mid_secret);
        memcpy (mid_table [index].ida, current->id, MESSAGE_ID_SIZE);
        mid_table [index].sent_to_tokens = current->sent_to_tokens;
        mid_table [index].used = 1;
        /* .max_hops = 0 -- max_hops not used in message ID table */
      }
    }
    return;
  }
  /* some error, initialize from scratch */
  if (data != NULL)
    free (data);
  printf ("error reading messages file, initializing from scratch\n");
  msg_table_size = get_size_from_file (1, 8 * min_hash_file_size);
  if (msg_table_size < 4 * 1024 * 1024)  /* at least four MBi */
    msg_table_size = 4 * 1024 * 1024;
  msg_table = malloc_or_fail (msg_table_size, "read_messages_file init");
  /* put an all-zero message_header as a marker that we are at the end */
  memset (msg_table, 0, sizeof (struct message_header));
  int mid_size = get_size_from_file (2, min_hash_file_size);
  if (mid_size < min_hash_file_size)
    mid_size = min_hash_file_size;
  mid_table = malloc_or_fail (mid_size, "read_messages_file mid init");
  num_mid = mid_size / sizeof (struct hash_entry);
  memset (mid_table, 0, mid_size);
/* print_buffer (msg_table, (int) msg_table_size,
                 "finished init msgtbl", 40, 1); */
}

static void write_messages_file (int always)
{
  if ((! always) && (! save_messages))
    return;
  size_t len = gc_messages (NULL, NULL, 0, 0);
#ifndef PRINT_CACHE_FILES
  int fd = open_write_config ("acache", "message", 1);
  if (fd >= 0) {
    size_t w = write (fd, msg_table, len);
    if (w != len) {
      perror ("write_messages_file error writing messages");
      printf ("error writing %zd bytes, wrote %zd\n", len, w);
    } else
      save_messages = 0;
    close (fd);
  }
#else /* PRINT_CACHE_FILES */
  if (len < 1000)
    printf ("after gc, %zd bytes left\n", len);
#endif /* PRINT_CACHE_FILES */
}

/* initialize and do any needed maintenance */
static int pcache_init_maint_initialized = 0;
static void pcache_init_maint ()
{
  if (! pcache_init_maint_initialized) {
    mid_secret = random_int (0, (unsigned long long int) (-1));
    read_tokens_file ();
    read_hash_files ();
    read_messages_file ();
    pcache_init_maint_initialized = 1;
  }
/* save at least once when first called.  Further, save every 1-60 minutes */
  static unsigned long long int next_save = 0;
  static unsigned long long int minutes_increment = 1;
  if (allnet_time () >= next_save) {
    write_tokens_file (0);
    write_hash_files (0);
    write_messages_file (0);
    next_save = allnet_time () + minutes_increment * 60;
    if (minutes_increment < 60)
      minutes_increment += 1;  /* add one minute */
  }
}

/* return 1 for success, 0 for failure.
 * look inside a message and fill in its ID (MESSAGE_ID_SIZE bytes). */
int pcache_message_id (const char * message, int msize, char * result_id)
{
  pcache_init_maint ();
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
  sha512_bytes (message + hsize, (int)(msize - hsize),
                result_id, MESSAGE_ID_SIZE);
  return 1;
}

/* if the packet has no ID, return 0
 * if the packet was already in the mid_table, return 0
 * else add to the mid_table and return 1
 * id must have MESSAGE_ID_SIZE bytes */
static int pcache_record_packet_id (const char * message, int msize, char * id)
{
  pcache_init_maint ();
  if (! pcache_message_id (message, msize, id)) {
    print_buffer (message, msize, "no message ID for packet: ", msize, 1);
    return 0;
  }
  int index = id_index (id, num_mid, mid_secret);
  if (memcmp (mid_table [index].ida, id, MESSAGE_ID_SIZE) == 0)
    return 0;    /* we have it already */
  memcpy (mid_table [index].ida, id, MESSAGE_ID_SIZE);
  mid_table [index].sent_to_tokens = 0; 
  mid_table [index].used = 1; 
  return 1;
}

/* save this (received) packet */
void pcache_save_packet (const char * message, int msize, int priority)
{
  char id [MESSAGE_ID_SIZE];
  if (! pcache_record_packet_id (message, msize, id))  /* cannot save */
    return;
  char * p = (char *) msg_table;
  const size_t mh_size = sizeof (struct message_header);
  const size_t needed = mh_size + msg_storage (msize);
  size_t i;
  for (i = 0; i + needed <= msg_table_size; ) {
    struct message_header * hp = (struct message_header *)(p + i);
    const size_t next_i = i + needed;
    /* to do later maybe: if we find a sufficiently large deleted message,
     * and the next message has lower priority, insert there.  Or else
     * do a gc as we go along, since we're copying many bytes anyway.
     * we could even combine this code with the gc code, so the same
     * code does a gc, and optionally inserts a packet (if the packet is
     * inserted, the gc could be partial, only up to the insertion point) */
    if (((hp->priority != 0) && (priority >= hp->priority)) || /* insert here */
        (hp->length == 0)) {           /* last message, used as a sentinel */
      if (next_i < msg_table_size)    /* move others out of the way */
        memmove (p + next_i, p + i, msg_table_size - next_i);
      save_message (p + i, id, message, msize, priority);
      save_messages = 1;
      return;
    }
    i += mh_size + msg_storage (hp->length);
  }
}

/* record this packet ID, without actually saving it */
void pcache_record_packet (const char * message, int msize)
{
  char id [MESSAGE_ID_SIZE];
  pcache_record_packet_id (message, msize, id);
}

/* return 1 if the ID is in the cache, 0 otherwise
 * ID is MESSAGE_ID_SIZE bytes. */
int pcache_id_found (const char * id)
{
  pcache_init_maint ();
  int index = id_index (id, num_mid, mid_secret);
  return (memcmp (mid_table [index].ida, id, MESSAGE_ID_SIZE) == 0);
}

/* return whether this packet is to be returned given this bitmap.
 * p2 is the power of two describing the bitmap size
 * return 1 if p2 == 0, meaning we should accept all packets
 * return 1 if nbits is zero, meaning packet matches any bitmap
 * return 1 if p2>0, nbits>0, and the address has a '1' bit set in the bitmap
 * return 0 otherwise */
static int
  address_matches_bitmap (unsigned int nbits, const unsigned char * addr,
                          unsigned int p2, const unsigned char * bitmap)
{
  if (p2 <= 0)
    return 1;   /* no bitmap, so accept */
  if (nbits <= 0)
    return 1;   /* no address, so accept */
  /* the index/mask functions always require 16 bits */
  int sixteen = readb16u (addr);
  int index = allnet_bitmap_byte_index (p2, sixteen);
  int mask = allnet_bitmap_byte_mask (p2, sixteen);
  return ((bitmap [index] & mask) != 0);
}

/* returns NULL if the address does not match the bitmap, and
 * the new bitmap otherwise */
static const unsigned char *
  check_bitmap (int bits_power_two, const unsigned char * bitmap,
                int nbits, const unsigned char * addr)
{
  if ((bits_power_two > 0) &&
      (! address_matches_bitmap (nbits, addr, bits_power_two, bitmap)))
    return NULL;
  if (bits_power_two >= 3)
    return bitmap + (1 << (bits_power_two - 3));
  else if (bits_power_two > 0)
    return bitmap + (1 << (bits_power_two - 3));
  return bitmap;
}

static int message_matches (const struct allnet_data_request * req, int rlen,
                            int nbits, const unsigned char * source,
                            const struct message_header * mhp,
                            const char * message)
{
  const struct allnet_header * hp = (const struct allnet_header *) message;
  int ti = ((rlen >= ALLNET_TOKEN_SIZE) ?
            (token_find_index (req->token)) : -1);
  if ((ti >= 0) && (mhp->sent_to_tokens & (one64 << ti)))
    return 0;             /* already returned this message to this token */
  /* An empty data request message is also allowed, and requests all
     packets addressed TO the sender of the request. */
  if ((rlen == 0) &&
      ((nbits <= 0) || (source == NULL) ||
       (matches (source, nbits, hp->destination, hp->dst_nbits))))
    return 1;  /* it's a match */

  const unsigned char * bitmap = req->dst_bitmap;
  bitmap = check_bitmap (req->dst_bits_power_two, bitmap,
                         hp->dst_nbits, hp->destination);
  if (bitmap == NULL) return 0;  /* destination address does not match */
  bitmap = check_bitmap (req->src_bits_power_two, bitmap,
                         hp->src_nbits, hp->source);
  if (bitmap == NULL) return 0;  /* source address does not match */
  bitmap = check_bitmap (req->mid_bits_power_two, bitmap,
                         MESSAGE_ID_BITS, (unsigned char *) (mhp->id));
  if (bitmap == NULL) return 0;  /* message ID does not match */
  return 1;
}

/* if successful, return the messages.
   return a result with n = 0 if there are no messages,
   and n = -1 in case of failure
   messages are in order of descending priority.
   If max > 0, at most max messages will be returned.
   if rlen <= 0, only returns messages addressed to source/nbits -- 
   and if nbits is 0 or source is NULL, returns all messages
   The memory used by pcache_result is allocated in the given buffer
   If the request includes a token, the token is marked as having received
   these messages.

   implementation: the front of the buffer is used for the messages array,
   the back of the buffer stores the actual messages */
struct pcache_result
  pcache_request (const struct allnet_data_request * req, int rlen,
                  int nbits, const unsigned char * source, int max,
                  char * buffer, int bsize)
{
  pcache_init_maint ();
  struct pcache_result
    result = {.n = 0, .messages = (struct pcache_message *) buffer };
  if (bsize <= 0)
    return result;
  memset (buffer, 0, bsize);
  size_t buffer_offset = bsize;     /* bytes in buffer not used for messages */
  struct message_header * current = NULL;
  while (((max <= 0) || (result.n < max)) &&
         ((current = next_message (current)) != NULL)) {
    const uint32_t eff_len = msg_storage (current->length);
    const size_t pm_size = sizeof (struct pcache_message);
    const size_t mh_size = sizeof (struct message_header);
    const size_t needed = pm_size + eff_len;
  /* to see if we have room, compute array size including this message, n+1 */
    const size_t array_size = pm_size * (result.n + 1);
    if (needed + array_size > buffer_offset)  /* no more space */
      break;
    const char * message = ((char *) current) + mh_size;
    if ((current->priority != 0) &&  /* the message has not been deleted */
        (is_valid_message (message, current->length, NULL)) &&
        (! id_is_acked (current->id))) {
      if (message_matches (req, rlen, nbits, source, current, message)) {
        /* add this message */
        if (buffer_offset < needed + array_size) {
          printf ("error: offset %zd <= needed %zd + array %zd\n",
                  buffer_offset, needed, array_size);
          printf ("  sizes %zd + %zd, n %d\n",
                  sizeof (struct pcache_message *),
                  sizeof (struct pcache_message), result.n);
          crash ("error adding message");
        }
        /* copy the message to the buffer */
        buffer_offset -= eff_len;
        memcpy (buffer + buffer_offset, message, eff_len);
        result.messages [result.n].message = buffer + buffer_offset;
        result.messages [result.n].msize = current->length;
        result.messages [result.n].priority = current->priority;
        result.n += 1;
        if ((rlen >= ALLNET_TOKEN_SIZE) &&
            (! (memget (req->token, 0, ALLNET_TOKEN_SIZE)))) {
          int ti = token_find_index (req->token);
          if (ti < 0)  /* no such token */
            ti = add_token (req->token);
          if (ti >= 0) {
            current->sent_to_tokens |= (one64 << ti);
            save_messages = 1;
          }
        }
      } /* else no match, do not add to the results */
    } else {   /* deleted or invalid (probably expired) or acked message */
      current->priority = 0;     /* mark as deleted */
    }
  }
  return result;
}
 
/* acks */

/* add this ack to ack_table, setting max_hops.
 * does NOT delete any matching message in msg_table -- that is
 * taken care of by pcache_request and gc_messages */
static void save_one_ack (const char * ack, int max_hops)
{
  int aindex = ack_index (ack);
  if (memcmp (ack_table [aindex].ida, ack, MESSAGE_ID_SIZE) != 0) {
    memcpy (ack_table [aindex].ida, ack, MESSAGE_ID_SIZE);
    ack_table [aindex].max_hops = max_hops;
    ack_table [aindex].used = 1;
    ack_table [aindex].sent_to_tokens = 0;
  }
}

/* each ack has size MESSAGE_ID_SIZE */
/* record all these acks and delete (stop caching) corresponding messages */
void pcache_save_acks (const char * acks, int num_acks, int max_hops)
{
  pcache_init_maint ();
  int i;
  for (i = 0; i < num_acks; i++)
    save_one_ack (acks + i * MESSAGE_ID_SIZE, max_hops);
  save_ack_hashes = 1;
}

/* return 1 if we have the ack, 0 if we do not */
int pcache_ack_found (const char * ack)
{
  pcache_init_maint ();
  int aindex = ack_index (ack);
  if (memcmp (ack_table [aindex].ida, ack, MESSAGE_ID_SIZE) == 0)
    return 1;
  return 0;
}

/* return 1 if we have the ack for this ID, 0 if we do not
 * if returning 1, fill in the ack */
int pcache_id_acked (const char * id, char * ack)
{
  pcache_init_maint ();
  int aindex = id_index (id, num_ack, ack_secret);
  char check_id [MESSAGE_ID_SIZE];
  sha512_bytes (ack_table [aindex].ida, MESSAGE_ID_SIZE,
                check_id, MESSAGE_ID_SIZE);
  if (memcmp (id, check_id, MESSAGE_ID_SIZE) == 0) {
    memcpy (ack, ack_table [aindex].ida, MESSAGE_ID_SIZE);
    return 1;
  }
  return 0;
}

/* return 1 if the ack has not yet been sent to this token,
 * and mark it as sent to this token.
 * otherwise, return 0 */
int pcache_ack_for_token (const unsigned char * token, const char * ack)
{
  pcache_init_maint ();
  int aindex = ack_index (ack);
  if (memcmp (ack_table [aindex].ida, ack, MESSAGE_ID_SIZE) != 0)
    return 1; /* this ack is not in the table, go ahead and forward it */
  int itoken = token_find_index (token);
  if (itoken < 0)  /* no such token */
    itoken = add_token (token);
  if (ack_table [aindex].sent_to_tokens & (one64 << itoken))
    return 0;    /* already sent */
  save_ack_hashes = 1;
  ack_table [aindex].sent_to_tokens |= (one64 << itoken);  /* mark it sent */
  return 1;
}

/* call pcache_ack_for_token repeatedly for all these acks,
 * moving the new ones to the front of the array and returning the
 * number that are new (0 for none, -1 for errors) */
int pcache_acks_for_token (const unsigned char * token,
                           char * acks, int num_acks)
{
  pcache_init_maint ();
  const char * ack = acks;
  char * offset = acks;
  int result = 0;
  int i;
  for (i = 0; i < num_acks; i++) {
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

/* return 1 if the trace request/reply has been seen before, or otherwise
 * return 0 and save the ID.  Trace ID should be MESSAGE_ID_SIZE bytes */
int pcache_trace_request (const char * id)
{
  pcache_init_maint ();
  int index = id_index (id, num_trc, trc_secret);
  if (memcmp (trc_table [index].ida, id, MESSAGE_ID_SIZE) == 0)
    return 1;  /* already there */
  save_trc_hashes = 1;
  memcpy (trc_table [index].ida, id, MESSAGE_ID_SIZE);
  trc_table [index].sent_to_tokens = 0;
  trc_table [index].used = 1;
  trc_table [index].max_hops = 0;   /* not used for traces */
  memset (trc_table [index].pad, 0, sizeof (trc_table [index].pad));
  return 0;
}

/* for replies, we look at the entire packet, without the header */
int pcache_trace_reply (const char * msg, int msize)
{
  pcache_init_maint ();
  char id [MESSAGE_ID_SIZE];
  sha512_bytes (msg, msize, id, sizeof (id));
  return pcache_trace_request (id);
}

/* save cached information to disk */
void pcache_write (void)
{
  if (pcache_init_maint_initialized) {
    write_tokens_file (1);
    write_hash_files (1);
    write_messages_file (1);
  }
}

#ifdef PRINT_CACHE_FILES

static int hash_stats (struct hash_entry * table, int num_entries)
{
  int result = 0;
  int i;
  for (i = 0; i < num_entries; i++)
    if (table [i].used)
      result++;
  return result;
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
          tokens.num_tokens, (int) MAX_TOKENS);
  int count = 0;
  unsigned long long int mbytes = 0;  /* bytes in messages */
  unsigned long long int tbytes = 0;  /* bytes used in storage */
  int max_prio = 0;
  struct message_header * current = NULL;
  while ((current = next_message (current)) != NULL) {
    count++;
    mbytes += current->length;
    tbytes += msg_storage (current->length) + sizeof (struct message_header);
    if (current->priority > max_prio)
      max_prio = current->priority;
  }
  int acount = hash_stats (ack_table, num_ack);
  int tcount = hash_stats (trc_table, num_trc);
  int mcount = hash_stats (mid_table, num_mid);
  printf ("%d messages with %lld/%lld bytes (%zd available), prio <= %x\n",
          count, mbytes, tbytes, msg_table_size, max_prio);
  printf ("%d acks, %d traces, %d message IDs\n", acount, tcount, mcount);
}

static void print_tokens ()
{
  int i;
  for (i = 0; i < MAX_TOKENS; i++) {
    if (! memget (tokens.tokens [i], 0, ALLNET_TOKEN_SIZE)) {
      if (i == 0) printf ("local token  "); else printf ("   token %2d  ", i);
      print_buffer (tokens.tokens [i], ALLNET_TOKEN_SIZE, NULL,
                    ALLNET_TOKEN_SIZE, 1);
    }
  }
}

static void print_hash_entry (const char * name, int index, int verbose,
                              struct hash_entry * table, int num_entries)
{
  struct hash_entry * current = table + index;
  if (verbose || current->used) {  /* print this ack */
    char desc [1000];
    snprintf (desc, sizeof (desc), "%s %d/%d: max %d, u %d, token %" PRIx64,
              name, index, num_entries, current->max_hops,
              current->used, current->sent_to_tokens);
    print_buffer (table [index].ida, MESSAGE_ID_SIZE, desc,
                  MESSAGE_ID_SIZE, 1);
  }
}

static void print_hash_all (const char * name, int index, int verbose,
                            struct hash_entry * table, int num_entries)
{
  if (index < 0) {
    int i;
    for (i = 0; i < num_entries; i++)
      print_hash_entry (name, i, verbose, table, num_entries);
  } else {
    print_hash_entry (name, index, verbose, table, num_entries);
  }
}

static void print_message_ack (int index, int verbose,
                               int msgs, int acks, int trcs)
{
  size_t msg_table_offset = 0;      /* where we are reading msg_table */
  const size_t mh_size = sizeof (struct message_header);
  char * p = (char *) msg_table;
  int count = 0;
  while (1) {
    if (msg_table_size < msg_table_offset + mh_size) {
      if (verbose)
        printf ("at end of table: %zd < %zd + %zd\n",
                msg_table_size, msg_table_offset, mh_size);
      break;  /* done */
    }
    struct message_header * current =
      (struct message_header *) (p + msg_table_offset);
    if (current->length <= 0) { /* sentinel to mark the end of the messages */
      if (verbose) printf ("found zero-length message\n");
      break;
    }
    uint32_t eff_len = msg_storage (current->length);
    size_t hdr_msg_size = mh_size + eff_len;
    if (msg_table_size < msg_table_offset + hdr_msg_size) {
      printf ("incomplete message at end of table: %zd < %zd + %zd\n",
              msg_table_size, msg_table_offset, hdr_msg_size);
      break;   /* no more messages */
    }
    if (((index == count) || (index < 0)) &&
        (verbose || (current->priority != 0))) {  /* print this message */
      char desc [1000];
      snprintf (desc, sizeof (desc),
                "message %d@%zx: id %02x.%02x.%02x.%02x "
                "p %x, token %" PRIx64 "", count, msg_table_offset,
                current->id [0] & 0xff, current->id [1] & 0xff,
                current->id [2] & 0xff, current->id [3] & 0xff,
                current->priority, current->sent_to_tokens);
      int first = 1;
      int x;
      for (x = 0; x < MAX_TOKENS; x++) {
        if ((current->sent_to_tokens & (one64 << x)) != 0) {  /* bit set */
          int c = ((first) ? '=' : ',');
          first = 0;
          int n = strlen (desc);
          snprintf (desc + n, minz (sizeof (desc), n), "%c%d", c, x);
        }
      }
    }
    count++;
    msg_table_offset += hdr_msg_size;
  }
  if (acks)
    print_hash_all ("ack", index, verbose, ack_table, num_ack);
  if (trcs)
    print_hash_all ("trc", index, verbose, trc_table, num_trc);
  if (msgs)
    print_hash_all ("mid", index, verbose, mid_table, num_mid);
}

int main (int argc, char ** argv)
{
  pcache_init_maint ();
  int do_print_messages = 0;
  int do_print_acks = 0;
  int do_print_traces = 0;
  int do_print_tokens = 0;
  if (argc > 1) {
    int i;
    for (i = 1; i < argc; i++) {
      if (strcasecmp (argv [i], "all") == 0) {
        do_print_messages = do_print_acks = 1;
        do_print_traces = do_print_tokens = 1;
      } else if (strcasecmp (argv [i], "msgs") == 0) {
        do_print_messages = 1;
      } else if (strcasecmp (argv [i], "acks") == 0) {
        do_print_acks = 1;
      } else if (strcasecmp (argv [i], "trcs") == 0) {
        do_print_traces = 1;
      } else if (strcasecmp (argv [i], "tkns") == 0) {
        do_print_tokens = 1;
      } else {
        char * endp = NULL;
        int index = (int) strtol (argv [i], &endp, 10);
        if ((index >= 0) && (endp != argv [i]))
          print_message_ack (index, 0, 1, 1, 1);
      }
    }
  }
  if (do_print_messages || do_print_acks || do_print_traces)
    print_message_ack (-1, 0,
                       do_print_messages, do_print_acks, do_print_traces);
  if (do_print_tokens)
    print_tokens ();
  print_stats ("print cache");
  return 0;
}

#endif /* PRINT_CACHE_FILES */
