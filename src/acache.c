/* acache.c: cache all data messages and respond to requests */
/* only one thread, listening on a pipe from ad, and responding
 * acache takes two arguments, the fd of a pipe from AD and of a pipe to AD
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "lib/packet.h"
#include "lib/mgmt.h"
#include "lib/pipemsg.h"
#include "lib/priority.h"
#include "lib/util.h"
#include "lib/app_util.h"
#include "lib/log.h"
#include "lib/config.h"
#include "lib/sha.h"

struct ack_entry {
  char message_id  [MESSAGE_ID_SIZE];
  char message_ack [MESSAGE_ID_SIZE];
};

static struct ack_entry * acks = NULL;
static int ack_space = 0;
static int last_ack = 0;

/* for now, a fixed-size entry, later, allocate dynamically according to size */
/* or, may just delete -- only needed for list_next_matching, used to loop
 * over all the messages, but we could loop over the hash table instead */
#ifdef SMALL_FIXED_SIZE
#define LIST_SIZE	16
#endif /* SMALL_FIXED_SIZE */

#ifdef USING_MESSAGE_LIST
struct list_entry {
  char message_id  [MESSAGE_ID_SIZE];
};
static struct list_entry message_list [LIST_SIZE];
static int message_list_used = 0;
#endif /* USING_MESSAGE_LIST */

struct hash_entry {
  struct hash_entry * next_by_hash;   /* this one also used for fre list */
  struct hash_entry * next_by_source;
  unsigned char id [MESSAGE_ID_SIZE];
  unsigned char received_at [ALLNET_TIME_SIZE];
  int file_position;
  unsigned char src_nbits;           /* limited to not more than 16 */
  unsigned char dst_nbits;           /* limited to not more than 16 */
  unsigned char source [2];
  unsigned char destination [2];
};

#ifdef SMALL_FIXED_SIZE
/* hash table for now is also fixed size -- same comment as for list */
#define HASH_POOL_SIZE	LIST_SIZE
static int hash_pool_size = HASH_POOL_SIZE;
#define HASH_SIZE	(HASH_POOL_SIZE / 4)
static int hash_size = HASH_SIZE;
static int bits_in_hash_table = 4;   /* re-initialized by compute_hash_div */
static struct hash_entry message_hash_pool [HASH_POOL_SIZE];
/* the head of the free list */
static struct hash_entry * message_hash_free = NULL;
/* hash table */
static struct hash_entry * message_hash_table [HASH_SIZE];
/* entries sorted by source address */
static struct hash_entry * message_source_table [HASH_SIZE];

#else /* SMALL_FIXED_SIZE */

static int hash_pool_size = 0;
static int hash_size = 0;
static int bits_in_hash_table = 0;   /* initialized by compute_hash_div */
static struct hash_entry * message_hash_pool;
/* the head of the free list */
static struct hash_entry * message_hash_free = NULL;
/* hash table */
static struct hash_entry * * message_hash_table;
/* entries sorted by source address */
static struct hash_entry * * message_source_table;
#endif /* SMALL_FIXED_SIZE */

static off_t fd_size (int fd)
{
  struct stat st;
  if (fstat (fd, &st) != 0) {
    perror ("fstat");
    return 0;
  }
  off_t fsize = st.st_size;
  if (fsize <= 0)
    return 0;
  return fsize;
}

static int read_at_pos (int fd, char * data, int max, off_t position)
{
  if (lseek (fd, position, SEEK_SET) != position) {
    /* perror ("acache read_at_pos lseek"); */
    snprintf (log_buf, LOG_SIZE,
              "acache unable to lseek to position %d for %d/%d\n",
              (int) position, max, (int) (fd_size (fd)));
    log_error ("acache read_at_pos lseek");
    return 0;
  }
  int r = read (fd, data, max);
  if (r < 0) {
    /* perror ("acache read_at_pos read"); */
    snprintf (log_buf, LOG_SIZE,
              "acache unable to read data at %d: %d %d %d %d\n",
              (int) position, fd, r, max, (int) (fd_size (fd)));
    log_error ("acache read_at_pos read");
    r = 0;
  }
  return r;
}

static void write_at_pos (int fd, char * data, int dsize, off_t position)
{
  if (lseek (fd, position, SEEK_SET) != position) {
    /* perror ("acache write_at_pos lseek"); */
    snprintf (log_buf, LOG_SIZE,
              "acache unable to lseek to pos %d for %d %d\n",
              (int) position, dsize, (int) (fd_size (fd)));
    log_error ("acache write_at_pos lseek");
    return;
  }
  int w = write (fd, data, dsize);
  if (w != dsize) {
    /* perror ("acache write_at_pos write"); */
    snprintf (log_buf, LOG_SIZE,
              "acache unable to save data at %d: %d %d %d\n",
              (int) position, w, dsize, (int) (fd_size (fd)));
    log_error ("acache write_at_pos write");
    return;
  }
}

static void truncate_to_size (int fd, int max_size, char * caller)
{
  if (fd_size (fd) > max_size) {
    if (ftruncate (fd, max_size) != 0)
      perror ("ftruncate");
    snprintf (log_buf, LOG_SIZE, "%s truncated to %d\n", caller, max_size);
    log_print ();
  }
}

static void save_ack_data (int fd)
{
  write_at_pos (fd, (char *) acks, sizeof (struct ack_entry) * ack_space, 0);
  fsync (fd);
}

static void read_ack_data (int fd)
{
  read_at_pos (fd, (char *) acks, sizeof (struct ack_entry) * ack_space, 0);
}

static void init_acks (int fd, int max_acks)
{
  int ack_size = sizeof (struct ack_entry);
  int max_size = ack_size * max_acks;
  /* if file is bigger than max_size, get rid of the last part */
  truncate_to_size (fd, max_size, "init_acks");
  int fsize = fd_size (fd);
  /* allocate the memory to hold the acks */
  ack_space = max_acks;
  acks = malloc_or_fail (max_size, "acache init_acks");
  /* if file is smaller than max_size, the last part should be zeros */
  bzero (acks, max_size);
  read_ack_data (fd);
  struct ack_entry empty;
  bzero (&empty, sizeof (struct ack_entry));
  read_ack_data (fd);
  int i;
  int limit = fsize / sizeof (struct ack_entry);
  for (i = 1; i < limit; i++) {
    if (memcmp (acks [i].message_id, empty.message_id, MESSAGE_ID_SIZE) == 0) {
      last_ack = i - 1;
      break;
    }
  }
}

static int ack_found (char * ack)
{
  int i;
  for (i = 0; i < ack_space; i++) {
    if (memcmp (acks [i].message_ack, ack, MESSAGE_ID_SIZE) == 0) {
      return 1;
    }
  }
  return 0;
}

static void ack_add (char * ack, char * id, int ack_fd)
{
  if (ack_found (ack))
    return;
  last_ack = (last_ack + 1) % ack_space;
  memcpy (acks [last_ack].message_ack, ack, MESSAGE_ID_SIZE);
  memcpy (acks [last_ack].message_id , id , MESSAGE_ID_SIZE);
  /* clear the next location, to mark it in the file */
  int next_ack = (last_ack + 1) % ack_space;
  bzero (&(acks [next_ack]), sizeof (struct ack_entry));
  save_ack_data (ack_fd);
}

/* storage of a message in the file: 12-byte header */
/* never used as a struct since we are not sure the C compiler to pack it
 * into 12 bytes */
#ifdef USE_STRUCT_NOT_OFFSETS
struct message_entry_do_not_use {
  unsigned char size [2];
  unsigned char id_offset [2]; /* how many bytes into the message is the ID */  
  unsigned char rcvd_at [ALLNET_TIME_SIZE];
  char message [0];  /* actually, msize bytes */
};
#endif /* USE_STRUCT_NOT_OFFSETS */

#define MESSAGE_ENTRY_HEADER_MSIZE_OFFSET	0
#define MESSAGE_ENTRY_HEADER_IDOFF_OFFSET	2
#define MESSAGE_ENTRY_HEADER_PRIORITY_OFFSET	4
#define MESSAGE_ENTRY_HEADER_TIME_OFFSET	8

#define MESSAGE_ENTRY_HEADER_SIZE	\
	(MESSAGE_ENTRY_HEADER_TIME_OFFSET + ALLNET_TIME_SIZE)  /* 16 */

#define MAX_MESSAGE_ENTRY_SIZE	(MESSAGE_ENTRY_HEADER_SIZE + ALLNET_MTU)

struct request_details {
  int src_nbits; /* limited to at most 16 */
  unsigned char source [ADDRESS_SIZE];
  int empty;     /* the other details are only filled in if emtpy is zero */
  unsigned char * since;
  int dpower_two;
  int dbits;
  unsigned char * dbitmap;
  int spower_two;
  int sbits;
  unsigned char * sbitmap;
};

/* all the pointers point into message */
static void build_request_details (char * message, int msize, 
                                   struct request_details * result)
{
  struct allnet_header * hp = (struct allnet_header *) message;
  int hsize = ALLNET_SIZE (hp->transport);
  int drsize = ALLNET_TIME_SIZE + 8;
  result->src_nbits = hp->src_nbits;
  if (result->src_nbits > ADDRESS_BITS)
    result->src_nbits = ADDRESS_BITS;
  if (result->src_nbits > 16)
    result->src_nbits = 16;
  if (result->src_nbits < 0)
    result->src_nbits = 0;
  memcpy (result->source, hp->source, ADDRESS_SIZE);
  if (msize < hsize + drsize) {
    result->empty = 1;
  } else {
    result->empty = 0;
    struct allnet_data_request * drp =
      (struct allnet_data_request *) (message + hsize);
    result->since = drp->since;
    char empty_time [ALLNET_TIME_SIZE];
    bzero (empty_time, sizeof (empty_time));
    if (memcmp (empty_time, result->since, sizeof (empty_time)) == 0)
      result->since = NULL;  /* time is zero, so don't use in comparisons */
    result->dpower_two = 0;
    result->dbits = 0;
    result->dbitmap = NULL;
    result->spower_two = 0;
    result->sbits = 0;
    result->sbitmap = NULL;
    int dbits = 0;
    int dbytes = 0;
    int sbits = 0;
    int sbytes = 0;
    if ((drp->dst_bits_power_two > 0) && (drp->dst_bits_power_two < 32)) {
      dbits = 1 << (drp->dst_bits_power_two - 1);
      dbytes = (dbits + 7) / 8;
      if (hsize + drsize + dbytes <= msize) {
        result->dpower_two = drp->dst_bits_power_two;
        result->dbits = dbits;
        result->dbitmap = (unsigned char *) (message + (hsize + drsize));
      }
    }
    if ((drp->src_bits_power_two > 0) && (drp->src_bits_power_two < 32)) {
      sbits = 1 << (drp->src_bits_power_two - 1);
      sbytes = (sbits + 7) / 8;
      if (hsize + drsize + dbytes + sbytes <= msize) {
        result->spower_two = drp->src_bits_power_two;
        result->sbits = sbits;
        result->sbitmap =
          (unsigned char *) (message + (hsize + drsize + dbytes));
      }
    }
  }
}

static uint64_t get_nbits (unsigned char * bits, int nbits)
{
  uint64_t result = 0;
  while (nbits >= 8) {
    result = ((result << 8) | ((*bits) & 0xff));
    nbits = nbits - 8;
    bits++;
  }
  if (nbits > 0)
    result = ((result << nbits) | (((*bits) & 0xff) >> (8 - nbits)));
  return result;
}

/* returns 1 if the address is (or may be) in the bitmap, 0 otherwise */
static int match_bitmap (int power_two, int bitmap_bits, unsigned char * bitmap,
                         unsigned char * address, int abits)
{
  if ((power_two <= 0) || (bitmap_bits <= 0) || (bitmap == NULL))
    return 1;   /* an empty bitmap matches every address */
  if (abits <= 0)
    return 1;   /* empty address matches every bitmap, even one with all 0's */
  uint64_t start_index = get_nbits (address, abits);
  uint64_t end_index = start_index;
  if (abits > power_two) {
    start_index = (start_index >> (abits - power_two));
  } else if (abits < power_two) {
    /* make end_index have all 1s in the last (power_two - abits) bits */
    end_index = ((start_index + 1) << (power_two - abits)) - 1;
    start_index = (start_index << (power_two - abits));
  }
  if ((start_index > end_index) ||
      (start_index > bitmap_bits) || (end_index > bitmap_bits)) {
    snprintf (log_buf, LOG_SIZE,
              "match_bitmap error: index %" PRIu64 "-%" PRIu64 ", %d bits\n",
              start_index, end_index, bitmap_bits);
    printf ("%s", log_buf);
    log_print ();
    return 1;
  }
  while (start_index <= end_index) {
    int byte = bitmap [start_index / 8] & 0xff;
    int i;
    for (i = start_index % 8;
         (i < 8) && (i < (end_index - (start_index / 8) * 8)); i++)
      if (((i == 7) && (( byte                   & 0x1) == 0x1)) ||
          ((i <  7) && (((byte >> (8 - (i + 1))) & 0x1) == 0x1)))
        return 1;
    start_index = (start_index - (start_index % 8)) + 8;
  }
  return 0;  /* did not match any bit in the bitmap */
}

static int packet_matches (struct request_details * req,
                           char * message, int msize, char * rcvd_time)
{
  struct allnet_header * hp = (struct allnet_header *) message;
  if (req->empty) {
    if (matches (req->source, req->src_nbits, hp->destination, hp->dst_nbits))
      return 1;
    return 0;
  }
  /* anything not matching leads to the packet being excluded */
  if (req->since != NULL) {
    uint64_t since = readb64u (req->since);
    uint64_t rcvd_at = readb64 (rcvd_time);
    if (since > rcvd_at)
      return 0;
  }
  if ((req->dbits > 0) && (req->dbitmap != NULL) &&
      (! match_bitmap (req->dpower_two, req->dbits, req->dbitmap,
                       hp->destination, hp->dst_nbits)))
    return 0;
  if ((req->sbits > 0) && (req->sbitmap != NULL) &&
      (! match_bitmap (req->spower_two, req->sbits, req->sbitmap,
                       hp->source, hp->src_nbits)))
    return 0;
  return 1;
}

static int hash_matches (struct request_details * req,
                         struct hash_entry * entry)
{
  if (req->empty) {
    if (matches (req->source, req->src_nbits,
                 entry->destination, entry->dst_nbits))
      return 1;
    return 0;
  }
  /* anything not matching leads to the packet being excluded */
  if (req->since != NULL) {
    uint64_t since = readb64u (req->since);
    uint64_t rcvd_at = readb64u (entry->received_at);
    if (since > rcvd_at)
      return 0;
  }
  if ((req->dbits > 0) && (req->dbitmap != NULL) &&
      (! match_bitmap (req->dpower_two, req->dbits, req->dbitmap,
                       entry->destination, entry->dst_nbits)))
    return 0;
  if ((req->sbits > 0) && (req->sbitmap != NULL) &&
      (! match_bitmap (req->spower_two, req->sbits, req->sbitmap,
                       entry->source, entry->src_nbits)))
    return 0;
  return 1;
}

/* see get_next_message */
static int next_prev_position (int next_position, int msize)
{
  return next_position - (MESSAGE_ENTRY_HEADER_SIZE + msize);
}

/* note that the return value is the position of the NEXT message, if any.
 * the position of this message is given by next_prev_position */
static int get_next_message (int fd, int max_size, int position,
                             struct request_details *rd,
                             char ** message, int * msize, int * id_off,
                             int * priority, char * received_time)
{
  if (position < 0)
    return -1;
  while (position < max_size) {
    static char buffer [MAX_MESSAGE_ENTRY_SIZE];
    int rsize = MAX_MESSAGE_ENTRY_SIZE;
    if (rsize > (max_size - position))
      rsize = max_size - position;
    int r = read_at_pos (fd, buffer, rsize, position);
    if (r <= 0) { /* unable to read */
#ifdef DEBUG_PRINT
      snprintf (log_buf, LOG_SIZE, "get_next_message r %d\n", r); log_print ();
#endif /* DEBUG_PRINT */
      return -1;
    }
    int found_size = readb16 (buffer + MESSAGE_ENTRY_HEADER_MSIZE_OFFSET);
    if ((found_size <= 0) || (found_size > ALLNET_MTU)) { /* unknown size */
#ifdef DEBUG_PRINT
      snprintf (log_buf, LOG_SIZE,
                "get_next_message found %d at %d (%d/%zd)\n",
                found_size, position, r, fd_size (fd));
      log_print ();
      buffer_to_string (buffer, r, "data", 16, 0, log_buf, LOG_SIZE);
      log_print ();
#endif /* DEBUG_PRINT */
      return -1;
    }
    position += (MESSAGE_ENTRY_HEADER_SIZE + found_size);
    int found_id_off = readb16 (buffer + MESSAGE_ENTRY_HEADER_IDOFF_OFFSET);
    char * found_time = buffer + MESSAGE_ENTRY_HEADER_TIME_OFFSET;
    char * found_message = buffer + MESSAGE_ENTRY_HEADER_SIZE;
    if ((found_id_off != 0) &&  /* not deleted */
        ((rd == NULL) ||    /* either accept all, or matches request */
         (packet_matches (rd, found_message, found_size, found_time)))) {
      if (message != NULL) *message = found_message;
      if (msize != NULL) *msize = found_size;
      if (id_off != NULL) *id_off = found_id_off;
      if (priority != NULL) *priority =
        readb32 (buffer + MESSAGE_ENTRY_HEADER_PRIORITY_OFFSET);
      if (received_time != NULL)
        memcpy (received_time, found_time, ALLNET_TIME_SIZE);
#ifdef DEBUG_PRINT
      snprintf (log_buf, LOG_SIZE, "get_next_message: %d %d ok\n",
                found_size, position);
      log_print ();
#endif /* DEBUG_PRINT */
      return position;
    }
#ifdef DEBUG_PRINT
    snprintf (log_buf, LOG_SIZE,
              "get_next_message found %d id_off %d p %d %d\n", found_size,
              found_id_off, position - (MESSAGE_ENTRY_HEADER_SIZE + found_size),
              position);
    log_print ();
#endif /* DEBUG_PRINT */
  }
  return -1;  /* reached the end */
}

#ifdef USING_MESSAGE_LIST
static void list_add_message (char * id)
{
  int i;
  int max_index = message_list_used;
  if (max_index >= LIST_SIZE)
    max_index = LIST_SIZE - 1;
  else
    message_list_used = max_index + 1;
  for (i = max_index; i > 0; i--)
    message_list [i] = message_list [i - 1];
  memcpy (message_list [0].message_id, id, MESSAGE_ID_SIZE);
}

static void list_remove_message (char * id)
{
  int from;
  int to = 0;
  int loop_to = message_list_used;
  for (from = 0; from < loop_to; from++) {
    if (memcmp (message_list [from].message_id, id, MESSAGE_ID_SIZE) == 0) {
      message_list_used--;  /* remove by not incrementing "to" */
    } else {
      if (from > to)        /* no need to copy if they are the same */
        message_list [to] = message_list [from];
      to++;
    }
  }
  if (from == to) {
    buffer_to_string (id, MESSAGE_ID_SIZE, "id not found, unable to delete from list", 16, 0, log_buf, LOG_SIZE);
    log_print ();
  }
}
#endif /* USING_MESSAGE_LIST */

/* assume 32-bit ints */
static int round_up (int n)
{
  int i;
  for (i = 0; i < 32; i++)
    if ((1 << i) >= n)
      return (1 << i);
  return 0x80000000;
}

/* later, take as parameters the size and dynamically allocate the message
 * list, the hash pool, and the hash table */
static void init_hash_table (int max_msg_size)
{
#ifdef SMALL_FIXED_SIZE
#else /* SMALL_FIXED_SIZE */
  hash_pool_size = round_up ((max_msg_size / sizeof (struct hash_entry)) / 10);
  if (hash_pool_size < 16)
    hash_pool_size = 16;
  hash_size = hash_pool_size / 4;
  message_hash_pool =
    malloc_or_fail (sizeof (struct hash_entry) * hash_pool_size,
                    "init_hash_table entries pool");
  message_hash_table =
    malloc_or_fail (sizeof (struct hash_entry *) * hash_size,
                    "init_hash_table hash table");
  message_source_table =
    malloc_or_fail (sizeof (struct hash_entry *) * hash_size,
                    "init_hash_table source table");
#endif /* SMALL_FIXED_SIZE */
  message_hash_pool [0].next_by_hash = NULL;
  int i;
  for (i = 1; i < hash_pool_size; i++) {
    message_hash_pool [i].next_by_hash = message_hash_pool + (i - 1);
    message_hash_free = message_hash_pool + i;
  }
  for (i = 0; i < hash_size; i++) {
    message_hash_table [i] = NULL;
    message_source_table [i] = NULL;
  }
}

static int count_list (struct hash_entry * entry, int index)
{
  int result = 0;
#ifdef DEBUG_PRINT
  int off = 0;
  if (index != -1)
    off = snprintf (log_buf, LOG_SIZE, "%d: ", index);
#endif /* DEBUG_PRINT */
  while (entry != NULL) {
#ifdef DEBUG_PRINT
    if (index != -1) {
      off += buffer_to_string ((char *) (entry->id), MESSAGE_ID_SIZE, " ",
                               16, 0, log_buf + off, LOG_SIZE - off);
      off += snprintf (log_buf + off, LOG_SIZE - off, " @ %d, ",
                       entry->file_position);
    }
#endif /* DEBUG_PRINT */
    result++;
    entry = entry->next_by_hash;
  }
#ifdef DEBUG_PRINT
  if (index != -1)
  log_print ();
#endif /* DEBUG_PRINT */
  return result;
}

static void print_stats (int exit_if_none_free, int must_match)
{
  int hcount = 0;
  int i;
  for (i = 0; i < hash_size; i++)
    hcount += count_list (message_hash_table [i], i);
#ifdef USING_MESSAGE_LIST
  int mcount = message_list_used;
#endif /* USING_MESSAGE_LIST */
  int fcount = count_list (message_hash_free, -1);
  int off = strlen (log_buf);
#ifdef USING_MESSAGE_LIST
  if (hcount == mcount)
    snprintf (log_buf + off, LOG_SIZE - off, "%d in hash/list, %d free\n",
              hcount, fcount);
  else
    snprintf (log_buf + off, LOG_SIZE - off,
              "%d in hash, %d in message list, %d free\n",
              hcount, mcount, fcount);
#else /* USING_MESSAGE_LIST */
    snprintf (log_buf + off, LOG_SIZE - off, "%d in hash, %d free\n",
              hcount, fcount);
#endif /* USING_MESSAGE_LIST */
  log_print ();
  if (exit_if_none_free && (fcount == 0))
    exit (1);
#ifdef USING_MESSAGE_LIST
  if ((must_match >= 0) && ((must_match != mcount) || (must_match != hcount))) {
    snprintf (log_buf, LOG_SIZE,
              "%d in hash, %d in message list, %d free, should have %d\n",
              hcount, mcount, fcount, must_match);
    log_print ();
    exit (1);
  }
#else /* USING_MESSAGE_LIST */
  if ((must_match >= 0) && (must_match != hcount)) {
    snprintf (log_buf, LOG_SIZE, "%d in hash, %d free, should have %d\n",
              hcount, fcount, must_match);
    log_print ();
    exit (1);
  }
#endif /* USING_MESSAGE_LIST */
}

static uint32_t compute_hash_div ()
{
  bits_in_hash_table = 1;   /* re-initialize the global bits_in_hash_table */
  while ((1 << bits_in_hash_table) < hash_size)
    bits_in_hash_table++;
  return (1 << (32 - bits_in_hash_table));
}

static uint32_t hash_index (char * id)
{
  static uint32_t hash_div = 0;
  if (hash_div == 0) { /* initialize */
    hash_div = compute_hash_div ();
#ifdef DEBUG_PRINT
    printf ("hash_div is %d, hash_size %d, hash_pool_size %d, %d bits\n",
            hash_div, hash_size, hash_pool_size, bits_in_hash_table);
#endif /* DEBUG_PRINT */
  }
  return (readb32 (id) / hash_div);
}

static int hash_has_space ()
{
  return (message_hash_free != NULL);
}

static void hash_add_message (char * message, int msize, char * id,
                              int position, char * time)
{
  /* allocate an entry from the pool */
  if (message_hash_free == NULL) {
    /* caller should have made sure we have at least one entry available */
    printf ("error in hash_add_message: no free entries\n");
    snprintf (log_buf, LOG_SIZE,
              "error in hash_add_message: no free entries\n");
    log_print ();
    exit (1);
  }
  struct allnet_header * hp = (struct allnet_header *) message;
  if (msize < ALLNET_SIZE (hp->transport))  /* invalid header */
    return;
  struct hash_entry * entry = message_hash_free;
  message_hash_free = entry->next_by_hash;
  /* initialize the entry */
  bzero (entry, sizeof (struct hash_entry));
  memcpy (entry->id, id, MESSAGE_ID_SIZE);
  entry->file_position = position;
  entry->src_nbits = hp->src_nbits;
  if (entry->src_nbits > 16) entry->src_nbits = 16;
  entry->dst_nbits = hp->dst_nbits;
  if (entry->dst_nbits > 16) entry->dst_nbits = 16;
  memcpy (entry->source,      hp->source,      (hp->src_nbits + 7) / 8);
  memcpy (entry->destination, hp->destination, (hp->dst_nbits + 7) / 8);
  memcpy (entry->received_at, time, ALLNET_TIME_SIZE);
  /* add the entry to the chain in the hash table */
  int h_index = hash_index (id);
  entry->next_by_hash = message_hash_table [h_index];
  message_hash_table [h_index] = entry;
  /* add the entry to the chain in the source table */
  int s_index = hash_index ((char *) (entry->source));
  entry->next_by_source = message_source_table [s_index];
  message_source_table [s_index] = entry;
}

static void update_hash_position (char * id, int position)
{
  int index = hash_index (id);
  struct hash_entry * entry = message_hash_table [index];
  while (entry != NULL) {
    if (memcmp (entry->id, id, MESSAGE_ID_SIZE) == 0)  /* found */
      entry->file_position = position;
    entry = entry->next_by_hash;
  }
}

static void remove_hash_entry (struct hash_entry * entry, int index)
{
  if (entry == NULL)
    return;
  if (entry == message_hash_table [index]) {
    message_hash_table [index] = entry->next_by_hash;
    return;
  }
  struct hash_entry * prev = message_hash_table [index];
  struct hash_entry * current = prev->next_by_hash;
  while (current != NULL) {
    if (current == entry) 
      prev->next_by_hash = current->next_by_hash;
    else
      prev = current;
    current = prev->next_by_hash;
  }
}

static void remove_source_entry (struct hash_entry * entry, int index)
{
  if (entry == NULL)
    return;
  if (entry == message_source_table [index]) {
    message_source_table [index] = entry->next_by_source;
    return;
  }
  struct hash_entry * prev = message_source_table [index];
  struct hash_entry * current = prev->next_by_source;
  while (current != NULL) {
    if (current == entry) 
      prev->next_by_source = current->next_by_source;
    else
      prev = current;
    current = prev->next_by_source;
  }
}

static struct hash_entry * hash_find (char * hash)
{
  int h_index = hash_index (hash);
  struct hash_entry * entry = message_hash_table [h_index];
  while (entry != NULL) {
    if (memcmp (hash, entry->id, MESSAGE_ID_SIZE) == 0)
      return entry;
    entry = entry->next_by_hash;
  }
  return NULL;
}

static void remove_from_hash_table (char * id)
{
  struct hash_entry * entry = hash_find (id);
  if (entry != NULL) {
    /* delete from hash table chain */
    remove_hash_entry (entry, hash_index (id));
    /* and delete from the source chain */
    remove_source_entry (entry, hash_index ((char *) (entry->source)));
    /* add back to free list */
    entry->next_by_hash = message_hash_free;
    message_hash_free = entry;
  } else {
    buffer_to_string (id, MESSAGE_ID_SIZE,
                      "id not found, unable to delete from list",
                      16, 0, log_buf, LOG_SIZE);
    log_print ();
  }
}

static int assign_matching (struct hash_entry * matching, int fd,
                            char ** message, int * msize, int * id_off,
                            int * priority, char * time)
{
  if (matching != NULL) {
    static char data [MAX_MESSAGE_ENTRY_SIZE];
    int r = read_at_pos (fd, data, sizeof (data), matching->file_position);
    if (r <= MESSAGE_ENTRY_HEADER_SIZE)
      return -1;
    int found_msize = readb16 (data + MESSAGE_ENTRY_HEADER_MSIZE_OFFSET);
    int found_id_off = readb16 (data + MESSAGE_ENTRY_HEADER_IDOFF_OFFSET);
    if (message != NULL) *message = data + MESSAGE_ENTRY_HEADER_SIZE;
    if (msize != NULL) *msize = found_msize;
    if (id_off != NULL) *id_off = found_id_off;
    if (priority != NULL) *priority =
      readb32 (data + MESSAGE_ENTRY_HEADER_PRIORITY_OFFSET);
    if (time != NULL)
      memcpy (time, data + MESSAGE_ENTRY_HEADER_TIME_OFFSET, ALLNET_TIME_SIZE);
    return matching->file_position + found_msize + MESSAGE_ENTRY_HEADER_SIZE;
  }
  return -1;
}

static int hash_get_next (int fd, int max, int pos, char * hash,
                          char ** message, int * msize, int * id_off,
                          int * priority, char * time)
{
  if (pos < 0)
    return -1;
  int h_index = hash_index (hash);
  int least_not_less_than = -1;
  struct hash_entry * entry = message_hash_table [h_index];
  struct hash_entry * matching = NULL;
  while (entry != NULL) {
    if ((entry->file_position >= pos) &&
        ((least_not_less_than == -1) ||
         (least_not_less_than > entry->file_position)) &&
        (memcmp (hash, entry->id, MESSAGE_ID_SIZE) == 0)) {
      matching = entry;
      least_not_less_than = entry->file_position;
    }
    entry = entry->next_by_hash;
  }
  return assign_matching (matching, fd, message, msize, id_off, priority, time);
}

static int source_get_next (int fd, int max, int pos, unsigned char * source,
                            char ** message, int * msize, int * id_off,
                            int * priority, char * time)
{
  if (pos < 0)
    return -1;
  int s_index = hash_index ((char *) source);
  int least_not_less_than = -1;
  struct hash_entry * entry = message_source_table [s_index];
  struct hash_entry * matching = NULL;
  while (entry != NULL) {
    if ((entry->file_position >= pos) &&
        ((least_not_less_than == -1) ||
         (least_not_less_than > entry->file_position))) {
      matching = entry;
      least_not_less_than = entry->file_position;
    }
    entry = entry->next_by_source;
  }
  return assign_matching (matching, fd, message, msize, id_off, priority, time);
}

static int64_t list_next_matching (int fd, int max_size, int64_t position,
                                   struct request_details * rd, char ** message,
                                   int * msize)
{
  if (position < 0)
    return -1;
  if ((rd == NULL) ||
      ((rd->empty) && (rd->src_nbits < bits_in_hash_table)))
    return get_next_message (fd, max_size, (int) position, NULL,
                             message, msize, NULL, NULL, NULL);
  if (rd->empty)
    return source_get_next (fd, max_size, (int) position, rd->source,
                            message, msize, NULL, NULL, NULL);
  int64_t index = position >> 32;
  int64_t count = position & 0xffffffff;
  int64_t use_count = count;
  struct hash_entry * entry = message_hash_table [index];
  for ( ; index < hash_size; index++) {
    while ((entry != NULL) && (count > 0)) {
      entry = entry->next_by_hash;
      count--;
    }
    while ((entry != NULL) && (! (hash_matches (rd, entry)))) {
      entry = entry->next_by_hash;
      use_count++;   /* skip over this one when looking next time */
    }
    if (entry != NULL) {  /* hash must match */
      assign_matching (entry, fd, message, msize, NULL, NULL, NULL);
      /* return same index, use_count + 1 */
      return (index << 32) | (use_count + 1);
    }
    /* not found at this hash index, continue with the next */
    use_count = 0;
    count = 0;
  }
  return -1;  /* nothing found */
}

#if 0
static int list_next_matching (int fd, int max_size, int position,
                               struct request_details * rd, char ** message,
                               int * msize)
{
  if (position < 0)
    return -1;
  if ((rd == NULL) ||
      ((rd->empty) && (rd->src_nbits < bits_in_hash_table)))
    return get_next_message (fd, max_size, position, NULL,
                             message, msize, NULL, NULL, NULL);
  if (rd->empty)
    return source_get_next (fd, max_size, position, rd->source,
                            message, msize, NULL, NULL, NULL);
  int index;
  for (index = position; index < message_list_used; index++) {
    struct hash_entry * entry = hash_find (message_list [index].message_id);
    if ((entry != NULL) && (hash_matches (rd, entry))) {
      int m = assign_matching (entry, fd, message, msize, NULL, NULL, NULL);
      if (m > 0)
        return index + 1;
    }
  }
  return -1;  /* nothing found */
}
#endif /* 0 */

/* returns 1 if this message is ready to be deleted, 0 otherwise */
static int delete_gc_message (char * message, int msize,
                              int id_off, int priority, char * time,
                              int end_pos, int file_max)
{
  if ((msize <= ALLNET_HEADER_SIZE + MESSAGE_ID_SIZE) || (msize > ALLNET_MTU) ||
      (id_off < ALLNET_HEADER_SIZE) || (id_off + MESSAGE_ID_SIZE > msize))
    return 1;  /* bad message, no need to keep */
  int file_pos = next_prev_position (end_pos, msize);
  struct allnet_header * hp = (struct allnet_header *) message;
  /* we should delete something, so at least the first 6% of the file */
  int min_delete = (file_max / 16);
#ifdef DEBUG_PRINT
  int off = buffer_to_string (message + id_off, MESSAGE_ID_SIZE, "id",
                              MESSAGE_ID_SIZE, 0, log_buf, LOG_SIZE);
  off += snprintf (log_buf + off, LOG_SIZE - off, ", pos %d/%d, transport %x",
                   file_pos, min_delete, hp->transport);
#endif /* DEBUG_PRINT */
  if (file_pos <= min_delete)
    return 1;
  /* earlier messages with lower priority should be deleted first */
  /* compare the priority to the fraction of the file (fof)
   * if the priority is less, go ahead and delete */
  /* for example, priority 3/4 should only be deleted if fof < 1/4 */
  /* for example, priority 1/5 should be deleted unless fof >= 4/5 */
  int fraction_of_file = allnet_divide (file_pos, file_max);
#ifdef DEBUG_PRINT
  off += snprintf (log_buf + off, LOG_SIZE - off,
                   ", %x<>%x (%d)", fraction_of_file,
                   ALLNET_PRIORITY_MAX - priority, priority);
#endif /* DEBUG_PRINT */
  if (fraction_of_file < ALLNET_PRIORITY_MAX - priority)
    return 1;
  /* delete expired messages */
  if ((hp->transport) & ALLNET_TRANSPORT_EXPIRATION) {
    char * exp = ALLNET_EXPIRATION (hp, hp->transport, msize);
    if (exp != NULL) {
      uint64_t exp_time = readb64 (exp);
      if (exp_time < allnet_time ()) {
#ifdef DEBUG_PRINT
        off += snprintf (log_buf + off, LOG_SIZE - off, ", expired");
#endif /* DEBUG_PRINT */
        return 1;
      }
    }
  }
  return 0;
}

static void gc (int fd, int max_size)
{
  int gc_size = max_size;
  if (gc_size > fd_size (fd))
    gc_size = fd_size (fd);
  int copied = 0, deleted = 0;
  int read_position = 0;
  int write_position = 0;
  char * message;
  int msize;
  int id_off;
  int priority;
  char time [ALLNET_TIME_SIZE];
  while ((read_position =
            get_next_message (fd, max_size, read_position, NULL, &message,
                              &msize, &id_off, &priority, time)) > 0) {
    int delete = delete_gc_message (message, msize, id_off, priority, time,
                                    read_position, gc_size);
#ifdef DEBUG_PRINT
    snprintf (log_buf + strlen (log_buf), LOG_SIZE - strlen (log_buf),
              "  ==> delete %d\n", delete);
    log_print ();
#endif /* DEBUG_PRINT */
    if (! delete) {
      char buffer [MAX_MESSAGE_ENTRY_SIZE];
      writeb16 (buffer + MESSAGE_ENTRY_HEADER_MSIZE_OFFSET, msize);
      writeb16 (buffer + MESSAGE_ENTRY_HEADER_IDOFF_OFFSET, id_off);
      writeb32 (buffer + MESSAGE_ENTRY_HEADER_PRIORITY_OFFSET, priority);
      memcpy (buffer + MESSAGE_ENTRY_HEADER_TIME_OFFSET, time,
              ALLNET_TIME_SIZE);
      memcpy (buffer + MESSAGE_ENTRY_HEADER_SIZE, message, msize);
      int write_size = MESSAGE_ENTRY_HEADER_SIZE + msize;
      write_at_pos (fd, buffer, write_size, write_position);
      update_hash_position (message + id_off, write_position);
      write_position += write_size;
      copied++;
    } else {
      remove_from_hash_table (message + id_off);
#ifdef USING_MESSAGE_LIST
      list_remove_message (message + id_off);
#endif /* USING_MESSAGE_LIST */
      deleted++;
    }
  }
  truncate_to_size (fd, write_position, "gc");
  fsync (fd);
  snprintf (log_buf, LOG_SIZE, "%d copied, %d deleted, ", copied, deleted);
#ifdef DEBUG_PRINT
#endif /* DEBUG_PRINT */
  print_stats (1, copied);
}

static void cache_message (int fd, int max_size,
                           int id_off, char * message, int msize, int priority)
{
  if (id_off + MESSAGE_ID_SIZE > msize)
    return;
  char mbuffer [MAX_MESSAGE_ENTRY_SIZE];
  int fsize = MESSAGE_ENTRY_HEADER_SIZE + msize;
  if ((fsize > max_size) || (fsize > MAX_MESSAGE_ENTRY_SIZE) || (fsize < 0)) {
    snprintf (log_buf, LOG_SIZE,
              "unable to save message of size %d/%d, max %d/%d\n",
              msize, fsize, max_size, MAX_MESSAGE_ENTRY_SIZE);
    log_print ();
    return;
  }
  writeb16 (mbuffer + MESSAGE_ENTRY_HEADER_MSIZE_OFFSET, msize);
  writeb16 (mbuffer + MESSAGE_ENTRY_HEADER_IDOFF_OFFSET, id_off);
  writeb32 (mbuffer + MESSAGE_ENTRY_HEADER_PRIORITY_OFFSET, priority);
  long long int now = allnet_time ();
  writeb64 (mbuffer + MESSAGE_ENTRY_HEADER_TIME_OFFSET, now);
  memcpy (mbuffer + MESSAGE_ENTRY_HEADER_SIZE, message, msize);
  int count = 0;
  while (! hash_has_space ()) { /* delete some entries in the hash table */
    snprintf (log_buf, LOG_SIZE, "gc'ing to make space for hash: %d\n",
              ++count);
    log_print ();
    if (count > 10)
      exit (1);
    gc (fd, max_size);
  }
  off_t write_position = fd_size (fd);
  write_at_pos (fd, mbuffer, fsize, write_position);
  fsync (fd);
  hash_add_message (message, msize, message + id_off, write_position,
                    mbuffer + MESSAGE_ENTRY_HEADER_TIME_OFFSET);
#ifdef USING_MESSAGE_LIST
  list_add_message (message + id_off);
#endif /* USING_MESSAGE_LIST */
snprintf (log_buf, LOG_SIZE, "saved message at position %d, hash index %d, ", (int) write_position, hash_index (message + id_off)); log_print (); print_stats (0, -1);
  count = 0;
  while (fd_size (fd) > max_size) {
    snprintf (log_buf, LOG_SIZE, "gc'ing to reduce space from %d to %d: %d\n",
              (int) (fd_size (fd)), max_size, ++count);
    log_print ();
    gc (fd, max_size);
  }
}

static void remove_cached_message (int fd, int max_size, char * id,
                                   int position, int msize)
{
  static char buffer [MAX_MESSAGE_ENTRY_SIZE];
  int fsize = MESSAGE_ENTRY_HEADER_SIZE + msize;
  if (fsize > MAX_MESSAGE_ENTRY_SIZE) {
    snprintf (log_buf, LOG_SIZE,
              "remove_cached_message error: size %d, max %d\n",
              fsize, MAX_MESSAGE_ENTRY_SIZE);
    log_print ();
    return;   /* invalid call */
  }
  /* read the entry, make sure the size matches */
  int next = get_next_message (fd, max_size, position, NULL,
                               NULL, NULL, NULL, NULL, NULL);
  if ((next != 0) && (next - position != fsize)) {
    snprintf (log_buf, LOG_SIZE,
              "warning in acache: next %d - pos %d != fsize %d (%d)\n",
              next, position, fsize, (int) (fd_size (fd)));
    log_print ();
    buffer_to_string (id, MESSAGE_ID_SIZE, "id", MESSAGE_ID_SIZE, 1,
                      log_buf, LOG_SIZE);
    log_print ();
    print_stats (0, -1);
  }
  buffer_to_string (id, MESSAGE_ID_SIZE, "removing cached", MESSAGE_ID_SIZE, 1,
                    log_buf, LOG_SIZE);
  log_print ();
  /* mark it as erased, but keep the size, so we can later skip */
  bzero (buffer, fsize);
  writeb16 (buffer + MESSAGE_ENTRY_HEADER_MSIZE_OFFSET, msize);
  write_at_pos (fd, buffer, fsize, position);
  fsync (fd);
  remove_from_hash_table (id);
#ifdef USING_MESSAGE_LIST
  list_remove_message (id);
#endif /* USING_MESSAGE_LIST */
}

/* if the header includes an id, returns a pointer to the ID field of hp */
static char * get_id (char * message, int size)
{
  struct allnet_header * hp = (struct allnet_header *) message;
  char * id = ALLNET_PACKET_ID (hp, hp->transport, size);
  if (id == NULL)
    id = ALLNET_MESSAGE_ID (hp, hp->transport, size);
  /* key messages usually don't have IDs, so use hmac or fingerprints */
  if ((id == NULL) && (size >= ALLNET_SIZE (hp->transport) + 1)) {
    int nbytes = message [ALLNET_SIZE (hp->transport) + 1] & 0xff;
    if ((size >= ALLNET_SIZE (hp->transport) + 1 + nbytes) &&
        (nbytes >= MESSAGE_ID_SIZE)) {
      if ((hp->message_type == ALLNET_TYPE_KEY_XCHG) ||
          (hp->message_type == ALLNET_TYPE_KEY_REQ))
        id = message + ALLNET_SIZE (hp->transport) + 1;
    }
  }
  return id;  /* a pointer (if any) into hp */ 
}

/* returns 1 if successful, 0 otherwise */
static int save_packet (int fd, int max_size, char * message, int msize,
                        int priority)
{
#ifdef DEBUG_PRINT
  snprintf (log_buf, LOG_SIZE, "save_packet: size %d\n", msize);
  log_print ();
#endif /* DEBUG_PRINT */
  char * id = get_id (message, msize);
  if (id == NULL)   /* no sort of message or packet ID found */
    return 0;
#ifdef DEBUG_PRINT
  buffer_to_string (id, MESSAGE_ID_SIZE, "id", MESSAGE_ID_SIZE, 1,
                    log_buf, LOG_SIZE);
  log_print ();
#endif /* DEBUG_PRINT */
  if (hash_find (id) != NULL) {
    buffer_to_string (id, MESSAGE_ID_SIZE, "save_packet: found",
                      MESSAGE_ID_SIZE, 1, log_buf, LOG_SIZE);
    log_print ();
#ifdef DEBUG_PRINT
#endif /* DEBUG_PRINT */
    return 0;
  }
  cache_message (fd, max_size, id - message, message, msize, priority);
  return 0;
}

/* to limit resource consumption, only respond to requests that are
 * local, or to at most 5 requests per second */
static unsigned long long int limit_resources (int local_request) 
{
  static unsigned long long int last_response = 0;
  unsigned long long int start = allnet_time_ms ();
  if (local_request)
    return start + 1000;   /* up to 1s for local requests */
  if ((last_response != 0) && (start <= last_response + 200))
    return 0;              /* too many requests */

  return start + 10;       /* allow 10ms */
}

static void resend_message (char * message, int msize, int64_t position,
                            int *priorityp, int local_request, int sock)
{
  int priority = *priorityp;
  snprintf (log_buf, LOG_SIZE,
            "sending %d-byte cached response at [%" PRId64 "]\n",
            msize, position);
  log_print ();
  struct allnet_header * send_hp = (struct allnet_header *) message;
  int saved_max = send_hp->max_hops;
  if (local_request)  /* only forward locally */
    send_hp->max_hops = send_hp->hops;
  /* send, no need to even check the return value of send_pipe_message */
  send_pipe_message (sock, message, msize, priority);
  if (local_request)  /* restore the packet as it was */
    send_hp->max_hops = saved_max;
  if (priority > ALLNET_PRIORITY_EPSILON)
    *priorityp = priority - 1;
}

/* returns the number of responses sent, or 0 */
static int respond_to_request (int fd, int max_size, char * in_message,
                               int in_msize, int sock)
{
  int local_request = 0;
  struct allnet_header * hp = (struct allnet_header *) (in_message);
  if (hp->hops == 0)   /* local request, do not forward elsewhere */
    local_request = 1;
  
  unsigned long long int limit = limit_resources (local_request);
  if (limit == 0)
    return 0;

  struct request_details rd;
  build_request_details (in_message, in_msize, &rd);
  int count = 0;
  int64_t position = 0;
  char * message;
  int msize = 0;
  int priority = ALLNET_PRIORITY_CACHE_RESPONSE;
  /* limit responses to 10ms.  There is probably a better way to do this */
  while ((local_request || (allnet_time_ms () < limit)) &&
         ((position = list_next_matching (fd, max_size, position, &rd,
                                          &message, &msize)) > 0)) {
    resend_message (message, msize, position, &priority, local_request, sock);
    count++;
  }
  snprintf (log_buf, LOG_SIZE, "respond_to_request: sent %d\n", count);
  log_print ();
  return count;
}

/* returns the number of responses sent, or 0 */
/* if any of the ids in the request are not found, also sends onwards
 * the message (unless it was sent locally and with max_hops > 0), with
 * only those ids that were not found */
static int respond_to_id_request (int fd, int max_size, char * in_message,
                                  int in_msize, int sock)
{
  struct allnet_header * in_hp = (struct allnet_header *) (in_message);
  struct allnet_mgmt_header * amhp = (struct allnet_mgmt_header *)
    (ALLNET_DATA_START (in_hp, in_hp->transport, in_msize));
  if (amhp->mgmt_type != ALLNET_MGMT_ID_REQUEST)
    return 0;
  struct allnet_mgmt_id_request * amirp = (struct allnet_mgmt_id_request *)
    (in_message + ALLNET_MGMT_HEADER_SIZE(in_hp->transport));
  int n = readb16u (amirp->n);
  if (n <= 0)
    return 0;

  int local_request = 0;
  int sent_locally = 0;
  if (in_hp->hops == 0) {  /* local request, do not forward elsewhere */
    local_request = 1;
    sent_locally = (in_hp->max_hops == 0);
  }
  unsigned long long int limit = limit_resources (local_request);
  if (limit == 0)
    return 0;

  int forward_missing = (! local_request) || sent_locally;
  int nmissing = 0;
  int nsent = 0;
  int priority = ALLNET_PRIORITY_CACHE_RESPONSE;

  int i;
  for (i = 0; i < n; i++) {
    char *id = (char *) (amirp->ids + i * MESSAGE_ID_SIZE);
    char * message;
    int msize = 0;
    int position = 0;
    if ((! local_request) && (allnet_time_ms () < limit) &&
        ((position = hash_get_next (fd, max_size, 0, id, &message, &msize,
                                    NULL, NULL, NULL)) >= 0)) {
      resend_message (message, msize, position, &priority, local_request, sock);
      nsent++;
    } else if (forward_missing) {
      /* copy the id to the left, so we can send it as a shorter packet */
      memcpy (amirp->ids + nmissing * MESSAGE_ID_SIZE, id, MESSAGE_ID_SIZE);
      nmissing++;
    }
  }
  if ((nmissing > 0) && forward_missing) {
    writeb16u (amirp->n, nmissing);
    int send_size = ALLNET_ID_REQ_SIZE (in_hp->transport, nmissing);
  /* send, no need to even check the return value of send_pipe_message */
    send_pipe_message (sock, in_message, send_size, priority);
  }
  return nsent;
}


/* save the ack, and delete any matching packets */
static void ack_packets (int msg_fd, int msg_size, int ack_fd,
                         char * in_message, int in_msize)
{
  struct allnet_header * hp = (struct allnet_header *) in_message;
  char * ack = ALLNET_DATA_START (hp, hp->transport, in_msize);
  in_msize -= (ack - in_message);
  int count = 0;
  while (in_msize >= MESSAGE_ID_SIZE) {
    char hash [MESSAGE_ID_SIZE];
    sha512_bytes (ack, MESSAGE_ID_SIZE, hash, MESSAGE_ID_SIZE);
    ack_add (ack, hash, ack_fd);
    /* delete any message corresponding to this ack */
    int position = 0;
    char * message;
    int msize;
    int id_off;
    while ((position =
              hash_get_next (msg_fd, msg_size, position, hash,
                             &message, &msize, &id_off, NULL, NULL)) > 0) {
      int current_pos = next_prev_position (position, msize);
      snprintf (log_buf, LOG_SIZE,
                "acking %d-byte cached response at [%d]\n", msize, current_pos);
      log_print ();
      char * id = message + id_off;
      remove_cached_message (msg_fd, msg_size, id, current_pos, msize);
      count++;
    }
    ack += MESSAGE_ID_SIZE;
    in_msize -= MESSAGE_ID_SIZE;
  }
  snprintf (log_buf, LOG_SIZE, "acked %d packets\n", count);
  log_print ();
}

static void init_msgs (int msg_fd, int max_msg_size)
{
  init_hash_table (max_msg_size);
  int read_position = 0;
  int count = 0;
  char * message;
  int msize;
  int id_off;
  int priority;
  char time [ALLNET_TIME_SIZE];
  while ((read_position =
            get_next_message (msg_fd, max_msg_size, read_position, NULL,
                              &message, &msize, &id_off, &priority, time))
         > 0) {
    char *  id = message + id_off;
    if ((msize > 0) && (msize <= ALLNET_MTU) && (id_off != 0) &&
        (message_hash_free != NULL)) {
#ifdef USING_MESSAGE_LIST
      list_add_message (id);
#endif /* USING_MESSAGE_LIST */
      hash_add_message (message, msize, id,
                        next_prev_position (read_position, msize), time);
      count++;
    }
  }
  snprintf (log_buf, LOG_SIZE, "init almost done, %d %d %d, ",
            msg_fd, (int) (fd_size (msg_fd)), max_msg_size);
  log_print ();
  print_stats (0, count);
  while (fd_size (msg_fd) > max_msg_size) {
    snprintf (log_buf, LOG_SIZE, "message file %d, max %d, gc'ing",
              (int) (fd_size (msg_fd)), max_msg_size);
    log_print ();
    gc (msg_fd, max_msg_size);
  }
  snprintf (log_buf, LOG_SIZE, "after init, ");
  print_stats (0, -1);
}

static void init_acache (int * msg_fd, int * max_msg_size,
                         int * ack_fd, int * max_acks, int * local_caching)
{
  /* either read or create ~/.allnet/acache/sizes */
  *max_msg_size = 1000000;  /* default values: 1M bytes for msgs, 5000 acks */
  *max_acks = 5000;
  int fd = open_read_config ("acache", "sizes", 1);
  if (fd < 0) {
  /* create ~/.allnet/acache/sizes */
    fd = open_write_config ("acache", "sizes", 1);
    if (fd < 0) {
      snprintf (log_buf, LOG_SIZE, "unable to create ~/.allnet/acache/sizes\n");
      log_error ("create ~/.allnet/acache/sizes");
      printf ("unable to create ~/.allnet/acache/sizes\n");
      exit (1);
    }
    /* by default, allow 1MB of messages, 5,000 acks, and no local caching */
    char string [] = "1000000\n5000\nno\n";
    int len = strlen (string);
    if (write (fd, string, len) != len) {
      snprintf (log_buf, LOG_SIZE, "unable to write ~/.allnet/acache/sizes\n");
      log_error ("write ~/.allnet/acache/sizes");
      printf ("unable to write ~/.allnet/acache/sizes\n");
      exit (1);
    }
  } else {
  /* read ~/.allnet/acache/sizes */
    static char buffer [1000];
    int n = read (fd, buffer, sizeof (buffer));
    if ((n > 0) && (n < sizeof (buffer))) {
      char yesno [10] = "no";
      buffer [n] = '\0';
      sscanf (buffer, "%d\n%d\n %c", max_msg_size, max_acks, yesno);
      *local_caching = 1;
      if (tolower (yesno [0]) == 'n')
        *local_caching = 0;
      snprintf (log_buf, LOG_SIZE, "local caching is %d\n", *local_caching);
      log_print ();
    } else {
      snprintf (log_buf, LOG_SIZE,
                "unable to read ~/.allnet/acache/sizes (%d)\n", n);
      log_error ("read ~/.allnet/acache/sizes");
      printf ("unable to read ~/.allnet/acache/sizes (%d)\n", n);
    }
  }
  close (fd);
  /* open (and possibly create) ~/.allnet/acache/messages and acks */
  *msg_fd = open_rw_config ("acache", "messages", 1);
  *ack_fd = open_rw_config ("acache", "acks", 1);
  if ((*msg_fd < 0) || (*ack_fd < 0)) {
    snprintf (log_buf, LOG_SIZE,
              "error, message FD %d, ack FD %d\n", *msg_fd, *ack_fd);
    log_print ();
    printf ("error, message FD %d, ack FD %d\n", *msg_fd, *ack_fd);
  }
  if (*ack_fd >= 0)
    init_acks (*ack_fd, *max_acks);
  if (*msg_fd >= 0)
    init_msgs (*msg_fd, *max_msg_size);
}

static void main_loop (int sock)
{
  int msg_fd;
  int max_msg_size;
  int ack_fd;
  int max_acks;
  int local_caching;
  init_acache (&msg_fd, &max_msg_size, &ack_fd, &max_acks, &local_caching);
  while (1) {
    char * message;
    int priority;
    int result = receive_pipe_message (sock, &message, &priority);
    struct allnet_header * hp = (struct allnet_header *) message;
    /* unless we save it, free the message */
    int mfree = 1;
    if (result <= 0) {
      snprintf (log_buf, LOG_SIZE, "ad pipe %d closed, result %d\n",
                sock, result);
      log_print ();
      /* mfree = 0;  not useful */
      break;
    } else if ((result >= ALLNET_HEADER_SIZE) &&
               (result >= ALLNET_SIZE (hp->transport))) {
if (priority == 0) {
snprintf (log_buf, LOG_SIZE, "error: received message with priority %d, %d hops\n", priority, hp->hops); log_print ();
priority = ALLNET_PRIORITY_EPSILON;
}
      /* valid message from ad: save, respond, or ignore */
      if (hp->message_type == ALLNET_TYPE_DATA_REQ) { /* respond */
        if (respond_to_request (msg_fd, max_msg_size, message, result, sock))
          snprintf (log_buf, LOG_SIZE, "responded to data request packet\n");
        else
          snprintf (log_buf, LOG_SIZE, "no response to data request packet\n");
      } else if (hp->message_type == ALLNET_TYPE_MGMT) {
        if (respond_to_id_request (msg_fd, max_msg_size, message, result, sock))
          snprintf (log_buf, LOG_SIZE, "responded to id request packet\n");
        else
          snprintf (log_buf, LOG_SIZE, "no response to id request packet\n");
      } else {   /* not a data request */
        if (hp->message_type == ALLNET_TYPE_ACK) {
          /* erase the message and save the ack */
          ack_packets (msg_fd, max_msg_size, ack_fd, message, result);
        } else if ((! local_caching) && (hp->hops == 0)) {
          snprintf (log_buf, LOG_SIZE, "not saving local packet\n");
        } else if (hp->transport & ALLNET_TRANSPORT_DO_NOT_CACHE) {
          snprintf (log_buf, LOG_SIZE, "did not save non-cacheable packet\n");
        } else if (save_packet (msg_fd, max_msg_size,
                                message, result, priority)) {
          mfree = 0;   /* saved, so do not free */
          snprintf (log_buf, LOG_SIZE, "saved packet type %d size %d pr %d\n",
                    hp->message_type, result, priority);
        } else {
          snprintf (log_buf, LOG_SIZE,
                    "did not save packet, type %d, size %d, priority %d\n",
                    hp->message_type, result, priority);
        }
      }
      log_print ();
    } else {
      snprintf (log_buf, LOG_SIZE, "ignoring packet of size %d\n", result);
      log_print ();
    }
    if (mfree)
      free (message);
  }
}

void acache_main (char * pname)
{
  /* printf ("sizeof struct hash_entry = %zd\n", sizeof (struct hash_entry));
              sizeof struct hash_entry = 56 */
  int sock = connect_to_local ("acache", pname);
  main_loop (sock);
  snprintf (log_buf, LOG_SIZE, "end of acache\n");
  log_print ();
}

#ifndef NO_MAIN_FUNCTION
/* global debugging variable -- if 1, expect more debugging output */
/* set in main */
int allnet_global_debugging = 0;

int main (int argc, char ** argv)
{
  int verbose = get_option ('v', &argc, argv);
  if (verbose)
    allnet_global_debugging = verbose;

  acache_main (argv [0]);
  return 0;
}

#endif /* NO_MAIN_FUNCTION */
