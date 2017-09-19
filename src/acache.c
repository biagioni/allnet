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
#include "lib/allnet_log.h"
#include "lib/configfiles.h"
#include "lib/sha.h"
#include "lib/cipher.h" /* for print_caches, in case we want to decrypt */

#ifdef ANDROID
#define DEBUG_UNINITIALIZED
#endif /* ANDROID */

struct ack_entry {
  char message_id  [MESSAGE_ID_SIZE];
  char message_ack [MESSAGE_ID_SIZE];
};

static struct ack_entry * acks = NULL;
static int ack_space = 0;
static int save_ack_pos = 0;  /* save the next ack at this index */

struct hash_entry {
  struct hash_entry * next_by_hash;  /* this one also used for free list */
  struct hash_entry * next_by_source;
  unsigned char id [MESSAGE_ID_SIZE];
  unsigned char received_at [ALLNET_TIME_SIZE];
  int64_t file_position;
  unsigned char src_nbits;           /* limited to not more than 16 */
  unsigned char dst_nbits;           /* limited to not more than 16 */
  unsigned char source [2];
  unsigned char destination [2];
};

static int hash_pool_size = 0;
static int hash_size = 0;
static int bits_in_hash_table = 0;   /* initialized by compute_hash_div */
static struct hash_entry * message_hash_pool;
/* the head of the free list */
static struct hash_entry * message_hash_free = NULL;
/* hash table */
static struct hash_entry * * message_hash_table = NULL;
/* entries sorted by source address */
static struct hash_entry * * message_source_table = NULL;

static struct allnet_log * alog = NULL;

static void debug_message_is_null (const char * message1, const char * message2)
{
  struct allnet_log * log = alog;
  if (log == NULL)
    log = init_log ("acache.c debugging");
  if (log != NULL) {
    snprintf (alog->b, alog->s,
              "%s %s: hash_pool_size %d, hash_size %d, bits_in_hash_table %d, "
              "message_hash_table %p, message_hash_free %p, "
              "message_hash_pool %p, message_source_table %p\n",
              message1, message2, hash_pool_size, hash_size, bits_in_hash_table,
              message_hash_table, message_hash_free, message_hash_pool,
              message_source_table);
    log_print (alog);
  }
  printf ("%s %s: hash_pool_size %d, hash_size %d, bits_in_hash_table %d, "
          "message_hash_table %p, message_hash_free %p, "
          "message_hash_pool %p, message_source_table %p\n",
          message1, message2, hash_pool_size, hash_size, bits_in_hash_table,
          message_hash_table, message_hash_free, message_hash_pool,
          message_source_table);
}

static unsigned long long int fd_size_or_zero (int fd)
{
  long long int result = fd_size (fd);
  /* fd_size in util.[ch] returns -1 in case of errors.  We want to return 0 */
  if (result < 0)
    return 0;
  return result;
}

static int read_at_pos (int fd, char * data, int64_t max, int64_t position)
{
  if (lseek (fd, position, SEEK_SET) != position) {
    /* perror ("acache read_at_pos lseek"); */
    snprintf (alog->b, alog->s,
              "acache unable to lseek to position %d for %d/%d\n",
              (int)position, (int)max, (int)fd_size (fd));
    log_error (alog, "acache read_at_pos lseek");
    return 0;
  }
  ssize_t r = read (fd, data, (int)max);
  if (r < 0) {
    /* perror ("acache read_at_pos read"); */
    snprintf (alog->b, alog->s,
              "acache unable to read data at %d: %d %d %d %d\n",
              (int)position, fd, (int)r, (int)max, (int)fd_size (fd));
    log_error (alog, "acache read_at_pos read");
    r = 0;
  }
  return (int)r;
}

static void write_at_pos (int fd, char * data, int dsize, int64_t position)
{
  if (lseek (fd, position, SEEK_SET) != position) {
    /* perror ("acache write_at_pos lseek"); */
    snprintf (alog->b, alog->s,
              "acache unable to lseek to pos %d for %d %d\n",
              (int)position, dsize, (int)fd_size (fd));
    log_error (alog, "acache write_at_pos lseek");
    return;
  }
  ssize_t w = write (fd, data, dsize);
  if (w != dsize) {
    /* perror ("acache write_at_pos write"); */
    snprintf (alog->b, alog->s,
              "acache unable to save data at %d: %d %d %d\n",
              (int)position, (int)w, dsize, (int)fd_size (fd));
    log_error (alog, "acache write_at_pos write");
    return;
  }
}

static void truncate_to_size (int fd, uint64_t max_size, char * caller)
{
  if (fd_size (fd) > (long long int) max_size) {
    if (ftruncate (fd, max_size) != 0)
      perror ("ftruncate");
    snprintf (alog->b, alog->s, "%s truncated to %d\n", caller, (int)max_size);
    log_print (alog);
  }
}

/* initially save after 5s, growing exponentially to after 10min */
static int time_to_save (unsigned long long int * last_saved,
                         unsigned long long int * num_saves, int always)
{
  if (always)
    return time_exp_interval (last_saved, num_saves, 0, 0);
  unsigned long long int min = 5 * ALLNET_US_PER_S;  /* 5 seconds */
  unsigned long long int max = 10 * 60 * ALLNET_US_PER_S;  /* 10 minutes */
  return time_exp_interval (last_saved, num_saves, min, max);
}

static void save_ack_data (int fd, int always)
{
  static unsigned long long int last_saved = 0;
  static unsigned long long int num_saves = 0;
  if (time_to_save (&last_saved, &num_saves, always)) {
#ifdef DEBUG_PRINT
    static unsigned long long int debug = 0;
    printf ("time %llu (delta %llus) count %llu, saving\n", last_saved,
            (last_saved - debug) / ALLNET_US_PER_S, num_saves);
    debug = last_saved;
#endif /* DEBUG_PRINT */
    write_at_pos (fd, (char *) acks, sizeof (struct ack_entry) * ack_space, 0);
    fsync (fd);
  }
}

static void read_ack_data (int fd)
{
  read_at_pos (fd, (char *) acks, sizeof (struct ack_entry) * ack_space, 0);
}

static void init_acks (int fd, unsigned int max_acks)
{
  unsigned int ack_size = sizeof (struct ack_entry);
  unsigned int max_size = ack_size * max_acks;
  /* if file is bigger than max_size, get rid of the last part */
  truncate_to_size (fd, max_size, "init_acks");
  /* allocate the memory to hold the acks */
  ack_space = max_acks;
  acks = malloc_or_fail (max_size, "acache init_acks");
  /* if file is smaller than max_size, the last part should be zeros */
  memset (acks, 0, max_size);
  read_ack_data (fd);
  /* find the last non-zero ack position */
  struct ack_entry empty;
  memset (&empty, 0, sizeof (struct ack_entry));
  read_ack_data (fd);
  /* if all filled, we start at random */
  save_ack_pos = (int)random_int (0, max_acks - 1);
  int i = max_acks;
  while (i-- > 0) {
    if (memcmp (acks [i].message_id, empty.message_id, MESSAGE_ID_SIZE) == 0)
      save_ack_pos = i;  /* lowest-numbered (so far) empty ack position */
  }
}

static int ack_found (char * ack)
{
  int i;
  for (i = 0; i < ack_space; i++) {
    if (memcmp (acks [i].message_ack, ack, MESSAGE_ID_SIZE) == 0) {
      return i + 1;
    }
  }
  return 0;
}

static int ack_add (char * ack, char * id, int ack_fd)
{
  if (ack_found (ack))
    return 0;  /* not new */
  memcpy (acks [save_ack_pos].message_ack, ack, MESSAGE_ID_SIZE);
  memcpy (acks [save_ack_pos].message_id , id , MESSAGE_ID_SIZE);
  /* clear the next location, to mark it in the file */
  int next_ack = (save_ack_pos + 1) % ack_space;
  memset (&(acks [next_ack]), 0, sizeof (struct ack_entry));
  save_ack_data (ack_fd, 0);
  save_ack_pos = next_ack;
  return 1;
}

/* storage of a message in the file: 12-byte header */
/* never used as a struct since we are not sure the C compiler will pack it
 * into 12 bytes */
#ifdef USE_STRUCT_NOT_OFFSETS
struct message_entry_do_not_use {
  unsigned char msize [2];
  unsigned char id_offset [2]; /* how many bytes into the message is the ID */  
  unsigned char priority [4];  /* message priority */  
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
  unsigned int dpower_two;
  unsigned int dbits;
  unsigned char * dbitmap;
  unsigned int spower_two;
  unsigned int sbits;
  unsigned char * sbitmap;
};

/* all the pointers point into message */
static void build_request_details (char * message, int msize, 
                                   struct request_details * result,
                                   char ** ack_bitset, int * ack_bits)
{
  struct allnet_header * hp = (struct allnet_header *) message;
  int hsize = ALLNET_SIZE (hp->transport);
  int drsize = ALLNET_TIME_SIZE + 8;
  int bsize = minz (msize, hsize + drsize);
  result->src_nbits = hp->src_nbits;
  if (result->src_nbits > ADDRESS_BITS)
    result->src_nbits = ADDRESS_BITS;
  if (result->src_nbits > 16)
    result->src_nbits = 16;
  if (result->src_nbits < 0)
    result->src_nbits = 0;
  memcpy (result->source, hp->source, ADDRESS_SIZE);
  result->empty = 1;
  if (bsize > 0) {
    result->empty = 0;
    struct allnet_data_request * drp =
      (struct allnet_data_request *) (message + hsize);
    int max_bits = bsize * 8;
    result->since = drp->since;
    char empty_time [ALLNET_TIME_SIZE];
    memset (empty_time, 0, sizeof (empty_time));
    if (memcmp (empty_time, result->since, sizeof (empty_time)) == 0)
      result->since = NULL;  /* time is zero, so don't use in comparisons */
    result->dpower_two = 0;
    result->dbits = 0;
    result->dbitmap = NULL;
    result->spower_two = 0;
    result->sbits = 0;
    result->sbitmap = NULL;
    *ack_bits = 0;
    *ack_bitset = NULL;
    int dbits = 0;
    int dbytes = 0;
    int sbits = 0;
    int sbytes = 0;
    int abits = 0;
    int abytes = 0;
    if ((drp->dst_bits_power_two > 0) &&
        (drp->dst_bits_power_two <= 12) &&
        ((dbits = (1 << (drp->dst_bits_power_two))) <= max_bits)) {
      dbytes = (dbits + 7) / 8;
      if (hsize + drsize + dbytes <= msize) {
        result->dpower_two = drp->dst_bits_power_two;
        result->dbits = dbits;
        result->dbitmap = (unsigned char *) (message + (hsize + drsize));
        max_bits = minz (max_bits, dbytes * 8);
      }
    }
    if ((drp->src_bits_power_two > 0) &&
        (drp->src_bits_power_two <= 12) &&
        ((sbits = (1 << (drp->src_bits_power_two))) <= max_bits)) {
      sbytes = (sbits + 7) / 8;
      if (hsize + drsize + dbytes + sbytes <= msize) {
        result->spower_two = drp->src_bits_power_two;
        result->sbits = sbits;
        result->sbitmap =
          (unsigned char *) (message + (hsize + drsize + dbytes));
        max_bits = minz (max_bits, sbytes * 8);
      }
    }
    if ((drp->mid_bits_power_two > 0) &&
        (drp->mid_bits_power_two <= 12) &&
        ((abits = (1 << (drp->mid_bits_power_two))) <= max_bits)) {
      abytes = (abits + 7) / 8;
      if (hsize + drsize + dbytes + sbytes + abytes <= msize) {
        *ack_bits = drp->mid_bits_power_two;
        *ack_bitset = (message + (hsize + drsize + dbytes + sbytes));
        max_bits = minz (max_bits, abytes * 8);
      }
    }
  }
#ifdef DEBUG_PRINT
  printf ("request, power_two s %d d %d (%d %d), bitmaps s %p d %p\n",
          result->spower_two, result->dpower_two, result->sbits, result->dbits,
          result->sbitmap, result->dbitmap);
#endif /* DEBUG_PRINT */
}

/* return the first n bits of the array, shifted all the way to the right */
static uint64_t get_nbits (unsigned char * bits, unsigned int nbits)
{
#ifdef DEBUG_PRINT
printf ("result of get_nbits (%02x.%02x.%02x.%02x.%02x.%02x.%02x.%02x %d) is ",
bits [0] & 0xff, bits [1] & 0xff, bits [2] & 0xff, bits [3] & 0xff,
bits [4] & 0xff, bits [5] & 0xff, bits [6] & 0xff, bits [7] & 0xff, nbits);
#endif /* DEBUG_PRINT */
  if (nbits > 64)
    nbits = 64;
  uint64_t result = readb64u (bits);
  if (nbits < 64)
    result = result >> (64 - nbits);
#ifdef DEBUG_PRINT
  printf ("%" PRIx64 "\n", result);
#endif /* DEBUG_PRINT */
  return result;
}

/* returns 0 or 1, the bit at the given position */
static int get_bit (unsigned char * bits, uint64_t pos)
{
  int byte = bits [pos / 8];
  unsigned int offset = pos % 8;
  if (offset == 0)
    return byte & 0x1;
  return (byte >> offset) & 0x1;
}

#ifdef USING_SET_BIT  /* currently unused, might be useful in the future */
static void set_bit (unsigned char * bits, uint64_t pos)
{
  uint64_t index = pos / 8;
  unsigned int offset = pos % 8;
  int mask = 1;
  if (offset != 0)
    mask = mask << offset;
  bits [index] |= mask;
}
#endif /* USING_SET_BIT */

/* returns 1 if the address is (or may be) in the bitmap, 0 otherwise */
static int match_bitmap (unsigned int power_two, unsigned int bitmap_bits,
                         unsigned char * bitmap,
                         unsigned char * address, unsigned int abits)
{
  if ((power_two <= 0) || (bitmap_bits <= 0) || (bitmap == NULL))
    return 1;   /* an empty bitmap matches every address */
  if (abits <= 0)
    return 1;   /* empty address matches every bitmap, even one with all 0's */
  uint64_t start_index = get_nbits (address, abits);
  uint64_t end_index = start_index;
  if (abits > power_two) {  /* rescale everything to the bitmap */
    int delta = abits - power_two;
    start_index = (start_index >> delta);
    end_index = start_index;
  } else if (abits < power_two) {
    /* make end_index have all 1s in the last (power_two - abits) bits */
    /* e.g. assume abits is 8, power_two 12, delta 4, start/end index 0x17
       the new end_index is 0x18 << 4 - 1 = 0x180 - 1 = 0x17f
       the new start_index is 0x17 << 4 = 0x170, or 0x170..0x17f */
    int delta = power_two - abits;
    end_index = ((start_index + 1) << delta) - 1;
    start_index = (start_index << delta);
  }
#ifdef DEBUG_PRINT
  printf ("start %" PRIx64 ", end %" PRIx64 ", a %d 2^%d %02x, bm %d %02x\n",
          start_index, end_index, abits, power_two, address [0],
          bitmap_bits, bitmap [start_index / 8]);
#endif /* DEBUG_PRINT */
  if ((start_index > end_index) ||
      (start_index > bitmap_bits) || (end_index > bitmap_bits)) {
    snprintf (alog->b, alog->s,
              "match_bitmap error: 2^%d, index %" PRIx64 "-%" PRIx64 ", %d+%d bits, a %02x\n",
              power_two, start_index, end_index, bitmap_bits, abits,
              address [0]);
    printf ("%s", alog->b);
    log_print (alog);
    return 1;
  }
  while (start_index <= end_index) {
#ifdef DEBUG_PRINT
    if (get_bit (bitmap, start_index))
      printf ("bit %" PRIx64 " is set\n", start_index);
#endif /* DEBUG_PRINT */
    if (get_bit (bitmap, start_index))
      return 1;
    start_index++;
  }
  return 0;  /* did not match any bit in the bitmap */
}

/* returns 1 if the message matches the request, 0 otherwise */
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
                       hp->destination, hp->dst_nbits))) {
    return 0;
  }
  if ((req->sbits > 0) && (req->sbitmap != NULL) &&
      (! match_bitmap (req->spower_two, req->sbits, req->sbitmap,
                       hp->source, hp->src_nbits))) {
    return 0;
  }
  return 1;
}

/* see get_next_message */
static int64_t next_prev_position (int64_t next_position, int msize)
{
  if (next_position >= (MESSAGE_ENTRY_HEADER_SIZE + msize))
    return next_position - (MESSAGE_ENTRY_HEADER_SIZE + msize);
  return -1;
}

/* note that the return value is the position of the NEXT message, if any.
 * the position of this message is given by next_prev_position */
static int64_t get_next_message (int fd, unsigned int max_size,
                                 int64_t position,
                                 struct request_details *rd,
                                 char ** message, int * msize, int * id_off,
                                 int * priority, char * received_time)
{
  if (position < 0)
    return -1;
  unsigned int original_max_size = max_size;
  if (max_size > fd_size (fd))
    max_size = (unsigned int)fd_size (fd);
  while (position < max_size) {
    static char buffer [MAX_MESSAGE_ENTRY_SIZE];
    memset (buffer, 0, sizeof (buffer));
    unsigned int rsize = MAX_MESSAGE_ENTRY_SIZE;
    if (rsize > (max_size - (unsigned int)position)) /* position < max_size */
      rsize = max_size - (unsigned int)position;
    if (rsize <= MESSAGE_ENTRY_HEADER_SIZE) {
      printf ("get_next_message rsize %d, min %d\n", rsize,
              MESSAGE_ENTRY_HEADER_SIZE);
      return -1;
    }
    int r = read_at_pos (fd, buffer, rsize, position);
    if (r <= MESSAGE_ENTRY_HEADER_SIZE) { /* unable to read */
      printf ("get_next_message r %d rsize %d pos %" PRId64 " max %u fd %lld\n",
              r, rsize, position, max_size, fd_size (fd));
#ifdef DEBUG_PRINT
      snprintf (alog->b, alog->s, "get_next_message r %d\n", r);
      log_print (alog);
#endif /* DEBUG_PRINT */
      return -1;
    }
    int found_size = readb16 (buffer + MESSAGE_ENTRY_HEADER_MSIZE_OFFSET);
    if ((found_size <= 0) || (found_size > ALLNET_MTU) ||
        (found_size > (int)rsize - MESSAGE_ENTRY_HEADER_SIZE)) {
      /* unknown size */
      printf ("get_next_message found %d at %" PRId64 " (%d/%lld/%d/%u/%u)\n",
              found_size, position, r, fd_size (fd), rsize, max_size,
              original_max_size);
      print_buffer (buffer, r, "data", 60, 1);
#ifdef DEBUG_PRINT
      snprintf (alog->b, alog->s,
                "get_next_message found %d at %" PRId64 " (%d/%lld/%d/%u/%u)\n",
                found_size, position, r, fd_size (fd), rsize, max_size,
                original_max_size);
      log_print (alog);
      buffer_to_string (buffer, r, "data", 16, 0, alog->b, alog->s);
      log_print (alog);
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
      if (priority != NULL)
        *priority = (int)readb32 (buffer +
                                  MESSAGE_ENTRY_HEADER_PRIORITY_OFFSET);
      if (received_time != NULL)
        memcpy (received_time, found_time, ALLNET_TIME_SIZE);
#ifdef DEBUG_PRINT
      snprintf (alog->b, alog->s, "get_next_message: %d %" PRId64 " ok\n",
                found_size, position);
      log_print (alog);
#endif /* DEBUG_PRINT */
      return position;
    }
#ifdef DEBUG_PRINT
    snprintf (alog->b, alog->s,
              "get_next_message found %d id_off %d p %" PRId64 " %" PRId64 "\n",
              found_size, found_id_off,
              position - (MESSAGE_ENTRY_HEADER_SIZE + found_size), position);
    log_print (alog);
#endif /* DEBUG_PRINT */
  }
#ifdef DEBUG_PRINT
  unsigned int rsize = MAX_MESSAGE_ENTRY_SIZE;
  if (rsize > (max_size - position))
    rsize = max_size - position;
  if (max_size < position)
    rsize = 0;
  printf ("get_next_message position = %" PRId64 ", max = %u/rs %u, => -1\n", 
          position, max_size, rsize);
#endif /* DEBUG_PRINT */
  return -1;  /* reached the end */
}

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
#ifdef DEBUG_UNINITIALIZED
  debug_message_is_null ("init_hash_table", "complete");
#endif /* DEBUG_UNINITIALIZED */
}

static int count_list (struct hash_entry * entry, int index)
{
  int result = 0;
#ifdef DEBUG_PRINT
  int off = 0;
  if (index != -1)
    off = snprintf (alog->b, alog->s, "%d: ", index);
#endif /* DEBUG_PRINT */
  while (entry != NULL) {
#ifdef DEBUG_PRINT
    if (index != -1) {
      off += buffer_to_string ((char *) (entry->id), MESSAGE_ID_SIZE, " ",
                               16, 0, alog->b + off, alog->s - off);
      off += snprintf (alog->b + off, alog->s - off, " @ %d, ",
                       (int)entry->file_position);
    }
#endif /* DEBUG_PRINT */
    result++;
    entry = entry->next_by_hash;
  }
#ifdef DEBUG_PRINT
  if (index != -1)
  log_print (alog);
#endif /* DEBUG_PRINT */
  return result;
}

static void print_stats (int exit_if_none_free, int must_match,
                         const char * caller)
{
  if (message_hash_table == NULL) {
    debug_message_is_null ("print_stats", caller);
    return;
  }
  int hcount = 0;
  int i;
  for (i = 0; i < hash_size; i++)
    hcount += count_list (message_hash_table [i], i);
  int fcount = count_list (message_hash_free, -1);
  int off = (int)strlen (alog->b);
  snprintf (alog->b + off, alog->s - off, "acache %s: %d in hash, %d free\n",
            caller, hcount, fcount);
  log_print (alog);
  if (exit_if_none_free && (fcount == 0))
    exit (1);
  if ((must_match >= 0) && (must_match != hcount)) {
    snprintf (alog->b, alog->s,
              "acache %s: %d in hash, %d free, should have %d\n",
              caller, hcount, fcount, must_match);
    printf ("%s", alog->b);
    log_print (alog);
    if (exit_if_none_free)
      exit (1);
  }
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
    printf ("hash_div is %" PRIu32
            ", hash_size %d, hash_pool_size %d, %d bits\n",
            hash_div, hash_size, hash_pool_size, bits_in_hash_table);
#endif /* DEBUG_PRINT */
  }
  uint32_t id_value = (uint32_t) readb32 (id);
  return (id_value / hash_div);
}

static int hash_has_space (unsigned int max_size, unsigned int new_size, int fd)
{
  return ((message_hash_free != NULL) &&
          (fd_size_or_zero (fd) + new_size <= max_size));
}

static void hash_add_message (char * message, unsigned int msize, char * id,
                              int64_t position, char * time)
{
  if (message_hash_table == NULL) {         /* not initialized */
    debug_message_is_null ("hash_add_message", "null message hash table");
    return;
  }
  struct allnet_header * hp = (struct allnet_header *) message;
  if (msize < ALLNET_SIZE (hp->transport))  /* invalid header */
    return;
  /* allocate an entry from the pool */
  if (message_hash_free == NULL) {
    /* caller should have made sure we have at least one entry available */
    printf ("error in hash_add_message: no free entries\n");
    snprintf (alog->b, alog->s,
              "error in hash_add_message: no free entries\n");
    log_print (alog);
    exit (1);
  }
  struct hash_entry * entry = message_hash_free;
  message_hash_free = entry->next_by_hash;
  /* initialize the entry */
  memset (entry, 0, sizeof (struct hash_entry));
  memcpy (entry->id, id, MESSAGE_ID_SIZE);
  entry->file_position = position;
  entry->src_nbits = hp->src_nbits;
  if (entry->src_nbits > 16) entry->src_nbits = 16;
  entry->dst_nbits = hp->dst_nbits;
  if (entry->dst_nbits > 16) entry->dst_nbits = 16;
  memcpy (entry->source,      hp->source,      (entry->src_nbits + 7) / 8);
  memcpy (entry->destination, hp->destination, (entry->dst_nbits + 7) / 8);
  memcpy (entry->received_at, time, ALLNET_TIME_SIZE);
  /* add the entry to the chain in the hash table */
  uint32_t h_index = hash_index (id);
  entry->next_by_hash = message_hash_table [h_index];
  message_hash_table [h_index] = entry;
  /* add the entry to the chain in the source table */
  uint32_t s_index = hash_index ((char *) (entry->source));
  entry->next_by_source = message_source_table [s_index];
  message_source_table [s_index] = entry;
}

static void update_hash_position (char * id, int64_t position)
{
  if (message_hash_table == NULL) {
    debug_message_is_null ("update_hash_position", "null message hash table");
    return;  /* not initialized */
  }
  uint32_t index = hash_index (id);
  struct hash_entry * entry = message_hash_table [index];
  while (entry != NULL) {
    if (memcmp (entry->id, id, MESSAGE_ID_SIZE) == 0)  /* found */
      entry->file_position = position;
    entry = entry->next_by_hash;
  }
}

static void remove_hash_entry (struct hash_entry * entry, uint32_t index)
{
  if (entry == NULL)
    return;
  if (message_hash_table == NULL) {
    debug_message_is_null ("remove_hash_entry", "null message hash table");
    return;  /* not initialized */
  }
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

static void remove_source_entry (struct hash_entry * entry, uint32_t index)
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

static struct hash_entry * hash_find (char * hash, const char * from)
{
  if (message_hash_table == NULL) {
    debug_message_is_null ("hash_find", from);
    return NULL;  /* not initialized */
  }
  uint32_t h_index = hash_index (hash);
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
  struct hash_entry * entry = hash_find (id, "remove_from_hash_table");
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
                      "acache rfht: id not found, unable to delete from list",
                      16, 0, alog->b, alog->s);
printf ("%s", alog->b);
    log_print (alog);
  }
}

/* return the next position, or -1 if it fails */
static int64_t assign_matching (struct hash_entry * matching, int fd, int fsize,
                                char ** message, int * msize, int * id_off,
                                int * priority, char * time)
{
  if (message != NULL) *message = NULL;
  if (msize != NULL) *msize = 0;
  if (id_off != NULL) *id_off = 0;
  if (priority != NULL) *priority = 0;
  if (time != NULL) memset (time, 0, ALLNET_TIME_SIZE);
  if (matching == NULL)
    return -1;
  /* static makes it OK to set message to point into here */
  static char data [MAX_MESSAGE_ENTRY_SIZE];
  if (matching->file_position >= fsize)
    return -1;
  int64_t rsize = sizeof (data);
  if (matching->file_position + rsize > fsize)
    rsize = fsize - matching->file_position;
  int r = read_at_pos (fd, data, rsize, matching->file_position);
  if (r <= MESSAGE_ENTRY_HEADER_SIZE)
    return -1;
  int found_msize = readb16 (data + MESSAGE_ENTRY_HEADER_MSIZE_OFFSET);
  if (r < MESSAGE_ENTRY_HEADER_SIZE + found_msize)
    return -1;
  int found_id_off = readb16 (data + MESSAGE_ENTRY_HEADER_IDOFF_OFFSET);
  if (message != NULL) *message = data + MESSAGE_ENTRY_HEADER_SIZE;
  if (msize != NULL) *msize = found_msize;
  if (id_off != NULL) *id_off = found_id_off;
  if (priority != NULL)
    *priority = (int)readb32 (data + MESSAGE_ENTRY_HEADER_PRIORITY_OFFSET);
  if (time != NULL)
    memcpy (time, data + MESSAGE_ENTRY_HEADER_TIME_OFFSET, ALLNET_TIME_SIZE);
  return matching->file_position + found_msize + MESSAGE_ENTRY_HEADER_SIZE;
}

static int64_t hash_get_next (int fd, int max, int64_t pos, char * hash,
                              char ** message, int * msize, int * id_off,
                              int * priority, char * time)
{
  if (pos < 0)
    return -1;
  if (message_hash_table == NULL) {
    debug_message_is_null ("hash_get_next", "");
    return -1;  /* not initialized */
  }
  uint32_t h_index = hash_index (hash);
  int64_t least_not_less_than = -1;
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
  return assign_matching (matching, fd, max, message, msize,
                          id_off, priority, time);
}

/* returns 1 if successful, 0 if we already returned all matching entries. */
/* first_call should only be set on the first call in a loop */
static int hash_next_match (int fd, unsigned int max_size, int first_call,
                            struct request_details * rd,
                            char ** message, int * msize)
{
  if (message_hash_table == NULL) {
    debug_message_is_null ("hash_next_match", "");
    return 0;  /* not initialized */
  }
  static int persistent_index = -1;
  static struct hash_entry * persistent_entry = NULL;
  static int first_index = -1;
#ifdef ALLNET_USE_THREADS  /* synchronize, otherwise persistent_entry sometimes
                              becomes NULL when we expect it not to be */
  static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
  pthread_mutex_lock (&mutex);
#endif /* ALLNET_USE_THREADS */
  if (first_call) {
    persistent_index = (int)random_int (0, hash_size - 1);
    persistent_entry = message_hash_table [persistent_index];
    first_index = persistent_index;
  } else if (persistent_index < 0) { /* already done */
#ifdef ALLNET_USE_THREADS
    pthread_mutex_unlock (&mutex);
#endif /* ALLNET_USE_THREADS */
    return 0;
  }
  while (1) {
    if (persistent_entry == NULL) { /* find the next available entry, if any */
      persistent_index = (persistent_index + 1) % hash_size;
      while ((persistent_index != first_index) &&
             (message_hash_table [persistent_index] == NULL))
        persistent_index = (persistent_index + 1) % hash_size;
      if (persistent_index == first_index) {  /* nothing found */
        persistent_index = -1;
        persistent_entry = NULL;
#ifdef ALLNET_USE_THREADS
        pthread_mutex_unlock (&mutex);
#endif /* ALLNET_USE_THREADS */
        return 0;
      }
      persistent_entry = message_hash_table [persistent_index];
    }
    if (persistent_entry == NULL) { /* this is an error! */
      snprintf (alog->b, alog->s,
                "error: persistent_entry is NULL, %d %d %p\n",
                persistent_index, first_index, persistent_entry);
      printf ("%s", alog->b);
      log_print (alog);
#ifdef ALLNET_USE_THREADS
      pthread_mutex_unlock (&mutex);
#endif /* ALLNET_USE_THREADS */
      return 0;
    }
    struct hash_entry * entry = persistent_entry;
    persistent_entry = entry->next_by_hash;   /* may be null */
    char ptime [ALLNET_TIME_SIZE];
    int64_t found = assign_matching (entry, fd, max_size, message, msize,
                                     NULL, NULL, ptime);
    if ((found < 0) || ((msize != NULL) && (*msize <= 0)))
      continue;   /* try again with the next entry */
    int match = packet_matches (rd, *message, *msize, ptime);
    if (match == 0)
      continue;   /* try again with the next entry */
    if (! is_valid_message (*message, *msize, NULL))
      continue;   /* message may have expired, try again with the next entry */
#ifdef ALLNET_USE_THREADS
    pthread_mutex_unlock (&mutex);
#endif /* ALLNET_USE_THREADS */
    return 1;  /* found */
  }
#if 0  /* after infinite loop, so, never executed */
#ifdef ALLNET_USE_THREADS
  pthread_mutex_unlock (&mutex);
#endif /* ALLNET_USE_THREADS */
  printf ("control flow error in acache\n");
  return 0;  /* should never be executed */
#endif /* 0 */
}

/* returns 1 if this message is ready to be deleted, 0 otherwise */
static int delete_gc_message (char * message, unsigned int msize,
                              unsigned int id_off, int priority, char * time,
                              int64_t end_pos, int file_max)
{
  if ((msize <= ALLNET_HEADER_SIZE + MESSAGE_ID_SIZE) || (msize > ALLNET_MTU) ||
      (id_off < ALLNET_HEADER_SIZE) || (id_off + MESSAGE_ID_SIZE > msize))
    return 1;  /* bad message, no need to keep */
  if (! is_valid_message (message, msize, NULL))
    return 1;  /* message may have expired, no need to keep */
  int file_pos = (int)next_prev_position (end_pos, msize);
  struct allnet_header * hp = (struct allnet_header *) message;
  /* we should delete something, so at least the first 6% of the file */
  int min_delete = (file_max / 16);
#ifdef DEBUG_PRINT
  int off = buffer_to_string (message + id_off, MESSAGE_ID_SIZE, "id",
                              MESSAGE_ID_SIZE, 0, alog->b, alog->s);
  off += snprintf (alog->b + off, alog->s - off, ", pos %d/%d, transport %x",
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
  off += snprintf (alog->b + off, alog->s - off,
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
        off += snprintf (alog->b + off, alog->s - off, ", expired");
#endif /* DEBUG_PRINT */
        return 1;
      }
    }
  }
  return 0;
}

static void gc (int fd, unsigned int max_size)
{
  unsigned int gc_size = max_size;
  unsigned int actual_size = (unsigned int)fd_size_or_zero (fd);
  if (gc_size > actual_size)
    gc_size = actual_size;
  int copied = 0, deleted = 0;
  int64_t read_position = 0;
  int64_t write_position = 0;
  char * message;
  int msize;
  int id_off;
  int priority;
  char time [ALLNET_TIME_SIZE];
  while ((read_position =
            get_next_message (fd, max_size, read_position, NULL, &message,
                              &msize, &id_off, &priority, time)) > 0) {
    int delete = 1;
    if ((msize > 0) && (id_off >= 0))
      delete = delete_gc_message (message, (unsigned int) msize,
                                  (unsigned int) id_off, priority, time,
                                  read_position, gc_size);
    snprintf (alog->b, alog->s,
              "read %" PRId64 ", write %" PRId64 ", hash %d ==> delete %d\n",
              read_position, write_position, hash_index (message + id_off),
              delete);
    log_print (alog);
#ifdef DEBUG_PRINT
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
      deleted++;
    }
  }
  truncate_to_size (fd, write_position, "gc");
  fsync (fd);
#ifdef DEBUG_PRINT
  printf ("end of gc, %d copied, %d deleted\n", copied, deleted);
  snprintf (alog->b, alog->s, "%d copied, %d deleted, ", copied, deleted);
  log_print (alog);
#endif /* DEBUG_PRINT */
  print_stats (1, copied, "gc");
}

static int debug_message_sig_size (char * message, int msize,
                                    const char * action)
{
  struct allnet_header * hp = (struct allnet_header *) message;
  if (hp->sig_algo != ALLNET_SIGTYPE_NONE) {
    int length = readb16 (message + (msize - 2));
    if (length != 512) {
      printf ("not %s cached message with weird signature size %d\n",
              action, length);
      print_packet (message, msize, "message", 1);
      print_buffer (message, msize, "message bytes", msize, 1);
      return 1;
    }
  }
  return 0;
}

static unsigned long long int num_msg_saves = 0;
static unsigned long long int last_msg_time = 0;

static void cache_message (int fd, unsigned int max_size, unsigned int id_off,
                           char * message, unsigned int msize, int priority)
{
  if (id_off + MESSAGE_ID_SIZE > msize)
    return;
  if (message_hash_table == NULL) {
    debug_message_is_null ("cache_message", "");
    return;  /* not initialized */
  }
  char mbuffer [MAX_MESSAGE_ENTRY_SIZE];
  unsigned int fsize = MESSAGE_ENTRY_HEADER_SIZE + msize;
  if ((fsize > max_size) || (fsize > MAX_MESSAGE_ENTRY_SIZE)) {
    snprintf (alog->b, alog->s,
              "unable to save message of size %d/%d, max %d/%d\n",
              msize, fsize, max_size, MAX_MESSAGE_ENTRY_SIZE);
    log_print (alog);
    return;
  }
if (debug_message_sig_size (message, msize, "saving")) {
snprintf (alog->b, alog->s, "odd signature size, not saving packet\n");
log_print (alog);
return;   }
  writeb16 (mbuffer + MESSAGE_ENTRY_HEADER_MSIZE_OFFSET, msize);
  writeb16 (mbuffer + MESSAGE_ENTRY_HEADER_IDOFF_OFFSET, id_off);
  writeb32 (mbuffer + MESSAGE_ENTRY_HEADER_PRIORITY_OFFSET, priority);
  unsigned long long int now = allnet_time ();
  writeb64 (mbuffer + MESSAGE_ENTRY_HEADER_TIME_OFFSET, now);
  memcpy (mbuffer + MESSAGE_ENTRY_HEADER_SIZE, message, msize);
  int count = 0;
  while (! hash_has_space (max_size, fsize, fd)) {
    /* we are out of hash descriptors or file space, delete some
     * entries in the hash table */
    snprintf (alog->b, alog->s, "gc'ing to make space for hash: %d\n",
              ++count);
    log_print (alog);
    if (count > 10) {
      printf ("count is 10 in acache.c cache_message, aborting\n");
      exit (1);
    }
    gc (fd, max_size);
  }
  int64_t write_position = (int64_t)fd_size_or_zero (fd);
  write_at_pos (fd, mbuffer, fsize, write_position);
  if (time_to_save (&last_msg_time, &num_msg_saves, 0))
    fsync (fd);   /* only fsync once in a while, lessen the disk traffic */
  hash_add_message (message, msize, message + id_off, write_position,
                    mbuffer + MESSAGE_ENTRY_HEADER_TIME_OFFSET);
snprintf (alog->b, alog->s, "saved message at position %d, hash index %d, ", (int) write_position, hash_index (message + id_off)); log_print (alog); print_stats (0, -1, "cache_message");
  count = 0;
  while (fd_size (fd) > max_size) {
    snprintf (alog->b, alog->s, "gc'ing to reduce space from %d to %d: %d\n",
              (int)fd_size (fd), max_size, ++count);
    log_print (alog);
    gc (fd, max_size);
  }
}

static void remove_cached_message (int fd, unsigned int max_size, char * id,
                                   int64_t position, int msize)
{
  static char buffer [MAX_MESSAGE_ENTRY_SIZE];
  int fsize = MESSAGE_ENTRY_HEADER_SIZE + msize;
  if (fsize > MAX_MESSAGE_ENTRY_SIZE) {
    snprintf (alog->b, alog->s,
              "remove_cached_message error: size %d, max %d\n",
              fsize, MAX_MESSAGE_ENTRY_SIZE);
    log_print (alog);
    return;   /* invalid call */
  }
  /* read the entry, make sure the size matches */
  int64_t next = get_next_message (fd, max_size, position, NULL,
                                   NULL, NULL, NULL, NULL, NULL);
  if ((next != 0) && (next - position != fsize)) {
    snprintf (alog->b, alog->s,
              "warning in acache: next %d - pos %d != fsize %d (%d)\n",
              (int)next, (int)position, fsize, (int)fd_size (fd));
    log_print (alog);
    buffer_to_string (id, MESSAGE_ID_SIZE, "id", MESSAGE_ID_SIZE, 1,
                      alog->b, alog->s);
    log_print (alog);
    print_stats (0, -1, "remove_cached_message");
  }
  buffer_to_string (id, MESSAGE_ID_SIZE, "removing cached", MESSAGE_ID_SIZE, 1,
                    alog->b, alog->s);
  log_print (alog);
  /* mark it as erased, but keep the size so we can later skip */
  memset (buffer, 0, fsize);
  writeb16 (buffer + MESSAGE_ENTRY_HEADER_MSIZE_OFFSET, msize);
  write_at_pos (fd, buffer, fsize, position);
  if (time_to_save (&last_msg_time, &num_msg_saves, 0))
    fsync (fd);   /* only fsync once in a while, lessen the disk traffic */
  remove_from_hash_table (id);
}

/* if the header includes an id, returns a pointer to the ID field of hp */
static char * get_id (char * message, unsigned int size)
{
  struct allnet_header * hp = (struct allnet_header *) message;
  char * id = ALLNET_PACKET_ID (hp, hp->transport, size);
  if (id == NULL)
    id = ALLNET_MESSAGE_ID (hp, hp->transport, size);
  /* key messages usually don't have IDs, so use hmac or fingerprints */
  if ((id == NULL) && (size >= ALLNET_SIZE (hp->transport) + MESSAGE_ID_SIZE)) {
    /* return the last MESSAGE_ID_SIZE bytes, which may be unique */
    id = message + size - MESSAGE_ID_SIZE;
  }
  return id;  /* a pointer (if any) into hp */ 
}

/* returns 1 if successful, 0 otherwise */
static int save_packet (int fd, unsigned int max_size, char * message,
                        unsigned int msize, int priority)
{
#ifdef DEBUG_PRINT
  snprintf (alog->b, alog->s, "save_packet: size %d\n", msize);
  log_print (alog);
#endif /* DEBUG_PRINT */
  char * id = get_id (message, msize);
  if (id == NULL)   /* no sort of message or packet ID found */
    return 0;
#ifdef DEBUG_PRINT
  buffer_to_string (id, MESSAGE_ID_SIZE, "id", MESSAGE_ID_SIZE, 1,
                    alog->b, alog->s);
  log_print (alog);
#endif /* DEBUG_PRINT */
  if (hash_find (id, "save_packet") != NULL) {
#ifdef LOG_PACKETS
    buffer_to_string (id, MESSAGE_ID_SIZE, "save_packet: found",
                      MESSAGE_ID_SIZE, 1, alog->b, alog->s);
    log_print (alog);
#endif /* LOG_PACKETS */
    return 0;
  }
  cache_message (fd, max_size, (unsigned int) (id - message),
                 message, msize, priority);
  return 1;
}

/* to limit resource consumption, only respond to requests that are
 * local, or to at most 1 outside request per second */
static void limit_resources (int local_request,
                             unsigned long long int * overall,
                             unsigned long long int * ack_limit) 
{
  static unsigned long long int next_external = 0;
  unsigned long long int start = allnet_time_ms ();
  if (overall   != NULL) *overall   = start - 1;
  if (ack_limit != NULL) *ack_limit = start - 1;
  if ((! local_request) && (next_external != 0) &&
      (start <= next_external))
    return;               /* responded to another request in the past 10s */
  next_external = start + 10000; /* respond to external requests
                                    once every 10s*/
  unsigned long long int first = start + 10;     /* allow 10ms for acks */
  unsigned long long int final = start + 100;    /* allow 90 more ms for msgs */
  if (local_request) {                  /* allow much more time */
    first = start + 1000;               /* up to 1s for acks */
    final = start + 10000;              /* up to 10s for local requests */
  }
  if (overall   != NULL) *overall   = final;
  if (ack_limit != NULL) *ack_limit = first;
}

static int send_ack (struct allnet_header * hp, unsigned int msize, int sock)
{
  if ((hp->transport & ALLNET_TRANSPORT_ACK_REQ) == 0)
    return 0;
  int index = ack_found (ALLNET_MESSAGE_ID (hp, hp->transport, msize));
  if (index == 0)
    return 0;
  index--;   /* the actual index is one less than the return value */

  unsigned int send_size;
  struct allnet_header * reply =
    create_packet (MESSAGE_ID_SIZE, ALLNET_TYPE_ACK, hp->hops + 1,
                   ALLNET_SIGTYPE_NONE, hp->destination, hp->dst_nbits,
                   hp->source, hp->src_nbits, NULL, NULL, &send_size);
  char * send = (char *) reply;
  char * data = send + ALLNET_SIZE (reply->transport);
  memcpy (data, acks [index].message_ack, MESSAGE_ID_SIZE);
  int priority = ALLNET_PRIORITY_CACHE_RESPONSE;
  send_pipe_message (sock, send, send_size, priority, alog);
  return 1;
}

/* return 1 if no acks are specified (NULL bits or zero nbits)
 * return 1 if the bit corresponding to the first bits of the array is set,
 *        0 otherwise (or if nbits >= 32) */
static int requested_ack (char * message_id, char * bits, int nbits)
{
  if ((bits == NULL) || (nbits <= 0))
    return 1;
  if (nbits >= 32)
    return 0;
  uint32_t pos = (((uint32_t)(readb32 (message_id))) >> (32 - nbits));
  return get_bit ((unsigned char *) bits, pos);
}

static int send_outstanding_acks (struct allnet_header * hp, int sock,
                                  unsigned long long int time_limit,
                                  char * ack_bitset, int ack_bits)
{
  if (ack_space <= 0)
    return 0;
  char packet [ALLNET_MTU];
  memset (packet, 0, sizeof (packet));
  struct allnet_header * reply =
    init_packet (packet, sizeof (packet), ALLNET_TYPE_ACK, hp->hops + 1,
                 ALLNET_SIGTYPE_NONE, hp->destination, hp->dst_nbits,
                 hp->source, hp->src_nbits, NULL, NULL);
  int hsize = ALLNET_SIZE (reply->transport);
  /* sanity checks.  acks should have transport = 0, so a header size of 24 */
  if (hsize != 24)
    printf ("acache error, hsize %d\n", hsize);
  if (reply->transport != 0)
    printf ("acache error 1, transport %d\n", hp->transport);
  char * message_acks = packet + hsize;
  /* add as many acks as possible, beginning from a random starting point. */
  unsigned char zero [MESSAGE_ID_SIZE];
  memset (zero, 0, sizeof (zero));
  int count = 0;
  int ack_index = (int)random_int (0, ack_space - 1); /* index into ack table */
  int initial_ack_index = ack_index;
  int msg_index = 0;                             /* index into ack message */
  int priority = ALLNET_PRIORITY_CACHE_RESPONSE;
  /* finished means we ran out of time or sent all available acks */
  int finished = (allnet_time_ms () >= time_limit);
  while (! finished) {
    /* if the ack was requested (or all were requested), return this ack
     * as long as it is nonzero */
    if ((requested_ack (acks [ack_index].message_id, ack_bitset, ack_bits)) &&
        (memcmp (acks [ack_index].message_ack, zero, MESSAGE_ID_SIZE) != 0)) {
      memcpy (message_acks + msg_index * MESSAGE_ID_SIZE,
              acks [ack_index].message_ack, MESSAGE_ID_SIZE);
      msg_index++;
    }
    ack_index = (ack_index + 1) % ack_space;
    finished = ((ack_index == initial_ack_index) ||
                (allnet_time_ms () >= time_limit));
    /* if we are done, or if we have max_acks to send, send what we have */
    if ((msg_index > 0) && (finished || (msg_index == ALLNET_MAX_ACKS))) {
      int send_size = hsize + msg_index * MESSAGE_ID_SIZE;
      /* more sanity checks, trying to find who is sending bogus packets */
      if (reply->transport != 0)
        printf ("acache error 2, transport %d\n", hp->transport);
      send_pipe_message (sock, packet, send_size, priority, alog);
      if (reply->transport != 0)
        printf ("acache error 3, transport %d\n", hp->transport);
      count += msg_index;
      msg_index = 0;
    }
  }
  return count;
}

/*
static void debug_resend_message (char * message, int msize,
                                  struct allnet_header * hp,
                                  int local_request, int64_t position)
{
  if (hp->sig_algo != ALLNET_SIGTYPE_NONE) {
    int length = readb16 (message + (msize - 2));
    if (length != 512) {
      printf ("sending cached message with weird signature size %d\n", length);
      print_packet (message, msize, "message", 1);
      print_buffer (message, msize, "message bytes", msize, 1);
    }
  }
}
*/

static void resend_message (char * message, int msize, int64_t position,
                            int *priorityp, int local_request, int sock)
{
  int priority = *priorityp;
#ifdef LOG_PACKETS
  snprintf (alog->b, alog->s,
            "sending %d-byte cached response at [%" PRIx64 "]\n",
            msize, position);
  log_print (alog);
#endif /* LOG_PACKETS */
  struct allnet_header * send_hp = (struct allnet_header *) message;
if (debug_message_sig_size (message, msize, "sending")) {
snprintf (alog->b, alog->s, "odd signature size, not sending packet\n");
log_print (alog);
return;   }
  int saved_max = send_hp->max_hops;
  if (local_request)  /* only forward locally */
    send_hp->max_hops = send_hp->hops;
  /* send, no need to even check the return value of send_pipe_message */
  send_pipe_message (sock, message, msize, priority, alog);
  if (local_request)  /* restore the packet as it was */
    send_hp->max_hops = saved_max;
  if (priority > ALLNET_PRIORITY_EPSILON)
    *priorityp = priority - 1;
}

/* returns the number of responses sent, or 0 */
static int respond_to_request (int fd, unsigned int max_size, char * in_message,
                               int in_msize, int sock)
{
  int local_request = 0;
  struct allnet_header * hp = (struct allnet_header *) (in_message);
  if (hp->hops == 0)   /* local request, do not forward elsewhere */
    local_request = 1;
  
  /* limit responses as specified by limit_resources */
  unsigned long long int overall_limit, ack_limit;
  limit_resources (local_request, &overall_limit, &ack_limit);
  struct request_details rd;
  char * ack_bitset = NULL;
  int ack_bits = 0;
  build_request_details (in_message, in_msize, &rd, &ack_bitset, &ack_bits);

  int num_acks =
    send_outstanding_acks (hp, sock, ack_limit, ack_bitset, ack_bits);

  int sent = 0;
  int count = 0;
  while (allnet_time_ms () < overall_limit) {
    char * message = NULL;
    int msize = 0;
    int first_call = (count++ == 0);
    if (hash_next_match (fd, max_size, first_call, &rd, &message, &msize))
    {
      sent++;
      int priority = ALLNET_PRIORITY_EPSILON;
      if (ALLNET_PRIORITY_CACHE_RESPONSE > ALLNET_PRIORITY_EPSILON + count)
        priority = ALLNET_PRIORITY_CACHE_RESPONSE - count;
      resend_message (message, msize, 0, &priority, local_request, sock);
    } else {
      break;  /* sequential search, none left, so done */
    }
  }
  snprintf (alog->b, alog->s, "respond_to_request: sent %d packets, %d acks\n",
            sent, num_acks);
  log_print (alog);
/* printf ("sent %d messages, %d acks\n", sent, num_acks); */
  return sent;
}

/* returns the number of responses sent, or 0 */
/* if any of the ids in the request are not found, also sends onwards
 * the message (unless it was sent locally and with max_hops == 0), with
 * only those ids that were not found */
static int respond_to_id_request (int fd, unsigned int max_size,
                                  char * in_message, unsigned int in_msize,
                                  int sock)
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
  unsigned long long int limit;
  limit_resources (local_request, &limit, NULL);

  int forward_missing = (! local_request) || sent_locally;
  int nmissing = 0;
  int nsent = 0;
  int priority = ALLNET_PRIORITY_CACHE_RESPONSE;

  int i;
  for (i = 0; i < n; i++) {
    char *id = (char *) (amirp->ids + i * MESSAGE_ID_SIZE);
    char * message = NULL;
    int msize = 0;
    int64_t position = 0;
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
    send_pipe_message (sock, in_message, send_size, priority, alog);
  }
  return nsent;
}


/* save the ack, and delete any matching packets */
static void ack_packets (int msg_fd, unsigned int msg_size, int ack_fd,
                         char * in_message, unsigned int in_msize)
{
  struct allnet_header * hp = (struct allnet_header *) in_message;
  char * ack = ALLNET_DATA_START (hp, hp->transport, in_msize);
  in_msize -= (ack - in_message);
  int count = 0;
  while (in_msize >= MESSAGE_ID_SIZE) {
    char hash [MESSAGE_ID_SIZE];
    sha512_bytes (ack, MESSAGE_ID_SIZE, hash, MESSAGE_ID_SIZE);
    if (ack_add (ack, hash, ack_fd)) {
      /* new ack, delete any message corresponding to this ack */
      int64_t position = 0;
      char * message;
      int msize;
      int id_off;
      while ((position =
                hash_get_next (msg_fd, msg_size, position, hash,
                               &message, &msize, &id_off, NULL, NULL)) > 0) {
        int64_t current_pos = next_prev_position (position, msize);
        snprintf (alog->b, alog->s,
                  "acking %d-byte cached response at [%d]\n",
                  msize, (int)current_pos);
        log_print (alog);
        char * id = message + id_off;
        remove_cached_message (msg_fd, msg_size, id, current_pos, msize);
        count++;
      }
    }
    ack += MESSAGE_ID_SIZE;
    in_msize -= MESSAGE_ID_SIZE;
  }
#ifdef LOG_PACKETS
  if (count > 0) {
    snprintf (alog->b, alog->s, "acked %d packets\n", count);
    log_print (alog);
  }
#endif /* LOG_PACKETS */
}

static void init_msgs (int msg_fd, int max_msg_size)
{
  init_hash_table (max_msg_size);
  int64_t read_position = 0;
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
      hash_add_message (message, msize, id,
                        next_prev_position (read_position, msize), time);
      count++;
    }
  }
  snprintf (alog->b, alog->s, "init almost done, %d %d %d, ",
            msg_fd, (int)fd_size (msg_fd), max_msg_size);
  log_print (alog);
  print_stats (0, count, "init_msgs");
  while (fd_size (msg_fd) > max_msg_size) {
    snprintf (alog->b, alog->s, "message file %d, max %d, gc'ing",
              (int)fd_size (msg_fd), max_msg_size);
    log_print (alog);
    gc (msg_fd, max_msg_size);
  }
  snprintf (alog->b, alog->s, "after init, saving at %d, ", save_ack_pos);
  print_stats (0, -1, "init_msgs");
}

static void init_acache (int * msg_fd, int * max_msg_size,
                         int * ack_fd, int * max_acks, int * local_caching)
{
  /* either read or create ~/.allnet/acache/sizes */
  /* by default, allow 1MB of messages, 5,000 acks = 80KB, no local caching */
  *max_msg_size = 1000000;
  *max_acks = 5000;
  *local_caching = 0;
  int fd = open_read_config ("acache", "sizes", 1);
  if (fd < 0) {
  /* create ~/.allnet/acache/sizes */
    fd = open_write_config ("acache", "sizes", 1);
    if (fd < 0) {
      snprintf (alog->b, alog->s, "unable to create ~/.allnet/acache/sizes\n");
      log_error (alog, "create ~/.allnet/acache/sizes");
      printf ("unable to create ~/.allnet/acache/sizes\n");
      /* not a fatal error: exit (1); */
    } else {
      char string [] = "1000000\n5000\nno\n";
      int len = (int)strlen (string);
      if (write (fd, string, len) != len) {
        snprintf (alog->b, alog->s,
                  "unable to write ~/.allnet/acache/sizes\n");
        log_error (alog, "write ~/.allnet/acache/sizes");
        printf ("unable to write ~/.allnet/acache/sizes\n");
        /* also not a fatal error: exit (1); */
      }
    }
  } else {     /* read input from ~/.allnet/acache/sizes */
    static char buffer [1000];
    ssize_t n = read (fd, buffer, sizeof (buffer));
    if ((n > 0) && (n < (ssize_t) (sizeof (buffer)))) {
      char yesno [10] = "no";
      buffer [n] = '\0';
      sscanf (buffer, "%d\n%d\n %c", max_msg_size, max_acks, yesno);
      *local_caching = 1;
      if (tolower (yesno [0]) == 'n')
        *local_caching = 0;
#ifdef DEBUG_PRINT
      snprintf (alog->b, alog->s, "local caching is %d\n", *local_caching);
      log_print (alog);
#endif /* DEBUG_PRINT */
    } else {
      snprintf (alog->b, alog->s,
                "unable to read ~/.allnet/acache/sizes (%d)\n", (int)n);
      log_error (alog, "read ~/.allnet/acache/sizes");
      printf ("unable to read ~/.allnet/acache/sizes (%d)\n", (int)n);
    }
  }
  close (fd);
  /* open (and possibly create) ~/.allnet/acache/messages and acks */
  *msg_fd = open_rw_config ("acache", "messages", 1);
  *ack_fd = open_rw_config ("acache", "acks", 1);
  if ((*msg_fd < 0) || (*ack_fd < 0)) {
    snprintf (alog->b, alog->s,
              "error, message FD %d, ack FD %d\n", *msg_fd, *ack_fd);
    log_print (alog);
    printf ("error, message FD %d, ack FD %d\n", *msg_fd, *ack_fd);
  }
  if (*ack_fd >= 0)
    init_acks (*ack_fd, *max_acks);
  if (*msg_fd >= 0)
    init_msgs (*msg_fd, *max_msg_size);
}

static int msg_fd = -1;
static int ack_fd = -1;

/* may be called externally, e.g. when the process is terminated */
void acache_save_data ()
{
  if (msg_fd != -1) {
    fsync (msg_fd);  /* save all the messages that are in memory */
    close (msg_fd);
    msg_fd = -1;
  }
  if (ack_fd != -1) {
    save_ack_data (ack_fd, 1);
    ack_fd = -1;
  }
}

static void main_loop (int rsock, int wsock, pd p)
{
  int signed_max;
  int max_acks;
  int local_caching = 0;
  init_acache (&msg_fd, &signed_max, &ack_fd, &max_acks, &local_caching);
  unsigned int max_msg_size = 0;
  if (signed_max > 0)
    max_msg_size = signed_max;
  snprintf (alog->b, alog->s, "acache main_loop fds %d, %d, max %u\n",
            rsock, wsock, max_msg_size);
  log_print (alog);
#ifdef DEBUG_UNINITIALIZED
  debug_message_is_null ("main_loop", "after init_acache");
#endif /* DEBUG_UNINITIALIZED */
  while (1) {
    char * message = NULL;
    unsigned int priority;
    int result = receive_pipe_message (p, rsock, &message, &priority);
    unsigned int uresult = result;  /* only used if result > 0 */
    struct allnet_header * hp = (struct allnet_header *) message;
    /* unless we save it, free the message */
    int mfree = 1;
    if (result <= 0) {
      snprintf (alog->b, alog->s, "alocal pipe %d closed, result %d\n",
                rsock, result);
      log_print (alog);
      mfree = 0;  /* nothing to free */
      break;      /* time to exit */
    } else if ((uresult >= ALLNET_HEADER_SIZE) &&
               (uresult >= ALLNET_SIZE (hp->transport))) {
      if (priority == 0) {
#ifdef LOG_PACKETS
        snprintf (alog->b, alog->s,
                  "received message with priority %d, %d hops\n", priority,
                  hp->hops);
        log_print (alog);
#endif /* LOG_PACKETS */
        priority = ALLNET_PRIORITY_EPSILON;
      }
      /* valid message from ad: save, respond, or ignore */
      if (hp->message_type == ALLNET_TYPE_DATA_REQ) { /* respond */
        if (respond_to_request (msg_fd, max_msg_size, message, uresult, wsock))
          snprintf (alog->b, alog->s, "responded to data request packet\n");
        else
          snprintf (alog->b, alog->s, "no response to data request packet\n");
      } else if (hp->message_type == ALLNET_TYPE_MGMT) {
        if (respond_to_id_request (msg_fd, max_msg_size, message,
                                   uresult, wsock))
          snprintf (alog->b, alog->s, "responded to id request packet\n");
        else
          snprintf (alog->b, alog->s, "no response to id request packet\n");
      } else {   /* not a data request and not a mgmt packet */
        if (hp->message_type == ALLNET_TYPE_ACK) {
          /* erase the message and save the ack */
          ack_packets (msg_fd, max_msg_size, ack_fd, message, uresult);
        } else if ((! local_caching) && (hp->hops == 0)) {
          snprintf (alog->b, alog->s, "not saving local packet\n");
        } else if (hp->transport & ALLNET_TRANSPORT_DO_NOT_CACHE) {
          snprintf (alog->b, alog->s, "did not save non-cacheable packet\n");
        } else if ((hp->transport & ALLNET_TRANSPORT_ACK_REQ) &&
                   (ack_found (ALLNET_MESSAGE_ID (hp, hp->transport,
                                                  uresult)))) {
          if (send_ack (hp, uresult, wsock))
            snprintf (alog->b, alog->s, "resent ack, did not save\n");
          else
            snprintf (alog->b, alog->s, "did not save acked packet\n");
        } else if (save_packet (msg_fd, max_msg_size,
                                message, uresult, priority)) {
          mfree = 0;   /* saved, so do not free */
          snprintf (alog->b, alog->s, "saved packet type %d size %u pr %d\n",
                    hp->message_type, uresult, priority);
        } else {
          snprintf (alog->b, alog->s,
                    "did not save packet, type %d, size %u, priority %d\n",
                    hp->message_type, uresult, priority);
        }
      }
#ifdef LOG_PACKETS
      if (strlen (alog->b) > 0)
        log_print (alog);
#endif /* LOG_PACKETS */
    } else {
#ifdef LOG_PACKETS
      snprintf (alog->b, alog->s, "ignoring packet of size %d\n", result);
      log_print (alog);
#endif /* LOG_PACKETS */
    }
    if (mfree)
      free (message);
  }
  acache_save_data ();
}

static void print_message (int fd, unsigned int max_size,
                           struct hash_entry * entry, int print_level,
                           int count, int h_index)
{
  if (print_level == 1) {
    char desc [1000];
    snprintf (desc, sizeof (desc), "%4d (h %d)", count, h_index);
    print_buffer ((char *)entry->id, MESSAGE_ID_SIZE, desc, 100, 1);
    return;
  }     /* print_level > 1, print the details about the entry */
  printf ("%4d (h %d), ", count, h_index);
  print_buffer ((char *)entry->id, MESSAGE_ID_SIZE, "id", 100, 1);
  char time_str [ALLNET_TIME_STRING_SIZE];
  allnet_localtime_string (readb64u (entry->received_at), time_str);
  printf ("  received at %s\n", time_str);
  if (entry->src_nbits > 0)
    printf ("  from %02x.%02x/%d", entry->source [0],
            entry->source [1], entry->src_nbits);
  else
    printf ("  from X");
  if (entry->dst_nbits > 0)
    printf (" to %02x.%02x/%d\n", entry->destination [0],
            entry->destination [1], entry->dst_nbits);
  else
    printf (" to Y\n");
  if (print_level <= 2)
    return;
  /* print_level > 2, print the packet */
  int msize;
  char * message;
  int priority;
  int id_off;
  char ptime [ALLNET_TIME_SIZE];
  int64_t assigned = assign_matching (entry, fd, max_size, &message, &msize,
                                      &id_off, &priority, ptime);
  if (assigned < 0) {
    printf ("error getting the actual message at position %d, max %d\n",
            (int)entry->file_position, max_size);
    return;
  }
  if (memcmp (ptime, entry->received_at, ALLNET_TIME_SIZE) != 0) {
    allnet_localtime_string (readb64 (ptime), time_str);
    printf ("   @%d, %d bytes, received at %s, prio %d, id %d\n",
            (int)assigned, msize, time_str, priority, id_off);
  } else {
    printf ("   @%d, %d bytes, prio %d, id %d\n",
            (int)assigned, msize, priority, id_off);
  }
  print_packet (message, msize, NULL, 1);
  struct allnet_header * hp = (struct allnet_header *) message;
  if (hp->sig_algo != ALLNET_SIGTYPE_NONE) {  /* check sig size */
    int length = readb16 (message + (msize - 2));
    if (length != 512) {
      printf ("odd signature length %d\n", length);
      print_buffer (message, msize, "packet", msize, 1);
    }
  }
  if (print_level <= 3)
    return;
  /* print_level > 3, attempt to decrypt data packets and verify signatures */
  if (hp->message_type == ALLNET_TYPE_DATA) {
    char * data = ALLNET_DATA_START (hp, hp->transport, (unsigned int) msize);
    unsigned int dsize = 0;
    if (msize > (data - message))
      dsize = msize - (int)(data - message);
    char * contact;
    char * text;
    keyset k;
    int tsize = decrypt_verify (hp->sig_algo, data, dsize,
                                &contact, &k, &text,
                                NULL, 0, NULL, 0, 0);
    if (tsize > 0) {
      char * desc = strcat_malloc (" decrypted from ", contact, "print_msg");
      print_buffer (text, tsize, desc, 100, 0);
      free (desc);
      if (tsize > 40) {
        int len = tsize - 40;
        char * copy = malloc_or_fail (len + 1, "print_caches");
        memcpy (copy, text + 40, len);
        copy [len] = '\0';
        printf (" (%s)", copy);
        free (copy);
      }
      free (text);
      printf ("\n");
    }
  } else if (hp->sig_algo != ALLNET_SIGTYPE_NONE) {
    /* should verify signatures.  Not implemented, but see code in sniffer.c */
  }
}

/* intended to be called by an outside program, for debugging */
/* each print variable is 0 to not print, 1 to print short, 2 for long */
void print_caches (int print_msgs, int print_acks)
{
  if (alog == NULL)
    alog = init_log ("print_caches");
  int print_msg_fd;
  int max_msg_size;
  int print_ack_fd;
  int max_acks;
  int local_caching = 0;
  init_acache (&print_msg_fd, &max_msg_size, &print_ack_fd,
               &max_acks, &local_caching);
  printf ("cache sizes are %d for messages, %d for acks\n",
          max_msg_size, max_acks);
  char zero [MESSAGE_ID_SIZE];
  memset (zero, 0, sizeof (zero));
  if (print_msgs > 0) {
    int count = 0;
    int ecount = 0;
    int h_index;
    for (h_index = 0; h_index < hash_size; h_index++) {
      struct hash_entry * entry = message_hash_table [h_index];
      if (entry != NULL)
        ecount++;
      while (entry != NULL) {
        if (memcmp (zero, entry->id, MESSAGE_ID_SIZE) != 0) {
          print_message (print_msg_fd, max_msg_size, entry,
                         print_msgs, count, h_index);
          count++;
        }
        entry = entry->next_by_hash;
      }
    }
    printf ("found %d messages in %d (out of %d) hash table entries\n",
            count, ecount, hash_size);
  }
  if (print_acks > 0) {
    int i;
    int count = 0;
    for (i = 0; i < ack_space; i++) {
      if (memcmp (acks [i].message_id, zero, MESSAGE_ID_SIZE) != 0) {
        count++;
        unsigned char * id = (unsigned char *) (acks [i].message_id);
        unsigned char * ack = (unsigned char *) (acks [i].message_ack);
        printf ("%4d@%d ", count, i);
        printf ("%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x ", ack [0], ack [1], ack [2], ack [3], ack [4], ack [5], ack [6], ack [7], ack [8], ack [9], ack [10], ack [11], ack [12], ack [13], ack [14], ack [15]);
        printf ("%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n", id [0], id [1], id [2], id [3], id [4], id [5], id [6], id [7], id [8], id [9], id [10], id [11], id [12], id [13], id [14], id [15]);
      }
    }
    printf ("found %d acks out of %d entries\n", count, ack_space);
  }
  /* print_stats (0, 0, "print_caches"); */
  close (print_msg_fd);
  close (print_ack_fd);
}

/* used for systems that don't support multiple processes */
void acache_thread (char * pname, int rpipe, int wpipe)
{
  alog = init_log ("acache_thread");
  pd p = init_pipe_descriptor (alog);
  main_loop (rpipe, wpipe, p);
}

void acache_main (char * pname)
{
  /* printf ("sizeof struct hash_entry = %zd\n", sizeof (struct hash_entry));
              sizeof struct hash_entry = 56 */
  alog = init_log ("acache");
  pd p = init_pipe_descriptor (alog);
#ifndef ALLNET_USE_FORK   /* if the connection is closed, keep trying */
  while (1) {
#endif /* ALLNET_USE_FORK */
    int sock = connect_to_local ("acache", pname, NULL, p);
    snprintf (alog->b, alog->s, "acache connected to local, fd %d\n", sock);
    log_print (alog);
    if (sock >= 0) {
      main_loop (sock, sock, p);
      remove_pipe (p, sock);
      close (sock);  /* may already be closed */
      sleep (60);    /* so we don't loop too tightly */
    }
#ifndef ALLNET_USE_FORK
  }
#endif /* ALLNET_USE_FORK */
  snprintf (alog->b, alog->s, "end of acache\n");
  log_print (alog);
}

#ifdef DAEMON_MAIN_FUNCTION
int main (int argc, char ** argv)
{
  log_to_output (get_option ('v', &argc, argv));

  acache_main (argv [0]);
  return 0;
}

#endif /* DAEMON_MAIN_FUNCTION */
