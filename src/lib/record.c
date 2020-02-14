/* record.c: keep track of recently received packets */

/* the way we keep track is to use two hash tables.  Each hash table
 * is indexed by two bytes of the hash of the packet, and records
 * the entire hash.  New hashes overwrite old hashes, but presumably
 * in different locations in the two hash tables, so in at least one
 * of the hash tables, the hash is likely to remain for a while.
 * When looking up, a match in either hash table means we have seen
 * the packet recently.
 */

#include <stdio.h>
#include <time.h>

#include "record.h"
#include "packet.h"

#define ENTRIES_PER_TABLE		(64 * 1024)

struct hash_entry {
  time_t last_seen;
  unsigned int hash;
};

static struct hash_entry hash1 [ENTRIES_PER_TABLE];
static struct hash_entry hash2 [ENTRIES_PER_TABLE];

/* data must have at least ((bits + 7) / 8) bytes, and bits should be > 0 */
int allnet_record_simple_hash_fn (char * data, unsigned int bits)
{
  if (bits <= 0)
    return 0;
  /* just xor all the 32-bit words in the data, shifting as we go along.
   * if there are any odd (< 32) bits at the end, they are used
   * to initialize the result
   */
  int * idata = ((int *) data);
  unsigned int isize = bits / 32;
  unsigned int i;
  int result = 0;
  if (isize * 32 < bits) {
    result = data [isize * 4];
    if (isize * 32 + 8 < bits)
      result |= ((data [isize * 4 + 1]) << 8);
    if (isize * 32 + 16 < bits)
      result |= ((data [isize * 4 + 2]) << 16);
    if (isize * 32 + 24 < bits)
      result |= ((data [isize * 4 + 3]) << 24);
  }
  result += bits;  /* include the size of the packet */
  for (i = 0; i < isize; i++) {
    result = (result << 1) | ((result >> 31) & 1);  /* rotate result */
    result = result ^ idata [i];                    /* xor with new data */
  }
  if (result < 0)
    result = - result;
  return result;
}

static void lr_hash_fun (char * data, unsigned int bits, unsigned int * hash,
                         unsigned int * lindex, unsigned int * rindex)
{
  *hash = allnet_record_simple_hash_fn (data, bits);
  int left_hash  = (((*hash) >> 16) & 0xff00) | (((*hash) >> 8) & 0xff);
  *lindex = left_hash % ENTRIES_PER_TABLE;
  int right_hash = (((*hash) >>  8) & 0xff00) | ( (*hash)       & 0xff);
  *rindex = right_hash % ENTRIES_PER_TABLE;
#ifdef DEBUG_PRINT
  printf ("hash = %x, left %d %x, right = %d %x\n", (*hash),
          left_hash % ENTRIES_PER_TABLE,
          hash1 [left_hash  % ENTRIES_PER_TABLE].hash,
          right_hash % ENTRIES_PER_TABLE,
          hash2 [right_hash  % ENTRIES_PER_TABLE].hash);
#endif /* DEBUG_PRINT */
}

/* returns 0 if not found, 1 or more if found */
static unsigned int get_hash_time (struct hash_entry * entry,
                                   unsigned int hash, time_t now)
{
  if ((entry->hash != hash) || (entry->last_seen == 0))
    return 0;
  time_t hash_time = now - entry->last_seen;
  if (hash_time <= 0)
    hash_time = 1;
  return (unsigned int) hash_time;
}

static void init ()
{
  static int initialized = 0;
  if (! initialized) {
    int i;
    for (i = 0; i < ENTRIES_PER_TABLE; i++) {
      hash1 [i].hash = 0; hash1 [i].last_seen = 0;
      hash2 [i].hash = 0; hash2 [i].last_seen = 0;
    }
    initialized = 1;
  }
}

/* return 0 if this is a new packet, and the number of seconds (at least 1)
 * since it has been seen, if it has been seen before on this connection */
unsigned int record_packet (char * packet, unsigned int psize)
{
  init ();

  if ((packet == NULL) || (psize < ALLNET_HEADER_SIZE))
    return 1;    /* do not forward */
  struct allnet_header * hp = (struct allnet_header *) packet;
  /* offset lets us skip the hop count when we compute the hash */
  size_t offset = (((char *) (&(hp->hops))) - packet) + 1;
  if (psize < (unsigned int) offset)
    return 1;   /* should never happen */

  unsigned int hash, left_index, right_index;
  lr_hash_fun (packet + offset, (psize - (unsigned int)offset) * 8,
               &hash, &left_index, &right_index);
  time_t now = time (NULL);
  unsigned int left_time  = get_hash_time (hash1 + left_index , hash, now);
  unsigned int right_time = get_hash_time (hash2 + right_index, hash, now);

  /* store into both hash tables */
  hash1 [left_index].hash = hash;
  hash1 [left_index].last_seen = now;
  hash2 [right_index].hash = hash;
  hash2 [right_index].last_seen = now;

  if (left_time  == 0)
    return right_time;
  if (right_time == 0)
    return left_time;
  if (left_time > right_time)
    return right_time;  /* return lesser time */
  return left_time;
}

