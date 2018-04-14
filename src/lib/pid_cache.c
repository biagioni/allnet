/* pid_cache.c:
   save acks and IDs that are removed from the main tables (cf pcache) */

/* command to compile it as a stand-alone program for testing
   of the caches:
   gcc -Wall -g -o pid_cache_test -DTEST_PID_CACHE src/lib/pid_cache.c src/lib/util.c src/lib/pipemsg.c src/lib/sha.c  src/lib/allnet_queue.c src/lib/allnet_log.c src/lib/ai.c src/lib/configfiles.c -lpthread
*/

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <assert.h>

#include "pid_cache.h"
#include "util.h"
#include "configfiles.h"

#define NUM_FILTERS	16
#define FILTER_DEPTH	8       /* 8 levels of filtering */
#define FILTER_WIDTH	65536   /* 16 bits at a time */
#define FILTER_BITS	16      /* 16 bits at a time */

/* bloom filter size should be 2MB = 2 * 16 * 8 * 65536 / 8 */

static char bloom_filter [PID_FILTER_SELECTORS] [NUM_FILTERS]
                         [FILTER_DEPTH] [FILTER_WIDTH / 8];
#define BLOOM_SIZE	(sizeof (bloom_filter))

static void init_bloom ()
{
  static int initialized = 0;
  if (! initialized) {
    memset (bloom_filter, 0, BLOOM_SIZE);  /* default of all zeroes */
    char * fname = NULL;
    if (config_file_name ("acache", "bloom", &fname) >= 0) {
      char * from_file = NULL;
      int size = read_file_malloc (fname, &from_file, 0);
      if ((from_file != NULL) && (size == BLOOM_SIZE)) {
        memcpy (bloom_filter, from_file, BLOOM_SIZE);
      } else if (from_file != NULL) {   /* size is wrong */
        printf ("error: expected %d bytes, got %d, deleting %s\n",
                (int) BLOOM_SIZE, size, fname);
        unlink (fname);
      } else {   /* from_file is NULL, the file does not exist */
        printf ("error reading %s: no such file\n", fname);
      }
      if (from_file != NULL) free (from_file);
    }
    if (fname != NULL) free (fname);
    initialized = 1;
  }
}

/* filter_selector should be 1 for acks, 0 for messages */
/* return 1 if the id (of size FILTER_BITS/8 * FILTER_DEPTH) is found
 * in one of the filters. */
int pid_is_in_bloom (const char * id, int filter_selector)
{
  assert(FILTER_WIDTH == 65536);
  assert(FILTER_BITS == 16);
  assert(FILTER_BITS * FILTER_DEPTH == 16 * 8);
  assert(FILTER_BITS == MESSAGE_ID_SIZE);
  assert(PID_SIZE >= 16);
  assert(filter_selector < PID_FILTER_SELECTORS);
  assert(filter_selector >= 0);
  assert(BLOOM_SIZE == (PID_FILTER_SELECTORS *
                        NUM_FILTERS * FILTER_DEPTH * FILTER_WIDTH / 8));
  init_bloom ();
  int filter_num;
  for (filter_num = 0; filter_num < NUM_FILTERS; filter_num++) {
    int filter_depth;
    for (filter_depth = 0; filter_depth < FILTER_DEPTH; filter_depth++) {
      uint16_t pos = readb16 (id + filter_depth * 2);
      assert (pos < FILTER_WIDTH);
      uint16_t index = pos / 8;
      uint16_t offset = pos % 8;
      int byte =
        bloom_filter [filter_selector] [filter_num] [filter_depth] [index];
      int bit = byte & (1 << offset);
      if (bit == 0)
        return 0;
    }
  }
  return 1;
}

/* add this id/ack to filter 0 */
void pid_add_to_bloom (const char * id, int filter_selector)
{
  assert(FILTER_WIDTH == 65536);
  assert(FILTER_BITS == 16);
  assert(FILTER_BITS * FILTER_DEPTH == 16 * 8);
  assert(FILTER_BITS == MESSAGE_ID_SIZE);
  assert(PID_SIZE >= 16);
  assert(filter_selector < PID_FILTER_SELECTORS);
  assert(filter_selector >= 0);
  assert(BLOOM_SIZE == (PID_FILTER_SELECTORS *
                        NUM_FILTERS * FILTER_DEPTH * FILTER_WIDTH / 8));
  init_bloom ();
  int filter_depth;
  for (filter_depth = 0; filter_depth < FILTER_DEPTH; filter_depth++) {
    uint16_t pos = readb16 (id + filter_depth * 2);
    assert (pos < FILTER_WIDTH);
    uint16_t index = pos / 8;
    uint16_t offset = pos % 8;
    bloom_filter [filter_selector] [0] [filter_depth] [index] |= (1 << offset);
  }
}

void pid_save_bloom ()
{
  init_bloom ();
  int fd = open_write_config ("acache", "bloom", 0);
  if (fd >= 0) {
    ssize_t write_size = BLOOM_SIZE;
    ssize_t written = write (fd, bloom_filter, BLOOM_SIZE);
    if (written < 0)
      perror ("write ~/.allnet/acache/bloom\n");
    else if (written != write_size)
      printf ("error writing %d bytes to ~/.allnet/acache/bloom, wrote %d\n",
              (int) write_size, (int) written);
  } else {
    printf ("error: unable to write ~/.allnet/acache/bloom\n");
  }
}

void pid_advance_bloom ()
{
  init_bloom ();
  int sel;
  for (sel = 0; sel < PID_FILTER_SELECTORS; sel++) {
    int index = 0;
    for (index = 0; index + 1< NUM_FILTERS; index++)
      memcpy (&(bloom_filter [sel] [index + 1]), &(bloom_filter [sel] [index]),
              sizeof (bloom_filter [sel] [index]));
  }
}

#ifdef TEST_PID_CACHE

static void print_sparse_buffer (const char * buffer, int bsize,
                                 const char * desc)
{
  printf ("%s, %d bytes:\n", desc, bsize);
  int i;
  for (i = 0; i < bsize; i++)
    if (buffer [i] != 0)
      printf ("  %5d: %02x\n", i, buffer [i] & 0xff);
}

int main ()
{
  char id [FILTER_BITS/8 * FILTER_DEPTH];
  assert (sizeof (id) == 16);
  random_bytes (id, sizeof (id));
  print_buffer (id, 16, "random id    ", 16, 1);
  if (pid_is_in_bloom (id, 0))
    print_buffer (id, 16, "id is in bloom before adding\n", 16, 1);
  pid_add_to_bloom (id, 0);
  id [1] |= 0x2;
  id [3] |= 0x4;
  id [5] |= 0x8;
  id [7] |= 0x10;
  print_buffer (id, 16, "new random id", 16, 1);
  if (pid_is_in_bloom (id, 0))
    print_buffer (id, 16, "second id is in bloom before adding\n", 16, 1);
  pid_add_to_bloom (id, 0);
  print_sparse_buffer ((char *) bloom_filter, BLOOM_SIZE, "filter");
}

#endif /* TEST_PID_CACHE */
