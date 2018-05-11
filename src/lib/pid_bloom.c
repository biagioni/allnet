/* pid_bloom.c:
   save acks and IDs that are removed from the main tables (cf pcache) */

/* command to compile it as a stand-alone program for testing
   of the caches:
   gcc -Wall -g -o pid_bloom_test -DTEST_PID_BLOOM src/lib/pid_bloom.c src/lib/util.c src/lib/pipemsg.c src/lib/sha.c  src/lib/allnet_queue.c src/lib/allnet_log.c src/lib/ai.c src/lib/configfiles.c -lpthread
*/

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <assert.h>

#include "pid_bloom.h"
#include "util.h"
#include "configfiles.h"

#define NUM_FILTERS	16
#define FILTER_DEPTH	8       /* 8 levels of filtering */
#define FILTER_WIDTH	65536   /* 16 bits at a time */
#define FILTER_BITS	16      /* 16 bits at a time */

/* bloom filter size should be 4MB = 4 * 16 * 8 * 65536 / 8 */

static char bloom_filter [PID_FILTER_SELECTORS] [NUM_FILTERS]
                         [FILTER_DEPTH] [FILTER_WIDTH / 8];
#define BLOOM_SIZE	(sizeof (bloom_filter))

/* if do_init is true, initialize if necessary, otherwise just return status */
static int bloom_init (int do_init)
{
  static int initialized = 0;
  if (! do_init)
    return initialized;
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
#ifdef DEBUG_PRINT
#endif /* DEBUG_PRINT */
      }
      if (from_file != NULL) free (from_file);
    }
    if (fname != NULL) free (fname);
    initialized = 1;
  }
  return 1;
}

/* id should refer to at least 16 bytes, and PID_SIZE should be 16 or more
 * filter_selector should be one of the PID_*_FILTER values
 * return 1 if the id (of size FILTER_BITS/8 * FILTER_DEPTH) is found
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
  bloom_init (1);
  int filter_num;
  for (filter_num = 0; filter_num < NUM_FILTERS; filter_num++) {
    int is_in_all = 1;
    int filter_depth;
    for (filter_depth = 0; filter_depth < FILTER_DEPTH; filter_depth++) {
      uint16_t pos = readb16 ((char *) id + filter_depth * 2);
      uint16_t index = pos / 8;
      uint16_t offset = pos % 8;
      int byte =
        bloom_filter [filter_selector] [filter_num] [filter_depth] [index];
      int bit = byte & (1 << offset);
      if (bit == 0) {  /* the ID is not in this filter */
        is_in_all = 0;
        break;         /* break out of the inner loop within one filter */
      }
    }
    if (is_in_all && (filter_num > 0))  /* also add into the top-level filter */
      pid_add_to_bloom (id, filter_selector);
    if (is_in_all)
      return 1;
  }
  return 0;
}

/* add this id to filter 0 */
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
  bloom_init (1);
  int filter_depth;
  for (filter_depth = 0; filter_depth < FILTER_DEPTH; filter_depth++) {
    uint16_t pos = readb16 ((char *) id + filter_depth * 2);
    uint16_t index = pos / 8;
    uint16_t offset = pos % 8;
    bloom_filter [filter_selector] [0] [filter_depth] [index] |= (1 << offset);
  }
}

void pid_save_bloom ()
{
  if (! bloom_init (0))   /* nothing to save */
    return;
  int fd = open_write_config ("acache", "bloom", 1);
  if (fd >= 0) {
    ssize_t write_size = BLOOM_SIZE;
    ssize_t written = write (fd, bloom_filter, BLOOM_SIZE);
    if (written < 0)
      perror ("write ~/.allnet/acache/bloom\n");
    else if (written != write_size)
      printf ("error writing %d bytes to ~/.allnet/acache/bloom, wrote %d\n",
              (int) write_size, (int) written);
    close (fd);
  } else {
    printf ("error: unable to write ~/.allnet/acache/bloom\n");
  }
}

void pid_advance_bloom ()
{
  if (! bloom_init (0))   /* nothing to advance */
    return;
  int sel;
  for (sel = 0; sel < PID_FILTER_SELECTORS; sel++) {
    int index;
/* for (index = NUM_FILTERS - 1; index >= 0; index--)
printf ("memcpy (%p, %p, %zd) (%p...%p)\n", &(bloom_filter [sel] [index + 1]),
&(bloom_filter [sel] [index]), sizeof (bloom_filter [sel] [index]),
bloom_filter, ((char *) bloom_filter) + sizeof (bloom_filter)); */
    for (index = NUM_FILTERS - 2; index >= 0; index--)
      memcpy (&(bloom_filter [sel] [index + 1]), &(bloom_filter [sel] [index]),
              sizeof (bloom_filter [sel] [index]));
    memset (&(bloom_filter [sel] [0]), 0, sizeof (bloom_filter [sel] [0]));
  }
}

#ifdef TEST_PID_BLOOM

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
  char id1 [MESSAGE_ID_SIZE];
  assert (sizeof (id1) == 16);
  assert (sizeof (id1) == FILTER_BITS/8 * FILTER_DEPTH);
  random_bytes (id1, sizeof (id1));
  print_buffer (id1, 16, "random id1    ", 16, 1);
  if (pid_is_in_bloom (id1, 0))
    print_buffer (id1, 16, "id1 is in bloom before adding\n", 16, 1);
  pid_add_to_bloom (id1, 0);
  print_sparse_buffer ((char *)bloom_filter, BLOOM_SIZE, "filter");
  if (! pid_is_in_bloom (id1, 0))
    print_buffer (id1, 16, "id1 not in bloom after adding\n", 16, 1);
  pid_advance_bloom ();
  print_sparse_buffer ((char *)bloom_filter, BLOOM_SIZE, "advanced");
  if (! pid_is_in_bloom (id1, 0))
    print_buffer (id1, 16, "id1 not in bloom after advance\n", 16, 1);
  print_sparse_buffer ((char *)bloom_filter, BLOOM_SIZE, "queried");
  char id2 [MESSAGE_ID_SIZE];
  memcpy (id2, id1, sizeof (id2));
  id2 [0] ^= 0x10;
  id2 [5] ^= 0x08;
  print_buffer (id2, 16, "new random id", 16, 1);
  if (pid_is_in_bloom (id2, 0))
    print_buffer (id2, 16, "id2 is in bloom before adding\n", 16, 1);
  pid_advance_bloom ();
  if (! pid_is_in_bloom (id1, 0))
    print_buffer (id1, 16, "id1 not in bloom after advance2\n", 16, 1);
  pid_add_to_bloom (id2, 0);
  if (! pid_is_in_bloom (id2, 0))
    print_buffer (id2, 16, "id2 not in bloom after adding\n", 16, 1);
  pid_advance_bloom ();
  pid_advance_bloom ();
  pid_advance_bloom ();
  if (! pid_is_in_bloom (id1, 0))
    print_buffer (id1, 16, "id1 not in bloom after advance3\n", 16, 1);
  if (! pid_is_in_bloom (id2, 0))
    print_buffer (id2, 16, "id2 not in bloom after advance\n", 16, 1);
}

#endif /* TEST_PID_BLOOM */
