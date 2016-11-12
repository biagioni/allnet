/* hash.c: maintain and search hash tables */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>

#include "hash.h"

/* a hash table is an array of pointers to entries, each of which may
 * point to another entry */
struct hash_entry {
  struct hash_entry * next;
  char data [0];    /* actually, hash->user_bytes of data */
};

void init_hash_table (struct hash_table * hash)
{
  hash->num_entries = 0;
  hash->user_bytes = 0;
  hash->bytes_per_entry = 0;
  hash->storage_size = 0;
  hash->table = NULL;
  hash->storage = NULL;
  hash->freeptr = NULL;
}

/* returns 0 if it fails, otherwise the number of bytes used */
static int init_hash_table_size (struct hash_table * hash, int num_entries,
                                 unsigned int user_bytes,
                                 unsigned int max_bytes)
{
  unsigned int needed_per_entry = sizeof (struct hash_entry) + user_bytes;
  unsigned int needed_per_table_entry = sizeof (struct hash_entry *);
  if (needed_per_entry % 8 != 0) {
  /* make the size a multiple of 8 bytes, which gives 64-bit alignment */
    int mod = needed_per_entry % 8;
    needed_per_entry += 8 - mod;
  }
  unsigned int total_per_entry = needed_per_entry + needed_per_table_entry;
  unsigned int needed = total_per_entry * num_entries;
  if (needed > max_bytes) {
    num_entries = max_bytes / total_per_entry;
    needed = total_per_entry * num_entries;
  }
  if (num_entries == 0)
    return 0;
  char * new_space = malloc (needed);
  if (new_space == NULL) {
    printf ("unable to allocate %d bytes for hash storage\n", needed);
    return 0;
  }
  if (hash->storage != NULL)
    free (hash->storage);
  hash->storage = new_space;
  /* table is at the end of the entries */
  int offset = num_entries * needed_per_entry;
  hash->table = ((struct hash_entry **) (hash->storage + offset));
  /* the first entry is at the beginning of storage */
  hash->freeptr = hash->storage;
  hash->num_entries = num_entries;
  hash->user_bytes = user_bytes;
  hash->bytes_per_entry = needed_per_entry;
  hash->storage_size = needed;
  int i;
  for (i = 0; i < num_entries; i++)
    hash->table [i] = NULL;
  return needed;
}

/* data must have at least ((bits + 7) / 8) bytes */
int my_hash_fn (char * data, int bits)
{
  /* just xor all the bytes in the data, shifting as we go along.
   * if there are any odd (< 32) bits at the end, they are used
   * to initialize the result
   */
  int * idata = ((int *) data);
  int isize = bits / 32;
  int i;
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
  for (i = 0; i < isize; i++) {
    result = (result << 1) | ((result >> 31) & 1);
    result = result ^ idata [i];
  }
  if (result < 0)
    result = - result;
  return result;
}

/* like memcmp, bur for fewer than 8 bits */
static int bitcmp (char b1, char b2, int bits)
{
  if (bits == 0)
    return 0;    /* match */
  b1 = b1 >> (8 - bits);
  b2 = b2 >> (8 - bits);
  if (b1 == b2)
    return 0;    /* match */
  return 1;      /* no match */
} 

static int get32bits (char * bitstring, int bits)
{
  int result = 0;
  if (bits >= 32) {
    result = (((bitstring [0] & 0xff) << 24) |
              ((bitstring [1] & 0xff) << 16) |
              ((bitstring [2] & 0xff) <<  8) |
               (bitstring [3] & 0xff));
  } else {
    if (bits >= 8)
      result = result | ((bitstring [0] & 0xff) << 24);
    if (bits >= 16)
      result = result | ((bitstring [1] & 0xff) << 16);
    if (bits >= 24)
      result = result | ((bitstring [2] & 0xff) <<  8);
  }
  if (result < 0)
    return - result;
  return result;
}

/* returns 1 if found, 0 otherwise */
int hash_find (char * bitstring, int bits, struct hash_table * hash_table)
{
  if (hash_table->table == NULL)
    return 0;

  int min_bits = bits;
  if (min_bits > hash_table->user_bytes * 8)
    min_bits = hash_table->user_bytes * 8;
  int min_bytes = min_bits / 8;

  int hash = get32bits (bitstring, bits);
  int index = hash % hash_table->num_entries;
  struct hash_entry * entry = hash_table->table [index];
  while (entry != NULL) {
    print_hash_entry (entry, hash_table->user_bytes);
    if ((memcmp (entry->data, bitstring, min_bytes) == 0) &&
        (bitcmp (entry->data [min_bytes], bitstring [min_bytes],
                 min_bits % 8) == 0))
      return 1;

    printf ("no match on entry\n");

    entry = entry->next;
  }
  return 0;   /* not found */
}

/* everything should have been allocated, so error checking is only for
 * debugging */
static void hash_add (struct hash_table * table, char * data, int dsize)
{
  int hash = get32bits (data, dsize * 8);
  int index = hash % table->num_entries;
  struct hash_entry * old = table->table [index];  /* old may be NULL */
  int entry_size = table->bytes_per_entry;
  struct hash_entry * new = (struct hash_entry *) table->freeptr;
  table->freeptr += entry_size;
  if (table->freeptr > ((char *) table->table)) { /* overflow */
    printf ("error: freeptr strayed into hash table index, %p %p %d\n",
            table->freeptr, table->table, entry_size);
    table->freeptr -= entry_size;  /* restore free ptr, if it does any good */
    return;
  }
  new->next = old;   /* link the new entry to the old entry (if any) */
  if (dsize > table->user_bytes)
    dsize = table->user_bytes;
  memcpy (new->data, data, dsize);
  table->table [index] = new;
}

static unsigned int countlines (int fd, unsigned int maxlen)
{
  if (lseek (fd, 0, SEEK_SET) == ((off_t) -1)) {
    perror ("countlines lseek");
    return 0;
  }
  int result = 0;
  ssize_t r;   /* result from reading */
  unsigned int this_line = 0;   /* how many bytes in this line */
  do {
    char buf [1];
    r = read (fd, buf, 1);
    if ((r == 1) && (buf [0] == '\n')) {
      if (this_line == maxlen)
        result++;
      this_line = 0;
    } else if (r == 1) {
      this_line++;
    }
  } while (r == 1);
  if (r < 0) {
    perror ("hash table read");
    return 0;
  }
  if (lseek (fd, 0, SEEK_SET) == ((off_t) -1)) {
    perror ("counlines 2 lseek");
    return 0;
  }
  return result;
}

int hexvalue (int c)
{
  if ((c >= '0') && (c <= '9'))
    return (c - '0');
  if ((c >= 'a') && (c <= 'f'))
    return (c - 'a' + 10);
  if ((c >= 'A') && (c <= 'F'))
    return (c - 'A' + 10);
  printf ("error: hash line in file has char %d/%x\n", c, c);
  exit (1);
}

int hexbyte (int c1, int c2)
{
  return (hexvalue (c1) << 4) | (hexvalue (c2));
}

#define MAX_ENTRY	1024
/* return the number of bytes read, or 0 if there are more than dsize */
static unsigned int readline_bytes (int fd, char * data, unsigned int dsize)
{
  if (dsize <= 0)
    return 0;
  char line [MAX_ENTRY * 2 + 1];
  unsigned int chars = 0;
  while (chars < sizeof (line)) {
    ssize_t r = read (fd, line + chars, 1);
    if ((r == 1) && (line [chars] == '\n'))
      break;       /* done!  Convert the hex to binary */
    chars++;
  }
  if (chars >= sizeof (line)) {    /* ran out of room, which is an error */
    printf ("error: hash line in file exceeds %zd bytes\n", sizeof (line));
    return 0;
  }
  if (chars != 2 * dsize) {
    printf ("error: hash line in file is %d, expected %d \n", chars, 2 * dsize);
    return 0;
  }
  unsigned int index = 0;
  for (index = 0; index < dsize; index++)
    data [index] = hexbyte (line [index * 2], line [index * 2 + 1]);
  return dsize;
}

/* returns the number of bytes in the hash table. */
/* will not exceed free_bytes, ignoring entries that would require
 * too much room */
/* ignores entries that have more or fewer than bytes_per_entry */
/* in case of failure returns 0 and the hash table is unchanged */
int hash_from_file (struct hash_table * hash_table, int fd,
		    unsigned int bytes_per_entry, unsigned int free_bytes)
{
  if (bytes_per_entry > MAX_ENTRY) {  /* sanity check */
    printf ("error: hash table can only handle %d bytes, requested %d\n",
            MAX_ENTRY, bytes_per_entry);
    return 0;  /* no change */
  }
  unsigned int num_lines = countlines (fd, bytes_per_entry * 2);
  int bytes_used = init_hash_table_size (hash_table, num_lines,
                                         bytes_per_entry, free_bytes);
  if (bytes_used == 0)
    return 0;
  while (num_lines-- > 0) {
    char line [MAX_ENTRY];
    unsigned int bytes = readline_bytes (fd, line, bytes_per_entry);
    if (bytes > 0)
      hash_add (hash_table, line, bytes);
  }
  return bytes_used;
}

/* for debugging */
void print_hash_entry (struct hash_entry * entry, int user_bytes)
{
  while (entry != NULL) {
    printf ("%p: next %p, data %d: ", entry, entry->next, user_bytes);
    int i;
    for (i = 0; i < user_bytes && i < 12; i++)
      printf (" %02x", entry->data [i] & 0xff);
    if (i < user_bytes)
      printf (" ...");
    printf ("\n");

    entry = entry->next;
  }
}
