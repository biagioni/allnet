/* table.c: maintain and search tables of bitstrings */

/* 2013/02/08 intermediate version, stores addresses but not public keys */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>

#include "table.h"
#include "util.h"

/* a table is an array of pointers to entries, each of which may
 * point to another entry */
struct table_entry {
  struct table_entry * next;
  char data [0];    /* actually, table->bytes_per_entry of data */
};

void init_table (struct table * table)
{
  table->num_entries = 0;
  table->num_slots = 0;
  table->bytes_per_entry = 0;
  /* table->bytes_per_entry = 0; */
  table->storage_size = 0;
  table->table = NULL;
  table->storage = NULL;
  table->freeptr = NULL;
}

/* returns the correct result except when n = 0, and the correct
 * result would be negative infinity -- we return -1 */
static int log2_floor (int n)
{
  /* int debug_n = n; */
  int result = -1;
  while (n > 0) {
    result++;
    n = n >> 1;
  }
  /* printf ("log2_floor (%d) is %d\n", debug_n, result); */
  return result;
}

static int round_up_power_two (int n)
{
/*
  if ((n & (n - 1)) == 0)
    printf ("round_up_power_two (%x) => %x\n", n, n);
*/
  /* is it already a power of two? if so, n & (n - 1) should be zero */
  if ((n & (n - 1)) == 0)
    return n;

  int log2 = log2_floor (n);
  int result = 1 << (log2 + 1);
/* printf ("round_up_power_two (%d/0x%x) => %d/0x%x\n", n, n, result, result);*/
  return result;
}

/* returns 0 if it fails, otherwise the number of bytes used */
static int init_table_size (struct table * table, int num_entries,
                            int num_data_bytes, int max_bytes)
{
  int needed_per_slot = sizeof (struct table_entry *);
  int needed_per_entry = sizeof (struct table_entry) + num_data_bytes;
  if (needed_per_entry % 8 != 0) {
  /* make the size a multiple of 8 bytes, which gives 64-bit alignment */
    int mod = needed_per_entry % 8;
    needed_per_entry += 8 - mod;
  }

  int num_slots = round_up_power_two (num_entries);
  int needed = needed_per_entry * num_entries + num_slots * needed_per_slot;
/*
  printf ("needed is %d * %d + %d * %d = %d\n",
          needed_per_entry, num_entries, num_slots, needed_per_slot, needed);
*/
  if (needed > max_bytes) {
    /* slight approximation -- assume we need twice as many slots as table
       entries.  This is safe, but may give us somewhat fewer entries than
       we could otherwise have. */
    num_entries = max_bytes / (needed_per_entry + 2 * needed_per_slot);
    num_slots = round_up_power_two (num_entries);
    needed = needed_per_entry * num_entries + num_slots * needed_per_slot;
/*
    printf ("new needed is %d * %d + %d * %d = %d\n",
            needed_per_entry, num_entries, num_slots, needed_per_slot, needed);
*/
  }
  if (num_entries == 0)
    return 0;

  char * new_space = malloc (needed);
  if (new_space == NULL) {
    printf ("unable to allocate %d bytes for table storage\n", needed);
    return 0;
  }
  if (table->storage != NULL)
    free (table->storage);
  table->storage = new_space;
  /* put slots (i.e. the table) after the entries */
  int offset = num_entries * needed_per_entry;
  table->table = ((struct table_entry **) (table->storage + offset));
  /* the first entry is at the beginning of storage */
  table->freeptr = table->storage;
  table->num_entries = num_entries;
  table->num_slots = num_slots;
  table->bytes_per_entry = num_data_bytes;
  table->storage_size = needed;
  int i;
  for (i = 0; i < num_slots; i++)
    table->table [i] = NULL;
/*
  printf ("initialized %d-byte table %d entries %d user bytes, %d slots\n",
          needed, num_entries, num_data_bytes, num_slots);
*/
  return needed;
}

#if 0
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
      result = result | ((bitstring [1] & 0xff) <<  8);
  }
  if (result < 0)
    return - result;
  return result;
}
#endif /* 0 */

static void get_indices (char * bitstring, int bits, int num_slots,
                         int * first_index, int * last_index)
{
  /* num_slots should be a power of two, so log2_floor should equal log2 */
  /* and that is the number of bits to use for indexing */
  int log2 = log2_floor (num_slots);
  int bits_to_use = log2;
  if (bits_to_use > bits)  /* too few bits in bitstring, so multiple indices */
    bits_to_use = bits;
  int index = 0;
  int i = 0;
  while (bits_to_use >= 8) {
    index = ((index << 8) | (bitstring [i] & 0xff));
    bits_to_use -= 8;
    i++;
  }
  if (bits_to_use > 0)
    index = ((index << bits_to_use) |
             ((bitstring [i] & 0xff) >> (8 - bits_to_use)));
  if (bits_to_use <= bits) {
    *first_index = index;
    *last_index  = index;
  } else {
    *first_index = index << (bits_to_use - bits);
    /* next statement does not work if
         (index + 1) << (bits_to_use - bits) >= 2^32,
       which implies a 4GB table, which leads to negative indices anyway.
       so it should be OK
     */
    *last_index = ((index + 1) << (bits_to_use - bits)) - 1;
  }
/*
  printf ("get_indices (%02x %02x %02x %02x, %d, %d) => %d, %d\n",
                          bitstring [0] & 0xff,
          ((bits >  8) ? (bitstring [1] & 0xff) : 0),
          ((bits > 16) ? (bitstring [2] & 0xff) : 0),
          ((bits > 24) ? (bitstring [3] & 0xff) : 0),
          bits, num_slots, *first_index, *last_index);
*/
}

#if 0  /* older version repeats the code in util.c/matches */
static int bits_match (char * data, int bytes, char * bitstring, int bits)
{
  int min_bits = bits;
  if (min_bits > bytes * 8)
    min_bits = bytes * 8;
  int min_bytes = min_bits / 8;
  if (memcmp (data, bitstring, min_bytes) != 0)
    return 0;   /* whole bytes don't match */

  int trailing_bits = min_bits % 8;
  if (trailing_bits == 0)   /* no trailing bits */
    return 1;   /* whole bytes match, so it is a match */

  int b1 = (data      [min_bytes] & 0xff) >> (8 - trailing_bits);
  int b2 = (bitstring [min_bytes] & 0xff) >> (8 - trailing_bits);
  if (b1 == b2)
    return 1;    /* match */
  return 0;      /* no match */
}
#endif /* 0 */

/* returns 1 if found, 0 otherwise */
/* if returns 1, also fills in *data and *dsize */
int table_find (char * bitstring, int bits, struct table * table,
                char ** data, int * dsize)
{
  *data = NULL;
  *dsize = 0;

  static int print_not_implemented = 1;
  if (print_not_implemented) {
    printf ("table_find: public key storage not implemented\n");
    print_not_implemented = 0;
  }

  if (table->table == NULL)
    return 0;

  int first, last;
  get_indices (bitstring, bits, table->num_slots, &first, &last);
  while (first <= last) {
    struct table_entry * entry = table->table [first];
    while (entry != NULL) {
      /* print_table_entry (first, entry, table->bytes_per_entry); */
      if (matches ((unsigned char *) (entry->data), table->bytes_per_entry * 8,
                   (unsigned char *) bitstring, bits))
        return 1;
      /* printf ("no match on entry\n"); */
      entry = entry->next;
    }
    first++;
  }
  return 0;   /* not found */
}

/* everything should have been allocated, so error checking is only for
 * debugging */
static void table_add (struct table * table, char * data, int dsize)
{
  int first, last;
  get_indices (data, dsize * 8, table->num_slots, &first, &last);
  if (first != last) {
    printf ("error: table_add dsize %d less than %d needed fro addressing\n",
            dsize * 8, log2_floor (table->num_slots));
    exit (1);
  }
  /* index to use is first == last */
  int entry_size = 8;   /* to do: fix this (was: table->bytes_per_entry;) */
  struct table_entry * new = (struct table_entry *) table->freeptr;
  if (table->freeptr + entry_size > ((char *) table->table)) { /* overflow */
    static int printed = 0;
    if (printed == 0) {  /* only print once */
      printf ("warning: out of space for new table entries\n");
/*
      printf ("warning: out of space for table entries, %p %p %d\n",
              table->freeptr, table->table, entry_size);
*/
      printed = 1;
    }
    return;
  }
  table->freeptr += entry_size;
  /* link the new entry to the old entry (if any) */
  new->next = table->table [first];
  if (dsize > table->bytes_per_entry)
    dsize = table->bytes_per_entry;
  memcpy (new->data, data, dsize);
  table->table [first] = new;
  /* printf ("added new entry at index %d\n", first); */
}

static int countlines (int fd, int maxlen)
{
  if (lseek (fd, 0, SEEK_SET) == ((off_t) -1)) {
    perror ("countlines lseek");
    return 0;
  }
  int result = 0;
  int r;   /* result from reading */
  int this_line = 0;   /* how many bytes in this line */
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
    perror ("table read");
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
  printf ("error: table line in file has char %d/%x\n", c, c);
  exit (1);
}

int hexbyte (int c1, int c2)
{
  return (hexvalue (c1) << 4) | (hexvalue (c2));
}

#define MAX_ENTRY	1024
/* return the number of bytes read, or 0 if there are more than dsize */
static int readline_bytes (int fd, char * data, int dsize)
{
  if (dsize <= 0)
    return 0;
  char line [MAX_ENTRY * 2 + 1];
  int chars = 0;
  while (chars < sizeof (line)) {
    int r = read (fd, line + chars, 1);
    if ((r == 1) && (line [chars] == '\n'))
      break;       /* done!  Convert the hex to binary */
    chars++;
  }
  if (chars >= sizeof (line)) {    /* ran out of room, which is an error */
    printf ("error: table line in file exceeds %zd bytes\n", sizeof (line));
    return 0;
  }
  if (chars != 2 * dsize) {
    printf ("error: table line in file is %d, expected %d \n",
            chars, 2 * dsize);
    return 0;
  }
  int index = 0;
  for (index = 0; index < dsize; index++)
    data [index] = hexbyte (line [index * 2], line [index * 2 + 1]);
  return dsize;
}

/* returns the number of bytes in the table. */
/* will not exceed free_bytes, ignoring entries that would require
 * too much room */
/* ignores entries that have more or fewer than bytes_per_entry */
/* in case of failure returns 0 and the table is unchanged */
int table_from_file (struct table * table,
		     int fd, int bytes_per_entry, int free_bytes)
{
  if (bytes_per_entry > MAX_ENTRY) {  /* sanity check */
    printf ("error: table can only handle %d bytes, requested %d\n",
            MAX_ENTRY, bytes_per_entry);
    return 0;  /* no change */
  }
  int num_lines = countlines (fd, bytes_per_entry * 2);
  int num_entries = num_lines;
  if (bytes_per_entry < 4) {
    /* maximum addressable entries with the given number of bits */
    int max_entries = 1 << (bytes_per_entry * 8);
    /* no sense putting any more than this many entries in the table */
    if (max_entries < num_entries)
      num_entries = max_entries;
  }
  int bytes_used = init_table_size (table, num_entries,
                                    bytes_per_entry, free_bytes);
  if (bytes_used == 0)
    return 0;

  while (num_lines-- > 0) {
    char line [MAX_ENTRY];
    int bytes = readline_bytes (fd, line, bytes_per_entry);
    if (bytes > 0)
      table_add (table, line, bytes);
  }
  return bytes_used;
}

/* for debugging */
void print_table_entry (int index, struct table_entry * entry,
                        int num_data_bytes)
{
  while (entry != NULL) {
    printf ("%d (%p): next %p, data %d: ", index, entry, entry->next,
            num_data_bytes);
    int i;
    for (i = 0; i < num_data_bytes && i < 10; i++)
      printf (" %02x", entry->data [i] & 0xff);
    if (i < num_data_bytes)
      printf (" ...");
    printf ("\n");

    entry = entry->next;
  }
}
