/* hash.h: store arbitrary bitstrings */

#ifndef ALLNET_HASH_H
#define ALLNET_HASH_H

struct hash_table {
  int num_entries;
  int user_bytes;        /* bytes of user data in each entry */
  int bytes_per_entry;   /* bytes allocated in each entry */
  struct hash_entry ** table;
  int storage_size;
  char * storage;
  char * freeptr;
};

/* will not exceed free_bytes, ignoring entries that would require
 * too much room */
/* ignores entries that have more or fewer than bytes_per_entry */
/* returns the number of bytes in the hash table. */
/* in case of failure returns 0 and the hash table is unchanged */
extern int hash_from_file (struct hash_table * hash,
                           int fd, unsigned int bytes_per_entry,
                           unsigned int free_bytes);

/* returns 1 if found, 0 otherwise */
extern int hash_find (char * bitstring, int bits,
                      struct hash_table * hash_table);

extern void init_hash_table (struct hash_table * hash);

/* possibly useful elsewhere */
extern int my_hash_fn (char * data, int bits);

/* for debugging */
extern void print_hash_entry (struct hash_entry * entry, int user_data);

#endif /* ALLNET_HASH_H */
