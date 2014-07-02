/* table.h: store arbitrary bitstrings */

#ifndef ALLNET_TABLE_H
#define ALLNET_TABLE_H

struct table {
  int num_entries;
  int num_slots;    /* the next higher power of two for num_entries */
  struct table_entry ** table;
  int bytes_per_entry;   /* how many bytes are kept per entry */
  int stored_size;
  int storage_size;
  char * storage;   /* freed when reallocating */
  char * freeptr;   /* data available */
};

/* initializes to an empty state, where essentially no space is used */
extern void init_table (struct table * table);

/* will not exceed free_bytes, ignoring entries that would require
 * too much room */
/* returns the number of bytes in the table. */
/* in case of failure returns 0 and the table is unchanged */
extern int table_from_file (struct table * table, int fd,
                            int bytes_per_entry, int free_bytes);

/* returns 1 if found, 0 otherwise */
/* if returns 1, also fills in *data and *dsize */
extern int table_find (char * bitstring, int bits, struct table * table,
                       char ** data, int * dsize);

/* for debugging */
extern void print_table_entry (int index, struct table_entry * entry,
                               int num_data_bytes);

#endif /* ALLNET_TABLE_H */
