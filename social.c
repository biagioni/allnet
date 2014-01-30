/* social.c: keep track of social network distance */
/* to do: lots!!!  Including keeping track by source address and
 * by packet certificate.
 */

#include <stdio.h>
#include <stdlib.h>

#include "packet.h"
#include "social.h"
#include "lib/table.h"
#include "lib/config.h"
#include "lib/log.h"

struct social_one_tier {
  int address_bytes_per_entry;
  /* the IDs and public keys of the contacts, in a table */
  struct table connections;
};

static void print_social_tier (int tier, struct social_one_tier * soc)
{
  snprintf (log_buf, LOG_SIZE,
            "social tier %d: %d contacts, %d slots, total size %d\n", tier,
            soc->connections.num_entries, soc->connections.num_slots,
            soc->connections.storage_size);
  log_print ();
/*
  snprintf (log_buf, LOG_SIZE,
            "  %d entries with %d user bytes give %d bytes, total %d bytes\n",
            soc->connections.num_entries, soc->connections.bytes_per_entry,
            soc->address_bytes_per_entry, soc->connections.storage_size);
  log_print ();
  int i;
  for (i = 0; i < soc->connections.num_slots; i++)
    print_table_entry (i, soc->connections.table [i],
                       soc->connections.num_data_bytes);
 */
}

/* keep track of people up to distance 3, friends of friends of friends
 define MAX_SOCIAL_TIER		3
*/

struct social_info {
  struct social_one_tier info [MAX_SOCIAL_TIER];
  int max_bytes;    /* should not use more than max_bytes of storage */
  int max_check;    /* should not check more than max_check sigs per call */
};

struct social_info * init_social (int max_bytes, int max_check)
{
  struct social_info * result = malloc (sizeof (struct social_info));
  if (result == NULL) {
    perror ("init_social(0) malloc");
    snprintf (log_buf, LOG_SIZE, "unable to allocate %zd bytes for social\n",
              sizeof (struct social_info));
    log_print ();
    exit (1);
  }
  result->max_bytes = max_bytes;
  result->max_check = max_check;
  int bytes = ADDRESS_SIZE;
  int i;
  for (i = 0; i < MAX_SOCIAL_TIER; i++) {
    init_table (&result->info [i].connections);
    result->info [i].address_bytes_per_entry = bytes;
    if (bytes == ADDRESS_SIZE)
      bytes -= 2;
    else
      bytes --;
  }
  return result;
}

/* return the number of bytes in the updated social tier, and in
 * any case never more than free_entries */
static int update_social_tier (int tier, struct social_one_tier * st,
                               int free_bytes)
{
  if (tier > 99) {
    snprintf (log_buf, LOG_SIZE,
              "error, using social tier %d, maximum tier is 99\n", tier);
    log_print ();
    if (st->connections.storage != NULL)
      free (st->connections.storage);
    init_table (&(st->connections));
    return 0;
  }
  char file_name [] = "social12";  /* two digits allow up to 99 tiers */
  snprintf (file_name, sizeof (file_name), "social%d", tier);
  static int printed = 0;
  int fd = open_read_config ("ad", file_name, ! printed);
  if (fd < 0) {
    char * path;
    int result = config_file_name ("ad", file_name, &path);
    if (! printed) {
      if (fd == -1)   /* no such file */
        snprintf (log_buf, LOG_SIZE,
                  "no social info file %s for ad, continuing\n", path);
      else
        snprintf (log_buf, LOG_SIZE,
                  "error reading social info file %s for ad\n", path);
     log_print ();
    }
    printed = 1;
    free (path);
    return free_bytes;
  }
  int bytes = table_from_file (&(st->connections), fd,
                               st->address_bytes_per_entry, free_bytes);
  close (fd);
  if (bytes != 0)
    return bytes;
  else   /* did not read from file, using older one */
    return st->connections.storage_size;
}

time_t update_social (struct social_info * soc, int update_seconds)
{
  int free_bytes = soc->max_bytes;
  int i;
  for (i = 0; i < MAX_SOCIAL_TIER; i++) {
    free_bytes -= update_social_tier (i, soc->info + i, free_bytes);
    print_social_tier (i, soc->info + i);
  }
  return (time (NULL) + update_seconds);
}

/* return 1 if the signature verifies the buffer for the given key,
 * and otherwise returns 0 */
static int verify_sig (char * buf, int bsize, int algo, char * sig, int ssize,
                       char * key, int ksize)
{
  static int print = 1;
  if (print) {
    printf ("need to implement verify_sig, for now returning 1\n");
    print = 0;
  }
  return 1;
}

/* checks the signature, and sets valid accordingly.
 * returns the social distance if known, and UNKNOWN_SOCIAL_TIER otherwise */
int social_connection (struct social_info * soc, char * verify, int vsize,
                       char * src, int sbits, int algo, char * sig, int ssize,
                       int * valid)
{
  *valid = 0;
  int checked = 0;
  int i;
  for (i = 0; (i < MAX_SOCIAL_TIER) && (checked < soc->max_check); i++) {
    /* to do: move verification to table_find (otherwise table_find always
       returns the same result */
    char * public_key;
    int ksize;
    if (table_find (src, sbits, &(soc->info [i].connections),
                    &public_key, &ksize)) {
      if (verify_sig (verify, vsize, algo, sig, ssize, public_key, ksize)) {
        *valid = 1;
        return i + 1;
      }
      checked++;
    }
  }
  return UNKNOWN_SOCIAL_TIER;
}

#if 0
int social_connection (struct social_info * soc, char * src, int sbits,
                       char * dest, int dbits)
{
  int result = COMPLETE_STRANGER;
  if (dbits < 8)   /* less than 8 bits, no use even checking */
    return result;
  int i;
  for (i = 0; i < MAX_SOCIAL_TIER; i++) {
    if (table_find (dest, dbits, &(soc->info [i].connections))) {
      result = i + 1;
      break;
    }
  }
  /* for every 4 additional bits beyond 8, allow it to be one degree closer */
  int best_allowed = COMPLETE_STRANGER - (dbits - 4) / 4;
  if (best_allowed < 1) best_allowed = 1;   /* one means a friend */
  /* printf ("result %d, best allowed %d for %d bits\n", result, best_allowed, dbits); */
  if (result < best_allowed) result = best_allowed;
  return result;
}
#endif /* 0 */
