/* social.c: keep track of social network distance */
/* social level 0 (our own contacts) is tracked independently by keys.c,
 * so here we (a) return the results from key.c for level 0, and
 * (b) keep track of and return the results for social levels 1 and 2 */
/* to do: lots!!!  Including keeping track by source address and
 * by packet signature.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "social.h"
#include "lib/packet.h"
#include "lib/util.h"
#include "lib/table.h"
#include "lib/config.h"
#include "lib/log.h"
#include "lib/keys.h"
#include "lib/cipher.h"
#include "lib/priority.h"

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
 * any case never more than free_bytes */
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
    if (result < 0) {
      snprintf (log_buf, LOG_SIZE, "unable to get config file name\n");
      log_print ();
      return 0;
    }
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
  for (i = 1; i < MAX_SOCIAL_TIER; i++) {  /* skip social level 0 */
    free_bytes -= update_social_tier (i, soc->info + i, free_bytes);
    print_social_tier (i, soc->info + i);
  }
  return (time (NULL) + update_seconds);
}

/* returns 1 if this message is from my contact, and 0 otherwise */
static int is_my_contact (char * message, int msize,
                          unsigned char * sender, int bits,
                          int algo, char * sig, int ssize)
{
  char ** contacts;
  int nc = all_contacts (&contacts);
  int ic;
  for (ic = 0; ic < nc; ic++) {
    keyset * keysets;
    int nk = all_keys (contacts [ic], &keysets);
    int ink;
    for (ink = 0; ink < nk; ink++) {
      unsigned char address [ADDRESS_SIZE];
      int na_bits = get_remote (keysets [ink], address);
      char * key;
      int ksize = get_contact_pubkey (keysets [ink], &key);
      if ((ksize > 0) && (matches (sender, bits, address, na_bits) > 0) &&
          (allnet_verify (message, msize, sig, ssize, key, ksize))) {
        snprintf (log_buf, LOG_SIZE, "verified from contact %d %d\n", ic, ink);
        log_print ();
        return 1;
      }
    }
  }

  struct bc_key_info * bc;
  int nbc = get_other_keys (&bc);
  int ibc;
  for (ibc = 0; ibc < nbc; ibc++) {
    if ((matches (sender, bits,
                  (unsigned char *) (bc [ibc].address), ADDRESS_BITS) > 0) &&
        (allnet_verify (message, msize, sig, ssize,
                 bc [ibc].pub_key, bc [ibc].pub_klen))) {
      snprintf (log_buf, LOG_SIZE, "verified from bc contact %d\n", ibc);
      log_print ();
      return 1;
    }
  }
/* printf ("is_my_contact (%d, %d) => 0\n", nc, nbc); */
  return 0;
}

/* checks the signature, and sets valid accordingly.
 * returns the social distance if known, and UNKNOWN_SOCIAL_TIER otherwise */
int social_connection (struct social_info * soc, char * vmessage, int vsize,
                       unsigned char * src, int sbits, int algo,
                       char * sig, int ssize, int * valid)
{
snprintf (log_buf, LOG_SIZE, "social_connection (%d) called\n", algo);
log_print ();
  if (algo == ALLNET_SIGTYPE_NONE)
    return UNKNOWN_SOCIAL_TIER;
  *valid = 0;
  if (is_my_contact (vmessage, vsize, src, sbits, algo, sig, ssize)) {
    *valid = 1;
    return 1;
  }
#if 0    /* to do: keep track of public keys of f^n */
  int checked = 0;
  int i;
  for (i = 1; (i < MAX_SOCIAL_TIER) && (checked < soc->max_check); i++) {
    /* to do: move verification to table_find (otherwise table_find always
       returns the same result */
    char * public_key;
    int ksize;
    if (table_find (src, sbits, &(soc->info [i].connections),
                    &public_key, &ksize)) {
      if (verify (vmessage, vsize, sig, ssize, public_key, ksize)) {
        *valid = 1;
        return i + 1;
      }
      checked++;
    }
  }
#endif /* 0 */
  return UNKNOWN_SOCIAL_TIER;
}

