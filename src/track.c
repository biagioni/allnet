/* track.c: keep track of recently received packets */
/* to do: fully integrate source as well as destination */

#include <stdio.h>
#include <string.h>

#include "lib/packet.h"
#include "lib/priority.h"

#define SAVED_ADDRESSES	128

struct rate_record {
  char address [ADDRESS_SIZE];
  unsigned char num_bits;
  int packet_size;
};

static struct rate_record record [SAVED_ADDRESSES];

static int next = -1;

/* return 1 if the address and record match, 0 otherwise */
static int matching (char * address, int bits, struct rate_record * record)
{
  int min_bits = (bits < record->num_bits) ? bits : record->num_bits;
  int full_bytes = min_bits / 8;
  int odd_bits = min_bits % 8;
  if ((full_bytes > 0) && (memcmp (address, record->address, full_bytes) != 0))
    return 0;   /* no match in the full bytes */
  if (odd_bits > 0) {
    int c1 = (address         [full_bytes] >> (8 - odd_bits)) & 0xff;
    int c2 = (record->address [full_bytes] >> (8 - odd_bits)) & 0xff;
    if (c1 != c2)
      return 0;
  }
  return 1;  /* matches the full bytes and the odd bits if any */
}

#define DEFAULT_MAX	(ALLNET_PRIORITY_MAX - 1)

/* return the rate of the sender that is sending the most at this time */
/* used by default when we cannot prove who the sender is */
int largest_rate ()
{
  if (next < 0) {   /* uninitialized, return default */
    return DEFAULT_MAX;
  } else {
    printf ("to do: implement largest rate\n");
    return DEFAULT_MAX;
  }
}

/* record that this source is sending this packet of given size */
/* return an integer, as a fraction of ALLNET_PRIORITY_MAX, to indicate what
 * fraction of the available bandwidth this source is using.
 * ALLNET_PRIORITY_MAX is defined in priority.h
 */
int track_rate (char * source, int sbits, int packet_size)
{
  if (packet_size <= 0) {
    printf ("error in track_rate: illegal packet size %d, returning epsilon\n",
            packet_size);
    return largest_rate ();
  }

  int i;
  if (next < 0) {    /* initialize */
    for (i = 0; i < SAVED_ADDRESSES; i++) {
      memset (record [i].address, 0, ADDRESS_SIZE);
      record [i].num_bits = 0;
      record [i].packet_size = 0;
    }
    next = 0;
  }

  /* how many saved packets have the same source as this one? */
  int matches = 0;
  int total = 0;
  for (i = 0; i < SAVED_ADDRESSES; i++) {
    if (record [i].packet_size > 0) {
      total += record [i].packet_size;
      if (matching (source, sbits, record + i))
        matches += record [i].packet_size;
    }
  }

  /* save this packet */
  memcpy (record [next].address, source, ADDRESS_SIZE);
  record [next].num_bits = sbits;
  record [next].packet_size = packet_size;
  next = (next + 1) % SAVED_ADDRESSES;

  matches += packet_size;    /* add in this packet */
  total += packet_size;    /* add in this packet */

  if (total == 0) {
    printf ("error in track_rate: illegal total size %d, returning one\n",
            total);
    return DEFAULT_MAX;
  }
  printf ("total %d, matching %d\n", total, matches);
  return (ALLNET_PRIORITY_MAX / total) * matches;
}

#if 0
int track_rate (char * source, int sbits, char * destination, int dbits,
                int packet_size)
{
  if (packet_size <= 0) {
    printf ("error in track_rate: illegal packet size %d, returning epsilon\n",
            packet_size);
    return 1;
  }

  int i;
  if (next < 0) {
    /* initialize */
    for (i = 0; i < SAVED_ADDRESSES; i++) {
      memset (record [i].dest, 0, ADDRESS_SIZE);
      record [i].num_bits = 0;
      record [i].packet_size = 0;
    }
    next = 0;
  }

/*
  for (i = 0; i < SAVED_ADDRESSES; i++)
    printf ("track_rate %d: %02x %02x %02x %02x, %d, %d\n", i,
            record [i].dest [0] & 0xff, record [i].dest [1] & 0xff,
            record [i].dest [2] & 0xff, record [i].dest [3] & 0xff,
            record [i].num_bits, record [i].packet_size);
*/

  /* how many saved packets have the same destination as this one? */
  int matches = 0;
  int total = 0;
  for (i = 0; i < SAVED_ADDRESSES; i++) {
    if (record [i].packet_size > 0) {
      total += record [i].packet_size;
      if (matching (destination, dbits, record + i))
        matches += record [i].packet_size;
    }
  }

  /* save this packet */
  memcpy (record [next].dest, destination, ADDRESS_SIZE);
  record [next].num_bits = dbits;
  record [next].packet_size = packet_size;
  next = (next + 1) % SAVED_ADDRESSES;

  matches += packet_size;    /* add in this packet */
  total += packet_size;    /* add in this packet */

  if (total == 0) {
    printf ("error in track_rate: illegal total size %d, returning one\n",
            total);
    return ALLNET_PRIORITY_MAX;
  }
  printf ("total %d, matching %d\n", total, matches);
  return (ALLNET_PRIORITY_MAX / total) * matches;
}
#endif /* 0 */

