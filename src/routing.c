/* routing.c: maintain routing tables for the Distributed Hash Table */

#include <stdio.h>
#include <string.h>
#include <pthread.h>

#include "lib/packet.h"
#include "lib/mgmt.h"
#include "lib/util.h"

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

static int fd = -1;

static int open_file ()
{
  static int initialized = 0;
  if (! initialized) {
    initialized = 1;
  }
  return -1;
}

/* returns a malloc'd array containing the top matches (up to max_matches)
 * for the given address.
 * returns zero and sets *result to NULL if there are no matches */
int routing_top_dht_matches (struct addr_info * addr, int max_matches,
                             struct addr_info ** result)
{
  pthread_mutex_lock (&mutex);
  int fd = open_file ();
  pthread_mutex_unlock (&mutex);
  printf ("routing_top_dht_matches not implemented\n");
  *result = NULL;
  return 0;
}

/* either adds or refreshes a DHT entry */
int routing_add_dht (struct addr_info * addr)
{
  pthread_mutex_lock (&mutex);
  int fd = open_file ();
  pthread_mutex_unlock (&mutex);
  printf ("routing_add_dht not implemented\n");
  return 0;
}

/* expires old DHT entries that haven't been refreshed since the last call */
int routing_expire_dht (struct addr_info * addr)
{
  pthread_mutex_lock (&mutex);
  int fd = open_file ();
  pthread_mutex_unlock (&mutex);
  printf ("routing_expire_dht not implemented\n");
  return 0;
}

/* fills in the given array, which must have room for num_entries addr_infos,
 * with data to send.
 * returns the actual number of entries, which may be less than num_entries */
int routing_table (struct addr_info * data, int num_entries)
{
  if (num_entries <= 0)
    return 0;
  pthread_mutex_lock (&mutex);
  int fd = open_file ();
  pthread_mutex_unlock (&mutex);
  printf ("routing_table (%d) not implemented\n", num_entries);
  /* create a fake entry */
  memset (data, 0, sizeof (struct addr_info));
  int i;
  for (i = 0; i < sizeof (data->ip.ip); i++)
    ((char *) (&(data->ip.ip))) [i] = i + 1;
  data->ip.port = 0x7856;
  data->ip.ip_version = 6;
  random_bytes (data->destination, ADDRESS_SIZE);
  data->nbits = 32;
  data->type = ALLNET_ADDR_INFO_DHT;
  return 1;
}

