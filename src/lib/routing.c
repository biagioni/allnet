/* routing.c: maintain routing tables for the Distributed Hash Table */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <net/if.h>
#include <arpa/inet.h>

#include "packet.h"
#include "mgmt.h"
#include "util.h"
#include "ai.h"
#include "allnet_log.h"
#include "configfiles.h"

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

/* up to 4 DHT neighbors per address bit */
#define PEERS_PER_BIT	4
#define MAX_PEERS	(ADDRESS_BITS * PEERS_PER_BIT)

struct peer_info {
  struct addr_info ai;
  int refreshed;
};

struct peer_info peers [MAX_PEERS];

/* for now use a fixed-size array of addr_infos to store the ping list. */
/* addresses are added at the front and dropped from the back */
#define MAX_PINGS	128

static struct peer_info pings [MAX_PINGS];

static char my_address [ADDRESS_SIZE] = {0, 0, 0, 0, 0, 0, 0, 0};

/* some of these domain names may not be defined, but at least some should be */
/* in case DNS is broken, we include the current IPv4 address for alnt.org */
static char * default_dns [] =
  { "a0.alnt.org", "108.161.130.251",
    "a1.alnt.org", "a2.alnt.org", "a3.alnt.org",
    "a4.alnt.org", "a5.alnt.org", "a6.alnt.org", "a7.alnt.org",
    "a8.alnt.org", "a9.alnt.org", "aa.alnt.org", "ab.alnt.org",
    "ac.alnt.org", "ad.alnt.org", "ae.alnt.org", "af.alnt.org" };
#define NUM_DEFAULTS	((sizeof (default_dns)) / (sizeof (char *)))
struct sockaddr_storage ip4_defaults [NUM_DEFAULTS];
struct sockaddr_storage ip6_defaults [NUM_DEFAULTS];

/* 0 before initialization, -1 during initialization, 1 after initialization */
static int dns_init = 0;

/* if the address in ~/.allnet/adht/my_id begins with '-', generate a
 * new address on every invocation (and perhaps more frequently?) */
static int save_my_own_address = 1;

static struct allnet_log * alog = NULL;

/* save addresses every day (86400s) even if there are no new ones */
#define PEER_SAVE_TIME		86400

void print_dht (int to_log)
{
  if ((dns_init <= 0) || (alog == NULL)) {  /* not initialized */
#ifdef DEBUG_PRINT
    printf ("print_dht called before initialization, state %d, alog %p\n",
            dns_init, alog);
#endif /* DEBUG_PRINT */
    return;
  }
  int npeers = 0;
  int i;
  for (i = 0; i < MAX_PEERS; i++)
    if (peers [i].ai.nbits != 0)
      npeers++;
  int n = snprintf (alog->b, alog->s, "%d peers: ", npeers);
  n += buffer_to_string (my_address, ADDRESS_SIZE, "my address is",
                         ADDRESS_SIZE, 1, alog->b + n, alog->s - n);
  if (to_log) log_print (alog); else printf ("%s", alog->b);
  for (i = 0; i < MAX_PEERS; i++) {
    if (peers [i].ai.nbits != 0) {
      n = snprintf (alog->b, alog->s, "%3d (%d): ", i, peers [i].refreshed);
      addr_info_to_string (&(peers [i].ai), alog->b + n, alog->s - n);
      if (to_log) log_print (alog); else printf ("%s", alog->b);
    }
  }
}

void print_ping_list (int to_log)
{
  if ((dns_init <= 0) || (alog == NULL)) {  /* not initialized */
#ifdef DEBUG_PRINT
    printf ("print_ping_list called before initialization, state %d, alog %p\n",
            dns_init, alog);
#endif /* DEBUG_PRINT */
    return;
  }
  int i, n;
  int count = 0;
  for (i = 0; i < MAX_PINGS; i++)
    if (pings [i].ai.nbits > 0)
      count++;
  snprintf (alog->b, alog->s, "pings: %d\n", count);
  if (to_log) log_print (alog); else printf ("%s", alog->b);
  for (i = 0; i < MAX_PINGS; i++) {
    if (pings [i].ai.nbits > 0) {
      n = snprintf (alog->b, alog->s, "%3d (%d): ", i, pings [i].refreshed);
      addr_info_to_string (&(pings [i].ai), alog->b + n, alog->s - n);
      if (to_log) log_print (alog); else printf ("%s", alog->b);
    }
  }
}

static int not_already_listed (struct sockaddr_storage * sap,
                               struct sockaddr_storage * already, int na)
{
  int i;
  struct addr_info compare_ai;
  sockaddr_to_ai ((struct sockaddr *) sap, sizeof (struct sockaddr_storage),
                  &compare_ai);
  for (i = 0; i < na; i++) {
    struct addr_info this_ai;
    sockaddr_to_ai ((struct sockaddr *) (already + i),
                    sizeof (struct sockaddr_storage), &this_ai);
    if (same_ai (&compare_ai, &this_ai))
      return 0;
  }
  return 1;
}

/* run as a thread since getaddrinfo can be extremely slow (10's of seconds) */
static void * init_default_dns (void * arg)
{
  int * initialized = (int *) arg;
  char service [10];
  snprintf (service, sizeof (service), "%d", ALLNET_PORT);
  unsigned int i;
  /* begin connecting at a random position in the DNS array */
  unsigned int random_offset = (unsigned int)(random_int (0, NUM_DEFAULTS - 1));
  for (i = 0; i < NUM_DEFAULTS; i++) {
    ip4_defaults [i].ss_family = 0;
    ip6_defaults [i].ss_family = 0;
    struct addrinfo * next;
    int dns_index = (random_offset + i) % NUM_DEFAULTS;
    int code = getaddrinfo (default_dns [dns_index], service, NULL, &next);
    if (code == 0) {   /* getaddrinfo succeded */
      struct addrinfo * original = next;  /* so we can free it */
      while (next != NULL) {
#ifdef DEBUG_PRINT
        print_sockaddr (next->ai_addr, next->ai_addrlen, -1);
        printf ("\n");
#endif /* DEBUG_PRINT */
        struct sockaddr * sap = NULL;
        if ((next->ai_family == AF_INET) && (ip4_defaults [i].ss_family == 0))
          sap = (struct sockaddr *) (&(ip4_defaults [i]));
        else if ((next->ai_family == AF_INET6) &&
                 (ip6_defaults [i].ss_family == 0))
          sap = (struct sockaddr *) (&(ip6_defaults [i]));
        else if ((next->ai_family != AF_INET) && (next->ai_family != AF_INET6))
          printf ("init_default_dns: unknown address family %d (%d, %d)\n",
                  next->ai_family, ip4_defaults [i].ss_family,
                  ip6_defaults [i].ss_family);
        if ((sap != NULL) &&
            (next->ai_addrlen <= sizeof (struct sockaddr_storage)))
          memcpy ((char *) sap, (char *) (next->ai_addr), next->ai_addrlen);
        next = next->ai_next;
      }
      freeaddrinfo (original);
    } else {
#ifdef DEBUG_PRINT
      {   /* print unconditionally */
#else /* ! DEBUG_PRINT */
      if (code != EAI_NONAME) {
#endif /* DEBUG_PRINT */
        snprintf (alog->b, alog->s, "getaddrinfo (%s): %s\n",
                  default_dns [dns_index], gai_strerror (code));
        log_print (alog);
      }
    }
  }
#ifdef DEBUG_PRINT
  for (i = 0; i < NUM_DEFAULTS; i++) {
    printf ("%d: (4 and 6): ", i);
    print_sockaddr ((struct sockaddr *) (&(ip4_defaults [i])),
                    sizeof (struct sockaddr_in), -1);
    printf (" ");
    print_sockaddr ((struct sockaddr *) (&(ip6_defaults [i])),
                    sizeof (struct sockaddr_in6), -1);
    printf ("\n");
  }
#endif /* DEBUG_PRINT */
  *initialized = 1;
  snprintf (alog->b, alog->s, "init_default_dns is complete\n");
  log_print (alog);
  dns_init = 1;  /* done initializing addresses from dns */
  return NULL;
}

static void start_dns_thread ()
{
  if (dns_init == -1)  /* already running */
    return;
  dns_init = -1;   /* initialization in progress */
  pthread_attr_t attr;
  pthread_attr_init (&attr);
  pthread_attr_setdetachstate (&attr, PTHREAD_CREATE_DETACHED);
  pthread_t thread;
  pthread_create (&thread, &attr, init_default_dns, (void *) (&dns_init));
}

/* returns number of entries added, 0...max */
static int add_default_routes (struct sockaddr_storage * result,
                               int off, int max)
{
  unsigned int i;
  int number = off;
  for (i = 0; (i < NUM_DEFAULTS) && (number >= 0) && (number < max); i++) {
    if ((ip4_defaults [i].ss_family == AF_INET) &&
        (not_already_listed (ip4_defaults + i, result, number)))
      result [number++] = ip4_defaults [i];
    if ((number < max) && (ip6_defaults [i].ss_family == AF_INET6) &&
        (not_already_listed (ip6_defaults + i, result, number)))
      result [number++] = ip6_defaults [i];
  }
  if ((number == off) && (dns_init == 1))
    start_dns_thread (); /* done initializing but no entries found, so repeat */
  return number - off;
}

static time_t peers_file_time = 0;

static int entry_to_file (int fd, struct addr_info * entry, int index)
{
  char line [300];
  char buf [200];
  if (entry->nbits != 0) {
    addr_info_to_string (entry, buf, sizeof (buf));
    if (index >= 0)
      snprintf (line, sizeof (line), "%d: %s", index, buf);
    else
      snprintf (line, sizeof (line), "p: %s", buf);
    if (write (fd, line, strlen (line)) != (int) (strlen (line)))
      perror ("write entry to peer file");
    return 1;
  }
  return 0;
}

static void save_id ()
{
#ifdef DEBUG_PRINT
  printf ("save_id()\n");
#endif /* DEBUG_PRINT */
  if (save_my_own_address) {
    int fd = open_write_config ("adht", "my_id", 1);
    if (fd >= 0) {
      char line [300];  /* write my address first */
      buffer_to_string (my_address, ADDRESS_SIZE, NULL, ADDRESS_SIZE, 1,
                        line, sizeof (line));
      if (write (fd, line, strlen (line)) != (int) (strlen (line)))
        perror ("save_id write");  /* report, but continue */
#ifdef DEBUG_EBADFD
snprintf (ebadfbuf, EBADFBUFS, "routing.c save_id, closing my_id fd %d\n", fd);
record_message (info->pipe_descriptor);
#endif /* DEBUG_EBADFD */
      close (fd);
    }
  }
}

static void save_peers ()
{
#ifdef DEBUG_PRINT
  printf ("save_peers():\n");
  print_dht (0);
  print_ping_list (0);
#endif /* DEBUG_PRINT */
  /* only save once every second to once every 30min, depending how
   * long we've been running */
  static unsigned long long int num_saves = 0;
  static unsigned long long int last_saved = 0;
  unsigned long long int min = 1 * ALLNET_US_PER_S;        /* 1 second */
  unsigned long long int max = 30 * 60 * ALLNET_US_PER_S;  /* 30 minutes */
  if (! time_exp_interval (&last_saved, &num_saves, min, max))
    return;  /* don't save now */
  int cpeer = 0;
  int cping = 0;
  int fd = open_write_config ("adht", "peers", 1);
  int i;
  for (i = 0; i < MAX_PEERS; i++)
    cpeer += entry_to_file (fd, &(peers [i].ai), i);
  for (i = 0; i < MAX_PINGS; i++)
    cping += entry_to_file (fd, &(pings [i].ai), -1);
#ifdef DEBUG_EBADFD
snprintf (ebadfbuf, EBADFBUFS,
"routing.c save_peers, closing peers fd %d\n", fd);
record_message (info->pipe_descriptor);
#endif /* DEBUG_EBADFD */
  close (fd);
  peers_file_time = time (NULL);  /* no need to re-read in load_peers (1) */
#ifdef DEBUG_PRINT
  printf ("saved %d peers and %d pings, time is %ld\n",
          cpeer, cping, peers_file_time);
#endif /* DEBUG_PRINT */
}

static int read_line (int fd, char * buf, int bsize)
{
  if (bsize <= 0)
    return 0;
  buf [0] = '\0';
  int index = 0;
  while (1) {
    if (index + 1 >= bsize)
      return (index > 0);
    buf [index + 1] = '\0';   /* set this in case we return */
    char cbuf [1];
    if (read (fd, cbuf, 1) != 1) {
      return (index > 0);
    }
    if (cbuf [0] == '\n')      /* do not include the newline in the string */
      return 1;
    buf [index++] = cbuf [0];
  }
  return 0;   /* should never happen */
}

/* returns the new input after skipping all of the chars read into buffer */
static const char * read_buffer (const char * in, int nbytes,
                                 char * buf, int bsize)
{
  if (nbytes > bsize)
    nbytes = bsize;
  while (nbytes > 0) {
    if ((*in == '.') || (*in == ' '))
      in++;
    char * end;
    buf [0] = (int)strtol (in, &end, 16);
    if (end == in) {
      return in;
    }
    in = end;
    buf++;
    nbytes--;
  }
  return in;
}

static void load_peer (struct addr_info * peer, const char * line,
                       int real_peer)
{
  const char * original_line = line;  /* for debugging */
  /* printf ("load_peer parsing line %s\n", line); */
  if (*line != ':')
    return;
  line++;
  char * end = (char *)line;  /* end cannot be const because used in strtol */
  if ((end [0] != ' ') || (end [1] != '('))
    return;
  line = end + 2;
  int nbits = (int)strtol (line, &end, 10);
  if (end == line)
    return;
  if ((end [0] != ')') || (end [1] != ' '))
    return;
  line = end + 2;
  int num_bytes = (int)strtol (line, &end, 10);
  if ((num_bytes > 8) || (end == line) || (memcmp (end, " bytes: ", 8) != 0))
    return;
  line = end + 8;
  char address [ADDRESS_SIZE];
  memset (address, 0, sizeof (address));
  line = read_buffer (line, (nbits + 7) / 8, address, sizeof (address));
  if (memcmp (line, ", v ", 4) != 0)
    return;
  line += 4;
  int ipversion = (int)strtol (line, &end, 10);
  if (end == line)
    return;
  if ((ipversion != 4) && (ipversion != 6)) {
    printf ("load_peer: IP version %d in '%s'\n", ipversion, original_line);
    return;
  }
  line = end;
  if (memcmp (line, ", port ", 7) != 0)
    return;
  line += 7;
  int port = (int)strtol (line, &end, 10);
  if (end == line)
    return;
  line = end;
  if (memcmp (line, ", addr ", 7) != 0)
    return;
  line += 7;
  int af = AF_INET;
  if (ipversion == 6)
    af = AF_INET6;
  char storage [sizeof (struct in6_addr)];
  if (inet_pton (af, line, storage) != 1)
    return;
  memset (((char *) (peer)), 0, sizeof (struct addr_info));
  peer->ip.ip.s6_addr [10] = 0xff;
  peer->ip.ip.s6_addr [11] = 0xff;
  if (ipversion == 4)
    memcpy (peer->ip.ip.s6_addr + 12, storage, 4);
  else
    memcpy (peer->ip.ip.s6_addr, storage, 16);
  peer->ip.port = htons (port);
  peer->ip.ip_version = ipversion;
  memcpy (peer->destination, address, ADDRESS_SIZE);
  peer->nbits = nbits;
}

static void init_defaults ()
{
  random_bytes (my_address, ADDRESS_SIZE);
  buffer_to_string (my_address, ADDRESS_SIZE, "new random address",
                    ADDRESS_SIZE, 1, alog->b, alog->s);
  log_print (alog);
  save_id ();
}

static void load_peers (int only_if_newer)
{
  time_t mtime = config_file_mod_time ("adht", "peers");
  if ((only_if_newer) && ((mtime == 0) || (mtime <= peers_file_time)))
    return;
  peers_file_time = mtime;
  /* an unused entry has nbits set to 0 -- might as well clear everything */
  memset ((char *) (peers), 0, sizeof (peers));
  memset ((char *) (pings), 0, sizeof (pings));
  memset (my_address, 0, sizeof (my_address));
  char line [1000];
  int fd = open_read_config ("adht", "my_id", 1);
  if (fd < 0) {
printf ("unable to open .allnet/adht/my_id\n");
    init_defaults ();
  } else {
    if ((! read_line (fd, line, sizeof (line))) ||
        (strlen (line) <= 0) ||
        ((line [0] != '-') &&
         ((strlen (line) < 30) || (strncmp (line, "8 bytes: ", 9) != 0)))) {
      printf ("unable to read ~/.allnet/adht/my_id file\n");
      init_defaults ();
    } else if (line [0] == '-') {
      save_my_own_address = 0;
      random_bytes (my_address, ADDRESS_SIZE);
      printf ("~/.allnet/adht/my_id begins with '-', not saving\n");
    } else {   /* line >= 30 bytes long, beginning with "8 bytes: " */
      read_buffer (line + 9, (int)strlen (line + 9), my_address, ADDRESS_SIZE);
    }
#ifdef DEBUG_EBADFD
snprintf (ebadfbuf, EBADFBUFS,
"routing.c load_peers, closing peers fd %d\n", fd);
record_message (info->pipe_descriptor);
#endif /* DEBUG_EBADFD */
    close (fd);
  }
  fd = open_read_config ("adht", "peers", 1);
  if (fd < 0)
    return;
  int ping_index = 0;
  while (read_line (fd, line, sizeof (line))) {
    if (strncmp (line, "p: ", 3) != 0) {
      char * end;
      int peer = (int)strtol (line, &end, 10);
      if ((end != line) && (peer >= 0) && (peer < MAX_PEERS)) {
        load_peer (&(peers [peer].ai), end, 1);
        peers [peer].refreshed = 1;
      }
    } else {
      load_peer (&(pings [ping_index++].ai), line + 1, 0);
    }
  }
#ifdef DEBUG_EBADFD
snprintf (ebadfbuf, EBADFBUFS,
"routing.c load_peers, re-closing peers fd %d\n", fd);
record_message (info->pipe_descriptor);
#endif /* DEBUG_EBADFD */
  close (fd);
/* printf ("load_peers complete:\n");
print_dht (0); */
  int i;
  int cpeers = 0;
  int cpings = 0;
  for (i = 0; i < MAX_PEERS; i++)
    if (peers [i].ai.nbits != 0) {
      peers [i].refreshed = 1;
      cpeers++;
    }
  for (i = 0; i < MAX_PINGS; i++)
    if (pings [i].ai.nbits != 0) {
      pings [i].refreshed = 1;
      cpings++;
    }
}

/* always called with lock held */
static int init_peers (int always)
{
  if (alog == NULL)
    alog = init_log ("routing");
  static int initialized = 0;
  int result = 1 - initialized;  /* return 1 if this is the first call */
  if ((! initialized) || (always)) {
    load_peers (0);
    unsigned int i;
    for (i = 0; i < NUM_DEFAULTS; i++) {
      ip4_defaults [i].ss_family = 0;
      ip6_defaults [i].ss_family = 0;
    }
    if (dns_init == 0)
      start_dns_thread ();
  } else {
    load_peers (1);
  }
  initialized = 1;
  return result;
}

/* fills in addr (of size at least ADDRESS_SIZE) with my address */
void routing_my_address (unsigned char * addr)
{
  pthread_mutex_lock (&mutex);
  init_peers (0);
  memcpy (addr, my_address, ADDRESS_SIZE);
  pthread_mutex_unlock (&mutex);
}

/* return true if the destination is closer to target than to
 * current.  Target and current are assumed to have ADDRESS_BITS */
/* if nbits is 0, will always return 0 */
static int addr_closer (unsigned char * dest, int nbits,
                        unsigned char * current, unsigned char * target)
{
  if (matching_bits (dest, nbits, current, ADDRESS_BITS) <
      matching_bits (dest, nbits, target, ADDRESS_BITS))
    return 1;
  return 0;
}

#if 0
/* return true if the destination is no farther from target than from
 * current.  Target and current are assumed to have ADDRESS_BITS */
/* if nbits is 0, will always return 1 */
static int addr_not_farther (unsigned char * dest, int nbits,
                             unsigned char * current, unsigned char * target)
{
  if (matching_bits (dest, nbits, current, ADDRESS_BITS) <=
      matching_bits (dest, nbits, target, ADDRESS_BITS))
    return 1;
  return 0;
}
#endif /* 0 */

/* fills in an array of sockaddr_storage to the top internet addresses
 * (up to max_matches) for the given AllNet address.
 * returns zero if there are no matches */
/* the top matches are the ones with the most matching bits, so we start
 * looking from the last row of the array. */
int routing_top_dht_matches (unsigned char * dest, int nbits,
                             struct sockaddr_storage * result, int max_matches)
{
/* print_buffer (dest, nbits, "routing_top_dht_matches:", (nbits + 7) / 8, 1);
print_dht (0); */
  memset (result, 0, max_matches * sizeof (struct sockaddr_storage));
  int peer = 0;
  if (nbits < 0)
    nbits = 0;
  if (nbits > ADDRESS_BITS)
    nbits = ADDRESS_BITS;
  pthread_mutex_lock (&mutex);
  init_peers (0);
  int row, col;
  for (row = ADDRESS_BITS - 1; row >= 0; row--) {
    for (col = 0; col < PEERS_PER_BIT; col++) {
      struct addr_info * ai = &(peers [row * PEERS_PER_BIT + col].ai);
      if ((ai->nbits > 0) &&
          (addr_closer (dest, nbits, (unsigned char *) my_address,
                        ai->destination))) {
        struct sockaddr * sap = (struct sockaddr *) (& (result [peer]));
        if (ai_to_sockaddr (ai, sap, NULL))
          peer++;   /* a valid translation */
      }
    }
  }
  pthread_mutex_unlock (&mutex);
  if (peer < max_matches)
    peer += add_default_routes (result, peer, max_matches);
#ifdef DEBUG_PRINT
  printf ("routing_top_dht_matches returning %d for ", peer);
  print_buffer ((char *) dest, (nbits + 7) / 8, NULL, ADDRESS_SIZE, 1);
  int i;
  for (i = 0; i < peer; i++) {
    printf ("%d: ", i);
    print_sockaddr ((struct sockaddr *) (&(result [i])),
                    sizeof (struct sockaddr_storage), 0);
    printf ("\n");
  }
#endif /* DEBUG_PRINT */
  return peer;
}

static void exact_match_print (char * description, int found,
                               const unsigned char * addr,
                               struct addr_info * result)
{
#ifdef DEBUG_PRINT
  printf ("%s (", description);
  print_buffer ((char *) addr, ADDRESS_SIZE, NULL, ADDRESS_SIZE, 0);
  printf (") ");
  if (found)
    print_addr_info (result);
  else
    printf ("==> %d\n", found);
  print_dht (0);
  print_ping_list (0);
#endif /* DEBUG_PRINT */
  snprintf (alog->b, alog->s, "%s returns %d\n", description, found);
  log_print (alog);
}

/* returns 1 if found (and fills in result if not NULL), otherwise returns 0 */
static int search_data_structure (struct peer_info * ds, int max,
                                  const unsigned char * addr,
                                  struct addr_info * result)
{
  int found = 0;
  int i;
  for (i = 0; (i < max) && (found == 0); i++) {
    if ((ds [i].ai.nbits != 0) &&
        (memcmp (addr, ds [i].ai.destination, ADDRESS_SIZE) == 0)) {
      found = 1;
      if (result != NULL)
        *result = ds [i].ai;
    }
  }
  return found;
}

/* returns 1 and fills in result (if not NULL) if it finds an exact
 * match for this address (assumed to be of size ADDRESS_SIZE.
 * otherwise returns 0.  */
int routing_exact_match (const unsigned char * addr, struct addr_info * result)
{
  int found = 0;
  pthread_mutex_lock (&mutex);
  init_peers (0);
#if 0
  int i;
  for (i = 0; (i < MAX_PEERS) && (found == 0); i++) {
    if ((peers [i].ai.nbits != 0) &&
        (memcmp (addr, peers [i].ai.destination, ADDRESS_SIZE) == 0)) {
      found = 1;
      if (result != NULL)
        *result = peers [i].ai;
    }
  }
  for (i = 0; (i < MAX_PINGS) && (found == 0); i++) {
    if ((pings [i].ai.nbits != 0) &&
        (memcmp (addr, pings [i].ai.destination, ADDRESS_SIZE) == 0)) {
      found = 1;
      if (result != NULL)
        *result = pings [i].ai;
    }
  }
#else /* ! 0 */
  found = search_data_structure (peers, MAX_PEERS, addr, result);
  if (! found)
    found = search_data_structure (pings, MAX_PINGS, addr, result);
#endif /* 0 */
  pthread_mutex_unlock (&mutex);
  exact_match_print ("routing_exact_match", found, addr, result);
  return found;
}

int ping_exact_match (const unsigned char * addr, struct addr_info * result)
{
  pthread_mutex_lock (&mutex);
  init_peers (0);
  int found = search_data_structure (pings, MAX_PINGS, addr, result);
  pthread_mutex_unlock (&mutex);
  exact_match_print ("ping_exact_match", found, addr, result);
  return found;
}

/* returns -1 if not found, the index if found */
static int find_peer (struct peer_info * peers_data, int max,
                      struct addr_info * addr)
{
  int i;
  for (i = 0; i < max; i++) {
    if ((peers_data [i].ai.nbits > 0) &&
        (matches (peers_data [i].ai.destination, ADDRESS_BITS,
                  addr->destination, ADDRESS_BITS) >= ADDRESS_BITS) &&
  /* allow same destination if different IP version, i.e. ipv4 and ipv6 */
  /* this makes sure we don't automatically default to IPv6, and lets us
   * keep track of IPv4 addresses for DHT hosts as well as IPv6 addresses */
        (peers_data [i].ai.ip.ip_version == addr->ip.ip_version))
      return i;
  } 
  return -1;
}

/* returns the index of the entry with the given IP, or -1 if none found */
static int find_ip (struct internet_addr * addr)
{
  int i;
  for (i = 0; i < MAX_PEERS; i++) {
    if ((peers [i].ai.nbits > 0) &&
        (memcmp (&(addr->ip), &(peers [i].ai.ip.ip), sizeof (addr->ip)) == 0))
      return i;
  }
  return -1;
}

static void delete_ping (struct addr_info * addr)
{
  int i;
  for (i = 0; i < MAX_PINGS; i++) {
    if ((pings [i].ai.nbits > 0) &&
        (matches (pings [i].ai.destination, ADDRESS_BITS,
                  addr->destination, ADDRESS_BITS) >= ADDRESS_BITS))
      pings [i].ai.nbits = 0;  /* delete */
  }
}

/* either adds or refreshes a DHT entry.
 * returns 1 for a new entry, 0 for an existing entry, -1 for errors */
int routing_add_dht (struct addr_info * addrp)
{
  int result = -1;
  struct addr_info addr = *addrp;
  /* sanity check first */
  if (addr.nbits > ADDRESS_BITS) {
    printf ("routing_add_dht given address with %d > %d bits, not saving\n",
            addr.nbits, ADDRESS_BITS);
    print_addr_info (&addr);
    return -1;
  }
  pthread_mutex_lock (&mutex);
  init_peers (0);
  if ((addr.nbits == ADDRESS_BITS) &&
      (addr.type == ALLNET_ADDR_INFO_TYPE_DHT)) {
    int bit_pos = matching_bits (addr.destination, ADDRESS_BITS,
                                 (unsigned char *) my_address, ADDRESS_BITS);
#ifdef DEBUG_PRINT
    printf ("adding at bit position %d, address ", bit_pos);
    print_addr_info (addr);
#endif /* DEBUG_PRINT */
    int index = bit_pos * PEERS_PER_BIT;
    int found = find_peer (peers + index, PEERS_PER_BIT, &addr);
    int ip_index = find_ip (&(addr.ip));
    /* there should not be any others with the same IP.  If found, delete */
    if ((found < 0) && (ip_index >= 0))
      peers [ip_index].ai.nbits = 0;
    int limit = PEERS_PER_BIT - 1;
    result = 1;   /* new, unless found >= 0 */
    if (found >= 0) {
      result = 0; /* not new */
      limit = found;
    }
#ifdef DEBUG_PRINT
    if (result != 0)
      printf ("found %d, limit %d, result %d\n", found, limit, result);
#endif /* DEBUG_PRINT */
    int i;
    /* move any addresses in front of this one back one position */
    /* if found < 0 (limit is PEERS_PER_BIT - 1), drop the last address */
    for (i = limit; i > 0; i--)
      peers [index + i] = peers [index + i - 1]; 
    peers [index].ai = addr;   /* put this one in front */
    peers [index].refreshed = 1;
    if (found < 0)   /* if it is in the ping list, delete it from there */
      delete_ping (&addr);
  }
  static unsigned long long int last_saved = 0;
  int save = result > 0;
  /* if result is zero, there are no new addresses but the order of
   * addresses has changed, so save less frequently */
  if ((result == 0) &&
      ((last_saved == 0) || (last_saved + PEER_SAVE_TIME < allnet_time ())))
    save = 1;
  if (save) {
    save_peers ();
    last_saved = allnet_time ();
  }
  pthread_mutex_unlock (&mutex);
  return result;
}

/* returns -1 if not found, the index if found */
static int find_ping (struct addr_info * addr)
{
  int i;
  for (i = 0; i < MAX_PINGS; i++) {
    if ((pings [i].ai.nbits > 0) &&
        (matches (pings [i].ai.destination, ADDRESS_BITS,
                  addr->destination, ADDRESS_BITS) >= ADDRESS_BITS))
      return i;
  } 
  return -1;
}

/* either adds or refreshes a ping entry.
 * returns 1 for a new entry, 0 for an existing entry, -1 for an entry that
 * is already in the DHT list, and -2 for other errors */
int routing_add_ping_locked (struct addr_info * addr)
{
  int result = -2;
  int i;
  if (find_peer (peers, MAX_PEERS, addr) >= 0) {
#ifdef DEBUG_PRINT
    printf ("rapl found peer, returning -1\n");
#endif /* DEBUG_PRINT */
    result = -1;
  } else if (find_ip (&(addr->ip)) >= 0) {
#ifdef DEBUG_PRINT
    printf ("rapl found ip, returning -1\n");
#endif /* DEBUG_PRINT */
    result = -1;
  } else {
    int n = find_ping (addr);
    if (n == -1) {   /* add to the front */
      for (i = MAX_PINGS - 1; i > 0; i--)
        pings [i] = pings [i - 1];
      pings [0].ai = *addr;
      pings [0].refreshed = 1;
      result = 1;
#ifdef DEBUG_PRINT
      printf ("rapl did not find ping, returning 1\n");
#endif /* DEBUG_PRINT */
    } else {         /* move to the front */
      for (i = n; i > 0; i--)
        pings [i] = pings [i - 1];
      pings [0].ai = *addr;
      pings [0].refreshed = 1;
      result = 0;
#ifdef DEBUG_PRINT
      printf ("rapl found ping, returning 0\n");
#endif /* DEBUG_PRINT */
    }
  }
  return result;
}

/* expires old DHT entries that haven't been refreshed since the last call */
void routing_expire_dht ()
{
#ifdef DEBUG_PRINT
  int debug_ping_count = 0;
  int debug_peer_count = 0;
  printf ("routing_expire_dht ()\n");
  print_dht (0);
  print_ping_list (0);
#endif /* DEBUG_PRINT */
  pthread_mutex_lock (&mutex);
  init_peers (0);
  int changed = 0;
  int i;
  /* delete pings that haven't been refreshed */
  for (i = 0; i < MAX_PINGS; i++) {
    if ((pings [i].ai.nbits > 0) && (! pings [i].refreshed)) {
      pings [i].ai.nbits = 0;
      changed = 1;
#ifdef DEBUG_PRINT
      debug_ping_count++;
#endif /* DEBUG_PRINT */
    }
    /* mark all pings as not refreshed */
    pings [i].refreshed = 0;
  }
  /* delete peers that haven't been refreshed (put them into the ping list) */
  for (i = 0; i < MAX_PEERS; i++) {
    if ((peers [i].ai.nbits > 0) && (! peers [i].refreshed)) {
      struct addr_info copy = peers [i].ai;
      peers [i].ai.nbits = 0;
      changed = 1;
      int rapl = routing_add_ping_locked (&copy);
      if (rapl < 0)
        printf ("rapl result is %d for", rapl);
#ifdef DEBUG_PRINT
      else
        printf ("rapl result is %d for", rapl);
      print_addr_info (&copy);
      debug_peer_count++;
#endif /* DEBUG_PRINT */
    }
    /* mark all peers as not refreshed */
    peers [i].refreshed = 0;
  }
  if (changed)
    save_peers ();
  pthread_mutex_unlock (&mutex);
#ifdef DEBUG_PRINT
  printf ("routing_expire_dht () finished, %s, expired %d pings, %d peers\n",
          (changed) ? "changed" : "no change", debug_ping_count,
          debug_peer_count);
  print_dht (0);
  print_ping_list (0);
#endif /* DEBUG_PRINT */
}

static struct addr_info * get_nth_peer (int n)
{
  int i;
  for (i = 0; i < MAX_PEERS; i++) {
    if (peers [i].ai.nbits > 0) {
      if (n == 0)
        return &(peers [i].ai);
      else
        n--;
    }
  }
  return NULL;
}

/* fills in the given array, which must have room for num_entries addr_infos,
 * with data to send.
 * returns the actual number of entries, which may be less than num_entries */
int routing_table (struct addr_info * data, int num_entries)
{
  int result = 0;
  pthread_mutex_lock (&mutex);
  init_peers (0);
  if (num_entries > 0) {
    int num_peers = 0;
    int i, index;
    for (i = 0; i < MAX_PEERS; i++)
      if (peers [i].ai.nbits > 0)
        num_peers++;
    result = num_peers;
    if (result > num_entries)
      result = num_entries;
    int * permutation = random_permute (num_peers);
    index = 0;  /* index into the permutation */
    struct addr_info * latest;
    for (i = 0; i < result; i++) { /* i is an index into data */
      latest = get_nth_peer (permutation [index++]);
      if (latest == NULL) { /* some error -- fewer than result found */
        printf ("error: permutation %d/%d did not find %d peers\n",
                index - 1, permutation [index - 1], num_peers);
        int x;
        for (x = 0; x < num_peers; x++)
          printf ("%d, ", permutation [x]);
        print_dht (0);
        exit (1);
      }
      data [i] = *latest;
    }
    free (permutation);
  }
  pthread_mutex_unlock (&mutex);
  return result;
}

/* either adds or refreshes a ping entry.
 * returns 1 for a new entry, 0 for an existing entry, -1 for an entry that
 * is already in the DHT list, and -2 for other errors */
int routing_add_ping (struct addr_info * addr)
{
  pthread_mutex_lock (&mutex);
  init_peers (0);
  int result = routing_add_ping_locked (addr);
  if (result >= 0)
    save_peers ();
  pthread_mutex_unlock (&mutex);
  return result;
}

/* when iter is zero, initializes the iterator and fills in the first
 * value, if any.  Every subsequent call should use the prior return value >= 0
 * When there are no more values to fill in, returns -1 */
int routing_ping_iterator (int iter, struct addr_info * ai)
{
  if ((iter < 0) || (iter >= MAX_PINGS))
    return -1;
  pthread_mutex_lock (&mutex);
  init_peers (0);
  while ((iter < MAX_PINGS) && (pings [iter].ai.nbits == 0))
    iter++;
  if ((iter < MAX_PINGS) && (ai != NULL))
    *ai = pings [iter].ai;
  pthread_mutex_unlock (&mutex);
  if (iter < MAX_PINGS) {
    if (pings [iter].ai.nbits > ADDRESS_BITS) {
      printf ("error: routing_ping_iterator %d/%d returning %d > %d bits\n",
              iter, MAX_PINGS, pings [iter].ai.nbits, ADDRESS_BITS);
      print_addr_info (&(pings [iter].ai));
    }
    return iter + 1;
  }
  return -1;
}

/* returns the number of entries filled in, 0...max */
/* entry may be NULL, in which case nothing is filled in */
int init_own_routing_entries (struct addr_info * entry, int max,
                              const unsigned char * dest, int nbits)
{
#ifdef DEBUG_PRINT
  struct addr_info * original = entry;
  int original_max = max;
#endif /* DEBUG_PRINT */
  int result = 0;
  if (entry != NULL)
    memset (entry, 0, sizeof (struct addr_info) * max);
  struct interface_addr * int_addrs;
  int num_interfaces = interface_addrs (&int_addrs);
  if (num_interfaces <= 0) {
    printf ("unable to obtain own IP addresses, ignoring\n");
    return 0;
  }
  int i;
  for (i = 0; ((max > 0) && (i < num_interfaces)); i++) {
    if (int_addrs [i].is_loopback) {
#ifdef DEBUG_PRINT
      printf ("skipping loopback address\n");
#endif /* DEBUG_PRINT */
    } else {
      int j;
      for (j = 0; ((max > 0) && (j < int_addrs [i].num_addresses)); j++) {
        int valid = 0;  /* set to 1 if we decide it's a valid entry */
        struct sockaddr * sa =
          (struct sockaddr *) (int_addrs [i].addresses + j);
        if (sa->sa_family == AF_INET) {
          struct sockaddr_in * sinp = (struct sockaddr_in *) (sa);
          int high_byte = ((char *) (&(sinp->sin_addr.s_addr))) [0] & 0xff;
          int next_byte = ((char *) (&(sinp->sin_addr.s_addr))) [1] & 0xff;
          if ((high_byte != 10) &&  /* anything beginning with 10 is private */
              ((high_byte != 172) || ((next_byte & 0xf0) != 16)) && /* 172.16/12 */
              ((high_byte != 192) || (next_byte != 168))) { /* 192.168/16 */
            if (entry != NULL) {
/* the address is already zeroed.  Assign the IP address to the last four
 * bytes (entry->ip.ip.s6_addr + 12), and 0xff to the immediately preceding
 * two bytes */
              memcpy (entry->ip.ip.s6_addr + 12, &(sinp->sin_addr.s_addr), 4);
              entry->ip.ip.s6_addr [10] = entry->ip.ip.s6_addr [11] = 0xff;
              entry->ip.ip_version = 4;
            }
            valid = 1;
          }
        } else if (sa->sa_family == AF_INET6) {
          struct sockaddr_in6 * sinp = (struct sockaddr_in6 *) (sa);
          int high_byte = sinp->sin6_addr.s6_addr [0] & 0xff;
          int next_bits = sinp->sin6_addr.s6_addr [1] & 0xc0;
          if ((high_byte != 0xff) &&  /* 0xff/8 is a multicast address */
                                      /* 0xfe80/10 is a link-local address */
              ((high_byte != 0xfe) || (next_bits != 0x80))) {
            if (entry != NULL) {
              entry->ip.ip = sinp->sin6_addr;
              entry->ip.ip_version = 6;
            }
            valid = 1;
          } else {
#ifdef DEBUG_PRINT
            printf ("ignoring address %02x%02x::\n", high_byte, next_bits);
#endif /* DEBUG_PRINT */
          }
        } else {  /* unknown address family, ignore */
#ifdef DEBUG_PRINT
          printf ("interface %s, ignoring address family %d\n", next->ifa_name,
                  next->ifa_addr->sa_family);
#endif /* DEBUG_PRINT */
        }
        if (valid) {
          if (entry != NULL) {
            entry->ip.port = allnet_htons (ALLNET_PORT);
            memcpy (entry->destination, dest, ADDRESS_SIZE);
            entry->nbits = nbits;
            entry->type = ALLNET_ADDR_INFO_TYPE_DHT;
#ifdef DEBUG_PRINT
            printf ("%d/%d: added own address: ", result, max);
            print_addr_info (entry);
#endif /* DEBUG_PRINT */
            entry++;
          }
          result++;
          max--;
        }
      }
    }
  }
#ifdef DEBUG_PRINT
  for (i = 0; i < (original_max - max); i++) {
    printf("result %d: ", i);
    print_addr_info (original + i);
  }
#endif /* DEBUG_PRINT */
  return result;
}

/* returns 1 if the given addr is one of mine, or matches my_address */
int is_own_address (struct addr_info * addr)
{
  if (memcmp (addr->destination, my_address, ADDRESS_SIZE) == 0)
    return 1;
#define MAX_MY_ADDRS	100
  struct addr_info mine [MAX_MY_ADDRS];
  int n = init_own_routing_entries (mine, MAX_MY_ADDRS - 1,
                                    addr->destination, ADDRESS_BITS);
#undef MAX_MY_ADDRS
  int i;
  for (i = 0; i < n; i++)
    if (same_ai (mine + i, addr))
      return 1;
  return 0;
}

/* return 1 after init is complete, 0 otherwise.  If parameter is nonzero,
 * waits for completion and always returns 1 */
int routing_init_is_complete (int wait_for_init)
{
  while (wait_for_init && (dns_init != 1)) {
    usleep (10 * 1000);  /* sleep 10ms */
    pthread_mutex_lock (&mutex);
    /* init_peers may or may not be needed, something to do while waiting */
    init_peers (0);
    pthread_mutex_unlock (&mutex);
  }
  if (dns_init == 1)
    return 1;
  return 0;
}

