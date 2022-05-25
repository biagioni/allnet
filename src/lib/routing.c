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

#include "routing.h"
#include "packet.h"
#include "mgmt.h"
#include "util.h"
#include "sockets.h"
#include "ai.h"
#include "allnet_log.h"
#include "configfiles.h"

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

/* up to 4 DHT neighbors per address bit */
#define PEERS_PER_BIT	4
#define MAX_PEERS	(ADDRESS_BITS * PEERS_PER_BIT)

struct peer_info {
  struct allnet_addr_info ai;
  int refreshed;
};

struct peer_info peers [MAX_PEERS];

/* for now use a fixed-size array of addr_infos to store the ping list. */
/* addresses are added at the front and dropped from the back */
#define MAX_PINGS	128

static struct peer_info pings [MAX_PINGS];

static char my_address [ADDRESS_SIZE] = {0, 0, 0, 0, 0, 0, 0, 0};
/* 0 before initialization, 1 after initialization */
static int my_address_initialized = 0;

/* some of these domain names may not be defined, but at least some should be */
static const char * default_dns [] =
  { "a0.alnt.org", "a1.alnt.org", "a2.alnt.org", "a3.alnt.org",
    "a4.alnt.org", "a5.alnt.org", "a6.alnt.org", "a7.alnt.org",
    "a8.alnt.org", "a9.alnt.org", "aa.alnt.org", "ab.alnt.org",
    "ac.alnt.org", "ad.alnt.org", "ae.alnt.org", "af.alnt.org" };
#define NUM_DEFAULTS	((sizeof (default_dns)) / (sizeof (char *)))
/* these arrays have the IP addresses of the default DNS names.
 * these defaults initially have family set to zero.  The family is set
 * to the correct value (AF_INET or AF_INET6) if the address is known,
 * and to AF_APPLETALK otherwise. */
struct sockaddr_storage ip4_defaults [NUM_DEFAULTS];
struct sockaddr_storage ip6_defaults [NUM_DEFAULTS];
/* ips saved from the previous run, if any -- useful if DNS is broken */
struct sockaddr_storage saved_ips [NUM_DEFAULTS + NUM_DEFAULTS];

/* own addresses, as reported by others */
struct self_addr_struct {
  int valid;
  unsigned long long int freshness;       /* higher numbers are fresher */
  struct allnet_addr_info ai;
};
#define NUM_SELF_ADDRS	10
struct self_addr_struct self_addr [NUM_SELF_ADDRS];
unsigned long long self_addr_init = 0;

static struct allnet_log * alog = NULL;

#if defined(__IPHONE_OS_VERSION_MIN_REQUIRED) || defined(ANDROID)
/* save addresses every 5min (300s), because we may not run very long */
#define PEER_SAVE_TIME		300
#else /* not ios and not android */
/* save addresses every day (86400s) even if there are no new ones */
#define PEER_SAVE_TIME		86400
#endif /* __IPHONE_OS_VERSION_MIN_REQUIRED */

/* fd is -1 to print to the log, 0 to print to stdout,
 * and a valid fd otherwise */
void print_dht (int fd)
{
  if (fd == 0)
    fd = STDOUT_FILENO;
  if (alog == NULL) {  /* not initialized */
    printf ("print_dht called before initialization, alog %p\n", alog);
    return;
  }
  int npeers = 0;
  int i;
  for (i = 0; i < MAX_PEERS; i++)
    if (peers [i].ai.nbits != 0)
      npeers++;
  int n = snprintf (alog->b, alog->s, "%d peers: ", npeers);
  buffer_to_string (my_address, ADDRESS_SIZE, "my address is",
                    ADDRESS_SIZE, 1, alog->b + n, alog->s - n);
  if (fd < 0) log_print (alog); else dprintf (fd, "%s", alog->b);
  int printed = 0;
  for (i = 0; i < MAX_PEERS; i++) {
    if (peers [i].ai.nbits != 0) {
      n = snprintf (alog->b, alog->s, "%3d (%d): ", i, peers [i].refreshed);
      addr_info_to_string (&(peers [i].ai), alog->b + n, alog->s - n);
      if (fd < 0) log_print (alog); else dprintf (fd, "%s", alog->b);
      printed = 1;
    }
  }
  if (! printed) {
    snprintf (alog->b, alog->s, "dht table is empty\n");
    if (fd < 0) log_print (alog); else dprintf (fd, "%s", alog->b);
  }
}

void print_ping_list (int fd)
{
  if (alog == NULL) {  /* not initialized */
    printf ("print_ping_list called before initialization, alog %p\n", alog);
    return;
  }
  if (fd == 0)
    fd = STDOUT_FILENO;
  int i, n;
  int count = 0;
  for (i = 0; i < MAX_PINGS; i++)
    if (pings [i].ai.nbits > 0)
      count++;
  snprintf (alog->b, alog->s, "pings: %d\n", count);
  if (fd < 0) log_print (alog); else dprintf (fd, "%s", alog->b);
  for (i = 0; i < MAX_PINGS; i++) {
    if (pings [i].ai.nbits > 0) {
      n = snprintf (alog->b, alog->s, "%3d (%d): ", i, pings [i].refreshed);
      addr_info_to_string (&(pings [i].ai), alog->b + n, alog->s - n);
      if (fd < 0) log_print (alog); else dprintf (fd, "%s", alog->b);
    }
  }
}

/* returns one if the addr_info passes sanity checks, 0 otherwise */
/* if desc is not NULL, prints error messages */
static int sane_addr_info (const struct allnet_addr_info * addr,
                           const char * desc)
{
  static int max_print = 10;
  if (max_print <= 0)
    desc = NULL;
  if (addr == NULL) {
    if (desc != NULL) printf ("sane_addr_info (%s): addr is NULL\n", desc);
    max_print--;
    return 0;
  }
  if ((addr->ip.ip_version != 4) && (addr->ip.ip_version != 6)) {
    if (desc != NULL) printf ("sane_addr_info (%s): ip version %d != %d, %d\n",
                              desc, addr->ip.ip_version, 4, 6);
    max_print--;
    return 0;
  }
  if (addr->nbits > ADDRESS_BITS) {
    if (desc != NULL) printf ("sane_addr_info (%s): nbits %d > %d\n",
                              desc, addr->nbits, ADDRESS_BITS);
    max_print--;
    return 0;
  }
  if ((addr->type != ALLNET_ADDR_INFO_TYPE_RP) &&
      (addr->type != ALLNET_ADDR_INFO_TYPE_DHT)) {
    if (desc != NULL)
      printf ("sane_addr_info (%s): addr type %d != %d, %d\n", desc, addr->type,
              ALLNET_ADDR_INFO_TYPE_RP, ALLNET_ADDR_INFO_TYPE_DHT);
    max_print--;
    return 0;
  }
  return 1;
}

/* for addresses that are not valid, say they are not listed */
static int already_listed (struct sockaddr_storage * sap,
                           struct sockaddr_storage * already, int na)
{
  if ((sap->ss_family != AF_INET) && (sap->ss_family != AF_INET6))
    return 0;     /* invalid address family, not listed */
  int i;
  struct allnet_addr_info compare_ai;
  sockaddr_to_ai ((struct sockaddr *) sap, sizeof (struct sockaddr_storage),
                  &compare_ai);
  for (i = 0; i < na; i++) {
    struct allnet_addr_info this_ai;
    sockaddr_to_ai ((struct sockaddr *) (already + i),
                    sizeof (struct sockaddr_storage), &this_ai);
    if (same_ai (&compare_ai, &this_ai))
      return 1;   /* already listed */
  }
  return 0;       /* not listed */
}

/* this is the callback for allnet_dns */
/* ID is a number 0..NUM_DEFAULTS-1 */
/* the name is ignored -- it is only here because allnet_dns provides it */
static void routing_add_dns (const char * name, int id, int valid,
                             const struct sockaddr * ip_addr)
{
  if ((id >= NUM_DEFAULTS) || (id < 0))
    return;
  if (! valid) {
/* AF_APPLETALK is used to show that there is no such address */
    if (ip_addr->sa_family == AF_INET)
      ip4_defaults [id].ss_family = AF_APPLETALK;
    if (ip_addr->sa_family == AF_INET6)
      ip6_defaults [id].ss_family = AF_APPLETALK;
    return;
  }
  struct allnet_addr_info addr;
  memset (&addr, 0, sizeof (addr));
  if (ip_addr->sa_family == AF_INET) {
    const struct sockaddr_in * sin = (const struct sockaddr_in *) ip_addr;
    /* ipv4-in-ipv6 is ::ffff:a.b.c.d */
    memset (addr.ip.ip.s6_addr + 10, 0xff, 2);
    memcpy (addr.ip.ip.s6_addr + 12, &(sin->sin_addr.s_addr), 4);
    addr.ip.ip_version = 4;
    /* clear the entire sockaddr_storage */
    memset (ip4_defaults + id, 0, sizeof (ip4_defaults [id]));
    /* and copy all the bytes of the sockaddr_in */
    memcpy (ip4_defaults + id, ip_addr, sizeof (struct sockaddr_in));
    /* also update saved_ips */
    memset (saved_ips + 2 * id + 0, 0, sizeof (saved_ips [0]));
    memcpy (saved_ips + 2 * id + 0, ip_addr, sizeof (struct sockaddr_in));
    addr.ip.port = sin->sin_port;
  } else if (ip_addr->sa_family == AF_INET6) {
    const struct sockaddr_in6 * sin = (const struct sockaddr_in6 *) ip_addr;
    memcpy (addr.ip.ip.s6_addr, sin->sin6_addr.s6_addr, 16);
    addr.ip.ip_version = 6;
    memset (ip6_defaults + id, 0, sizeof (ip6_defaults [id]));
    memcpy (ip6_defaults + id, ip_addr, sizeof (struct sockaddr_in6));
    /* also update saved_ips */
    memset (saved_ips + 2 * id + 1, 0, sizeof (saved_ips [0]));
    memcpy (saved_ips + 2 * id + 1, ip_addr, sizeof (struct sockaddr_in6));
    addr.ip.port = sin->sin6_port;
  }
  if ((addr.ip.ip_version != 4) && (addr.ip.ip_version != 6)) {
    printf ("error: routing_add_dns IP version %d\n",
            addr.ip.ip_version);
    return;
  }
  addr.destination [0] = (id % 16) << 4;
  addr.nbits = ADDRESS_BITS;
  addr.hops = 16;  /* a high number to discourage use */
  addr.type = ALLNET_ADDR_INFO_TYPE_DHT;
  routing_add_dht (addr);
}

static time_t peers_file_time = 0;

static int entry_to_file (int fd, struct allnet_addr_info * entry, int index,
                          const char * caller)
{
  if (! sane_addr_info (entry, caller)) /* don't save insane entries */
    return 0;
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

static void save_peers (int unconditional)
{
#ifdef DEBUG_PRINT
  printf ("save_peers():\n");
  print_dht (0);
  print_ping_list (0);
#endif /* DEBUG_PRINT */
  /* unless unconditional is true, only save once every second to
   * once every 30min, depending how long we've been running */
  if (! unconditional) {
    static unsigned long long int num_saves = 0;
    static unsigned long long int last_saved = 0;
    unsigned long long int min = 1 * ALLNET_US_PER_S;        /* 1 second */
    unsigned long long int max = 30 * 60 * ALLNET_US_PER_S;  /* 30 minutes */
    if (! time_exp_interval (&last_saved, &num_saves, min, max))
      return;  /* don't save now */
  }
  int cpeer = 0;
  int cping = 0;
  int fd = open_write_config ("adht", "peers", 0);
  int i;
  for (i = 0; i < MAX_PEERS; i++) {
    if (peers [i].refreshed)
      cpeer += entry_to_file (fd, &(peers [i].ai), i, "save_peers/peer");
  }
  for (i = 0; i < MAX_PINGS; i++) {
    if (pings [i].refreshed)
      cping += entry_to_file (fd, &(pings [i].ai), -1, "save_peers/ping");
  }
  close (fd);
  peers_file_time = time (NULL);  /* no need to re-read in load_peers (1) */
  int fdi = open_write_config ("adht", "saved_ips", 0);
  if (fdi >= 0) {
    ssize_t w = write (fdi, saved_ips, sizeof (saved_ips));
    if (w != sizeof (saved_ips)) {
      perror ("writing saved_ips");
      printf ("wrote %zd rather than %zd\n", w, sizeof (saved_ips));
    }
    close (fdi);
  }
#ifdef DEBUG_PRINT
  printf ("saved %d peers and %d pings, time is %ld\n",
          cpeer, cping, peers_file_time);
#endif /* DEBUG_PRINT */
}

/* create a DNS from the fixed_dht file */
static void sim_dns (int sim_fd) {
  static char buffer [5000];
  int r = (int) read (sim_fd, buffer, sizeof (buffer));
  close (sim_fd);
  if ((r < 0) || (r >= sizeof (buffer))) {
    printf ("error: fixed_dht file read returns %d\n", r);
    return;
  }
  int id = 0;
  int c = 0;
  char * line_start = buffer;
  for (c = 0; c < r; c++) {
    if (buffer [c] == '\n') {   /* end of line, process */
      if (&(buffer [c]) == line_start) {  /* empty line */
        line_start = &(buffer [c + 1]);
        id++;        /* skip this ID */
        continue;    /* next loop */
      }
      buffer [c] = '\0';        /* terminate the line */
      /* a sockaddr in the file has type (4 or 6):port/address (no blanks) */
      char * port_end = NULL;
      int port = (int) strtol (line_start + 2, &port_end, 10);
      if (*port_end != '/') {
        printf ("sim_dns error parsing port in %s\n", line_start);
        exit (1);   /* debugging code, don't try to keep running */
      }
      char * address_start = port_end + 1;
      struct sockaddr * sap = NULL;
      struct sockaddr_in  sin =  { .sin_family = AF_INET,
                                   .sin_port = htons (port) };
      struct sockaddr_in6 sin6 = { .sin6_family = AF_INET6,
                                   .sin6_port = htons (port) };
int len = 0;
      if (*line_start == '4') {
        if (inet_aton (address_start, &(sin.sin_addr)) == 0) {
          printf ("sim_dns error parsing ipv4 address %s\n", line_start);
          exit (1);   /* debugging code, don't try to keep running */
        }
        sap = (struct sockaddr *) &sin;
len = sizeof (sin);
printf ("ipv4: read %s\n", line_start);
      } else if (*line_start == '6') {
        if (inet_pton (AF_INET6, address_start, &(sin6.sin6_addr)) <= 0) {
          printf ("sim_dns error parsing ipv6 address %s\n", line_start);
          exit (1);   /* debugging code, don't try to keep running */
        }
        sap = (struct sockaddr *) &sin6;
len = sizeof (sin6);
printf ("ipv6: read %s\n", line_start);
      } else {
        printf ("sim_dns error parsing %s\n", line_start);
        exit (1);   /* debugging code, don't try to keep running */
      }
printf ("%d: adding ", getpid ());
print_sockaddr (sap, len);
printf (", id %d\n", id);
      routing_add_dns ("sim", id++, 1, sap);
      line_start = &(buffer [c + 1]);
    }
  }
  save_peers (1);
  printf ("%d: after sim init:\n", getpid ());
  print_dht (0);
}

/* allnet_dns takes about 4-5s and is called repeatedly,
 * so init_default_dns is run as a separate thread
 * arg is ignored */
static void * init_default_dns (void * arg)
{
  /* there is no point to running multiple dns threads at the same time */
  static pthread_mutex_t only_one_thread_at_a_time = PTHREAD_MUTEX_INITIALIZER;
  if (pthread_mutex_trylock (&only_one_thread_at_a_time) != 0)
    return NULL;
  unsigned int i;
  int indices [NUM_DEFAULTS];
  for (i = 0; i < NUM_DEFAULTS; i++) {
    ip4_defaults [i].ss_family = 0;
    ip6_defaults [i].ss_family = 0;
    indices [i] = i;
  }
  /* for simulations, we take a fixed list of dht addresses */
  int sim_fd = open_read_config ("adht", "fixed_dht", 0);
  if (sim_fd >= 0) {
    sim_dns (sim_fd);
    pthread_mutex_unlock (&only_one_thread_at_a_time);
    return NULL;
  }
  char * * default_dns_copy = malloc_or_fail (sizeof (default_dns),
                                              "default_dns_copy");
  memcpy (default_dns_copy, default_dns, sizeof (default_dns));
  int num_defaults = NUM_DEFAULTS;
  int sleep_sec = 2;
  int failed_loops = 0;
  while ((num_defaults > 0) && (failed_loops < 10)) {
    int num_found = 0;
    for (i = 0; i < num_defaults; /* on each loop, i++ or num_defaults-- */ ) {
      if ((ip4_defaults [indices [i]].ss_family == AF_INET) ||
          (ip6_defaults [indices [i]].ss_family == AF_INET6) ||
/* AF_APPLETALK is used to show that there is no such address */
          ((ip4_defaults [indices [i]].ss_family == AF_APPLETALK) &&
           (ip6_defaults [indices [i]].ss_family == AF_APPLETALK))) { 
        /* received positive or negative response, stop trying for this one */
        num_defaults--;
        default_dns_copy [i] = default_dns_copy [num_defaults];
        indices [i] = indices [num_defaults];
        num_found++;
      } else {   /* received no response, or received only 1 of v4/v6 */
        i++;     /* negative responses, try this entry again in the future */
      }
    }
    if (num_defaults <= 0)
      break;
    if (num_found == 0)
      failed_loops++;
    allnet_dns ((const char **) default_dns_copy, indices, num_defaults,
                routing_add_dns);
    sleep_time_random_us (sleep_sec * 1000 * 1000);
    if (sleep_sec < 15) /* ~15 quick sets of requests, one more sec each time */
      sleep_sec++;
    else if (sleep_sec < 600) /* exponential growth up to 10 min or so */
      sleep_sec = sleep_sec + sleep_sec;
  }
  free (default_dns_copy);
#ifdef DEBUG_PRINT
  for (i = 0; i < NUM_DEFAULTS; i++) {
    printf ("%d: (4 and 6): ", i);
    if (ip4_defaults [i].ss_family == 0)
      printf ("no ipv4");
    else
      print_sockaddr ((struct sockaddr *) (&(ip4_defaults [i])),
                      sizeof (struct sockaddr_in));
    printf (", ");
    if (ip6_defaults [i].ss_family == 0)
      printf ("no ipv6");
    else
      print_sockaddr ((struct sockaddr *) (&(ip6_defaults [i])),
                      sizeof (struct sockaddr_in6));
    printf ("\n");
  }
#endif /* DEBUG_PRINT */
  snprintf (alog->b, alog->s, "init_default_dns is complete\n");
#ifdef DEBUG_PRINT
  printf ("%s", alog->b);
#endif /* DEBUG_PRINT */
  log_print (alog);
  pthread_mutex_lock (&mutex);
  save_peers (0);
  pthread_mutex_unlock (&mutex);
#ifdef DEBUG_PRINT
  printf ("after init, ");
  print_dht (0);
#endif /* DEBUG_PRINT */
  pthread_mutex_unlock (&only_one_thread_at_a_time);
  return NULL;
}

/* may be called multiple times.  If another thread is already
 * executing, this one will bow out gracefully (with the
 *   pthread_mutex_trylock (&only_one_thread_at_a_time) != 0
 * of init_default_dns). */
static void start_dns_thread ()
{
  pthread_t thread;
  pthread_create (&thread, NULL, init_default_dns, NULL);
  pthread_detach (thread);
}

/* returns number of entries added, 0...max */
/* if an entry has both IPv4 and IPv6, only list the IPv4 -- in 2018,
 * probably still the safe thing to do.   Later, perhaps, list only
 * the IPv6.  Listing both would double the traffic for little
 * obvious benefit */
static int add_default_routes (struct sockaddr_storage * result,
                               socklen_t * alen,
                               int off, int max)
{
  unsigned int i;
  int number = off;
  /* first add any currently resolved IP numbers from ip[45]_defaults */
  for (i = 0; (i < NUM_DEFAULTS) && (number >= 0) && (number < max); i++) {
    if ((! already_listed (ip4_defaults + i, result, number)) &&
        (! already_listed (ip6_defaults + i, result, number))) {
      /* prefer IPv4 for now (2018) by checking it first */
      if (ip4_defaults [i].ss_family == AF_INET) {
        if (alen != NULL) alen [number] = sizeof (struct sockaddr_in);
        result [number++] = ip4_defaults [i];
      } else if (ip6_defaults [i].ss_family == AF_INET6) {
        if (alen != NULL) alen [number] = sizeof (struct sockaddr_in6);
        result [number++] = ip6_defaults [i];
      }
    }
  }
  /* if still room, add any IP numbers from previous runs, in saved_ips */
  for (i = 0; (i < NUM_DEFAULTS) && (number >= 0) && (number < max); i++) {
    int index4 = 2 * i;
    int index6 = index4 + 1;
    if ((! already_listed (saved_ips + index4, result, number)) &&
        (! already_listed (saved_ips + index6, result, number))) {
      if (saved_ips [index4].ss_family == AF_INET) {
        if (alen != NULL) alen [number] = sizeof (struct sockaddr_in);
        result [number++] = saved_ips [index4];
      } else if (saved_ips [index6].ss_family == AF_INET6) {
        if (alen != NULL) alen [number] = sizeof (struct sockaddr_in6);
        result [number++] = saved_ips [index6];
      }
    }
  }
  /* if no entries found, repeat, but not more than once every 5min */
  static unsigned long long int last_reinitialized = 0;
  if ((number == 0) && (last_reinitialized + 300 < allnet_time ())) {
    last_reinitialized = allnet_time ();
    start_dns_thread (); /* done initializing but no entries found, so repeat */
  }
  return number - off;
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
static char * read_buffer (char * in, int nbytes, char * buf, int bsize)
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

/* returns 1 if successful, 0 otherwise */
static int load_peer (char * line, struct allnet_addr_info * peer) 
{
  memset (peer, 0, sizeof (struct allnet_addr_info));
  const char * original_line = line;  /* for debugging */
  /* printf ("load_peer parsing line %s\n", original_line); */
  char * end = line;
  if (*line != ':')
    return 0;
  line++;
  end = line;
  if ((end [0] != ' ') || (end [1] != '('))
    return 0;
  line = end + 2;
  int nbits = (int)strtol (line, &end, 10);
  if ((end == line) || (nbits < 0) || (nbits > ADDRESS_BITS))
    return 0;
  if ((end [0] != ')') || (end [1] != ' '))
    return 0;
  line = end + 2;
  int num_bytes = (int)strtol (line, &end, 10);
  if ((num_bytes < 0) || (num_bytes > ADDRESS_SIZE) || (end == line) ||
      (memcmp (end, " bytes: ", 8) != 0))
    return 0;
  line = end + 8;
  char address [ADDRESS_SIZE];
  memset (address, 0, sizeof (address));
  line = read_buffer (line, (nbits + 7) / 8, address, sizeof (address));
  if (memcmp (line, ", dist ", 7) != 0)
    return 0;
  line += 7;
  int dist = (int)strtol (line, &end, 10);
  if (end == line)
    return 0;
  line = end;
  if (memcmp (line, ", v ", 4) != 0)
    return 0;
  line += 4;
  int ipversion = (int)strtol (line, &end, 10);
  if (end == line)
    return 0;
  if ((ipversion != 4) && (ipversion != 6)) {
    printf ("load_peer: IP version %d in '%s'\n", ipversion, original_line);
    return 0;
  }
  line = end;
  if (memcmp (line, ", port ", 7) != 0)
    return 0;
  line += 7;
  int port = (int)strtol (line, &end, 10);
  if (end == line)
    return 0;
  line = end;
  if (memcmp (line, ", addr ", 7) != 0)
    return 0;
  line += 7;
  int af = AF_INET;
  if (ipversion == 6)
    af = AF_INET6;
  char storage [sizeof (struct in6_addr)];
  if (inet_pton (af, line, storage) != 1)
    return 0;
  memset (((char *) (peer)), 0, sizeof (struct allnet_addr_info));
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
  peer->hops = dist;
  peer->type = ALLNET_ADDR_INFO_TYPE_DHT;
  if (! sane_addr_info (peer, "load_peer"))
    return 0;
  return 1;
}

static void init_defaults ()
{
  if (alog == NULL)
    alog = init_log ("routing-init-defaults");
  random_bytes (my_address, ADDRESS_SIZE);
  buffer_to_string (my_address, ADDRESS_SIZE, "new random address",
                    ADDRESS_SIZE, 1, alog->b, alog->s);
  log_print (alog);
#ifdef DEBUG_PRINT
  print_buffer (my_address, ADDRESS_SIZE, "init_defaults: my_id", 99, 1);
#endif /* DEBUG_PRINT */
}

static void read_saved_ips ()
{
  static int initialized = 0;
  if (initialized)   /* only do this once */
    return;
  initialized = 1;
  int fd = open_read_config ("adht", "saved_ips", 0);
  if (fd >= 0) {
    ssize_t r = read (fd, saved_ips, sizeof (saved_ips));
    if (r != sizeof (saved_ips)) {
      perror ("reading saved_ips");
      printf ("read %zd rather than %zd, ignoring\n", r, sizeof (saved_ips));
      memset (saved_ips, 0, sizeof (saved_ips));
    }
    close (fd);
  }
}

/* always called with lock held */
/* returns 1 for a newly created ID, 0 for an existing ID */
static int read_create_my_id ()
{
  if (my_address_initialized)
    return 0;
  int result = 1;
  my_address_initialized = 1;
  char line [1000];
  int fd = open_read_config ("adht", "my_id", 0);
  if (fd < 0) {
    /* printf ("unable to open .allnet/adht/my_id\n"); */
    init_defaults ();
  } else {
    if ((! read_line (fd, line, sizeof (line))) ||
        (strlen (line) <= 0) ||
        ((line [0] != '-') &&
         ((strlen (line) < 30) || (strncmp (line, "8 bytes: ", 9) != 0)))) {
      printf ("unable to read ~/.allnet/adht/my_id file\n");
      init_defaults ();
    } else if (line [0] == '-') {
      printf ("~/.allnet/adht/my_id begins with '-', not saving\n");
      init_defaults ();
    } else {   /* line >= 30 bytes long, beginning with "8 bytes: " */
      read_buffer (line + 9, (int)strlen (line + 9), my_address, ADDRESS_SIZE);
      result = 0;
    }
    close (fd);
  }
  return result;
}

static int routing_add_dht_locked (struct allnet_addr_info addr);

/* since peers are stored in locations relative to the local address,
 * must be called AFTER the local address has been initialized */
static void read_peers_file ()
{
  char line [1000];
  int fd = open_read_config ("adht", "peers", 0);
  if (fd < 0)
    return;
  int ping_index = 0;
  while (read_line (fd, line, sizeof (line))) {
    if (strncmp (line, "p: ", 3) != 0) {  /* peer address, not a ping address */
      struct allnet_addr_info peer;
      char * end;
      int old_index = (int)strtol (line, &end, 10);
      if ((end != line) && (*end == ':') &&
          (old_index >= 0) && (old_index < MAX_PEERS) &&
          (load_peer (end + 1, &peer)))
        routing_add_dht_locked (peer);
    } else {   /* ping address, beginning with p: */
      if (load_peer (line + 3, &(pings [ping_index].ai))) {
        pings [ping_index].refreshed = 1;
        ping_index++;
      }
    }
  }
  close (fd);
}

/* always called with lock held */
static void load_peers (int only_if_newer)
{
  time_t mtime = config_file_mod_time ("adht", "peers", 0);
  if ((only_if_newer) && ((mtime == 0) || (mtime <= peers_file_time)))
    return;
  peers_file_time = mtime;
  /* an unused entry has nbits set to 0 -- might as well clear everything */
  memset ((char *) (peers), 0, sizeof (peers));
  memset ((char *) (pings), 0, sizeof (pings));
  read_saved_ips ();
  int new_id = read_create_my_id ();
  read_peers_file ();
#ifdef DEBUG_PRINT
  printf ("load_peers complete:\n");
  print_dht (0);
#endif /* DEBUG_PRINT */
  if (new_id)       /* the order likely changed because my_address changed */
    save_peers (0);
}

/* always called with lock held
 * returns 1 if initialized by this call, 0 after it is initialized */
static int init_peers ()
{
  if (alog == NULL)
    alog = init_log ("routing");
  static int initialized = 0;
  int result = 1 - initialized;  /* return 1 if this is the first call */
  load_peers (initialized);
  if (! initialized)
    start_dns_thread ();
  initialized = 1;
  return result;
}

/* fills in addr (of size at least ADDRESS_SIZE) with my address */
void routing_my_address (unsigned char * addr)
{
  pthread_mutex_lock (&mutex);
  /* routing_my_address is called from all the applications, so do
   * not call init_peers (), which should only be called by allnetd */
  read_create_my_id ();
  memcpy (addr, my_address, ADDRESS_SIZE);
  pthread_mutex_unlock (&mutex);
}

/* return true if the destination is closer to target than to
 * current.  Target and current are assumed to have ADDRESS_BITS
 * also returns true if the first nbits of dest match the target address
 * if nbits is 0, will always return 1 */
static int addr_closer (const unsigned char * dest, int nbits,
                        const unsigned char * current,
                        const unsigned char * target)
{
  if ((matching_bits (dest, nbits, current, ADDRESS_BITS) <
       matching_bits (dest, nbits, target, ADDRESS_BITS)) ||
      (matching_bits (dest, nbits, target, ADDRESS_BITS) == nbits))
    return 1;
  return 0;
}

static int addr_in_list (const unsigned char * addr,
                         const char * prev, int prev_count)
{
  int i;
  for (i = 0; i < prev_count; i++)
    if (memcmp (addr, prev + (i * ADDRESS_SIZE), ADDRESS_SIZE) == 0)
      return 1;
  return 0;
}

/* fills in an array of sockaddr_storage to the top internet addresses
 * (up to max_matches) for the given AllNet address.
 * returns the number of matches
 * returns zero if there are no matches */
/* the top matches are the ones with the most matching bits, so we start
 * looking from the last row of the array. */
int routing_top_dht_matches (const unsigned char * dest, int nbits,
                             struct sockaddr_storage * result, socklen_t * alen,
                             int max_matches)
{
/* print_buffer (dest, nbits, "routing_top_dht_matches:", (nbits + 7) / 8, 1);
print_dht (0); */
  memset (result, 0, max_matches * sizeof (struct sockaddr_storage));
  int peer = 0;
  if (nbits < 0)
    nbits = 0;
  if (nbits > ADDRESS_BITS)
    nbits = ADDRESS_BITS;
  /* peers may have both IPv4 and IPv6 addresses: send to each at most once */
  char prev_matches [1000 * ADDRESS_SIZE];
  int prev_count = 0;
  if (max_matches > 1000) {   /* prevent overflow of our fixed-sized array */
    printf ("error: max_matches %d > 1000\n", max_matches);
    max_matches = 1000;
  }
  pthread_mutex_lock (&mutex);
  init_peers ();
  int row, col;
  for (row = ADDRESS_BITS - 1; ((peer < max_matches) && (row >= 0)); row--) {
    for (col = 0; ((peer < max_matches) && (col < PEERS_PER_BIT)); col++) {
      struct allnet_addr_info * ai = &(peers [row * PEERS_PER_BIT + col].ai);
/* the DHT forwarding is to include up to max_matches neighbors from
 * the routing table, each of them closer than I am to the destination */
      if ((ai->nbits > 0) &&
          (addr_closer (dest, nbits, (unsigned char *) my_address,
                        ai->destination)) &&
          (! addr_in_list (ai->destination, prev_matches, prev_count))) {
        if (ai_to_sockaddr (ai, result + peer, alen + peer)) {
          peer++;   /* a valid translation */
          memcpy (prev_matches + (prev_count * ADDRESS_SIZE),  /* add to list */
                  ai->destination, ADDRESS_SIZE);
          prev_count++;
        }
      }
    }
  }
  pthread_mutex_unlock (&mutex);
/* if there is room left, include the "seeds" from the DNS list */
  if (peer < max_matches)
    peer += add_default_routes (result, alen, peer, max_matches);
#ifdef DEBUG_PRINT
  printf ("routing_top_dht_matches returning %d for ", peer);
  print_buffer ((char *) dest, (nbits + 7) / 8, NULL, ADDRESS_SIZE, 1);
  int i;
  for (i = 0; i < peer; i++) {
    if (alen == NULL)
      printf ("%d: ", i);
    else
      printf ("%d (%d): ", i, alen [i]);
    print_sockaddr ((struct sockaddr *) (&(result [i])),
                    sizeof (struct sockaddr_storage), 0);
    printf ("\n");
  }
#endif /* DEBUG_PRINT */
  return peer;
}

static void exact_match_print (char * description, int found,
                               const unsigned char * addr,
                               struct allnet_addr_info * result)
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
                                  struct allnet_addr_info * result)
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
 * match for this address (assumed to be of size ADDRESS_SIZE)
 * otherwise returns 0.  */
int routing_exact_match (const unsigned char * addr,
                         struct allnet_addr_info * result)
{
  int found = 0;
  pthread_mutex_lock (&mutex);
  init_peers ();
  found = search_data_structure (peers, MAX_PEERS, addr, result);
  if (! found)
    found = search_data_structure (pings, MAX_PINGS, addr, result);
  pthread_mutex_unlock (&mutex);
  exact_match_print ("routing_exact_match", found, addr, result);
  return found;
}

int ping_exact_match (const unsigned char * addr,
                      struct allnet_addr_info * result)
{
  pthread_mutex_lock (&mutex);
  init_peers ();
  int found = search_data_structure (pings, MAX_PINGS, addr, result);
  pthread_mutex_unlock (&mutex);
  exact_match_print ("ping_exact_match", found, addr, result);
  return found;
}

/* returns -1 if not found, the index if found */
static int find_peer (struct peer_info * peers_data, int max,
                      struct allnet_addr_info * addr)
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
static int find_ip (struct allnet_internet_addr * addr)
{
  /* ipv6 local host (::1) is used in the simulator and generally not found
   * in real deployments, so as long as it is a different port, we treat it
   * as not found */
  int is_ipv6_localhost = ((addr->ip_version == 6) &&
                           (memget (&(addr->ip), 0, sizeof (addr->ip) - 1)) &&
                           (addr->ip.s6_addr [sizeof (addr->ip) - 1] == 1));
  int i;
  for (i = 0; i < MAX_PEERS; i++) {
    if ((peers [i].ai.nbits > 0) &&
        (memcmp (&(addr->ip), &(peers [i].ai.ip.ip), sizeof (addr->ip)) == 0) &&
        /* if IPs are same, return found if it is not an IPv6 localhost,
         * or if it is, and the ports are the same */
        ((! is_ipv6_localhost) || (peers [i].ai.ip.port == addr->port)))
      return i;
  }
  return -1;
}

static void delete_ping (struct allnet_addr_info * addr)
{
  int i;
  for (i = 0; i < MAX_PINGS; i++) {
    if ((pings [i].ai.nbits > 0) &&
        (matches (pings [i].ai.destination, ADDRESS_BITS,
                  addr->destination, ADDRESS_BITS) >= ADDRESS_BITS))
      pings [i].ai.nbits = 0;  /* delete */
  }
}

/* same as routing_add_dht, but must be called with lock held and never
 * calls init_peers
 * either adds or refreshes a DHT entry.
 * returns 1 for a new entry, 0 for an existing entry, -1 for errors */
static int routing_add_dht_locked (struct allnet_addr_info addr)
{
  int result = -1;
  static int print_errors = 5;   /* only print the first 5 errors */
  char * description = ((print_errors > 0) ? "routing_add_dht_locked" : NULL);
  /* sanity checks first */
  if (! sane_addr_info (&addr, description)) {
    if (print_errors > 0) {
      printf ("routing_add_dht_locked given bad address, not saving\n");
      print_buffer (&addr, sizeof (addr), NULL, 1000, 1);
      print_addr_info (&addr);
      print_errors--;
    }
    return -1;
  }
  if (! is_valid_address (&(addr.ip))) {
    printf ("routing_add_dht_locked given invalid address, not saving\n");
    print_buffer (&addr, sizeof (addr), NULL, 1000, 1);
    print_addr_info (&addr);
    return -1;
  }
  if ((addr.nbits == ADDRESS_BITS) &&
      (addr.type == ALLNET_ADDR_INFO_TYPE_DHT)) {
    int bit_pos = matching_bits (addr.destination, ADDRESS_BITS,
                                 (unsigned char *) my_address, ADDRESS_BITS);
#ifdef DEBUG_PRINT
    printf ("adding at bit position %d, address ", bit_pos);
    print_addr_info (&addr);
#endif /* DEBUG_PRINT */
    int index = bit_pos * PEERS_PER_BIT;
    int received_dist = addr.hops + 1;
    int found = find_peer (peers + index, PEERS_PER_BIT, &addr);
    int table_dist = 256;
    if (found >= 0)
      table_dist = addr.hops;
    if ((found < 0) || (table_dist >= received_dist)) {
      int ip_index = find_ip (&(addr.ip));
      /* there should not be any others with the same IP.  If found, delete */
      if ((found < 0) && (ip_index >= 0))
        peers [ip_index].ai.nbits = 0;
      int limit = PEERS_PER_BIT - 1;
      result = 1;   /* new, unless found >= 0 */
      if (found >= 0) {
        result = 0; /* not new */
        limit = found;   /* move this address to the front of this bit */
      }
  #ifdef DEBUG_PRINT
      if (result != 0)
        printf ("found %d, limit %d, result %d\n", found, limit, result);
  #endif /* DEBUG_PRINT */
      int i;
      /* any addresses in front of this, but at the same bit position,
         move them back (i.e. to higher index) by one position
       * if found < 0, limit is PEERS_PER_BIT - 1, drop the last address */
      /* 2022/01/18 note: maybe preferentially keep low-distance addresses? */
      for (i = limit; i > 0; i--)
        peers [index + i] = peers [index + i - 1]; 
      peers [index].ai = addr;   /* put this one in front */
      peers [index].ai.hops = received_dist;
      peers [index].refreshed = 1;
      if (found < 0)   /* if it is in the ping list, delete it from there */
        delete_ping (&addr);
    }
  }
  static unsigned long long int last_saved = 0;
  int save = result > 0;
  /* if result is zero, there are no new addresses but the order of
   * addresses has changed, so save less frequently */
  if ((result == 0) &&
      ((last_saved == 0) || (last_saved + PEER_SAVE_TIME < allnet_time ())))
    save = 1;
  if (save) {
    save_peers (0);
    last_saved = allnet_time ();
  }
#ifdef DEBUG_PRINT
  printf ("after adding %s", (save ? "(saved) " : ""));
  print_addr_info (&addr);
  print_dht (0);
#endif /* DEBUG_PRINT */
  return result;
}

/* either adds or refreshes a DHT entry.
 * returns 1 for a new entry, 0 for an existing entry, -1 for errors */
int routing_add_dht (struct allnet_addr_info addr)
{
  pthread_mutex_lock (&mutex);
  init_peers ();
  int result = routing_add_dht_locked (addr);
  pthread_mutex_unlock (&mutex);
  return result;
}

/* either adds or refreshes an external IP address.
 * returns 1 for a new entry, 0 for an existing entry, -1 for errors */
int routing_add_external (struct allnet_internet_addr ip)
{
#ifdef DEBUG_PRINT
  printf ("starting routing_add_external for "); print_ia (&ip); printf ("\n");
#endif /* DEBUG_PRINT */
  /* sanity checks first */
  int v = is_valid_address (&ip);
  if ((v != 1) && (v != -1)) {
    printf ("routing_add_external given bad address\n");
    print_ia (&ip);
    return -1;
  }
  /* to lessen the opportunities for DDoS, only accept addrs with ALLNET_PORT */
  /* this means if we're behind a firewall, we discard external addrs */
  if (ip.port != htons (ALLNET_PORT)) {
#ifdef DEBUG_PRINT
    printf ("routing_add_external given bad port\n");
    print_ia (&ip);
#endif /* DEBUG_PRINT */
    return -1;
  }
  struct allnet_addr_info ai;
  memset (&ai, 0, sizeof (ai));
  ai.ip = ip;
  routing_my_address (ai.destination);
  ai.nbits = ADDRESS_BITS;
  ai.hops = 1;
  ai.type = ALLNET_ADDR_INFO_TYPE_DHT;
  pthread_mutex_lock (&mutex);
  if (self_addr_init == 0) {
    memset (self_addr, 0, sizeof (self_addr));
    self_addr_init = 1;
  } else {
    self_addr_init++;
  }
  int i;
  int free_index = -1;
  int least_fresh_index = -1;
  unsigned long long least_freshness = ((unsigned long long) 0) - 1;  /* max */
  for (i = 0; i < NUM_SELF_ADDRS; i++) {
    if (self_addr [i].valid) {
      if (same_aip (&(self_addr [i].ai), &ai)) {
        self_addr [i].freshness = self_addr_init;
        pthread_mutex_unlock (&mutex);
#ifdef DEBUG_PRINT
        printf ("routing_add_external already found address\n");
#endif /* DEBUG_PRINT */
        return 0;
      }
      if (least_freshness > self_addr [i].freshness) {
        least_freshness = self_addr [i].freshness;
        least_fresh_index = i;
      }
    } else {
      free_index = i;
    }
  }
  if (free_index < 0) {
    if (least_fresh_index < 0) {  /* strange */
      printf ("error (%lld): free index and least fresh index are both < 0\n",
              self_addr_init);
      for (i = 0; i < NUM_SELF_ADDRS; i++) {
        printf ("%d: %d %lld ", i, self_addr [i].valid,
                self_addr [i].freshness);
        print_addr_info (&(self_addr [i].ai));
      }
      least_fresh_index = 0;   /* or random */
    }
    free_index = least_fresh_index;
  } /* from here, free_index is a valid index >= 0 */
  self_addr [free_index].valid = 1;
  self_addr [free_index].ai = ai;
  self_addr [free_index].freshness = self_addr_init;
  pthread_mutex_unlock (&mutex);
#ifdef DEBUG_PRINT
  printf ("successful completion of routing_add_external\n");
#endif /* DEBUG_PRINT */
  return 1;
}

/* returns -1 if not found, the index if found */
static int find_ping (struct allnet_addr_info * addr)
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
static int routing_add_ping_locked (struct allnet_addr_info * addr)
{
  int i;
  if (! sane_addr_info (addr, "routing_add_ping_locked"))
{ print_buffer (addr, sizeof (struct allnet_addr_info), "rapl: bad addr_info", 40, 1);
    return -2;
}
  if (! is_valid_address (&(addr->ip))) {
    printf ("routing_add_ping_locked given invalid address, not saving\n");
    print_addr_info (addr);
    return -1;
  }
  if (find_peer (peers, MAX_PEERS, addr) >= 0) {
#ifdef DEBUG_PRINT
    printf ("rapl found peer, returning -1\n");
#endif /* DEBUG_PRINT */
    return -1;
  } else if (find_ip (&(addr->ip)) >= 0) {
    printf ("rapl found ip, returning -1\n");
#ifdef DEBUG_PRINT
#endif /* DEBUG_PRINT */
    return -1;
  } else {
    int n = find_ping (addr);
    if (n == -1) {   /* add to the front */
      for (i = MAX_PINGS - 1; i > 0; i--)
        pings [i] = pings [i - 1];
      pings [0].ai = *addr;
      pings [0].refreshed = 1;
#ifdef DEBUG_PRINT
      printf ("rapl did not find ping, returning 1\n");
#endif /* DEBUG_PRINT */
      return 1;
    } else {         /* move to the front */
      for (i = n; i > 0; i--)
        pings [i] = pings [i - 1];
      pings [0].ai = *addr;
      pings [0].refreshed = 1;
#ifdef DEBUG_PRINT
      printf ("rapl found ping, returning 0\n");
#endif /* DEBUG_PRINT */
      return 0;
    }
  }
  return -2;
}

static int delete_matching_address (struct socket_address_set * sock,
                                    struct socket_address_validity * sav,
                                    void * ref)
{
  struct allnet_addr_info * aip = (struct allnet_addr_info *) ref;
  struct sockaddr_storage sas;
  memset (&sas, 0, sizeof (sas));
  socklen_t alen;
  if (! ai_to_sockaddr (aip, &sas, &alen)) {
    printf ("error converting to sockaddr ai ");
    print_addr_info (aip);
    return 1;  /* keep */
  }
  if ((alen == sav->alen) &&
      (memcmp (&sas, &(sav->addr), alen) == 0))
    return 0;    /* delete */
  return 1;      /* keep */
}

/* expires old DHT entries that haven't been refreshed since the last call
 * and removes them from the socket set */
void routing_expire_dht (struct socket_set * s)
{
#ifdef DEBUG_PRINT
  int debug_ping_count = 0;
  int debug_peer_count = 0;
  printf ("routing_expire_dht ()\n");
  print_dht (0);
  print_ping_list (0);
#endif /* DEBUG_PRINT */
  pthread_mutex_lock (&mutex);
  init_peers ();
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
      struct allnet_addr_info copy = peers [i].ai;
      socket_addr_loop (s, delete_matching_address, &copy);
      peers [i].ai.nbits = 0;
      changed = 1;
      int rapl = routing_add_ping_locked (&copy);
      if (rapl < 0)
        printf ("routing_add_ping_locked result is %d\n", rapl);
#ifdef DEBUG_PRINT
      else
        printf ("routing_add_ping_locked result is %d for ", rapl);
      print_addr_info (&copy);
      debug_peer_count++;
#endif /* DEBUG_PRINT */
    } else {  /* increment the peer's distance */
      peers [i].ai.hops++;
    }
    /* mark all peers as not refreshed */
    peers [i].refreshed = 0;
  }
  if (changed)
    save_peers (0);
  pthread_mutex_unlock (&mutex);
#ifdef DEBUG_PRINT
  printf ("routing_expire_dht () finished, %s, expired %d pings, %d peers\n",
          (changed) ? "changed" : "no change", debug_ping_count,
          debug_peer_count);
  print_dht (0);
  print_ping_list (0);
#endif /* DEBUG_PRINT */
}

static struct allnet_addr_info * get_nth_peer (int n)
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

/* returns 1 if the address is in the routing table, 0 otherwise */
int is_in_routing_table (const struct sockaddr * addr, socklen_t alen)
{
  int result = 0;
  pthread_mutex_lock (&mutex);
  init_peers ();
  int i;
  for (i = 0; i < MAX_PEERS; i++) {
    if (peers [i].ai.nbits > 0) {
      struct sockaddr_storage peer;
      socklen_t plen;
      ai_to_sockaddr (&(peers [i].ai), &peer, &plen);
      if (same_sockaddr ((struct sockaddr_storage *) addr, alen, &peer, plen)) {
        result = 1;
        break;
      }
    }
  }
  pthread_mutex_unlock (&mutex);
  return result;
}

/* fills in the given array, which must have room for num_entries addr_infos,
 * with data to send.
 * returns the actual number of entries, which may be less than num_entries */
int routing_table (struct allnet_addr_info * data, int num_entries)
{
  int result = 0;
  pthread_mutex_lock (&mutex);
  init_peers ();
  if (num_entries > 0) {
    int num_peers = 0;
    int i;
    for (i = 0; i < MAX_PEERS; i++)
      if (peers [i].ai.nbits > 0)
        num_peers++;
    result = num_peers;
    if (result > num_entries)
      result = num_entries;
    int * permutation = random_permute (num_peers);
    int index = 0;  /* index into the permutation */
    for (i = 0; i < result; i++) { /* i is an index into data */
      struct allnet_addr_info * latest = get_nth_peer (permutation [index++]);
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
int routing_add_ping (struct allnet_addr_info * addr)
{
  pthread_mutex_lock (&mutex);
  init_peers ();
  int result = routing_add_ping_locked (addr);
  if (result >= 0)
    save_peers (0);
  pthread_mutex_unlock (&mutex);
  return result;
}

/* when iter is zero, initializes the iterator and fills in the first
 * value, if any.  Every subsequent call should use the prior return value > 0
 * When there are no more values to fill in, returns -1 */
int routing_ping_iterator (int iter, struct allnet_addr_info * ai)
{
  if ((iter < 0) || (iter >= MAX_PINGS))
    return -1;
  pthread_mutex_lock (&mutex);
  init_peers ();
  while ((iter < MAX_PINGS) &&
         ((pings [iter].ai.nbits == 0) || 
          (pings [iter].ai.nbits > ADDRESS_BITS))) {
    if (pings [iter].ai.nbits > ADDRESS_BITS) {
      printf ("error: routing_ping_iterator %d/%d seeing %d > %d bits\n",
              iter, MAX_PINGS, pings [iter].ai.nbits, ADDRESS_BITS);
      print_addr_info (&(pings [iter].ai));
      pings [iter].ai.nbits = 0;   /* something wrong, delete entry */
    }
    iter++;
  }
  if ((iter < MAX_PINGS) && (ai != NULL))
    *ai = pings [iter].ai;
  pthread_mutex_unlock (&mutex);
  if (iter < MAX_PINGS) {
    if (pings [iter].ai.nbits > ADDRESS_BITS) {
      printf ("error: routing_ping_iterator %d/%d returning %d > %d bits\n",
              iter, MAX_PINGS, pings [iter].ai.nbits, ADDRESS_BITS);
      print_addr_info (&(pings [iter].ai));
      return -1;
    }
    return iter + 1;
  }
  return -1;
}

/* returns the number of entries filled in, 0...max */
/* entry may be NULL, in which case nothing is filled in */
int init_own_routing_entries (struct allnet_addr_info * entry, int max,
                              const unsigned char * dest, int nbits)
{
  /* we change entry to go through the array, so keep track of the original */
  struct allnet_addr_info * original = entry;
  int original_max = max;
  pthread_mutex_lock (&mutex);
  init_peers ();
  pthread_mutex_unlock (&mutex);
  int result = 0;
  if (entry != NULL)
    memset (entry, 0, sizeof (struct allnet_addr_info) * max);
  struct interface_addr * int_addrs = NULL;
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
        struct allnet_internet_addr check;
        memset (&check, 0, sizeof (check));
        check.port = allnet_htons (ALLNET_PORT);
        if (is_loopback_ip (sa, sizeof (struct sockaddr_storage))) {
          /* ignore */
        } else if (sa->sa_family == AF_INET) {
          struct sockaddr_in * sinp = (struct sockaddr_in *) (sa);
          check.ip_version = 4;
          check.ip.s6_addr [10] = 0xff;
          check.ip.s6_addr [11] = 0xff;
          memcpy (check.ip.s6_addr + 12, &(sinp->sin_addr.s_addr), 4);
          valid = 1;
        } else if (sa->sa_family == AF_INET6) {
          struct sockaddr_in6 * sinp = (struct sockaddr_in6 *) (sa);
          check.ip_version = 6;
          memcpy (check.ip.s6_addr, &(sinp->sin6_addr.s6_addr), 16);
          valid = 1;
        } else {  /* unknown address family, ignore */
#ifdef DEBUG_PRINT
          printf ("interface %s, ignoring address family %d\n", next->ifa_name,
                  next->ifa_addr->sa_family);
#endif /* DEBUG_PRINT */
        }
        if (valid && is_valid_address (&check) && (entry != NULL)) {
          entry->ip = check;
          memcpy (entry->destination, dest, ADDRESS_SIZE);
          entry->nbits = nbits;
          entry->hops = 0;
          entry->type = ALLNET_ADDR_INFO_TYPE_DHT;
#ifdef DEBUG_PRINT
          printf ("%d/%d: added own address: ", result, max);
          print_addr_info (entry);
#endif /* DEBUG_PRINT */
          entry++;
          result++;
          max--;
        }
#ifdef DEBUG_PRINT
          else if (! is_valid_address (&check)) {
          printf ("init_own_routing_entries not adding, local IP address: ");
          print_sockaddr (sa, sizeof (struct sockaddr_storage));
          printf ("\n");
        }
#endif /* DEBUG_PRINT */
      }
    }
  }
  if ((entry != NULL) && (self_addr_init > 0)) {
/* add non-duplicate externally reported addresses as long as there is room */
    static int next_pos = 0;
    for (i = 0; ((max > 0) && (i < NUM_SELF_ADDRS)); i++) {
      next_pos = (next_pos + 1) % NUM_SELF_ADDRS;
      int index = next_pos;
      if (self_addr [index].valid) {
        struct allnet_addr_info * loop_entry = original;
        int num_loops = 0;  /* avoid infinite loops from errors */
        while ((loop_entry != entry) && (num_loops++ < original_max) &&
               (! same_aip (loop_entry, &(self_addr [index].ai))))
          loop_entry++;
        if (loop_entry == entry) { /* address is not already in the list */
          *entry = self_addr [index].ai;
          entry++;
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
  if (int_addrs != NULL)
    free (int_addrs);
  return result;
}

/* returns 1 if the given addr is one of mine, or matches my_address */
int is_own_address (struct allnet_addr_info * addr)
{
  if (memcmp (addr->destination, my_address, ADDRESS_SIZE) == 0)
    return 1;
#define MAX_MY_ADDRS	100
  struct allnet_addr_info mine [MAX_MY_ADDRS];
  int n = init_own_routing_entries (mine, MAX_MY_ADDRS - 1,
                                    addr->destination, ADDRESS_BITS);
#undef MAX_MY_ADDRS
  int i;
  for (i = 0; i < n; i++)
    if (same_ai (mine + i, addr))
      return 1;
  return 0;
}

/* save the peers file before shutting down */
void routing_save_peers ()
{
  pthread_mutex_lock (&mutex);
  save_peers (1);
  pthread_mutex_unlock (&mutex);
}

/* if token is not NULL, this call fills its ALLNET_TOKEN_SIZE bytes */
/* if it is NULL, this call generates a new token */ 
/* tokens are saved in ~/.allnet/acache/local_token */
void routing_local_token (unsigned char * token) {
  static int initialized = 0;
  static char local_token [ALLNET_TOKEN_SIZE];
  int create_random_token = (token == NULL);
  if ((! initialized) && (! create_random_token)) {
    int fd = open_read_config ("acache", "local_token", 0);
    if (fd < 0) {   /* create a new token */
      create_random_token = 1;
    } else {        /* try to read an existing token */
      ssize_t n = read (fd, local_token, sizeof (local_token));
      if (n != sizeof (local_token)) {
        perror ("read of local token");
        create_random_token = 1;
      }
      close (fd);
    }
  }
  initialized = 1;
  if (create_random_token) {
    random_bytes (local_token, sizeof (local_token));
print_buffer (local_token, ALLNET_TOKEN_SIZE, "generated new token", 100, 1);
    int fd = open_write_config ("acache", "local_token", 1);
    if (fd >= 0) {
      ssize_t n = write (fd, local_token, sizeof (local_token));
      if (n != sizeof (local_token))
        perror ("write of local token");
    }
  }
  if (token != NULL)
    memcpy (token, local_token, ALLNET_TOKEN_SIZE);
}
