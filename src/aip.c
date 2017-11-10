/* aip.c: get allnet messages from ad, send them to DHT and known hosts */
/*        get allnet messages from the internet, forward them to ad */
/* aip stands for A(llNet) IP interface */
/* main thread uses select to check the pipe from ad and the sockets */
/* secondary threads:
 * - listen and open TCP connections
 */
/* arguments are:
  - the fd number of the pipe from ad
  - the fd number of the pipe to ad
  - the name of the Unix socket
 */
/* config file "aip" "max_bps_for_others"
 * (e.g. ~/.allnet/aip/max_bps_for_others)
 * gives the maximum speed to send over the internet, in bytes/second
 * this speed limit only applies to messages with priority 0.5 or less.
 * if not given, the speed limit is 1% of the total traffic rate on
 * all internet interfaces since aip was started.
 * not currently implemented
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <limits.h> 		/* HOST_NAME_MAX */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>

#include "lib/packet.h"
#include "listen.h"
#include "lib/routing.h"
#include "lib/ai.h"
#include "lib/pipemsg.h"
#include "lib/priority.h"
#include "lib/util.h"
#include "lib/dcache.h"
#include "lib/allnet_log.h"
#include "lib/keys.h"

#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__) || defined(__IPHONE_OS_VERSION_MIN_REQUIRED)
#ifndef CONVERT_IPV4_TO_IPV6
#define CONVERT_IPV4_TO_IPV6 /* IPv6 UDP socket requires IPv4-mapped address */
#endif /* CONVERT_IPV4_TO_IPV6 */
#endif /* _WIN32 || _WIN64 || __CYGWIN__ || __IPHONE_OS_VERSION_MIN_REQUIRED */

struct udp_cache_record {
  struct sockaddr_storage sas;
  socklen_t salen;
  time_t last_received;
};

static struct allnet_log * alog = NULL;
static time_t last_successful_udp;

/* UDPv4 messages are limited to less than 2^16 bytes */
#define MAX_RECEIVE_BUFFER	ALLNET_MAX_UDP_SIZE

#if 0  /* not used, but may be useful in the future */
static int debug_always_match (void * a1, void * a2)
{
  return 1;
}

static void debug_print_addr_cache (void * addr_cache)
{
  void ** result = NULL;
  int n = cache_all_matches (addr_cache, debug_always_match, NULL, &result);
  if (n <= 0) {
    printf ("cache is empty: %d\n", n);
    return;
  }
  int i;
  for (i = 0; i < n; i++) {
    printf ("%d/%d: %p ", i, n, result [i]);
    if (result [i] != NULL)
      print_addr_info (result [i]);
  }
  if ((n > 0) && (result != NULL))
    free (result);
}
#endif /* 0 */

#if 0
static void add_ai_to_cache_or_record_usage (void * cache, 
                                             struct addr_info * ai)
{
  void * found = cache_get_match (cache, (match_function)(&same_ai), ai);
  if (found == NULL) { /* not already there, so add to cache */
    cache_add (cache, ai);
  } else { /* found, addr different pointers -- record that found is in use */
    cache_record_usage (cache, found);
    free (ai);   /* not saved in the cache */
  }
}

struct match_arg {
  /* arguments */
  unsigned char destination [ADDRESS_SIZE];
  unsigned char nbits;    /* how many bits of the destination are given */
};

/* aip_match should return nonzero for a matching entry (higher
 * values for a better match), and 0 for no match */
static int aip_match (void * a, void * data)
{
  struct match_arg * ma = (struct match_arg *) a;
  struct addr_info * ai = (struct addr_info *) data;
  int r = matching_bits (ma->destination, ma->nbits,
                         ai->destination, ai->nbits);
/*
  printf ("matching %d bits of ", ma->nbits);
  print_buffer (ma->destination, (ma->nbits + 7) / 8, NULL, 8, 0);
  printf (" to %d bits of ", ai->nbits);
  print_buffer (ai->destination, (ai->nbits + 7) / 8, NULL, 8, 0);
  printf (", result %d\n", r);
*/
  return r;
}

/* mallocs and sets result to an n-element array of struct sockaddr_in6
 * that are the best matches for the given destination */
/* returns the actual number of destinations found, or 0 */
static int top_destinations (void * addr_cache, int max, unsigned char * dest,
                             int nbits, struct sockaddr_in6 ** result)
{
  void ** matches;
  struct match_arg dest_arg;
  memcpy (dest_arg.destination, dest, (nbits + 7) / 8); 
  dest_arg.nbits = nbits;
  int num_matches = cache_all_matches (addr_cache, aip_match, &dest_arg,
                                       &matches);
/*
  printf ("top_destination (");
  print_buffer (dest, (nbits + 7) / 8, NULL, 100, 0);
  printf (" (%d), %d)\n", nbits, num_matches);
*/
  if (num_matches <= 0)
    return 0;
  if (num_matches > max)
    num_matches = max;    /* only return the first n matches */
  if (max > num_matches)
    max = num_matches;    /* only allocate enough for num_matches */
  struct sockaddr_in6 * new =
    malloc_or_fail (sizeof (struct sockaddr_in6) * max, "top_destinations");
  int i;
  for (i = 0; i < num_matches; i++) {
/* print_addr_info ((struct addr_info *) (matches [i])); */
    if (! ai_to_sockaddr (((struct addr_info *) (matches [i])),
                          (struct sockaddr *) (new + i), NULL)) {
      printf ("coding error: match %d of %d could not be made a sockaddr\n",
              i, num_matches); 
      exit (1);
    }
  }
  *result = new;
  free (matches);
  return num_matches;
}
#endif /* 0 */

#if 0
static int same_sockaddr (void * arg1, void * arg2)
{
  struct sockaddr_in6 * a1 = (struct sockaddr_in6 *) arg1;
  struct sockaddr_in6 * a2 = (struct sockaddr_in6 *) arg2;
  if (a1->sin6_family != a2->sin6_family)
    return 0;
  if (a1->sin6_family == AF_INET6) {
    if ((a1->sin6_port == a2->sin6_port) &&
        (memcmp (a1->sin6_addr.s6_addr, a2->sin6_addr.s6_addr,
                 sizeof (a1->sin6_addr)) == 0))
      return 1;
    return 0;
  }
  if (a1->sin6_family == AF_INET) {
    struct sockaddr_in * sin1 = (struct sockaddr_in  *) arg1;
    struct sockaddr_in * sin2 = (struct sockaddr_in  *) arg2;
    if ((sin1->sin_port == sin2->sin_port) &&
        (sin1->sin_addr.s_addr == sin2->sin_addr.s_addr))
      return 1;
    return 0;
  }
  snprintf (alog->b, alog->s,
            "same_sockaddr: unknown address family %d\n", a1->sin6_family);
  log_print (alog);
  return 0;
}
#endif /* 0 */

static int same_sockaddr_udp (void * arg1, void * arg2)
{
  struct sockaddr_in6 * a1 = (struct sockaddr_in6 *) arg1;
  struct udp_cache_record * ucr2 = (struct udp_cache_record *) arg2;
  struct sockaddr_in6 * a2 = (struct sockaddr_in6 *) (&(ucr2->sas));
  if (a1->sin6_family != a2->sin6_family)
    return 0;
  /* try to compare IPv6 first */
  if (a1->sin6_family == AF_INET6) {
    if ((a1->sin6_port == a2->sin6_port) &&
        (memcmp (a1->sin6_addr.s6_addr, a2->sin6_addr.s6_addr,
                 sizeof (a1->sin6_addr)) == 0))
      return 1;
    return 0;
  }
  /* not IPv6, now try to compare IPv4 */
  if (a1->sin6_family == AF_INET) {
    struct sockaddr_in * sin1 = (struct sockaddr_in  *) arg1;
    struct sockaddr_in * sin2 = (struct sockaddr_in  *) arg2;
    if ((sin1->sin_port == sin2->sin_port) &&
        (sin1->sin_addr.s_addr == sin2->sin_addr.s_addr))
      return 1;
    return 0;
  }
  /* neither IPv6 nor IPv4 -- what is it? */
  printf ("same_sockaddr: unknown address family %d\n", a1->sin6_family);
  return 0;
}

/* save the IP address of the sender, unless it is already there */
static void add_sockaddr_to_cache (void * cache, struct sockaddr * addr,
                                   socklen_t sasize)
{
  if ((addr->sa_family != AF_INET) && (addr->sa_family != AF_INET6)) {
    snprintf (alog->b, alog->s,
              "%s %d (not %d or %d), sasize %d (maybe %zd or %zd?)\n", 
              "add_sockaddr error: unexpected family",
              addr->sa_family, AF_INET, AF_INET6, sasize,
              sizeof (struct sockaddr_in), sizeof (struct sockaddr_in6));
    log_print (alog);
    return;
  }
  if ((sasize != sizeof (struct sockaddr_in)) &&
      (sasize != sizeof (struct sockaddr_in6))) {
    snprintf (alog->b, alog->s,
              "add_sockaddr error: unexpected sasize %d (not %zd or %zd)\n", 
              sasize,
              sizeof (struct sockaddr_in), sizeof (struct sockaddr_in6));
    log_print (alog);
    return;
  }
  /* found and addr are different pointers, so cannot rely on cache_add
   * detecting that this is a duplicate */
  void * found = cache_get_match (cache, same_sockaddr_udp, addr);
  if (found != NULL) {  /* found */
    int off = snprintf (alog->b, alog->s, "sockaddr already in cache: "); 
    print_sockaddr_str (addr, sasize, -1, alog->b + off, alog->s - off);
    cache_record_usage (cache, found); /* found, addr are different pointers */
    struct udp_cache_record * record = (struct udp_cache_record *) found;
    record->last_received = time (NULL);
  } else { /* add to cache */
    struct udp_cache_record * record =
      malloc_or_fail (sizeof (struct udp_cache_record), "add_sockaddr_cache");
    memcpy (&(record->sas), addr, sasize);
    record->salen = sasize;
    record->last_received = time (NULL);
    int off =
      snprintf (alog->b, alog->s, "adding sockaddr %p to cache: ", record); 
    print_sockaddr_str (addr, sasize, -1, alog->b + off, alog->s - off);
    cache_add (cache, record);
  }
/* if (found == NULL) printf ("%s\n", alog->b); */
  log_print (alog);
#ifdef DEBUG_PRINT
#endif /* DEBUG_PRINT */
}

static int send_udp (int udp, char * message, unsigned int msize,
                     struct sockaddr * sa, const char * caller)
{
  socklen_t addr_len = sizeof (struct sockaddr_storage);
  if (sa->sa_family == AF_INET)
    addr_len = sizeof (struct sockaddr_in);
  else
    addr_len = sizeof (struct sockaddr_in6);
#ifdef CONVERT_IPV4_TO_IPV6
  struct sockaddr_in6 sin6;  /* used only within send_udp */
  if (sa->sa_family == AF_INET) {
/* IPv4 addresses represented as IPv6 addresses are preceded by xffff */
    addr_len = sizeof (sin6);
    /* clear the parts of the address that we don't set */
    memset (&sin6, 0, addr_len);
    sin6.sin6_family = AF_INET6;
    unsigned char * ap = sin6.sin6_addr.s6_addr;  /* IPv6 address goes here */
    ap [10] = 0xff;
    ap [11] = 0xff;
    struct sockaddr_in * sinp = (struct sockaddr_in *) sa;
    memcpy (ap + 12, &(sinp->sin_addr), 4);
    sin6.sin6_port = sinp->sin_port;
/* use the new IPv6 address.  Again, sa is only used within send_udp */
    sa = (struct sockaddr *) (&sin6);
  }
#endif /* CONVERT_IPV4_TO_IPV6 */
  char description [1000];
  snprintf (description, sizeof (description),
            "send_udp %s sending to address", caller);
  buffer_to_string ((char *) sa, addr_len, description,
                    alog->s / 4, 1, alog->b, alog->s);
  log_print (alog);
  snprintf (alog->b, alog->s, "sendto (%d, %p, %d, 0, %p, %d)\n",
            udp, message, msize, sa, (int) addr_len);
  log_print (alog);
#ifndef MSG_NOSIGNAL  /* some OSs don't define MSG_NOSIGNAL.  To handle this,
                       * astart requests ignoring SIGPIPE.  But using
                       * MSG_NOSIGNAL, where available, is more
                       * fine-grained and therefore better in principle */
#define MSG_NOSIGNAL	0		/* no flag */
#endif /* MSG_NOSIGNAL */
  int flags = MSG_NOSIGNAL;
  size_t s = sendto (udp, message, msize, flags, sa, addr_len);
  int saved_errno = errno;
  if (s != msize) {
    int n = snprintf (alog->b, alog->s,
                      "error sending %d (sent %d, error %d) on udp %d to ",
                      msize, (int)s, saved_errno, udp);
    print_sockaddr_str (sa, 0, 0, alog->b + n, alog->s - n);
    errno = saved_errno;
    log_error (alog, "sendto");
    return 0;
  } else {  /* record successful send */
    last_successful_udp = time (NULL);
#ifdef LOG_PACKETS
    int n = snprintf (alog->b, alog->s, "send_udp %s sent %d bytes to ",
                      caller, msize);
    n += print_sockaddr_str (sa, 0, 0, alog->b + n, alog->s - n);
    log_print (alog);
#endif /* LOG_PACKETS */
  }
  return 1;
}

/* returns 1 for success, 0 for failure */
static int send_udp_addr (int udp, char * message, unsigned int msize,
                          struct internet_addr * addr)
{
  struct sockaddr_storage sas;
  memset (&sas, 0, sizeof (sas));
  struct sockaddr     * sap  = (struct sockaddr     *) (&sas);
  if (! ia_to_sockaddr (addr, sap, NULL)) {
    snprintf (alog->b, alog->s,
              "send_udp_addr unable to convert ia to sockaddr (%d)\n",
              addr->ip_version);
    log_print (alog);
    return 0;
  }
  int off = snprintf (alog->b, alog->s,
                      "send_udp_addr sending %d bytes to: ", msize);
  print_sockaddr_str (sap, sizeof (sas), 0, alog->b + off, alog->s - off);
#ifdef DEBUG_PRINT
#else /* DEBUG_PRINT */
  snprintf (alog->b, alog->s, "send_udp_addr sending %d bytes\n", msize);
#endif /* DEBUG_PRINT */
  log_print (alog);

  return send_udp (udp, message, msize, sap, "send_udp_addr");
}

/* assumed to be an outgoing, so do not check overall packet validity */
static int is_outgoing_dht (struct allnet_header * hp, unsigned int msize,
                            int min_entries)
{
  char * message = ((char *) hp);
  struct allnet_mgmt_header * mhp = 
    (struct allnet_mgmt_header *) (message + ALLNET_SIZE (hp->transport));
  if ((hp->message_type != ALLNET_TYPE_MGMT) ||
      (msize < ALLNET_DHT_SIZE (hp->transport, min_entries)) ||
      (mhp->mgmt_type != ALLNET_MGMT_DHT))
    return 0;
  return 1;
}

static char * cached_dht_packet = NULL;
static int cached_dht_size = 0;

static void dht_save_cached (struct allnet_header * hp, unsigned int msize)
{
  if (is_outgoing_dht (hp, msize, 1)) {
    int off = snprintf (alog->b, alog->s,
                        "dht_save_cache saving outgoing %d: ", msize);
    packet_to_string ((char *) hp, msize, NULL, 1,
                      alog->b + off, alog->s - off);
    log_print (alog);
    /* cache if possible, but if malloc fails, no big deal */
    if (cached_dht_packet != NULL)
      free (cached_dht_packet);
    cached_dht_packet = malloc (msize);
    if (cached_dht_packet != NULL) {
      cached_dht_size = msize;
      memcpy (cached_dht_packet, (char *) hp, msize);
    } else {
      cached_dht_size = 0;
      snprintf (alog->b, alog->s,
                "dht_save_cached unable to allocate %d bytes\n", msize);
      log_print (alog);
    }
  }
}

static int dht_ping_match (struct allnet_header * hp, unsigned int msize,
                           struct addr_info * match)
{
  if (! is_outgoing_dht (hp, msize, 0)) {
    snprintf (alog->b, alog->s, "dht_ping_match type+size %d+%d/%zd, done\n",
              hp->message_type, msize, ALLNET_DHT_SIZE (hp->transport, 0));
    log_print (alog);
    return 0;  /* not a dht message */
  }
  buffer_to_string ((char *) (hp->destination), ADDRESS_SIZE,
                    "dht_ping_match matching",
                    ADDRESS_SIZE, 1, alog->b, alog->s);
  log_print (alog);

  /* if it is a DHT message, try to send it to the ping addresses first */
  /* but only with 50% likelihood -- we should use the regular addresses too */
  if (((random () % 2) == 0) && (ping_exact_match (hp->destination, match))) {
    int off = snprintf (alog->b, alog->s, "dht_ping_match matched ping: ");
    addr_info_to_string (match, alog->b + off, alog->s - off);
    log_print (alog);
    return 1;
  }
  /* otherwise use the regular addresses -- note this is redundant,
   * since forward_message calls routing_exact_match if we return 0 */
  if (routing_exact_match (hp->destination, match)) {
    int off = snprintf (alog->b, alog->s, "dht_ping_match exact match: ");
    addr_info_to_string (match, alog->b + off, alog->s - off);
    log_print (alog);
    return 1;
  }
  snprintf (alog->b, alog->s, "dht_ping_match: no match\n");
  log_print (alog);
  return 0;
}

/* send at most about max_send/2 of the UDPs for which we have matching
 * translations, then the rest to a random permutation of other udps
 * we have heard from and tcps we are connected to */
static void forward_message (int * fds, int num_fds, int udp, void * udp_cache,
                             struct listen_info * info,
                             char * message, unsigned int msize,
                             int priority, int max_send)
{
#ifdef LOG_PACKETS
  snprintf (alog->b, alog->s, "forward_message %d fds\n", num_fds);
  log_print (alog);
#endif /* LOG_PACKETS */
  char * reason = NULL;
  if (! is_valid_message (message, msize, &reason)) {
#ifdef DEBUG_PRINT
    printf ("message is not valid: %s\n", reason);
#endif /* DEBUG_PRINT */
    return;
  }
  struct allnet_header * hp = (struct allnet_header *) message;
  dht_save_cached (hp, msize);

  struct addr_info exact_match;
  if ((hp->dst_nbits == ADDRESS_BITS) &&
      ((dht_ping_match (hp, msize, &exact_match)) ||
       (routing_exact_match (hp->destination, &exact_match))) &&
      (send_udp_addr (udp, message, msize, &(exact_match.ip)))) {
    int n = snprintf (alog->b, alog->s, "sent to exact match: ");
    addr_info_to_string (&exact_match, alog->b + n, alog->s - n);
    log_print (alog);
    return;   /* sent to exact match, done */
  }

/* send to at most 4 closer DHT nodes */
  int i;
#define DHT_SENDS	4
  struct sockaddr_storage dht_storage [DHT_SENDS];
  int dht_sends = routing_top_dht_matches (hp->destination, hp->dst_nbits,
                                           dht_storage, DHT_SENDS);
  if (dht_sends > max_send)
    dht_sends = max_send;
#undef DHT_SENDS
#ifdef LOG_PACKETS
  snprintf (alog->b, alog->s, "routing_top_dht_matches: %d\n", dht_sends);
  log_print (alog);
#endif /* LOG_PACKETS */
  for (i = 0; i < dht_sends; i++)
    send_udp (udp, message, msize, ((struct sockaddr *) (&(dht_storage [i]))),
              "forward_message dht_storage");
  max_send -= dht_sends;

  int max_listen = max_send / 2 + 1;
  int num_send_fds = 0;
  if (max_listen > 0) {
    int * send_fds = NULL;
    num_send_fds = listen_top_destinations (info, max_listen,
                                            hp->destination, hp->dst_nbits,
                                            &send_fds);
    for (i = 0; i < num_send_fds; i++)  /* send here first */
      send_pipe_message (send_fds [i], message, msize,
                         ALLNET_PRIORITY_DEFAULT, alog);
    if ((num_send_fds > 0) && (send_fds != NULL))
      free (send_fds);
    if (num_send_fds > 0) {
      snprintf (alog->b, alog->s, "forwarded to %d mappings\n", num_send_fds);
      log_print (alog);
    }
    max_send -= num_send_fds;
  }

  /* now send to a random subset of recently received-from addresses */
#define FORWARDING_UDPS	100
  void * udps [FORWARDING_UDPS];
  int num_udps = cache_random (udp_cache, FORWARDING_UDPS, udps);
  struct udp_cache_record * * ucrs = (struct udp_cache_record * *) udps;
#undef FORWARDING_UDPS
  int num_send_udps = num_udps;
  if (num_send_udps > max_send)
    num_send_udps = max_send;
  if (num_send_udps > 0) {
    int * random_selection = random_permute (num_udps);
    for (i = 0; i < num_send_udps; i++) {
      struct udp_cache_record * ucr = ucrs [random_selection [i]];
      send_udp (udp, message, msize, (struct sockaddr *) (&(ucr->sas)),
              "forward_message udp_cache");
    }
    if ((num_udps > 0) && (random_selection != NULL))
      free (random_selection);
  }
  max_send -= num_send_udps;  /* useful if we want to add code below this */
#ifdef LOG_PACKETS
  snprintf (alog->b, alog->s, "forwarded to %d+%d TCP and %d UDP\n",
            dht_sends, num_send_fds, num_send_udps);
  log_print (alog);
#endif /* LOG_PACKETS */
}

/* returns -1 for failure */
static int udp_socket (unsigned int max_depth)
{
  int udp = socket (AF_INET6, SOCK_DGRAM, 0);
  if (udp < 0) {
    snprintf (alog->b, alog->s, "unable to open UDP socket, exiting");
    log_error (alog, "main loop socket");
    return -1;
  }
  /* enable dual-stack IPv6 and IPv4 for systems that don't enable it
     by default */
  int v6only_flag = 0;   /* disable v6 only */
#ifndef __OpenBSD__  /* on openbsd, IPV6_V6ONLY is read-only */
  if (setsockopt (udp, IPPROTO_IPV6, IPV6_V6ONLY,
                  &v6only_flag, sizeof (v6only_flag)) != 0) {
    snprintf (alog->b, alog->s, "unable to setsockopt on UDP socket, exiting");
    log_error (alog, "setsockopt");
    return -1;
  }
#endif /* __OpenBSD__ */
#ifdef SO_NOSIGPIPE
  int option = 1;
  if (setsockopt (udp, SOL_SOCKET, SO_NOSIGPIPE, &option, sizeof (int)) != 0)
    perror ("aip setsockopt nosigpipe");
#endif /* SO_NOSIGPIPE */
  struct sockaddr_storage address;
  struct sockaddr     * ap  = (struct sockaddr     *) &address;
  /* struct sockaddr_in  * ap4 = (struct sockaddr_in  *) ap; */
  struct sockaddr_in6 * ap6 = (struct sockaddr_in6 *) ap;
  int addr_size = sizeof (struct sockaddr_in6);

  memset (&address, 0, addr_size);
  ap6->sin6_family = AF_INET6;
  memcpy (&(ap6->sin6_addr), &(in6addr_any), sizeof (ap6->sin6_addr));
  ap6->sin6_port = allnet_htons (ALLNET_PORT);
  if (bind (udp, ap, addr_size) < 0) {
    perror ("aip UDP bind");
    printf ("aip unable to bind to UDP %d/%x, probably already running\n",
            ALLNET_PORT, ALLNET_PORT);
#ifndef ALLNET_USE_FORK
/* keep trying -- we may be waking up from sleep */
snprintf (alog->b, alog->s, "aip closing udp %d\n", udp); log_print (alog);
    close (udp);   /* may be closed already */
    sleep (5);
    if (max_depth > 0)
      return udp_socket (max_depth - 1);
    else
      return -1;
#else  /* not iOS, so probably already running */
    return -1;
#endif /* ALLNET_USE_FORK */
  }
  snprintf (alog->b, alog->s, "opened UDP socket %d\n", udp);
  log_print (alog);
  return udp;
}

void listen_callback (int fd)
{
  if ((cached_dht_packet != NULL) && (cached_dht_size > 0)) {
    if (send_pipe_message (fd, cached_dht_packet, cached_dht_size,
                             ALLNET_PRIORITY_EPSILON, alog)) {
#ifdef DEBUG_PRINT
      snprintf (alog->b, alog->s, "sent cached dht to new socket %d\n", fd);
      log_print (alog);
#endif /* DEBUG_PRINT */
    } else {
      snprintf (alog->b, alog->s,
                "error sending %d-byte cached dht to new socket %d\n",
                cached_dht_size, fd);
      log_print (alog);
    }
  }
}

/* NUM_LISTENERS is the number of DHT nodes that we listen to.
 * We keep at most 2 for each of 2^LISTEN_BITS.
 * for example, when LISTEN_BITS is 5, we keep at most 32*2 = 64 listeners,
 * two for each 32nd part of the address space.  However, we
 * only keep listeners for the addresses that we actually care about,
 * so if all these addresses are in, e.g. 3 of the parts, we only listen
 * to at most 2 nodes in each of these parts, that is, 6 listeners.
 * Multiple parts may be assigned to the same DHT node -- if so, we only
 * open a single listen connection to that node.
 * All this makes the code more complex, but the networking more efficient.
 *
 * current code in make_listeners and connect_thread only works if
 * listen_bits <= 8 */
#define LISTEN_BITS	5
#define NUM_LISTENERS	(1 << LISTEN_BITS) * 2   /* 2 ^ LISTEN_BITS for v4/v6*/
static int listener_fds [NUM_LISTENERS];
static pthread_mutex_t listener_mutex = PTHREAD_MUTEX_INITIALIZER;
/* only modify active_listeners or any of these data structures,
 * while holding the mutex */
static int active_listeners = 0;

/* if successful, returns the socket to communicate as a listener
 * if not successful, returns -1 */
static int connect_listener (unsigned char * address, struct listen_info * info,
                             int af)
{
  int result = -1;
#define MAX_DHT	10
  struct sockaddr_storage sas [MAX_DHT];
  int num_dhts = routing_top_dht_matches (address, LISTEN_BITS, sas, MAX_DHT);
  if (num_dhts <= 0) {
    snprintf (alog->b, alog->s,
              "%d dhts, connect_listener (%d/0x%x, %d, %d) => %d\n", num_dhts,
              (address [0] & 0xff) >> (8 - LISTEN_BITS), address [0] & 0xff,
              af, num_dhts, result);
    log_print (alog);
    return result;
  }
#undef MAX_DHT
#ifdef LOG_PACKETS
  int i;
  for (i = 0; i < num_dhts; i++) {
    int off = snprintf (alog->b, alog->s, "routing_top_dht_matches [%d/%d]: ",
                        i, num_dhts);
    print_sockaddr_str ((struct sockaddr *) (sas + i),
                        sizeof (struct sockaddr_storage), -1,
                        alog->b + off, alog->s - off);
    log_print (alog);
  }
#endif /* LOG_PACKETS */

  int k;
  for (k = 0; (k < num_dhts) && (result < 0); k++) {
    if (af == sas [k].ss_family) {
      socklen_t salen = 0;
      if (af == AF_INET)
        salen = sizeof (struct sockaddr_in);
      else if (af == AF_INET6)
        salen = sizeof (struct sockaddr_in6);
      if (salen == 0)
        continue;   /* invalid address, ignore */
      /* check to see if we are already connected or connecting */
      struct addr_info ai;
      if (! sockaddr_to_ai ((struct sockaddr *) (sas + k), salen, &ai))
        continue;   /* invalid address, ignore */
      memcpy (ai.destination, address, sizeof (ai.destination));
      ai.nbits = LISTEN_BITS;
      int prev_fd = already_listening (&ai, info);
/* printf ("initial prev_fd returned %d for ", prev_fd); print_addr_info (&ai); */
      unsigned long long int start_time = allnet_time ();
      /* if prev_fd is -2, somebody else is trying to connect to the same */
      int wait_time = 2000;   /* 2ms, doubled on each loop */
      while ((prev_fd == -2) && (allnet_time () < start_time + 5)) {
/* printf ("prev_fd = %d in thread %u proc %d interval %d for ", prev_fd, (unsigned int) pthread_self (), getpid (), wait_time); print_addr_info (ai); */
        sleep_time_random_us (wait_time);  /* sleep for 0-2ms */
        wait_time += wait_time;            /* double the wait time */
        prev_fd = already_listening (&ai, info);  /* and try again */
/* printf ("loop prev_fd returned %d for ", prev_fd); print_addr_info (&ai);
sleep (1); */
      }
/* printf ("prev_fd = %d in thread %u proc %d interval %d for ", prev_fd, (unsigned int) pthread_self (), getpid (), wait_time); print_addr_info (&ai); */
      if (prev_fd >= 0) {  /* already listening for this address, done */
        result = prev_fd;
        break;
      }
      if (prev_fd == -2) {  /* timed out, give up */
/* printf ("giving up: prev_fd = %d in thread %u proc %d interval %d for ", prev_fd, (unsigned int) pthread_self (), getpid (), wait_time); print_addr_info (&ai); */
        break;
      }
      /* standard socket connection code supporting both IPv4 and IPv6 */
      int s = socket (af, SOCK_STREAM, 0);
      if (s < 0) {
        perror ("listener socket");
/* printf ("thread %u proc %d unable to open socket, releasing addr ", (unsigned int) pthread_self (), getpid ()); print_addr_info (&ai); */
        listen_clear_reservation (&ai, info);
        continue;
      }
      struct sockaddr * sap = (struct sockaddr *) (sas + k);
      if (connect (s, sap, salen) < 0) {
        int n = snprintf (alog->b, alog->s, "unable to connect %d to ", s);
        print_sockaddr_str (sap, salen, 1, alog->b + n, alog->s - n);
        log_error (alog, "listener connect");
snprintf (alog->b, alog->s, "aip c closing socket %d\n", s); log_print (alog);
        close (s);
#ifdef DEBUG_EBADFD
snprintf (ebadbuf, EBADBUFS,
"thread %ud proc %d unable to connect, closed %d, releasing addr ", (unsigned int) pthread_self (), getpid (), s);
addr_info_to_string (&ai, ebadbuf + strlen (ebadbuf),
                     EBADBUFS - strlen (ebadbuf));
record_message (info->pipe_descriptor);
#endif /* DEBUG_EBADFD */
        listen_clear_reservation (&ai, info);
        continue;   /* return to the top of the loop and try the next addr */
      }
#ifdef DEBUG_PRINT
      printf ("aip added fd %d, %p: ", s, &ai);
      print_addr_info (&ai);
#endif /* DEBUG_PRINT */
      /* listen_add_fd clears the reservation if it is successful */
      if (listen_add_fd (info, s, &ai, 1, "aip.c connect_listener")) {
        /* success! */
        int offset = snprintf (alog->b, alog->s,
                               "listening for %x/%d on socket %d at ",
                               address [0] & 0xff, LISTEN_BITS, s);
        offset += addr_info_to_string (&ai, alog->b + offset, alog->s - offset);
        log_print (alog);
        result = s;
        break;   /* found our listener */
      } else {   /* somebody else already has that address */
        int offset = snprintf (alog->b, alog->s,
                               "listen_add_fd => 0 for %x/%d on socket %d at ",
                               address [0] & 0xff, LISTEN_BITS, s);
        offset += addr_info_to_string (&ai, alog->b + offset, alog->s - offset);
#ifdef DEBUG_EBADFD
snprintf (ebadbuf, EBADBUFS, "%s", alog->b);
record_message (info->pipe_descriptor);
#endif /* DEBUG_EBADFD */
        log_print (alog);
snprintf (alog->b, alog->s, "aip m closing socket %d\n", s); log_print (alog);
        close (s);
        listen_clear_reservation (&ai, info);
      }
    }
  }
  snprintf (alog->b, alog->s,
            "connect_listener (%d(%d)/0x%x/0x%x, %d, %d) => %d\n",
            (address [0] & 0xff) >> (8 - LISTEN_BITS), LISTEN_BITS,
            (address [0] & 0xff) >> (8 - LISTEN_BITS), address [0] & 0xff,
            af, num_dhts, result);
  log_print (alog);
  return result;
}

struct connect_thread_arg {
  unsigned char address [ADDRESS_SIZE];
  struct listen_info * info;
  int af;
  int listener_index;
};

static void * connect_thread (void * a)
{
#ifdef DEBUG_PRINT
  static pthread_mutex_t connect_counter_mutex = PTHREAD_MUTEX_INITIALIZER;
  static int counter = 0;
  srandom (time (NULL) + getpid () + pthread_self ());
  int r = random () % 10000;
  pthread_mutex_lock (&connect_counter_mutex);
  counter++;
  printf ("starting connect thread %d, %d threads alive\n", r, counter);
  pthread_mutex_unlock (&connect_counter_mutex);
#endif /* DEBUG_PRINT */
  struct connect_thread_arg * arg = (struct connect_thread_arg *) a; 
  unsigned char address [ADDRESS_SIZE];
  memcpy (address, arg->address, ADDRESS_SIZE);
  struct listen_info * info = arg->info;
  int af = arg->af;
  int listener_index = arg->listener_index;
  free (a);  /* the caller can't do it, so we should */
  arg = NULL;
  routing_init_is_complete (1);   /* wait for routing to complete */
  int fd = connect_listener (address, info, af);
  if (fd >= 0) {
    pthread_mutex_lock (&listener_mutex);
    if (listener_fds [listener_index] == -1) {
      active_listeners++;
      listener_fds [listener_index] = fd;
    } else {   /* undo connect */
#ifdef DEBUG_EBADFD
snprintf (ebadbuf, EBADBUFS,
"connect_thread closing %d because listener_fds [%d] = %d\n", fd,
listener_index, listener_fds [listener_index]);
record_message (info->pipe_descriptor);
#endif /* DEBUG_EBADFD */
      if (listen_remove_fd (info, fd)) {      /* remove from info */
snprintf (alog->b, alog->s, "aip l closing socket %d\n", fd); log_print (alog);
        close (fd);                       /* remove from kernel */
      }
    }
    pthread_mutex_unlock (&listener_mutex);
  }
#ifdef DEBUG_EBADFD
else {
snprintf (ebadbuf, EBADBUFS,
"connect_thread connect_listener failed, result %d\n", fd);
record_message (info->pipe_descriptor);
}
#endif /* DEBUG_EBADFD */
#ifdef DEBUG_PRINT
  pthread_mutex_lock (&connect_counter_mutex);
  counter--;
  printf ("finished connect thread %d, %d threads alive\n", r, counter);
  pthread_mutex_unlock (&connect_counter_mutex);
#endif /* DEBUG_PRINT */
  return NULL;
}

static void create_connect_thread (struct listen_info * info,
                                   int af, int listener_index)
{
  struct connect_thread_arg * arg =
    malloc_or_fail (sizeof (struct connect_thread_arg), "connect_thread");
  memset (arg, 0, sizeof (struct connect_thread_arg));
  arg->address [0] = (listener_index / 2) << (8 - LISTEN_BITS);
  /* printf ("index %02x, new address %02x\n", listener_index,
          arg->address [0] & 0xff); */
  arg->info = info;
  arg->af = af;
  arg->listener_index = listener_index;
  pthread_attr_t attr;
  if (pthread_attr_init (&attr) != 0)
    log_error (alog, "pthread_attr_init");
  if (pthread_attr_setdetachstate (&attr, PTHREAD_CREATE_DETACHED) != 0)
    log_error (alog, "pthread_attr_setdetachstate");
  pthread_t thread;
  if (pthread_create (&thread, &attr, &connect_thread, (void *) arg))
    log_error (alog, "pthread_create");
}

static void remove_listener (int fd, struct listen_info * info)
{
#ifdef DEBUG_PRINT
  printf ("remove_listener (fd %d)\n", fd);
  int debug_removed = 0;
#endif /* DEBUG_PRINT */
  pthread_mutex_lock (&listener_mutex);
  int i;
  for (i = 0; i < NUM_LISTENERS; i++) {
    if (listener_fds [i] == fd) {
      listener_fds [i] = -1;
      if (active_listeners > 0)
        active_listeners--;
#ifdef DEBUG_PRINT
      debug_removed = 1;
#endif /* DEBUG_PRINT */
    }
  }
  if (listen_remove_fd (info, fd)) { /* remove from info and pipemsg */
#ifdef DEBUG_EBADFD
snprintf (ebadbuf, EBADBUFS, "remove_listener removing fd %d\n", fd);
record_message (info->pipe_descriptor);
#endif /* DEBUG_EBADFD */
snprintf (alog->b, alog->s, "aip r closing socket %d\n", fd); log_print (alog);
    close (fd);       /* remove from kernel */
  }
  pthread_mutex_unlock (&listener_mutex);
#ifdef DEBUG_PRINT
  if (debug_removed)
    printf ("removed fd %d, status %d\n", fd, debug_removed);
  else
    printf ("fd %d not found, not removed\n", fd);
#endif /* DEBUG_PRINT */
}

/* Connect can block for several seconds, so spawn a thread for
   each listener.  Listeners are selected to correspond to at least
   one of our local addresses. */
static void make_listeners (struct listen_info * info)
{
  int i;
  int connect_to_index [NUM_LISTENERS];
  int in_use [NUM_LISTENERS];
  for (i = 0; i < NUM_LISTENERS; i++) {
    connect_to_index [i] = 0;  /* set to 1 if we should connect */
    in_use [i] = 0;            /* set to 1 if already in use */
  }
  char ** contacts;
  int num_contacts = all_contacts (&contacts);
  int dht_count = 0;
  int existing = 0;
  for (i = 0; i < num_contacts; i++) {
    int j;
    keyset * keysets = NULL;
    int num_keysets = all_keys (contacts [i], &keysets);
    for (j = 0; j < num_keysets; j++) {
      unsigned char address [ADDRESS_SIZE];
      if (get_local (keysets [j], address) >= LISTEN_BITS) {
        int index = ((address [0] & 0xff) >> (8 - LISTEN_BITS)) * 2;
        if (index + 1 >= NUM_LISTENERS) { /* sanity check, should not happen */
          printf ("error: original address %02x, index %02x (%d %d), %d bits\n",
                  address [0] & 0xff, index, index, index + 1, LISTEN_BITS);
          continue;
        }
        if (listener_fds [index] < 0) {
          connect_to_index [index] = 1;
          dht_count++;
        } else {
          in_use [index] = 1;
          existing++;
        }
        if (listener_fds [index + 1] < 0) {
          connect_to_index [index + 1] = 1;
          dht_count++;
        } else {
          in_use [index + 1] = 1;
          existing++;
        }
      }
    }
    if ((num_keysets > 0) && (keysets != NULL))
      free (keysets);
  }
  if ((num_contacts > 0) && (contacts != NULL))
    free (contacts);
  for (i = 0; i < NUM_LISTENERS; i++) {
    if (! in_use [i]) {   /* close socket (if any) if it is not in use */
      if (listener_fds [i] >= 0)
        remove_listener (listener_fds [i], info);
      listener_fds [i] = -1;
    }
  }
#define MIN_DHT_CONNECTIONS     4
  int debug_loop_count = 0;  /* sanity check, make sure we don't loop forever */
  while (existing + dht_count < MIN_DHT_CONNECTIONS) {
    /* if we have too few contacts, connect some random addresses */
    unsigned long long int r = random_int (0, NUM_LISTENERS - 1);
    int index = (int) r;
    if (listener_fds [index] < 0) {
      connect_to_index [index] = 1;
      dht_count++;
    }
    if (debug_loop_count++ > 1000 * NUM_LISTENERS) {
      printf ("error: infinite loop in make_listeners\n");
      printf ("       existing %d, dht_count %d, min %d, num %d %d\n",
              existing, dht_count, MIN_DHT_CONNECTIONS, NUM_LISTENERS,
              debug_loop_count);
      printf ("       ");
      for (index = 0; index < NUM_LISTENERS; index++)
        printf ("%d, ", listener_fds [index]);
      printf ("\n");
      break;
    }
  }
  for (i = 0; i < NUM_LISTENERS; i += 2) {
    if (connect_to_index [i])
      create_connect_thread (info, AF_INET, i);
    if (connect_to_index [i + 1])
      create_connect_thread (info, AF_INET6, i + 1);
  }
}

void send_keepalive (void * udp_cache, int udp,
                     int * listeners, int num_listeners)
{
  unsigned int max_size = ALLNET_MGMT_HEADER_SIZE (0xff);
  char keepalive [ALLNET_MTU];
  memset (keepalive, 0, max_size);
  unsigned char address [ADDRESS_SIZE];
  memset (address, 0, sizeof (address));
  struct allnet_header * hp =
    init_packet (keepalive, sizeof (keepalive), ALLNET_TYPE_MGMT, 1,
                 ALLNET_SIGTYPE_NONE, address, 0, address, 0, NULL, NULL);
  struct allnet_mgmt_header * mhp =
    (struct allnet_mgmt_header *) (keepalive + ALLNET_SIZE (hp->transport));
  mhp->mgmt_type = ALLNET_MGMT_KEEPALIVE;
  unsigned int size = ALLNET_MGMT_HEADER_SIZE (hp->transport);
  if (size > max_size) {  /* sanity check */
    snprintf (alog->b, alog->s, "error: keepalive size %d, max %d\n",
              size, max_size);
    log_print (alog);
  }

  void * udp_void_ptr;
  int nudps = cache_random (udp_cache, 1, &udp_void_ptr);
  if (nudps > 0) {
    struct udp_cache_record * ucr = udp_void_ptr;
/* keep a copy of the sockaddr, since before we print it, it might be freed */
    struct sockaddr_storage sas_copy = ucr->sas;
    struct sockaddr * sap = (struct sockaddr *) (&sas_copy);
    int off = 0;
    /* send keepalives for at most 2 hours. after that, remove from cache */
    if ((time (NULL) - ucr->last_received) < 7200) {
      send_udp (udp, keepalive, size, sap, "send_keepalive");
      off = snprintf (alog->b, alog->s, "sent %d-byte keepalive to ", size);
    } else {
      cache_remove (udp_cache, udp_void_ptr);
      off = snprintf (alog->b, alog->s, "time out (%ld seconds), removed ",
                      (long) (time (NULL) - ucr->last_received));
    } 
#ifdef DEBUG_PRINT
    off += print_sockaddr_str (sap, sizeof (sas_copy), 0,
                               alog->b + off, alog->s - off);
#else /* DEBUG_PRINT */
    snprintf (alog->b + off, alog->s - off, "\n");
#endif /* DEBUG_PRINT */
#ifdef LOG_PACKETS
    log_print (alog);
#endif /* LOG_PACKETS */
  }

  if (num_listeners > 0) {
    int i;
    int sent = 0;
    for (i = 0; i < num_listeners; i++) {
      if (listeners [i] >= 0) {
        /* send with lowest priority -- if anything else is going, we don't
           need a keepalive */
        if (! send_pipe_message (listeners [i], keepalive, size,
                                 ALLNET_PRIORITY_EPSILON, alog)) {
          snprintf (alog->b, alog->s,
                    "aip error sending keepalive to socket %d\n",
                    listeners [i]);
          log_print (alog);
        } else {
          sent++;
        }
      }
    }
#ifdef LOG_PACKETS
    snprintf (alog->b, alog->s,
              "aip sent %d-byte keepalive to %d listeners\n", size, sent);
    log_print (alog);
#endif /* LOG_PACKETS */
  }
}

static void send_dht_ping_response (struct sockaddr * sap, socklen_t sasize,
                                    struct allnet_header * in_hp, int udp)
{
  int off = snprintf (alog->b, alog->s, "send_dht_ping_response ");
#ifdef DEBUG_PRINT
  print_sockaddr_str (sap, sasize, 0, alog->b + off, alog->s - off);
#else /* DEBUG_PRINT */
  snprintf (alog->b + off, alog->s - off, "\n");
#endif /* DEBUG_PRINT */
  log_print (alog);
  unsigned char message [ADHT_MAX_PACKET_SIZE];
  memset (message, 0, sizeof (message));
  struct allnet_header * hp =
    init_packet ((char *) message, sizeof (message), ALLNET_TYPE_MGMT, 1,
                 ALLNET_SIGTYPE_NONE, in_hp->destination, in_hp->dst_nbits,
                 in_hp->source, in_hp->src_nbits, NULL, NULL);
  struct allnet_mgmt_header * mp =
    (struct allnet_mgmt_header *) (message + ALLNET_SIZE (hp->transport));
  mp->mgmt_type = ALLNET_MGMT_DHT;
  unsigned char * dhtp = message + ALLNET_MGMT_HEADER_SIZE (hp->transport);
  struct allnet_mgmt_dht * dht = (struct allnet_mgmt_dht *) dhtp;
  
  size_t max = (sizeof (message) -
                (((unsigned char *) (dht->nodes)) - message)) /
               sizeof (struct addr_info);

  unsigned char my_addr [ADDRESS_SIZE];
  routing_my_address (my_addr);
  int n = init_own_routing_entries (dht->nodes, (int)max,
                                    my_addr, ADDRESS_BITS);
  if (n > 0) {
    dht->num_sender = n;
    dht->num_dht_nodes = 0;
    writeb64u (dht->timestamp, allnet_time ());
    if (ALLNET_DHT_SIZE (hp->transport, n) > ADHT_MAX_PACKET_SIZE) {
      snprintf (alog->b, alog->s, "error: dht_size %d (%02x, %d) > %d\n",
                (int) (ALLNET_DHT_SIZE (hp->transport, n)), hp->transport, n,
                ADHT_MAX_PACKET_SIZE);
      log_print (alog);
      return;
    }
    send_udp (udp, (char *) message, ALLNET_DHT_SIZE (hp->transport, n), sap,
              "send_dht_ping_response");
#ifdef DEBUG_PRINT
    packet_to_string ((char *) message, ALLNET_DHT_SIZE (hp->transport, n),
                      "sent ping response", 1, alog->b, alog->s);
    int off = strlen (alog->b);
    off += snprintf (alog->b + off, alog->s - off, " to: ");
    print_sockaddr_str (sap, sasize, 0, alog->b + off, alog->s - off);
    log_print (alog);
#endif /* DEBUG_PRINT */
  }
}

/* returns how much smaller the new packet is after removing the
 * senders that do not match sap */
static int dht_filter_senders (struct sockaddr * sap, socklen_t sasize,
                               struct allnet_mgmt_dht * mdp)
{
  int result = 0;
  unsigned int n_sender = mdp->num_sender;
#ifdef DEBUG_PRINT
  snprintf (alog->b, alog->s, "dht_filter_senders %d senders\n", n_sender);
  log_print (alog);
#endif /* DEBUG_PRINT */
  if (n_sender == 0)
    return 0;   /* nothing to do */
  unsigned int n_dht = mdp->num_dht_nodes;
  struct sockaddr_in * sin = (struct sockaddr_in *) sap;
  struct sockaddr_in6 * sin6 = (struct sockaddr_in6 *) sap;
#ifdef DEBUG_PRINT
  printf ("removing from DHT packet senders that do not match: ");
  print_sockaddr (sap, sasize, -1);
  printf ("\n");
#endif /* DEBUG_PRINT */
  static const char ipv4_in_ipv6 [] =
                     { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff }; 
  int i, found = -1;
  for (i = 0; i < n_sender; i++) {
    if (((mdp->nodes [i].ip.ip_version == 4) &&
         (sap->sa_family == AF_INET) &&
         (memcmp (mdp->nodes [i].ip.ip.s6_addr + 12,
                  &(sin->sin_addr.s_addr), 4) == 0) &&
         (mdp->nodes [i].ip.port == sin->sin_port)) ||
        ((mdp->nodes [i].ip.ip_version == 6) &&
         (sap->sa_family == AF_INET6) &&
         (memcmp (mdp->nodes [i].ip.ip.s6_addr, sin6->sin6_addr.s6_addr, 16)
          == 0) &&
         (mdp->nodes [i].ip.port == sin->sin_port)) ||
        ((mdp->nodes [i].ip.ip_version == 4) &&  /* ipv6-encoded ipv4 */
         (sap->sa_family == AF_INET6) &&
         (memcmp (ipv4_in_ipv6, sin6->sin6_addr.s6_addr, 12) == 0) &&
         (memcmp (mdp->nodes [i].ip.ip.s6_addr + 12,
                  sin6->sin6_addr.s6_addr + 12, 4) == 0) &&
         (mdp->nodes [i].ip.port == sin6->sin6_port)))
      found = i;
  }
  if (found >= 0) {
#ifdef DEBUG_PRINT
    printf ("found sender address %d/%d, ", found, n_sender);
    print_addr_info (mdp->nodes + found);
#endif /* DEBUG_PRINT */
  }
  /* eliminate all non-matching sender addrs */
  if (((found >= 0) && (n_sender > 1)) || ((found < 0) && (n_sender > 0))) {
    unsigned int offset = 0;
    if (found >= 0)
      offset = 1;
    if (found > 0)
      mdp->nodes [0] = mdp->nodes [found];
    if (n_sender > 0)
      for (i = 0; i < n_dht; i++)
        mdp->nodes [i + offset] = mdp->nodes [i + n_sender];
    result = (n_sender - offset) * sizeof (struct addr_info);
    mdp->num_sender = offset;
  }
  return result;
}

/* handle peer, DHT, and keepalive messages */
/* if it is a peer message, changes the listener to listen to one of
 * the peers instead */
/* returns 1 if we are done processing, 0 if processing should continue */
static int handle_mgmt (int * listeners, int num_listeners, int peer,
                        char * message, int * msizep, int udp,
                        struct sockaddr * sap, socklen_t sasize, pd p)
{
#ifdef DEBUG_PRINT
  int off = snprintf (alog->b, alog->s, "handle_mgmt (%d, %d, %d, %p, %d, ",
                      *listeners, num_listeners, peer, message, *msizep);
  if (sasize > 0)
    print_sockaddr_str (sap, sasize, 0, alog->b + off, alog->s - off);
  else
    snprintf (alog->b + off, alog->s - off, ")\n");
  log_print (alog);
#endif /* DEBUG_PRINT */
  unsigned int msize = 0;
  if (*msizep > 0)
    msize = *msizep;
  if (msize < ALLNET_HEADER_SIZE)
    return 0;
  struct allnet_header * hp = (struct allnet_header *) message;
  if (msize < ALLNET_MGMT_HEADER_SIZE (hp->transport))
    return 0;
  struct allnet_mgmt_header * mp =
    (struct allnet_mgmt_header *) (message + ALLNET_SIZE (hp->transport));
#ifdef DEBUG_PRINT
  snprintf (alog->b, alog->s, "handle_mgmt type %d/%d\n",
            hp->message_type, mp->mgmt_type);
  log_print (alog);
#endif /* DEBUG_PRINT */
  if (hp->message_type != ALLNET_TYPE_MGMT)
    return 0;
  if (mp->mgmt_type == ALLNET_MGMT_PEERS) {
    if (msize < ALLNET_PEER_SIZE (hp->transport, 1))
      return 0;
    int listener_index = -1;
    int i;
    for (i = 0; i < num_listeners; i++)
      if (listeners [i] == peer)
        listener_index = i;
    if (listener_index < 0) {
      printf ("unsolicited peer message fd %d\n", peer);
      return 0;
    }
    struct allnet_mgmt_peers * mpp =
      (struct allnet_mgmt_peers *)
        (message + ALLNET_MGMT_HEADER_SIZE (hp->transport));
    unsigned int npeers = mpp->num_peers & 0xff;
    if (msize < ALLNET_PEER_SIZE(hp->transport, npeers))
      return 0;
    unsigned int index;
    for (index = 0; index < npeers; index++) {
      struct internet_addr * ia = mpp->peers + index;
      struct sockaddr_storage sas;
      struct sockaddr * sap2 = (struct sockaddr *) (&sas);
      socklen_t salen;
      if (ia_to_sockaddr (ia, sap2, &salen)) {
        int af = (ia->ip_version == 4) ? AF_INET : AF_INET6;
        int new_sock = socket (af, SOCK_STREAM, 0);
        if (connect (new_sock, sap2, salen) == 0) {  /* success */
#ifdef DEBUG_EBADFD
          snprintf (ebadbuf, EBADBUFS,
                    "handle_mgmt, connect succeeded, closing list [%d] = %d\n",
                    listener_index, listeners [listener_index]);
          record_message (p);
#endif /* DEBUG_EBADFD */
snprintf (alog->b, alog->s, "aip h closing socket %d [%d] for %d\n", listeners [listener_index], listener_index, new_sock); log_print (alog);
          close (listeners [listener_index]);
          listeners [listener_index] = new_sock;
          return 1;
        } else {
          perror ("warning: connect/listener");  /* not really an error */
#ifdef DEBUG_EBADFD
          snprintf (ebadbuf, EBADBUFS,
                    "handle_mgmt, connect failed, closing %d\n", new_sock);
          record_message (p);
#endif /* DEBUG_EBADFD */
snprintf (alog->b, alog->s, "aip h2 closing socket %d\n", new_sock); log_print (alog);
          close (new_sock);
        }
      }
    }
    if (npeers > 0) {
      printf ("error: none of the %d peers given were valid:\n", npeers);
      for (index = 0; index < npeers; index++)
        print_ia (mpp->peers + index);
    }
  } else if (mp->mgmt_type == ALLNET_MGMT_DHT) {
#ifdef DEBUG_PRINT
    snprintf (alog->b, alog->s, "handle_mgmt DHT %d\n", sap->sa_family);
    log_print (alog);
#endif /* DEBUG_PRINT */
    if (((int) (sap->sa_family)) == -1)
      return 1;   /* discard message, don't forward any further */
    struct allnet_mgmt_dht * mdp =
      (struct allnet_mgmt_dht *)
        (message + ALLNET_MGMT_HEADER_SIZE (hp->transport));
snprintf (alog->b, alog->s, "%d senders, %d nodes\n",
mdp->num_sender, mdp->num_dht_nodes);
log_print (alog);
    if (msize < ALLNET_DHT_SIZE (hp->transport,
                                 (mdp->num_sender + mdp->num_dht_nodes)))
      return 0;
    if ((mdp->num_sender == 0) && (mdp->num_dht_nodes == 0)) {
      /* ping req from behind a NAT/firewall */
      send_dht_ping_response (sap, sasize, hp, udp);
      return 1;   /* message handled */
    }
    (*msizep) -= dht_filter_senders (sap, sasize, mdp);
#ifdef DEBUG_PRINT
    print_packet (message, *msizep, "packet with all but sender removed", 1); 
    snprintf (alog->b, alog->s, "handle_mgmt returning 0, %d senders left\n",
              mdp->num_sender);
    log_print (alog);
#endif /* DEBUG_PRINT */
    return 0;   /* forward to adht process */
  } else if (mp->mgmt_type == ALLNET_MGMT_KEEPALIVE) {
    return 1;   /* do not forward */
  }
  return 0;   /* no peer connection established, or no valid DHT msg */
}

/* int debug_print_fd = -1; */

static void main_loop (int rpipe, int wpipe, struct listen_info * info)
{
  int udp = udp_socket (100);
  void * udp_cache = cache_init (128, free, "aip UDP cache");
  int removed_listener = 0;
  time_t last_listen = 0;
  time_t last_keepalive = 0;
  /* global */ last_successful_udp = time (NULL);
  while (1) {
    if ((last_listen == 0) ||                 /* if never updated */
        (time (NULL) - last_listen > 300) || /* once every 5min try to update */
  /* or once every 30sec if we've recently removed an fd or are disconnected */
        ((removed_listener || (active_listeners == 0)) &&
         ((time (NULL) - last_listen) > 30))) {
/* printf ("making listeners\n"); */
/* if we are already connected to everyone we want to connect to, then the
   call to make_listeners should be essentially free */
      make_listeners (info);
      last_listen = time (NULL);
      removed_listener = 0;
    }
    if ((last_keepalive == 0) || (time (NULL) - last_keepalive >= 55)) {
      send_keepalive (udp_cache, udp, listener_fds, NUM_LISTENERS);
      last_keepalive = time (NULL);
    }
    if ((udp == -1) || (time (NULL) - last_successful_udp >= 30)) {
      if (udp != -1) {
#ifdef DEBUG_EBADFD
snprintf (ebadbuf, EBADBUFS,
"aip main loop, timeout, closing UDP socket %d\n", udp);
record_message (info->pipe_descriptor);
#endif /* DEBUG_EBADFD */
snprintf (alog->b, alog->s, "aip ml closing udp %d\n", udp); log_print (alog);
        close (udp);
      }
#ifdef DEBUG_PRINT
      int old_udp = udp;
#endif /* DEBUG_PRINT */
      udp = udp_socket (100);
      last_successful_udp = time (NULL);
#ifdef DEBUG_PRINT
      printf ("aip: reset udp fd from %d to %d\n", old_udp, udp);
#endif /* DEBUG_PRINT */
    }
    int fd = -1;
    unsigned int priority;
    char * message = NULL;
    struct sockaddr_storage sockaddr;
    struct sockaddr * sap = (struct sockaddr *) (&sockaddr);
    socklen_t sasize = sizeof (sockaddr);
    int result = receive_pipe_message_fd (info->pipe_descriptor, 1000,
                                          &message, udp, sap, &sasize,
                                          &fd, &priority);
    char * reason = NULL;
    int valid = ((result > 0) && (is_valid_message (message, result, &reason)));
    if ((result > 0) && (! valid)) {  /* not a valid message */
      int off =
        snprintf (alog->b, alog->s,
                  "aip invalid (%s) from %d/udp %d ad %d, size %d pri %d\n",
                  reason, fd, udp, rpipe, result, priority);
      off += buffer_to_string (message, result, "aip invalid packet", 100, 1,
                               alog->b + off, alog->s - off);
      log_print (alog);
    }
    if (result < 0) {
#ifdef ALLNET_USE_FORK
      if ((fd == rpipe) || (fd == udp))
#else /* ALLNET_USE_FORK */
      if (fd == rpipe)    /* iOS closes the udp socket when the device
                           * goes to sleep, which is not a reason to exit */
#endif /* ALLNET_USE_FORK */
      {
        snprintf (alog->b, alog->s, "aip %s %d closed (%d)\n",
                  ((fd == rpipe) ? "ad pipe" : "udp socket"), fd, result);
        log_print (alog);
        break;  /* exit the loop and the program */
      }
#ifdef DEBUG_PRINT
      printf ("aip: error %d on file descriptor %d, closing\n", result, fd);
#endif /* DEBUG_PRINT */
      snprintf (alog->b, alog->s,
                "aip: error %d on file descriptor %d, closing\n", result, fd);
      log_print (alog);
      remove_listener (fd, info);
      removed_listener = 1;
    } else if ((result > 0) && valid) {
      if (fd == rpipe) {    /* message from ad, send to IP neighbors */
#ifdef LOG_PACKETS
        snprintf (alog->b, alog->s, "got %d-byte message from ad\n", result);
        log_print (alog);
#endif /* LOG_PACKETS */
        forward_message (info->fds + 1, info->num_fds - 1, udp, udp_cache,
                         info, message, (unsigned int) result, priority, 10);
      } else {
        int off = snprintf (alog->b, alog->s,
                            "got %d bytes from Internet on fd %d",
                            result, fd);
        if (fd == udp) {
          standardize_ip (sap, sasize);
#ifdef DEBUG_PRINT
          off += snprintf (alog->b + off, alog->s - off, "/udp, saving ");
          off += print_sockaddr_str (sap, sasize, 0,
                                     alog->b + off, alog->s - off);
#else /* DEBUG_PRINT */
          off += snprintf (alog->b + off, alog->s - off, "/udp\n");
#endif /* DEBUG_PRINT */
          log_print (alog);
          add_sockaddr_to_cache (udp_cache, sap, sasize);
        } else {   /* received on TCP, not UDP */
          struct addr_info * ai = listen_fd_addr (info, fd);
          if (ai != NULL)
            ai_to_sockaddr (ai, sap, &sasize);
#ifdef DEBUG_PRINT
          off += snprintf (alog->b + off, alog->s - off, ", ");
          off += print_sockaddr_str (sap, sasize, 1,
                                     alog->b + off, alog->s - off);
#else /* DEBUG_PRINT */
          off += snprintf (alog->b + off, alog->s - off, "\n");
#endif /* DEBUG_PRINT */
          log_print (alog);
        }
        if (handle_mgmt (listener_fds, NUM_LISTENERS, fd, message,
                         &result, udp, sap, sasize, info->pipe_descriptor)) {
          /* handled, no action needed */
          /* if not handled, the message may be changed (for the better!) */
        } else {              /* message from a client, send to ad */
          /* send the message to ad.  Often ad will just send it back,
           * with a new priority */
          if (! send_pipe_message (wpipe, message, result,
                                   ALLNET_PRIORITY_EPSILON, alog)) {
            snprintf (alog->b, alog->s,
                      "error sending to ad pipe %d\n", wpipe);
            log_print (alog);
            break;
          }
        }
        listen_record_usage (info, fd);   /* this fd was used */
      }
    }   /* else result is zero, timed out, or packet is invalid, try again */
    if ((result > 0) && (message != NULL))
      free (message);   /* allocated by receive_pipe_message_fd */
  }
#ifdef DEBUG_EBADFD
snprintf (ebadbuf, EBADBUFS,
"aip main loop, exiting, closing UDP socket %d\n", udp);
record_message (info->pipe_descriptor);
#endif /* DEBUG_EBADFD */
snprintf (alog->b, alog->s, "aip c closing udp %d\n", udp); log_print (alog);
  close (udp);  /* on iOS we may get restarted later */
  cache_close (udp_cache);
}

void aip_main (int rpipe, int wpipe, char * addr_socket_name)
{
  alog = init_log ("aip");
  snprintf (alog->b, alog->s,
            "read pipe is fd %d, write pipe fd %d, socket %s\n",
            rpipe, wpipe, addr_socket_name);
  log_print (alog);

  pd p = init_pipe_descriptor (alog);
  static struct listen_info info;
  listen_init_info (&info, 256, "aip", ALLNET_PORT, 0, 1, 0,
                    listen_callback, p);

  if (! listen_add_fd (&info, rpipe, NULL, 0, "aip_main"))
    /* should always succeed */
    printf ("aip_main: listen_add_fd failed\n");
  pthread_mutex_init (&listener_mutex, NULL);
  int i;
  for (i = 0; i < NUM_LISTENERS; i++)
    listener_fds [i] = -1;

  srandom ((int)time (NULL));
  main_loop (rpipe, wpipe, &info);

  snprintf (alog->b, alog->s,
            "end of aip main thread, shutting down listen info");
  log_print (alog);
  listen_shutdown (&info);
#ifdef ALLNET_ADDRS
  snprintf (alog->b, alog->s,
            "end of aip main thread, deleting %s\n", addr_socket_name);
  log_print (alog);
  if (unlink (addr_socket_name) < 0)
    perror ("aip unlink addr_socket");
#endif /* ALLNET_ADDRS */
}

#ifdef DAEMON_MAIN_FUNCTION
int main (int argc, char ** argv)
{
  log_to_output (get_option ('v', &argc, argv));

  if (argc != 4) {
    printf ("aip: arguments are read pipe from ad and write pipe to ad,\n");
    printf (" and a unix domain socket for address info (argc == 4)\n");
    printf (" but argc == %d\n", argc);
    print_usage (argc, argv, 0, 1);
    return -1;
  }

  int rpipe = atoi (argv [1]);  /* read pipe */
  int wpipe = atoi (argv [2]);  /* write pipe */
  char * addr_socket_name = argv [3];
  aip_main (rpipe, wpipe, addr_socket_name);
  return 0;
}
#endif /* DAEMON_MAIN_FUNCTION */
