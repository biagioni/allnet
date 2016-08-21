/* aip.c: get allnet messages from ad, send them to DHT and known hosts */
/*        get allnet messages from the internet, forward them to ad */
/* aip stands for A(llNet) IP interface */
/* main thread uses select to check the pipe from ad and the sockets */
/* secondary threads:
 * - listen and open TCP connections
#ifdef ALLNET_ADDRS
 * - listen on the unix socket for allnet-destination-address to IP mappings
#endif ALLNET_ADDRS
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
#include "routing.h"
#include "lib/ai.h"
#include "lib/pipemsg.h"
#include "lib/priority.h"
#include "lib/util.h"
#include "lib/dcache.h"
#include "lib/allnet_log.h"
#include "lib/keys.h"

#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
#ifndef CONVERT_IPV4_TO_IPV6
#define CONVERT_IPV4_TO_IPV6 /* IPv6 UDP socket requires IPv4-mapped address */
#endif /* CONVERT_IPV4_TO_IPV6 */
#endif /* _WIN32 || _WIN64 */

struct udp_cache_record {
  struct sockaddr_storage sas;
  socklen_t salen;
  time_t last_received;
};

static struct allnet_log * alog = NULL;
static time_t last_successful_udp;

/* UDPv4 messages are limited to less than 2^16 bytes */
#define MAX_RECEIVE_BUFFER	ALLNET_MAX_UDP_SIZE

#ifdef DEBUG_PRINT
static int debug_always_match (void * a1, void * a2)
{
  return 1;
}

static void debug_print_addr_cache (void * addr_cache)
{
  void ** result;
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
  free (result);
}
#endif /* DEBUG_PRINT */

#ifdef ALLNET_ADDRS
static int init_unix_socket (char * addr_socket_name)
{
  int addr_socket = socket (AF_UNIX, SOCK_DGRAM, 0);
  if (addr_socket < 0) {
    perror ("af_unix socket");
    exit (1);    /* not sure what this error would mean */
  }
  struct sockaddr_un sun;
  sun.sun_family = AF_UNIX;
  snprintf (sun.sun_path, sizeof (sun.sun_path), "%s", addr_socket_name);
  if (bind (addr_socket, (struct sockaddr *) (&sun), sizeof (sun)) < 0) {
    perror ("af_unix bind");
    printf ("unable to bind to unix socket ");
    print_sockaddr ((struct sockaddr *) (&sun), sizeof (sun), -1);
    printf ("\nmake sure no other aip is running and delete %s\n",
            addr_socket_name);
    exit (1);
  }
  return addr_socket;
}
#endif /* ALLNET_ADDRS */

struct receive_arg {
  char * socket_name;
  void * rp_cache;
  void * dht_cache;
};

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

#ifdef ALLNET_ADDRS
#define max(a, b)	(((a) > (b)) ? (a) : (b))

static void * receive_addrs (void * arg)
{
  struct receive_arg * ra = (struct receive_arg *) arg;
  int addr_socket = init_unix_socket (ra->socket_name);
  snprintf (alog->b, alog->s, "receive_addrs, socket is %d\n", addr_socket);
  log_print (alog);

  int size = sizeof (struct addr_info);
  while (1) {
    char * buffer = malloc_or_fail (size, "receive_addrs");
    struct addr_info * ai = (struct addr_info *) buffer;
    int bytes = recv (addr_socket, buffer, size, 0);
    if (bytes < 0)
      perror ("recv");
    if (bytes <= 0) {
      printf ("error: address socket %d closed, thread exiting\n", addr_socket);
      free (ai);
      break;
    }
    if (bytes == sizeof (struct addr_info)) {
      /* error checking, print or abort loop if find inconsistencies */
      if ((ai->ip.ip_version != 6) && (ai->ip.ip_version != 4))
        printf ("ip version %d, expected 4 or 6\n", ai->ip.ip_version);
      if ((ai->type != ALLNET_ADDR_INFO_TYPE_RP) &&
          (ai->type != ALLNET_ADDR_INFO_TYPE_DHT))
        printf ("ai type %d, expected 1 or 2\n", ai->type);
      printf ("receive_addrs got %d bytes, ", bytes);
      print_addr_info (ai);
      if (ai->type == ALLNET_ADDR_INFO_TYPE_RP) {
        add_ai_to_cache_or_record_usage (ra->rp_cache, ai);
      } else if (ai->type == ALLNET_ADDR_INFO_TYPE_DHT) {
        add_ai_to_cache_or_record_usage (ra->dht_cache, ai);
      } else {
        printf ("ai type %d, expected 1 or 2\n", ai->type);
        free (buffer);
      }
    } else {
      printf ("expected %zd bytes, got %d\n", sizeof (struct addr_info),
              bytes);
      free (buffer);
    }
  }
  return NULL;
}
#endif /* ALLNET_ADDRS */

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

/* mallocs and sets result to an n-element array of addr_infos that are the
 * best matches for the given destination */
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

static int send_udp (int udp, char * message, int msize, struct sockaddr * sa)
{
  socklen_t addr_len = sizeof (struct sockaddr_storage);
  if (sa->sa_family == AF_INET)
    addr_len = sizeof (struct sockaddr_in);
  else
    addr_len = sizeof (struct sockaddr_in6);
#ifdef CONVERT_IPV4_TO_IPV6
  if (sa->sa_family == AF_INET) {
/* IPv4 addresses represented as IPv6 addresses are preceded by xffff */
    struct sockaddr_in6 sin6;
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
/* copy the now IPv6 address back into the sockaddr_storage that sa points to */
    memcpy (sa, &(sin6), addr_len);
  }
#endif /* CONVERT_IPV4_TO_IPV6 */
  buffer_to_string ((char *) sa, addr_len, "send_udp sending to address",
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
    int n = snprintf (alog->b, alog->s, "send_udp sent %d bytes to ", msize);
    n += print_sockaddr_str (sa, 0, 0, alog->b + n, alog->s - n);
    log_print (alog);
#endif /* LOG_PACKETS */
  }
  return 1;
}

/* returns 1 for success, 0 for failure */
static int send_udp_addr (int udp, char * message, int msize,
                          struct internet_addr * addr)
{
  struct sockaddr_storage sas;
  bzero (&sas, sizeof (sas));
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

  return send_udp (udp, message, msize, sap);
}

/* assumed to be an outgoing, so do not check overall packet validity */
static int is_outgoing_dht (struct allnet_header * hp, int msize,
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

static void dht_save_cached (struct allnet_header * hp, int msize)
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

static int dht_ping_match (struct allnet_header * hp, int msize,
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
                             void * addr_cache, char * message, int msize,
                             int priority, int max_send)
{
#ifdef LOG_PACKETS
  snprintf (alog->b, alog->s, "forward_message %d fds\n", num_fds);
  log_print (alog);
#endif /* LOG_PACKETS */
  if (! is_valid_message (message, msize))
    return;
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
#undef DHT_SENDS
#ifdef LOG_PACKETS
  snprintf (alog->b, alog->s, "routing_top_dht_matches: %d\n", dht_sends);
  log_print (alog);
#endif /* LOG_PACKETS */
  for (i = 0; i < dht_sends; i++)
    send_udp (udp, message, msize, ((struct sockaddr *) (&(dht_storage [i]))));

  struct sockaddr_in6 * destinations;
  int max_translations = max_send / 2 + 1;
/* first send to recently-received from destinations from the rp cache */
  int translations =
    top_destinations (addr_cache, max_translations, hp->destination,
                      hp->dst_nbits, &destinations);
  for (i = 0; i < translations; i++)  /* send here first */
    send_udp (udp, message, msize, (struct sockaddr *) (destinations + i));
  if (translations > 0)
    free (destinations);
  if (translations > 1) {
    snprintf (alog->b, alog->s, "forwarded to %d mappings\n", translations);
    log_print (alog);
  }

  int sent_fds = 0;
  int sent_udps = 0;
  int remaining = max_send - translations;
#define FORWARDING_UDPS	100
  void * udps [FORWARDING_UDPS];
  int nudps = cache_random (udp_cache, FORWARDING_UDPS, udps);
  struct udp_cache_record * * ucrs = (struct udp_cache_record * *) udps;
#undef FORWARDING_UDPS
  int size = num_fds + nudps;
  if (size > 0) {
    int * random_selection = random_permute (size);
    for (i = 0; i < size && i < remaining; i++) {
      int index = random_selection [i];
      if (index < num_fds) {
        if (! send_pipe_message (fds [index], message, msize,
                                 ALLNET_PRIORITY_DEFAULT, alog)) {
          snprintf (alog->b, alog->s,
                    "aip error sending to socket %d at %d\n",
                    fds [index], i);
          log_print (alog);
        }
#ifdef LOG_PACKETS
        snprintf (alog->b, alog->s, "aip sent %d bytes to TCP socket %d\n",
                  msize, fds [index]);
        log_print (alog);
#endif /* LOG_PACKETS */
        sent_fds++;
      } else {
        struct udp_cache_record * ucr = ucrs [index - num_fds];
        send_udp (udp, message, msize, (struct sockaddr *) (&(ucr->sas)));
        sent_udps++;
      }
    }
    free (random_selection);
  }
#ifdef LOG_PACKETS
  snprintf (alog->b, alog->s, "forwarded to %d TCP and %d UDP\n",
            sent_fds, sent_udps);
  log_print (alog);
#endif /* LOG_PACKETS */
}

static int udp_socket ()
{
  int udp = socket (AF_INET6, SOCK_DGRAM, 0);
  if (udp < 0) {
    snprintf (alog->b, alog->s, "unable to open UDP socket, exiting");
    log_error (alog, "main loop socket");
    exit (1);
  }
  /* enable dual-stack IPv6 and IPv4 for systems that don't enable it
     by default */
  int v6only_flag = 0;   /* disable v6 only */
#ifndef __OpenBSD__  /* on openbsd, IPV6_V6ONLY is read-only */
  if (setsockopt (udp, IPPROTO_IPV6, IPV6_V6ONLY,
                  &v6only_flag, sizeof (v6only_flag)) != 0) {
    snprintf (alog->b, alog->s, "unable to setsockopt on UDP socket, exiting");
    log_error (alog, "setsockopt");
    exit (1);
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
  ap6->sin6_port = ALLNET_PORT;
  if (bind (udp, ap, addr_size) < 0) {
    perror ("aip UDP bind");
    printf ("aip unable to bind to UDP %d/%x, probably already running\n",
            ntohs (ALLNET_PORT), ntohs (ALLNET_PORT));
#ifdef __IPHONE_OS_VERSION_MIN_REQUIRED
/* keep trying -- we may be waking up from sleep */
    while (bind (udp, ap, addr_size) < 0) {
      perror ("aip UDP repeated bind");
      sleep (2);
    }
#else  /* not iOS, so probably already running */
    exit (1);
#endif /* __IPHONE_OS_VERSION_MIN_REQUIRED */
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

static int connect_listener (unsigned char * address, struct listen_info * info,
                             void * addr_cache, int af)
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
      /* standard socket connection code supporting both IPv4 and IPv6 */
      socklen_t salen = 0;
      if (af == AF_INET)
        salen = sizeof (struct sockaddr_in);
      else if (af == AF_INET6)
        salen = sizeof (struct sockaddr_in6);
      if (salen == 0)
        continue;   /* invalid address, ignore */
      /* check to see if we are already connected or connecting */
      int size = sizeof (struct addr_info);
      struct addr_info * ai = malloc_or_fail (size, "connect_listener ai");
      if (! sockaddr_to_ai ((struct sockaddr *) (sas + k), salen, ai)) {
        free (ai);
        continue;   /* invalid address, ignore */
      }
      int prev_fd = already_listening (ai, info);
/* printf ("initial prev_fd returned %d for ", prev_fd); print_addr_info (ai); */
      time_t start_time = time (NULL);
      int wait_time = 2000;   /* 2ms, doubled on each loop */
      while ((prev_fd == -2) && (time (NULL) < start_time + 2)) {
/* printf ("prev_fd = %d in thread %u proc %d interval %d for ", prev_fd, (unsigned int) pthread_self (), getpid (), wait_time); print_addr_info (ai); */
        sleep_time_random_us (wait_time);  /* sleep for 0-2ms */
        wait_time += wait_time;            /* double the wait time */
        prev_fd = already_listening (ai, info);  /* and try again */
/* printf ("loop prev_fd returned %d for ", prev_fd); print_addr_info (ai);
sleep (1); */
      }
/* printf ("prev_fd = %d in thread %u proc %d interval %d for ", prev_fd, (unsigned int) pthread_self (), getpid (), wait_time); print_addr_info (ai); */
      if (prev_fd >= 0) {  /* already listening for this address, done */
        free (ai);
        result = prev_fd;
        break;
      }
      if (prev_fd == -2) {  /* timed out, give up */
/* printf ("giving up: prev_fd = %d in thread %u proc %d interval %d for ", prev_fd, (unsigned int) pthread_self (), getpid (), wait_time); print_addr_info (ai); */
        free (ai);
        break;
      }

      /* standard socket connection code supporting both IPv4 and IPv6 */
      int s = socket (af, SOCK_STREAM, 0);
      if (s < 0) {
        perror ("listener socket");
/* printf ("thread %u proc %d unable to open socket, releasing addr ", (unsigned int) pthread_self (), getpid ()); print_addr_info (ai); */
        listen_clear_reservation (ai, info);
        free (ai);
        continue;
      }
      struct sockaddr * sap = (struct sockaddr *) (sas + k);
      if (connect (s, sap, salen) < 0) {
        int n = snprintf (alog->b, alog->s, "unable to connect %d to ", s);
        print_sockaddr_str (sap, salen, 1, alog->b + n, alog->s - n);
        log_error (alog, "listener connect");
        close (s);
/* printf ("thread %ud proc %d unable to connect, releasing addr ", (unsigned int) pthread_self (), getpid ()); print_addr_info (ai); */
        listen_clear_reservation (ai, info);
        free (ai);
        continue;   /* return to the top of the loop and try the next addr */
      }
#ifdef DEBUG_PRINT
      printf ("aip added fd %d, %p: ", s, ai);
      print_addr_info (ai);
      debug_print_addr_cache (addr_cache);
#endif /* DEBUG_PRINT */
      if (listen_add_fd (info, s, ai, 1)) {  /* clears the reservation */
        /* success! */
        result = s;
        add_ai_to_cache_or_record_usage (addr_cache, ai);
        int offset = snprintf (alog->b, alog->s,
                               "listening for %x/%d on socket %d at ",
                               address [0] & 0xff, LISTEN_BITS, s);
        offset += addr_info_to_string (ai, alog->b + offset, alog->s - offset);
        log_print (alog);
      } else {
        close (s);
        free (ai);
        int offset = snprintf (alog->b, alog->s,
                               "listen_add_fd => 0 for %x/%d on socket %d at ",
                               address [0] & 0xff, LISTEN_BITS, s);
        offset += addr_info_to_string (ai, alog->b + offset, alog->s - offset);
        log_print (alog);
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
  void * addr_cache;
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
  routing_init_is_complete (1);   /* wait for routing to complete */
  int fd = connect_listener (arg->address, arg->info, arg->addr_cache, arg->af);
  if (fd >= 0) {
    pthread_mutex_lock (&listener_mutex);
    if (listener_fds [arg->listener_index] == -1) {
      active_listeners++;
      listener_fds [arg->listener_index] = fd;
    } else {   /* undo connect */
      close (fd);       /* remove from kernel */
      /* remove from cache, info, and pipemsg */
struct addr_info * ai = listen_fd_addr (arg->info, fd);
printf ("for now closed fd %d addr is %p, ", fd, ai);
print_addr_info (ai);
      cache_remove (arg->addr_cache, ai);
      listen_remove_fd (arg->info, fd);
    }
    pthread_mutex_unlock (&listener_mutex);
  }
  free (a);  /* the caller doesn't do it, so we should */
#ifdef DEBUG_PRINT
  pthread_mutex_lock (&connect_counter_mutex);
  counter--;
  printf ("finished connect thread %d, %d threads alive\n", r, counter);
  pthread_mutex_unlock (&connect_counter_mutex);
#endif /* DEBUG_PRINT */
  return NULL;
}

static void create_connect_thread (struct listen_info * info, void * addr_cache,
                                   int af, int listener_index)
{
  struct connect_thread_arg * arg =
    malloc_or_fail (sizeof (struct connect_thread_arg), "connect_thread");
  bzero (arg, sizeof (struct connect_thread_arg));
  arg->address [0] = (listener_index / 2) << (8 - LISTEN_BITS);
  /* printf ("index %02x, new address %02x\n", listener_index,
          arg->address [0] & 0xff); */
  arg->info = info;
  arg->addr_cache = addr_cache;
  arg->af = af;
  arg->listener_index = listener_index;
  pthread_t thread;
  if (pthread_create (&thread, NULL, &connect_thread, (void *) arg))
    log_error (alog, "pthread_create");
}

static void remove_listener (int fd, struct listen_info * info,
                             void * addr_cache)
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
  struct addr_info * ai = listen_fd_addr (info, fd);
  struct addr_info * cached =
    cache_get_match (addr_cache, (match_function)(&same_ai), ai);
#ifdef DEBUG_PRINT
  printf ("1: removing %p (%p) from address cache\n", cached, ai);
  if (ai != NULL) print_addr_info (ai);
  if (cached != NULL) print_addr_info (cached);
  debug_print_addr_cache (addr_cache);
  if (cached != NULL) debug_removed += 2;
#endif /* DEBUG_PRINT */
  if (cached != NULL)
    cache_remove (addr_cache, cached); /* remove from cache */
  listen_remove_fd (info, fd); /* remove from info and pipemsg */
  close (fd);       /* remove from kernel */
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
static void make_listeners (struct listen_info * info, void * addr_cache)
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
        remove_listener (listener_fds [i], info, addr_cache);
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
      create_connect_thread (info, addr_cache, AF_INET, i);
    if (connect_to_index [i + 1])
      create_connect_thread (info, addr_cache, AF_INET6, i + 1);
  }
}

void send_keepalive (void * udp_cache, int udp,
                     int * listeners, int num_listeners)
{
  int max_size = ALLNET_MGMT_HEADER_SIZE (0xff);
  char keepalive [ALLNET_MTU];
  bzero (keepalive, max_size);
  unsigned char address [ADDRESS_SIZE];
  bzero (address, sizeof (address));
  struct allnet_header * hp =
    init_packet (keepalive, sizeof (keepalive), ALLNET_TYPE_MGMT, 1,
                 ALLNET_SIGTYPE_NONE, address, 0, address, 0, NULL, NULL);
  struct allnet_mgmt_header * mhp =
    (struct allnet_mgmt_header *) (keepalive + ALLNET_SIZE (hp->transport));
  mhp->mgmt_type = ALLNET_MGMT_KEEPALIVE;
  int size = ALLNET_MGMT_HEADER_SIZE (hp->transport);
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
      send_udp (udp, keepalive, size, sap);
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
  bzero (message, sizeof (message));
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
    send_udp (udp, (char *) message, ALLNET_DHT_SIZE (hp->transport, n), sap);
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
  int n_sender = mdp->num_sender & 0xff;
#ifdef DEBUG_PRINT
  snprintf (alog->b, alog->s, "dht_filter_senders %d senders\n", n_sender);
  log_print (alog);
#endif /* DEBUG_PRINT */
  if (n_sender == 0)
    return 0;   /* nothing to do */
  int n_dht = mdp->num_dht_nodes & 0xff;
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
    int offset = 0;
    if (found >= 0)
      offset = 1;
    if (found > 0)
      mdp->nodes [0] = mdp->nodes [found];
    if (n_sender > 0)
      for (i = 0; i < n_dht; i++)
        mdp->nodes [i + offset] = mdp->nodes [i + n_sender];
    result = (mdp->num_sender - offset) * sizeof (struct addr_info);
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
                        struct sockaddr * sap, socklen_t sasize)
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
  int msize = *msizep;
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
    int npeers = mpp->num_peers & 0xff;
    if (msize < ALLNET_PEER_SIZE(hp->transport, npeers))
      return 0;
    int index;
    for (index = 0; index < npeers; index++) {
      struct internet_addr * ia = mpp->peers + index;
      struct sockaddr_storage sas;
      struct sockaddr * sap2 = (struct sockaddr *) (&sas);
      socklen_t salen;
      if (ia_to_sockaddr (ia, sap2, &salen)) {
        int af = (ia->ip_version == 4) ? AF_INET : AF_INET6;
        int new_sock = socket (af, SOCK_STREAM, 0);
        if (connect (new_sock, sap2, salen) < 0) {
          close (listeners [listener_index]);
          listeners [listener_index] = new_sock;
          return 1;
        } else {
          perror ("warning: connect/listener");  /* not really an error */
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

static void main_loop (pd p, int rpipe, int wpipe, struct listen_info * info,
                       void * addr_cache, void * dht_cache)
{
  int udp = udp_socket ();
  static void * udp_cache = NULL;
  if (udp_cache == NULL)
    udp_cache = cache_init (128, free, "aip UPD cache");
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
      make_listeners (info, addr_cache);
      last_listen = time (NULL);
      removed_listener = 0;
    }
    if ((last_keepalive == 0) || (time (NULL) - last_keepalive >= 55)) {
      send_keepalive (udp_cache, udp, listener_fds, NUM_LISTENERS);
      last_keepalive = time (NULL);
    }
    if (time (NULL) - last_successful_udp >= 30) {
      close (udp);
#ifdef DEBUG_PRINT
      int old_udp = udp;
#endif /* DEBUG_PRINT */
      udp = udp_socket();
      last_successful_udp = time (NULL);
#ifdef DEBUG_PRINT
      printf ("aip: reset udp fd from %d to %d\n", old_udp, udp);
#endif /* DEBUG_PRINT */

    }
    int fd = -1;
    int priority;
    char * message;
    struct sockaddr_storage sockaddr;
    struct sockaddr * sap = (struct sockaddr *) (&sockaddr);
    socklen_t sasize = sizeof (sockaddr);
    int result = receive_pipe_message_fd (p, 1000, &message, udp, sap, &sasize,
                                          &fd, &priority);
    int valid = ((result > 0) && (is_valid_message (message, result)));
    if ((result > 0) && (! valid)) {
      int off =
        snprintf (alog->b, alog->s,
                  "aip invalid packet from %d/udp %d ad %d, size %d pri %d\n",
                  fd, udp, rpipe, result, priority);
      off += buffer_to_string (message, result, "aip invalid packet", 100, 1,
                               alog->b + off, alog->s - off);
      log_print (alog);
    }
    if (result < 0) {
      if ((fd == rpipe) || (fd == udp)) {
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
      remove_listener (fd, info, addr_cache);
      removed_listener = 1;
    } else if ((result > 0) && valid) {
      if (fd == rpipe) {    /* message from ad, send to IP neighbors */
     /* printf ("aip: got %d-byte message from ad on fd %d\n", result, fd); */
#ifdef LOG_PACKETS
        snprintf (alog->b, alog->s, "got %d-byte message from ad\n", result);
        log_print (alog);
#endif /* LOG_PACKETS */
        forward_message (info->fds + 1, info->num_fds - 1, udp, udp_cache,
                         addr_cache, message, result, priority, 10);
      } else {
/* for debugging of 255-peer peer messages
if (result == 6160) print_buffer (message, result, NULL, 100, 1); */
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
                         &result, udp, sap, sasize)) {
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
      free (message);   /* allocated by receive_pipe_message_fd */
    }   /* else result is zero, timed out, or packet is invalid, try again */
  }
  close (udp);  /* on iOS we may get restarted later */
}

void aip_main (int rpipe, int wpipe, char * addr_socket_name)
{
  alog = init_log ("aip");
  snprintf (alog->b, alog->s,
            "read pipe is fd %d, write pipe fd %d, socket %s\n",
            rpipe, wpipe, addr_socket_name);
  log_print (alog);

  static struct receive_arg ra;
  ra.socket_name = addr_socket_name;
  ra.rp_cache = cache_init (128, free, "aip RP cache");
  ra.dht_cache = cache_init (256, free, "aip DHT cache");
#ifdef ALLNET_ADDRS
  pthread_t addr_thread;
  if (pthread_create (&addr_thread, NULL, receive_addrs, &ra) != 0) {
    perror ("pthread_create/addrs");
    snprintf (alog->b, alog->s, "unable to create receive_addrs thread\n");
    log_error ("pthread_create/addrs");
    return;
  }
#endif /* ALLNET_ADDRS */
  pd p = init_pipe_descriptor (alog);
  static struct listen_info info;
  listen_init_info (&info, 256, "aip", ALLNET_PORT, 0, 1, 0,
                    listen_callback, p);

  if (! listen_add_fd (&info, rpipe, NULL, 0))
    printf ("aip_main: listen_add_fd failed\n");
  pthread_mutex_init (&listener_mutex, NULL);
  int i;
  for (i = 0; i < NUM_LISTENERS; i++)
    listener_fds [i] = -1;

  srandom ((int)time (NULL));
  main_loop (p, rpipe, wpipe, &info, ra.rp_cache, ra.dht_cache);

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
