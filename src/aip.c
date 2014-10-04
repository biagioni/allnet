/* aip.c: get allnet messages from ad, send them to DHT and known hosts */
/*        get allnet messages from the internet, forward them to ad */
/* aip stands for A(llNet) IP interface */
/* main thread uses select to check the pipe from ad and the sockets */
/* secondary threads:
 * - listen and open TCP connections
 * - listen on the unix socket for allnet-destination-address to IP mappings
 */
/* arguments are:
  - the fd number of the pipe from ad
  - the fd number of the pipe to ad
  - the name of the Unix socket
 */
/* config file "aip" "speed" (e.g. ~/.allnet/aip/speed)
 * gives the maximum speed to send over the internet, in bytes/second
 * this speed limit only applies to messages with priority 0.5 or less,
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
#include "lib/log.h"
#include "lib/keys.h"

struct udp_cache_record {
  struct sockaddr_storage sas;
  socklen_t salen;
  time_t last_received;
};

/* UDPv4 messages are limited to less than 2^16 bytes */
#define MAX_RECEIVE_BUFFER	ALLNET_MAX_UDP_SIZE

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

struct receive_arg {
  char * socket_name;
  void * rp_cache;
  void * dht_cache;
};

#define max(a, b)	(((a) > (b)) ? (a) : (b))

static void * receive_addrs (void * arg)
{
  struct receive_arg * ra = (struct receive_arg *) arg;
  int addr_socket = init_unix_socket (ra->socket_name);
  snprintf (log_buf, LOG_SIZE, "receive_addrs, socket is %d\n", addr_socket);
  log_print ();

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
      return NULL;
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
      if (ai->type == ALLNET_ADDR_INFO_TYPE_RP)
        cache_add (ra->rp_cache, ai); /* if already in cache, records usage */
      else if (ai->type == ALLNET_ADDR_INFO_TYPE_DHT)
        cache_add (ra->dht_cache, ai); /* if already in cache, records usage */
      else
        printf ("ai type %d, expected 1 or 2\n", ai->type);
    } else {
      printf ("expected %zd bytes, got %d\n", sizeof (struct addr_info),
              bytes);
      free (buffer);
    }
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
                          (struct sockaddr *) (new + i))) {
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
  snprintf (log_buf, LOG_SIZE,
            "same_sockaddr: unknown address family %d\n", a1->sin6_family);
  log_print ();
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
  printf ("same_sockaddr: unknown address family %d\n", a1->sin6_family);
  return 0;
}

/* save the IP address of the sender, unless it is already there */
static void add_sockaddr_to_cache (void * cache, struct sockaddr * addr,
                                   socklen_t sasize)
{
  if ((addr->sa_family != AF_INET) && (addr->sa_family != AF_INET6)) {
    snprintf (log_buf, LOG_SIZE,
              "add_sockaddr error: unexpected family %d (not %d or %d), sasize %d (maybe %zd or %zd?)\n", 
              addr->sa_family, AF_INET, AF_INET6, sasize,
              sizeof (struct sockaddr_in), sizeof (struct sockaddr_in6));
    log_print ();
    return;
  }
  if ((sasize != sizeof (struct sockaddr_in)) &&
      (sasize != sizeof (struct sockaddr_in6))) {
    snprintf (log_buf, LOG_SIZE,
              "add_sockaddr error: unexpected sasize %d (not %zd or %zd)\n", 
              sasize,
              sizeof (struct sockaddr_in), sizeof (struct sockaddr_in6));
    log_print ();
    return;
  }
  /* found and addr are different pointers, so cannot rely on cache_add
   * detecting that this is a duplicate */
  void * found = cache_get_match (cache, same_sockaddr_udp, addr);
  if (found != NULL) {  /* found */
    int off = snprintf (log_buf, LOG_SIZE, "sockaddr already in cache: "); 
    print_sockaddr_str (addr, sasize, -1, log_buf + off, LOG_SIZE - off);
    cache_record_usage (cache, found); /* found, addr are different pointers */
    struct udp_cache_record * record = (struct udp_cache_record *) found;
    record->last_received = time (NULL);
  } else { /* add to cache */
    int off = snprintf (log_buf, LOG_SIZE, "adding sockaddr to cache: "); 
    print_sockaddr_str (addr, sasize, -1, log_buf + off, LOG_SIZE - off);
    struct udp_cache_record * record =
      malloc_or_fail (sizeof (struct udp_cache_record), "add_sockaddr_cache");
    memcpy (&(record->sas), addr, sasize);
    record->salen = sasize;
    record->last_received = time (NULL);
    cache_add (cache, record);
  }
#ifdef DEBUG_PRINT
  log_print ();
#else /* DEBUG_PRINT */
  log_buf [0] = '\0';
#endif /* DEBUG_PRINT */
}

static void send_udp (int udp, char * message, int msize, struct sockaddr * sa)
{
  socklen_t addr_len = sizeof (struct sockaddr_in6);
  if (sa->sa_family == AF_INET)
    addr_len = sizeof (struct sockaddr_in);
  int s = sendto (udp, message, msize, 0, sa, addr_len);
  if (s < msize) {
#ifdef DEBUG_PRINT
    int n = 
#endif /* DEBUG_PRINT */
    snprintf (log_buf, LOG_SIZE,
                      "error sending %d (sent %d) on udp %d to ",
                      msize, s, udp);
#ifdef DEBUG_PRINT
    print_sockaddr_str (sa, 0, 0, log_buf + n, LOG_SIZE - n);
#endif /* DEBUG_PRINT */
    log_error ("sendto");
  } else {
/*
    int n = snprintf (log_buf, LOG_SIZE, "sent %d bytes to ", msize);
    n += print_sockaddr_str (sa, 0, 0, log_buf + n, LOG_SIZE - n);
    log_print ();
*/
  }
}

/* returns 1 for success, 0 for failure */
static int send_udp_addr (int udp, char * message, int msize,
                           struct internet_addr * addr)
{
  struct sockaddr_storage sas;
  bzero (&sas, sizeof (sas));
  struct sockaddr     * sap  = (struct sockaddr     *) (&sas);
  struct sockaddr_in  * si4p = (struct sockaddr_in  *) (&sas);
  struct sockaddr_in6 * si6p = (struct sockaddr_in6 *) (&sas);
  if (addr->ip_version == 4) {
    si4p->sin_family = AF_INET;
    si4p->sin_port = addr->port;
    memcpy ((char *) (&(si4p->sin_addr.s_addr)), (addr->ip.s6_addr + 12), 4);
  } else if (addr->ip_version == 6) {
    si6p->sin6_family = AF_INET6;
    si6p->sin6_port = addr->port;
    memcpy (si6p->sin6_addr.s6_addr, addr->ip.s6_addr,
            sizeof (si6p->sin6_addr.s6_addr));
  } else {
    printf ("error in send_udp_addr: unknown IP version %d\n",
            addr->ip_version);
    return 0;
  }
#ifdef DEBUG_PRINT
  int off = snprintf (log_buf, LOG_SIZE,
                      "send_udp_addr sending %d bytes to: ", msize);
  print_sockaddr_str (sap, sizeof (sas), 0, log_buf + off, LOG_SIZE - off);
#else /* DEBUG_PRINT */
  snprintf (log_buf, LOG_SIZE, "send_udp_addr sending %d bytes\n", msize);
#endif /* DEBUG_PRINT */
  log_print ();

  send_udp (udp, message, msize, sap);
  return 1;
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
    int off = snprintf (log_buf, LOG_SIZE,
                        "dht_save_cache saving outgoing %d: ", msize);
    packet_to_string ((char *) hp, msize, NULL, 1,
                      log_buf + off, LOG_SIZE - off);
    log_print ();
    /* cache if possible, but if malloc fails, no big deal */
    if (cached_dht_packet != NULL)
      free (cached_dht_packet);
    cached_dht_packet = malloc (msize);
    if (cached_dht_packet != NULL) {
      cached_dht_size = msize;
      memcpy (cached_dht_packet, (char *) hp, msize);
    } else {
      cached_dht_size = 0;
      snprintf (log_buf, LOG_SIZE,
                "dht_save_cached unable to allocate %d bytes\n", msize);
      log_print ();
    }
  }
}

static int dht_ping_match (struct allnet_header * hp, int msize,
                           struct addr_info * match)
{
  if (! is_outgoing_dht (hp, msize, 0)) {
    snprintf (log_buf, LOG_SIZE, "dht_ping_match type+size %d+%d/%zd, done\n",
              hp->message_type, msize, ALLNET_DHT_SIZE (hp->transport, 0));
    log_print ();
    return 0;  /* not a dht message */
  }
  buffer_to_string ((char *) (hp->destination), ADDRESS_SIZE,
                    "dht_ping_match matching",
                    ADDRESS_SIZE, 1, log_buf, LOG_SIZE);
  log_print ();

  /* if it is a DHT message, try to send it to the ping addresses first */
  /* but only with 50% likelihood -- we should use the regular addresses too */
  if (((random () % 2) == 0) && (ping_exact_match (hp->destination, match))) {
    int off = snprintf (log_buf, LOG_SIZE, "dht_ping_match matched ping: ");
    addr_info_to_string (match, log_buf + off, LOG_SIZE - off);
    log_print ();
    return 1;
  }
  /* otherwise use the regular addresses -- note this is redundant,
   * since forward_message calls routing_exact_match if we return 0 */
  if (routing_exact_match (hp->destination, match)) {
    int off = snprintf (log_buf, LOG_SIZE, "dht_ping_match exact match: ");
    addr_info_to_string (match, log_buf + off, LOG_SIZE - off);
    log_print ();
    return 1;
  }
  snprintf (log_buf, LOG_SIZE, "dht_ping_match: no match\n");
  log_print ();
  return 0;
}

/* send at most about max_send/2 of the UDPs for which we have matching
 * translations, then the rest to a random permutation of other udps
 * we have heard from and tcps we are connected to */
static void forward_message (int * fds, int num_fds, int udp, void * udp_cache,
                             void * addr_cache, char * message, int msize,
                             int priority, int max_send)
{
snprintf (log_buf, LOG_SIZE, "forward_message %d fds\n", num_fds);
log_print ();
  if (! is_valid_message (message, msize))
    return;
  struct allnet_header * hp = (struct allnet_header *) message;
  dht_save_cached (hp, msize);

  struct addr_info exact_match;
  if ((hp->dst_nbits == ADDRESS_BITS) &&
      ((dht_ping_match (hp, msize, &exact_match)) ||
       (routing_exact_match (hp->destination, &exact_match))) &&
      (send_udp_addr (udp, message, msize, &(exact_match.ip)))) {
    int n = snprintf (log_buf, LOG_SIZE, "sent to exact match: ");
    addr_info_to_string (&exact_match, log_buf + n, LOG_SIZE - n);
    log_print ();
    return;   /* sent to exact match, done */
  }

/* send to at most 4 closer DHT nodes */
  int i;
#define DHT_SENDS	4
  struct sockaddr_storage dht_storage [DHT_SENDS];
  int dht_sends = routing_top_dht_matches (hp->destination, hp->dst_nbits,
                                           dht_storage, DHT_SENDS);
#undef DHT_SENDS
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
    snprintf (log_buf, LOG_SIZE, "forwarded to %d mappings\n", translations);
    log_print ();
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
                                 ALLNET_PRIORITY_DEFAULT)) {
          snprintf (log_buf, LOG_SIZE,
                    "aip error sending to socket %d at %d\n",
                    fds [index], i);
          log_print ();
        }
        snprintf (log_buf, LOG_SIZE, "aip sent %d bytes to TCP socket %d\n",
                  msize, fds [index]);
        log_print ();
        sent_fds++;
      } else {
        struct udp_cache_record * ucr = ucrs [index - num_fds];
        send_udp (udp, message, msize, (struct sockaddr *) (&(ucr->sas)));
        sent_udps++;
      }
    }
    free (random_selection);
  }
  snprintf (log_buf, LOG_SIZE, "forwarded to %d TCP and %d UDP\n",
            sent_fds, sent_udps);
  log_print ();
}

static int udp_socket ()
{
  int udp = socket (AF_INET6, SOCK_DGRAM, 0);
  if (udp < 0) {
    snprintf (log_buf, LOG_SIZE, "unable to open UDP socket, exiting");
    log_error ("main loop socket");
    exit (1);
  }
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
    perror ("bind");
    printf ("aip unable to bind to UDP %d/%x, probably already running\n",
            ntohs (ALLNET_PORT), ntohs (ALLNET_PORT));
    exit (1);
  }
  snprintf (log_buf, LOG_SIZE, "opened UDP socket %d\n", udp);
  log_print ();
  return udp;
}

void listen_callback (int fd)
{
  if ((cached_dht_packet != NULL) && (cached_dht_size > 0)) {
    if (send_pipe_message (fd, cached_dht_packet, cached_dht_size,
                             ALLNET_PRIORITY_EPSILON)) {
#ifdef DEBUG_PRINT
      snprintf (log_buf, LOG_SIZE, "sent cached dht to new socket %d\n", fd);
      log_print ();
#endif /* DEBUG_PRINT */
    } else {
      snprintf (log_buf, LOG_SIZE,
                "error sending %d-byte cached dht to new socket %d\n",
                cached_dht_size, fd);
      log_print ();
    }
  }
}

/* DHT nodes that we listen to.  We keep at most 2 for each of 2^LISTEN_BITS.
 * for example, when LISTEN_BITS is 5, we keep at most 32*2 = 64 listeners,
 * two for each 32nd part of the address space.  However, note that we
 * only keep listeners for the addresses that we actually care about,
 * so if all these addresses are in, e.g. 3 of the parts, we only listen
 * to at most 2 nodes in each of these parts.  Also note that multiple
 * parts may be assigned to the same DHT node -- if so, we only open a
 * single listen connection to that node. */
#define LISTEN_BITS	5
#define NUM_LISTENERS	(1 << LISTEN_BITS) * 2   /* 2 ^ LISTEN_BITS for v4/v6*/
static int listener_fds [NUM_LISTENERS];

static int connect_listener (unsigned char * address, struct listen_info * info,
                             void * addr_cache, int af)
{
  int result = -1;
#define MAX_DHT	10
  struct sockaddr_storage sas [MAX_DHT];
  int num_dhts = routing_top_dht_matches (address, LISTEN_BITS, sas, MAX_DHT);
#undef MAX_DHT
#ifdef DEBUG_PRINT
  int i;
  for (i = 0; i < num_dhts; i++) {
    printf ("routing_top_dht_matches [%d]: ", i);
    print_sockaddr ((struct sockaddr *) (sas + i),
                    sizeof (struct sockaddr_storage), -1);
    printf ("\n");
  }
#endif /* DEBUG_PRINT */

  int k;
  for (k = 0; (k < num_dhts) && (result < 0); k++) {
    if (af == sas [k].ss_family) {
      unsigned char * ip_addrp = NULL;
      socklen_t salen = 0;
      int port = 0;
      struct sockaddr_in  * sin  = (struct sockaddr_in *) (&(sas [k]));
      struct sockaddr_in6 * sin6 = (struct sockaddr_in6 *) (&(sas [k]));
      if (af == AF_INET) {
        ip_addrp = (unsigned char *) (&(sin->sin_addr));
        port = sin->sin_port;
        salen = sizeof (struct sockaddr_in);
      } else if (af == AF_INET6) {
        ip_addrp = sin6->sin6_addr.s6_addr; 
        port = sin6->sin6_port;
        salen = sizeof (struct sockaddr_in6);
      }
      if (ip_addrp == NULL)
        continue;
      struct addr_info local_ai;
      init_ai (af, ip_addrp, port, LISTEN_BITS, address, &local_ai);
      if (already_listening (&local_ai, info)) {
        continue;
      }

      int s = socket (af, SOCK_STREAM, 0);
      if (s < 0) {
        perror ("listener socket");
        continue;
      }
      if (connect (s, (struct sockaddr *) (sin), salen) < 0) {
        log_error ("listener connect");
        continue;
      }
      /* ai now needs to be malloc'd, to make it good even after we return */
      int size = sizeof (struct addr_info);
      struct addr_info * ai = malloc_or_fail (size, "connect_listener");
      *ai = local_ai;
      result = s;
      cache_add (addr_cache, ai);
      listen_add_fd (info, s, ai);
      int offset = snprintf (log_buf, LOG_SIZE,
                             "listening for %x/%d on socket %d at ",
                             address [0] & 0xff, LISTEN_BITS, s);
      offset += addr_info_to_string (ai, log_buf + offset, LOG_SIZE - offset);
/* printf ("%s", log_buf); */
      log_print ();
    }
  }
  snprintf (log_buf, LOG_SIZE, "connect_listener (%d/0x%x, %d) => %d\n",
            (address [0] & 0xff) >> (8 - LISTEN_BITS), address [0] & 0xff,
            af, result);
  log_print ();
  return result;
}

static void make_listeners (struct listen_info * info, void * addr_cache)
{
  int i;
  char ** contacts;
  int num_contacts = all_contacts (&contacts);
  for (i = 0; i < num_contacts; i++) {
    int j;
    keyset * keysets;
    int num_keysets = all_keys (contacts [i], &keysets);
    for (j = 0; j < num_keysets; j++) {
      unsigned char address [ADDRESS_SIZE];
      if (get_local (keysets [j], address) >= LISTEN_BITS) {
        int index = ((address [0] & 0xff) >> (8 - LISTEN_BITS)) * 2;
/* printf ("calling connect_listener [%d/%d] [%d/%d] [%d, %d]\n",
i, num_contacts, j, num_keysets, index, index + 1); */
        if (listener_fds [index] < 0)
          listener_fds [index] =
            connect_listener (address, info, addr_cache, AF_INET);
        if (listener_fds [index + 1] < 0)
          listener_fds [index + 1] =
            connect_listener (address, info, addr_cache, AF_INET6);
/* printf ("set listeners_fds [%d] = %d, [%d] = %d\n",
        index, listener_fds [index], index + 1, listener_fds [index + 1]); */
      }
    }
  }
}

static void remove_listener (int fd, struct listen_info * info,
                             void * addr_cache)
{
#ifdef DEBUG_PRINT
  printf ("remove_listener (fd %d)\n", fd);
  int removed = 0;
#endif /* DEBUG_PRINT */
  int i;
  for (i = 0; i < NUM_LISTENERS; i++) {
    if (listener_fds [i] == fd) {
      listener_fds [i] = -1;
#ifdef DEBUG_PRINT
      removed = 1;
#endif /* DEBUG_PRINT */
    }
  }
  cache_remove (addr_cache, listen_fd_addr (info, fd)); /* remove from cache */
  listen_remove_fd (info, fd); /* remove from info and pipemsg */
  close (fd);       /* remove from kernel */
#ifdef DEBUG_PRINT
  if (removed)
    printf ("removed fd %d\n", fd);
  else
    printf ("fd %d not found, not removed\n", fd);
#endif /* DEBUG_PRINT */
}

void send_keepalive (void * udp_cache, int fd,
                     int * listeners, int num_listeners)
{
  int max_size = ALLNET_MGMT_HEADER_SIZE (0xff);
  char keepalive [ALLNET_MTU];
  bzero (keepalive, max_size);
  unsigned char address [ADDRESS_SIZE];
  bzero (address, sizeof (address));
  struct allnet_header * hp =
    init_packet (keepalive, sizeof (keepalive), ALLNET_TYPE_MGMT, 1,
                 ALLNET_SIGTYPE_NONE, address, 0, address, 0, NULL);
  struct allnet_mgmt_header * mhp =
    (struct allnet_mgmt_header *) (keepalive + ALLNET_SIZE (hp->transport));
  mhp->mgmt_type = ALLNET_MGMT_KEEPALIVE;
  int size = ALLNET_MGMT_HEADER_SIZE (hp->transport);
  if (size > max_size) {  /* sanity check */
    snprintf (log_buf, LOG_SIZE, "error: keepalive size %d, max %d\n",
              size, max_size);
    log_print ();
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
      send_udp (fd, keepalive, size, sap);
      off = snprintf (log_buf, LOG_SIZE, "sent %d-byte keepalive to ", size);
    } else {
      cache_remove (udp_cache, udp_void_ptr);
      off = snprintf (log_buf, LOG_SIZE, "time out (%ld seconds), removed ",
                      time (NULL) - ucr->last_received);
    } 
#ifdef DEBUG_PRINT
    off += print_sockaddr_str (sap, sizeof (sas_copy), 0,
                               log_buf + off, LOG_SIZE - off);
#else /* DEBUG_PRINT */
    snprintf (log_buf + off, LOG_SIZE - off, "\n");
#endif /* DEBUG_PRINT */
    log_print ();
  }

  if (num_listeners > 0) {
    int i;
    int sent = 0;
    for (i = 0; i < num_listeners; i++) {
      if (listeners [i] >= 0) {
        /* send with lowest priority -- if anything else is going, we don't
           need a keepalive */
        if (! send_pipe_message (listeners [i], keepalive, size,
                                 ALLNET_PRIORITY_EPSILON)) {
          snprintf (log_buf, LOG_SIZE,
                    "aip error sending keepalive to socket %d\n",
                    listeners [i]);
          log_print ();
        } else {
          sent++;
        }
      }
    }
    snprintf (log_buf, LOG_SIZE,
              "aip sent %d-byte keepalive to %d listeners\n", size, sent);
    log_print ();
  }
}

static void send_dht_ping_response (struct sockaddr * sap, socklen_t sasize,
                                    struct allnet_header * in_hp, int fd)
{
  int off = snprintf (log_buf, LOG_SIZE, "send_dht_ping_response ");
#ifdef DEBUG_PRINT
  print_sockaddr_str (sap, sasize, 0, log_buf + off, LOG_SIZE - off);
#else /* DEBUG_PRINT */
  snprintf (log_buf + off, LOG_SIZE - off, "\n");
#endif /* DEBUG_PRINT */
  log_print ();
  unsigned char message [1024];
  bzero (message, sizeof (message));
  struct allnet_header * hp =
    init_packet ((char *) message, sizeof (message), ALLNET_TYPE_MGMT, 1,
                 ALLNET_SIGTYPE_NONE, in_hp->destination, in_hp->dst_nbits,
                 in_hp->source, in_hp->src_nbits, NULL);
  struct allnet_mgmt_header * mp =
    (struct allnet_mgmt_header *) (message + ALLNET_SIZE (hp->transport));
  mp->mgmt_type = ALLNET_MGMT_DHT;
  unsigned char * dhtp = message + ALLNET_MGMT_HEADER_SIZE (hp->transport);
  struct allnet_mgmt_dht * dht = (struct allnet_mgmt_dht *) dhtp;
  
  int max = (sizeof (message) - (((unsigned char *) (dht->nodes)) - message)) /
            sizeof (struct addr_info);

  unsigned char my_addr [ADDRESS_SIZE];
  routing_my_address (my_addr);
  int n = init_own_routing_entries (dht->nodes, max, my_addr, ADDRESS_BITS);
  if (n > 0) {
    dht->num_sender = n;
    dht->num_dht_nodes = 0;
    writeb64u (dht->timestamp, allnet_time ());
    send_udp (fd, (char *) message, ALLNET_DHT_SIZE (hp->transport, n), sap);
#ifdef DEBUG_PRINT
    packet_to_string ((char *) message, ALLNET_DHT_SIZE (hp->transport, n),
                      "sent ping response", 1, log_buf, LOG_SIZE);
    int off = strlen (log_buf);
    off += snprintf (log_buf + off, LOG_SIZE - off, " to: ");
    print_sockaddr_str (sap, sasize, 0, log_buf + off, LOG_SIZE - off);
    log_print ();
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
  snprintf (log_buf, LOG_SIZE, "dht_filter_senders %d senders\n", n_sender);
  log_print ();
#endif /* DEBUG_PRINT */
  if (n_sender == 0)
    return 0;   /* nothing to do */
  int n_dht = mdp->num_dht_nodes & 0xff;
  struct sockaddr_in * sin = (struct sockaddr_in *) sap;
  struct sockaddr_in6 * sin6 = (struct sockaddr_in6 *) sap;
#ifdef DEBUG_PRINT
  print_sockaddr (sap, sasize, -1);
  printf ("\n");
  print_packet (message, msize, "original packet", 1); 
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
  int off = snprintf (log_buf, LOG_SIZE, "handle_mgmt (%d, %d, %p, %d, ",
                      *listener, peer, message, *msizep);
  if (sasize > 0)
    print_sockaddr_str (sap, sasize, 0, log_buf + off, LOG_SIZE - off);
  else
    snprintf (log_buf + off, LOG_SIZE - off, ")\n");
  log_print ();
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
  snprintf (log_buf, LOG_SIZE, "handle_mgmt type %d/%d\n",
            hp->message_type, mp->mgmt_type);
  log_print ();
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
      if (ia_to_sockaddr (ia, sap2)) {
        int af = (ia->ip_version == 4) ? AF_INET : AF_INET6;
        int new_sock = socket (af, SOCK_STREAM, 0);
        if (connect (new_sock, sap2, sizeof (sas)) < 0) {
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
    snprintf (log_buf, LOG_SIZE, "handle_mgmt DHT %d\n", sap->sa_family);
    log_print ();
#endif /* DEBUG_PRINT */
    if (((int) (sap->sa_family)) == -1)
      return 1;   /* discard message, don't forward any further */
    struct allnet_mgmt_dht * mdp =
      (struct allnet_mgmt_dht *)
        (message + ALLNET_MGMT_HEADER_SIZE (hp->transport));
snprintf (log_buf, LOG_SIZE, "%d senders, %d nodes\n",
mdp->num_sender, mdp->num_dht_nodes);
log_print ();
    if ((mdp->num_sender == 0) && (mdp->num_dht_nodes == 0)) {
      /* ping req from behind a NAT/firewall */
      send_dht_ping_response (sap, sasize, hp, udp);
      return 1;   /* message handled */
    }
    (*msizep) -= dht_filter_senders (sap, sasize, mdp);
#ifdef DEBUG_PRINT
    print_packet (message, *msizep, "packet with all but sender removed", 1); 
    snprintf (log_buf, LOG_SIZE, "handle_mgmt returning 0, %d senders left\n",
              mdp->num_sender);
    log_print ();
#endif /* DEBUG_PRINT */
    return 0;   /* forward to adht process */
  } else if (mp->mgmt_type == ALLNET_MGMT_KEEPALIVE) {
    return 1;   /* do not forward */
  }
  return 0;   /* no peer connection established, or no valid DHT msg */
}

static void main_loop (int rpipe, int wpipe, struct listen_info * info,
                       void * addr_cache, void * dht_cache)
{
  int udp = udp_socket ();
  void * udp_cache = NULL;
  udp_cache = cache_init (128, free);
  int removed_listener = 0;
  time_t last_listen = 0;
  time_t last_keepalive = 0;
  while (1) {
    if ((time (NULL) - last_listen > 3600) || /* once an hour try to update */
        /* or once a minute if we've recently removed an fd */
        ((removed_listener) && (time (NULL) - last_listen > 60))) {
/* printf ("making listeners\n"); */
      make_listeners (info, addr_cache);
      last_listen = time (NULL);
      removed_listener = 0;
    }
    if ((last_keepalive == 0) || (time (NULL) - last_keepalive >= 55)) {
      send_keepalive (udp_cache, udp, listener_fds, NUM_LISTENERS);
      last_keepalive = time (NULL);
    }
    int fd = -1;
    int priority;
    char * message;
    struct sockaddr_storage sockaddr;
    struct sockaddr * sap = (struct sockaddr *) (&sockaddr);
    socklen_t sasize = sizeof (sockaddr);
    int result = receive_pipe_message_fd (1000, &message, udp, sap, &sasize,
                                          &fd, &priority);
if ((result > 0) && (fd == udp)&&(sap->sa_family != AF_INET) && (sap->sa_family != AF_INET6)) {
snprintf (log_buf, LOG_SIZE, "00: fd %d/%d, result %d/%d/%zd, bad afamily %d\n",
udp, fd, result, sasize, sizeof (sockaddr), sap->sa_family); log_print (); }
    if (result < 0) {
if ((sap->sa_family != AF_INET) && (sap->sa_family != AF_INET6)) {
snprintf (log_buf, LOG_SIZE, "0/%d: fd %d/%d, bad address family %d\n", result, udp, fd,
sap->sa_family); log_print (); }
      if ((fd == rpipe) || (fd == udp)) {
        snprintf (log_buf, LOG_SIZE, "aip %s %d closed\n",
                  ((fd == rpipe) ? "ad pipe" : "udp socket"), fd);
        log_print ();
        break;  /* exit the loop and the program */
      }
#ifdef DEBUG_PRINT
      printf ("aip: error %d on file descriptor %d, closing\n", result, fd);
#endif /* DEBUG_PRINT */
      snprintf (log_buf, LOG_SIZE,
                "aip: error %d on file descriptor %d, closing\n", result, fd);
      log_print ();
      remove_listener (fd, info, addr_cache);
      removed_listener = 1;
    } else if (result > 0) {
if ((fd == udp)&&(sap->sa_family != AF_INET) && (sap->sa_family != AF_INET6)) {
snprintf (log_buf, LOG_SIZE, "1: fd %d/%d, result %d/%d, bad addr family %d\n",
udp, fd, result, sasize, sap->sa_family); log_print (); }
      if (fd == rpipe) {    /* message from ad, send to IP neighbors */
        snprintf (log_buf, LOG_SIZE, "got %d-byte message from ad\n", result);
        log_print ();
        forward_message (info->fds + 1, info->num_fds - 1, udp, udp_cache,
                         addr_cache, message, result, priority, 10);
      } else {
        int off = snprintf (log_buf, LOG_SIZE,
                            "got %d bytes from Internet on fd %d",
                            result, fd);
        if (fd == udp) {
if ((sap->sa_family != AF_INET) && (sap->sa_family != AF_INET6)) {
snprintf (log_buf, LOG_SIZE, "2: fd %d/%d, bad address family %d\n", udp, fd,
sap->sa_family); log_print (); }
          standardize_ip (sap, sasize);
if ((sap->sa_family != AF_INET) && (sap->sa_family != AF_INET6)) {
snprintf (log_buf, LOG_SIZE, "3: fd %d/%d, bad address family %d\n", udp, fd,
sap->sa_family); log_print (); }
#ifdef DEBUG_PRINT
          off += snprintf (log_buf + off, LOG_SIZE - off, "/udp, saving ");
          off += print_sockaddr_str (sap, sasize, 0,
                                     log_buf + off, LOG_SIZE - off);
#else /* DEBUG_PRINT */
          off += snprintf (log_buf + off, LOG_SIZE - off, "/udp\n");
#endif /* DEBUG_PRINT */
          log_print ();
if ((sap->sa_family != AF_INET) && (sap->sa_family != AF_INET6)) {
snprintf (log_buf, LOG_SIZE, "4: fd %d/%d, bad address family %d\n", udp, fd,
sap->sa_family); log_print (); }
          add_sockaddr_to_cache (udp_cache, sap, sasize);
        } else {
          struct addr_info * ai = listen_fd_addr (info, fd);
          if (ai != NULL)
            if (ai_to_sockaddr (ai, sap))
              sasize = sizeof (struct sockaddr_in6);
#ifdef DEBUG_PRINT
          off += snprintf (log_buf + off, LOG_SIZE - off, ", ");
          off += print_sockaddr_str (sap, sasize, 1,
                                     log_buf + off, LOG_SIZE - off);
#else /* DEBUG_PRINT */
          off += snprintf (log_buf + off, LOG_SIZE - off, "\n");
#endif /* DEBUG_PRINT */
          log_print ();
        }
        if (handle_mgmt (listener_fds, NUM_LISTENERS, fd, message,
                         &result, udp, sap, sasize)) {
          /* handled, no action needed */
          /* if not handled, the message may be changed (for the better!) */
        } else {              /* message from a client, send to ad */
          /* send the message to ad.  Often ad will just send it back,
           * with a new priority */
          if (! send_pipe_message (wpipe, message, result,
                                   ALLNET_PRIORITY_EPSILON)) {
            snprintf (log_buf, LOG_SIZE,
                      "error sending to ad pipe %d\n", wpipe);
            log_print ();
            break;
          }
        }
        listen_record_usage (info, fd);   /* this fd was used */
      }
      free (message);   /* allocated by receive_pipe_message_fd */
    }   /* else result is zero, timed out, try again */
  }
}

void aip_main (int rpipe, int wpipe, char * addr_socket_name)
{
  init_log ("aip");
  snprintf (log_buf, LOG_SIZE,
            "read pipe is fd %d, write pipe fd %d, socket %s\n",
            rpipe, wpipe, addr_socket_name);
  log_print ();

  pthread_t addr_thread;
  struct receive_arg ra;
  ra.socket_name = addr_socket_name;
  ra.rp_cache = cache_init (128, free);
  ra.dht_cache = cache_init (256, free);
  if (pthread_create (&addr_thread, NULL, receive_addrs, &ra) != 0) {
    perror ("pthread_create/addrs");
    return;
  }
  struct listen_info info;
  listen_init_info (&info, 256, "aip", ALLNET_PORT, 0, 1, 0, listen_callback);

  listen_add_fd (&info, rpipe, NULL);
  int i;
  for (i = 0; i < NUM_LISTENERS; i++)
    listener_fds [i] = -1;

  srandom (time (NULL));
  main_loop (rpipe, wpipe, &info, ra.rp_cache, ra.dht_cache);

  snprintf (log_buf, LOG_SIZE,
            "end of aip main thread, deleting %s\n", addr_socket_name);
  log_print ();
  if (unlink (addr_socket_name) < 0)
    perror ("aip unlink addr_socket");
}

#ifndef NO_MAIN_FUNCTION
/* global debugging variable -- if 1, expect more debugging output */
/* set in main */
int allnet_global_debugging = 0;

int main (int argc, char ** argv)
{
  int verbose = get_option ('v', &argc, argv);
  if (verbose)
    allnet_global_debugging = verbose;

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
#endif /* NO_MAIN_FUNCTION */
