/* adht.c: maintain a Distributed Hash Table of connected nodes
 * every allnet daemon runs a DHT node.
 * nodes that are externally reachable cooperate to build the distributed
 *   hash table
 * each DHT node stores data for one range of the possible AllNet
 *   destination addresses
 * together, all DHT nodes span the space of AllNet addresses.
 *   Data for each AllNet address should be in at multiple DHT nodes,
 *   preferably at least 4
 * each node tries to connect as a listener to at least one
 *   (at most 2, one for IPv4, and one for IPv6) DHT nodes for each
 *   of its addresses, but in such a way that there is at most one listener
 *   for each DHT IP addreses
 * a message is forwarded to the top 4 DHT matches as well as
 *   local broadcasts, rendez-vous points, or any other destinations
 * DHT messages refresh each node's DHT table
 * an empty DHT message is just a ping to confirm the address works
 * DHT messages are sent once a day, and DHT table entries expire after
 *   10 days
 * (2015 note: after learning that the average IPv6 address lives for
 *  a day or less, changed this to send messages once every 3 minutes,
 *  and expire after 30 minutes)
 * this program maintains a persistent table of known DHT nodes (up
 *   to 4 per address bit), and a table of nodes to ping.
 * the local DHT identifier is maintained or generated here

 * to do (maybe not in this file):
 * when a disconnected node comes online, it sends a message to the first node
 *   it hears from to request any new messages for its address(es) a.
 *   Each node that stores a replies with a bitmap of the hashes of the
 *   available messages.  the node then sends requests for individual
 *   messages matching some of these hashes.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>

#include "adht.h"
#include "packet.h"
#include "mgmt.h"
#include "ai.h"
#include "allnet_log.h"
#include "app_util.h"
#include "util.h"
#include "priority.h"
#include "routing.h"
#include "sockets.h"

#ifndef ALLNET_RESOURCE_CONSTRAINED  /* actively participate in the DHT */
struct ping_all_args {
  int finished;
  int sockfd_v6;   /* -1 if not valid */
  int sockfd_v4;   /* -1 if not valid */
  char * message;
  struct allnet_internet_addr * iap;
  int msize;
};

static int assign_sockfds (struct socket_address_set * sock, void * ref)
{
  struct ping_all_args * a = (struct ping_all_args *) ref;
  if ((a->sockfd_v6 == -1) && (sock->is_global_v6))
    a->sockfd_v6 = sock->sockfd;
  if ((a->sockfd_v4 == -1) && (sock->is_global_v4) && (! sock->is_global_v6))
    a->sockfd_v4 = sock->sockfd;
  return 1;
}

static struct ping_all_args
  make_ping_args (struct socket_set * s, unsigned char * my_address, int nbits,
                  char * message, struct allnet_internet_addr * iap, int msize)
{
  struct ping_all_args result =
    { .finished = 0, .sockfd_v6 = -1, .sockfd_v4 = -1,
      .message = NULL, .iap = NULL, .msize = 0 };
  socket_sock_loop (s, assign_sockfds, &result);
  result.message = memcpy_malloc (message, msize, "make_ping_args");
  size_t offset = ((char *) iap) - message;
  result.iap = (struct allnet_internet_addr *) (result.message + offset);
  result.msize = msize;
  return result;
}

static void * ping_all_pending (void * arg)
{
  /* there is no point to running multiple ping threads at the same time */
  static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
  if (pthread_mutex_trylock (&mutex) != 0)
    return NULL;
  struct ping_all_args * a = (struct ping_all_args *) arg;
  struct allnet_header * hp = (struct allnet_header *) a->message;
#define MAX_ROUTES	32
  struct allnet_addr_info peers [MAX_ROUTES];
  int num_routes = routing_table (peers, MAX_ROUTES);
#undef MAX_ROUTES
  int route_index = 0;
  int iter = 0;
  struct allnet_addr_info ai;
  while ((route_index < num_routes) ||
         ((iter = routing_ping_iterator (iter, &ai)) >= 0)) {
    sleep (1); /* sleep between messages, that's why we are in a thread */
    if (route_index < num_routes)   /* sending to a peer, not a ping */
      ai = peers [route_index++];
    memcpy (hp->destination, ai.destination, ADDRESS_SIZE);
    hp->dst_nbits = ai.nbits;
    if ((hp->dst_nbits > ADDRESS_BITS) || (hp->dst_nbits > 64)) {
      printf ("error in ping_all_pending, %d destination bits > %d/64 (%d)\n",
              hp->dst_nbits, ADDRESS_BITS, iter);
      print_addr_info (&ai);
      hp->dst_nbits = ADDRESS_BITS;
    }
    struct sockaddr_storage sas;
    memset (&sas, 0, sizeof (sas));
    socklen_t alen = 0;
    ia_to_sockaddr (&(ai.ip), &sas, &alen);
    int sockfd = a->sockfd_v4;
    if ((ai.ip.ip_version == 6) || (a->sockfd_v4 < 0)) {
      sockfd = a->sockfd_v6;
      if (ai.ip.ip_version == 4)  /* sockfd_v4 is < 0, send on v6 socket */
        ai_embed_v4_in_v6 (&sas, &alen);
    }
    memcpy (a->iap, &(ai.ip), sizeof (ai.ip));
#ifdef DEBUG_PRINT
    printf ("%llu  ping_all_pending sending ", allnet_time ());
    print_packet (a->message, a->msize, NULL, 0);
    printf (" (sending to ");
    print_sockaddr ((struct sockaddr *) (&sas), alen);
    printf (")\n");
#endif /* DEBUG_PRINT */
    if (sockfd >= 0)
      socket_send_to_ip (sockfd, a->message, a->msize, sas, alen,
                         "adht.c/ping_all_pending");
  }
  free (a->message);
  a->finished = 1;
  pthread_mutex_unlock (&mutex);
  return NULL;
}
#endif /* ALLNET_RESOURCE_CONSTRAINED -- actively participate in the DHT */

/* at the right time, create a DHT packet to send out my routing table
 * the socket set is used to send messages to potential DHT peers
 * returns the packet size
 * if successful, *iap points into the message for the spot to save the
 * the destination internet address before sending */
int dht_update (struct socket_set * s,
                char ** message, struct allnet_internet_addr ** iap)
{
  *message = NULL;
  *iap = NULL;
#ifdef ALLNET_RESOURCE_CONSTRAINED  /* do not actively participate in the DHT */
  return 0;
#else /* ! ALLNET_RESOURCE_CONSTRAINED -- actively participate in the DHT */
  static unsigned long long int next_time = 0;
  static unsigned long long int num_pings = 0;
  static int expire_count = 0;    /* when it reaches 10, expire old entries */
  static unsigned char my_address [ADDRESS_SIZE];
  static unsigned char zero_address [ADDRESS_SIZE];
  if (next_time == 0) {            /* initialize */
    routing_my_address (my_address);
    memset (zero_address, 0, sizeof (zero_address));
  }
  unsigned long long int min = 10 * ALLNET_US_PER_S;        /* 10 seconds */
  unsigned long long int max = (unsigned long long int) ADHT_INTERVAL /* 2hrs */
                             * (unsigned long long int) ALLNET_US_PER_S;
  if (! time_exp_interval (&next_time, &num_pings, min, max))
    return 0;   /* not time to send to my neighbors yet */
  int send_size = dht_create (NULL, 0, message, iap);
  if (send_size <= 0)
    return 0;
  static struct ping_all_args ping_arg = { .finished = 1,
                                           .sockfd_v6 = -1, .sockfd_v4 = -1,
                                           .message = NULL, .iap = NULL,
                                           .msize = 0 };
  if (ping_arg.finished) {
    ping_arg = make_ping_args (s, my_address, ADDRESS_BITS,
                               *message, *iap, send_size);
    pthread_t ping_thread;
    pthread_create (&ping_thread, NULL, ping_all_pending, &ping_arg);
    pthread_detach (ping_thread);
  }
  if (expire_count++ >= EXPIRATION_MULT) {
    routing_expire_dht (s);
    expire_count = 0;
  }
  return send_size;
#endif /* ALLNET_RESOURCE_CONSTRAINED */
}

/* add information from a newly received DHT packet */
void dht_process (char * dht_bytes, unsigned int dsize,
                  const struct sockaddr * sap, socklen_t alen)
{
  struct allnet_mgmt_dht * dhtp = (struct allnet_mgmt_dht *) dht_bytes;

  int n_sender = (dhtp->num_sender & 0xff);
  int n_dht = (dhtp->num_dht_nodes & 0xff);
  int n = n_sender + n_dht;
  struct allnet_addr_info * aip = dhtp->nodes;
  unsigned int expected_size = sizeof (struct allnet_mgmt_dht) + 
                               n * sizeof (struct allnet_addr_info);
  if ((n < 1) || (dsize < expected_size)) {
    printf ("packet %d entries, %d/%d size, nothing to add to DHT/pings\n",
            n, dsize, expected_size);
    return;
  }

  /* found a valid dht packet */
  int i;
  for (i = 0; i < n_sender; i++) {
    struct allnet_addr_info ai = aip [i];
    if (! is_own_address (&ai)) {
      int validity = is_valid_address (&ai.ip);
      if (validity == 1) {
        routing_add_dht (ai);
      } else if (validity == -1) {  /* IPv4 in IPv6 address */
        ai.ip.ip_version = 4;
        routing_add_dht (ai);
      } else {               /* zero address, use the sender's IP instead */
#ifdef DEBUG_PRINT
        print_buffer (&ai, sizeof (ai), "dht process adding invalid", 40, 1);
        print_buffer (sap, (sap->sa_family == AF_INET) ? 16 : 28,
                      "sender address", 99, 1);
        print_packet (dht_bytes, dsize, "entire message", 1);
#endif /* DEBUG_PRINT */
        struct allnet_addr_info sender_ai = ai;
        sockaddr_to_ia (sap, alen, &(sender_ai.ip));
        if (is_valid_address (&sender_ai.ip) == 1) {
          routing_add_dht (sender_ai);
        } else {
          printf ("adht.h dht_process, bad sender IP address: ");
          print_sockaddr (sap, alen);
          printf ("\n");
          printf ("while processing address: ");
          print_addr_info (&ai);
        }
      }
    }
  }
  if ((dsize == expected_size) &&
      /* all-zeros address is sensible sometimes, e.g. when sending locally */
      (! memget (&dhtp->sending_to_ip, 0, sizeof (dhtp->sending_to_ip))) &&
      (is_valid_address (&(dhtp->sending_to_ip)))) {
  /* record my IP address as seen by the peer */
    if (routing_add_external (dhtp->sending_to_ip) < 0) {
#ifdef DEBUG_PRINT
      printf ("dsize %d == %d, routing_add_external failed at %zd\n",
              dsize, expected_size,
              ((char *) (&(dhtp->sending_to_ip))) - dht_bytes);
      print_packet (dht_bytes, dsize, NULL, 1);
      print_buffer ((char *) (&(dhtp->sending_to_ip)),
                    sizeof (dhtp->sending_to_ip), "sending_to_ip", 100, 1);
#endif /* DEBUG_PRINT */
    }
  }
#ifdef DEBUG_PRINT
    else if (! memget (&dhtp->sending_to_ip, 0, sizeof (dhtp->sending_to_ip))) {
      printf ("dsize %d =? %d, invalid address?\n", dsize, expected_size);
      print_packet (dht_bytes, dsize, NULL, 1);
      print_buffer (dht_bytes, dsize, "packet", dsize, 1);
  }
#endif /* DEBUG_PRINT */
#ifdef DEBUG_PRINT
  print_dht (-1);
#endif /* DEBUG_PRINT */
  for (i = 0; i < n_dht; i++) {
    struct allnet_addr_info * ai = aip + n_sender + i;
    if (! is_own_address (ai)) {
      struct sockaddr_storage ping_addr;
      struct sockaddr * pingp = (struct sockaddr *) (&ping_addr);
      socklen_t plen = 0;
      ai_to_sockaddr (ai, &ping_addr, &plen);
      if ((ai->type == ALLNET_ADDR_INFO_TYPE_DHT) &&
          (! is_in_routing_table (pingp, plen))) {
        int validity = is_valid_address (&(ai->ip));
        if (validity == 1) {  /* valid address */
          int rapl = routing_add_ping (ai);
          if (rapl < -1) {
            printf ("adht dht_process: routing_add_ping result is %d, val %d\n",
                    rapl, validity);
print_buffer (sap, alen, "from", alen, 1);
print_addr_info (ai);
print_buffer (ai, sizeof (*ai), "ai", sizeof (*ai), 1);
          }
        } else if (validity == -1) {  /* IPv4 in IPv6 address */
          ai->ip.ip_version = 4;
          int rapl = routing_add_ping (ai);
          if (rapl < -1) {
            printf ("adht dht_process2: routing_add_ping result %d, val %d\n",
                    rapl, validity);
print_buffer (sap, alen, "from", alen, 1);
print_addr_info (ai);
print_buffer (&ai, sizeof (ai), "ai", sizeof (ai), 1);
          }
        } /* else: invalid address, do not add */
      }
    }
  }
  print_ping_list (-1);
#ifdef DEBUG_PRINT
#endif /* DEBUG_PRINT */
}

/* create a DHT packet to send out my routing table.
 * Returns the packet size, or 0 for errors
 * if successful and sockaddr is not null and slen > 0, the
 * sending_to_ip address is set to the corresponding address
 * (otherwise to all zeros)
 * if successful and iap is not NULL, *iap points into to the
 * location of the sending_to_ip_address (same address that the
 * sockaddr, if any, was copied to). */
int dht_create (const struct sockaddr * sap, socklen_t slen,
                char ** message, struct allnet_internet_addr ** iap)
{
  char buffer [ADHT_MAX_PACKET_SIZE];
  memset (buffer, 0, sizeof (buffer));
  static unsigned char my_address [ADDRESS_SIZE];
  static unsigned char zero_address [ADDRESS_SIZE];
  static int initialized = 0;
  if (! initialized) {
    routing_my_address (my_address);
    memset (zero_address, 0, sizeof (zero_address));
    initialized = 1;
  }
  struct allnet_header * hp =  /* create one packet with my address */
    init_packet (buffer, sizeof (buffer),
                 ALLNET_TYPE_MGMT, 1, ALLNET_SIGTYPE_NONE,
                 my_address, ADDRESS_BITS, zero_address, 0, NULL, NULL);
  int hsize = ALLNET_SIZE_HEADER (hp);
  struct allnet_mgmt_header * mp = 
    (struct allnet_mgmt_header *) (buffer + hsize);
  int msize = ALLNET_MGMT_HEADER_SIZE (hp->transport);
  struct allnet_mgmt_dht * dhtp =
    (struct allnet_mgmt_dht *) (buffer + msize);
  struct allnet_addr_info * entries =
    (struct allnet_addr_info *) (&(dhtp->nodes[0]));
  size_t total_header_bytes = (((char *) entries) - ((char *) hp));
  size_t possible = (sizeof (buffer) - total_header_bytes)
                  / sizeof (struct allnet_addr_info);
  int self = init_own_routing_entries (entries, 2, my_address, ADDRESS_BITS);
  if (self <= 0) { /* only send if we have one or more public IP addresses */
    printf ("no publically routable IP address, not sending\n");
#ifdef DEBUG_PRINT
    print_dht (-1);
    print_ping_list (-1);
#endif /* DEBUG_PRINT */
    return 0;
  }
  int added = routing_table (entries + self, (int)(possible - self));
#ifdef DEBUG_PRINT
  if (added <= 0)
    printf ("adht: routing table returned %d\n", added);
#endif /* DEBUG_PRINT */
  int actual = self + ((added > 0) ? added : 0);
  mp->mgmt_type = ALLNET_MGMT_DHT;
  dhtp->num_sender = self;
  dhtp->num_dht_nodes = added;
  writeb64u (dhtp->timestamp, allnet_time ());
  size_t send_size = total_header_bytes +
                     actual * sizeof (struct allnet_addr_info);
  size_t ip_offset = (((char *) (&(dhtp->sending_to_ip))) - buffer);
  if (send_size > sizeof (buffer)) {
    printf ("dht_update send_size %zd > %zd, truncating\n", 
            send_size, sizeof (buffer));
    send_size = sizeof (buffer);
  }
  /* copy the message to *message, the result */
  *message = memcpy_malloc (buffer, (int) send_size, "dht_update");
  /* iap is ip_offset into the copied message */
  struct allnet_internet_addr * internet_addr_ptr =
    (struct allnet_internet_addr *) ((*message) + ip_offset);
  if ((sap != NULL) && (slen > 0))
    sockaddr_to_ia (sap, slen, internet_addr_ptr);
  if (iap != NULL)
    *iap = internet_addr_ptr;
#ifdef DEBUG_PRINT
  print_packet (*message, send_size, "dht_create packet", 1);
#endif /* DEBUG_PRINT */
  return send_size;
}
