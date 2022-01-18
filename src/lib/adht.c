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

static struct allnet_log * alog = NULL;

#ifndef ALLNET_RESOURCE_CONSTRAINED  /* actively participate in the DHT */
struct ping_all_args {
  int finished;
  int sockfd_v6;   /* -1 if not valid */
  int sockfd_v4;   /* -1 if not valid */
  unsigned char address [ADDRESS_SIZE];
  int nbits;
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
  make_ping_args (struct socket_set * s, unsigned char * my_address, int nbits)
{
  struct ping_all_args result =
    { .finished = 0, .sockfd_v6 = -1, .sockfd_v4 = -1, .nbits = nbits };
  memcpy (result.address, my_address, sizeof (result.address));
  socket_sock_loop (s, assign_sockfds, &result);
  return result;
}

static void * ping_all_pending (void * arg)
{
  struct ping_all_args * a = (struct ping_all_args *) arg;
  unsigned char * my_address = a->address;
  int nbits = a->nbits;
#define MAX_MY_ADDRS	10
  unsigned int dsize = ALLNET_DHT_SIZE (0, MAX_MY_ADDRS);
  unsigned int msize;
/* for now, create a packet addressed to my own address.  In the loop,
 * replace this address with the actual address we are sending to */
  struct allnet_header * hp =
    create_packet (dsize - ALLNET_SIZE (0),
                   ALLNET_TYPE_MGMT, 1, ALLNET_SIGTYPE_NONE,
                   my_address, nbits, my_address, ADDRESS_BITS,
                   NULL, NULL, &msize);
  if (msize != dsize) {
    printf ("error: created message expected size %d, actual %d\n",
            dsize, msize);
    exit (1);  /* for now */
  }
  int t = hp->transport;
  char * message = (char *) hp;
  memset (message + ALLNET_SIZE (t), 0, msize - ALLNET_SIZE (t));
  struct allnet_mgmt_header * mhp = 
    (struct allnet_mgmt_header *) (message + ALLNET_SIZE (t));
  struct allnet_mgmt_dht * mdp = 
    (struct allnet_mgmt_dht *) (message + ALLNET_MGMT_HEADER_SIZE (t));
  mhp->mgmt_type = ALLNET_MGMT_DHT;
  int n = init_own_routing_entries (mdp->nodes, MAX_MY_ADDRS,
                                    my_address, ADDRESS_BITS);
  mdp->num_sender = n;
  mdp->num_dht_nodes = 0;
  writeb64u (mdp->timestamp, allnet_time ());
  if (n < MAX_MY_ADDRS)
    msize -= (MAX_MY_ADDRS - n) * sizeof (struct addr_info);
#undef MAX_MY_ADDRS
  int iter = 0;
  struct addr_info ai;
  while ((iter = routing_ping_iterator (iter, &ai)) >= 0) {
    sleep (1); /* sleep between messages, that's why we are in a thread */
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
    memcpy (&(mdp->sending_to_ip), &(ai.ip), sizeof (ai.ip));
    if (sockfd >= 0) {
      packet_to_string (message, msize, "ping_all_pending sending", 1,
                        alog->b, alog->s);
      log_print (alog);
      socket_send_to_ip (sockfd, message, msize, sas, alen,
                         "adht.c/ping_all_pending");
    }
  }
  free (message);
  a->finished = 1;
  return NULL;
}
#endif /* ALLNET_RESOURCE_CONSTRAINED -- actively participate in the DHT */

/* at the right time, create a DHT packet to send out my routing table
 * the socket set is used to send messages to potential DHT peers
 * returns the packet size
 * if successful, *iap points into the message for the spot to save the
 * the destination internet address before sending */
int dht_update (struct socket_set * s,
                char ** message, struct internet_addr ** iap)
{
  if (alog == NULL)
    alog = init_log ("adht");
  *message = NULL;
  *iap = NULL;
#ifdef ALLNET_RESOURCE_CONSTRAINED  /* do not actively participate in the DHT */
  return 0;
#else /* ! ALLNET_RESOURCE_CONSTRAINED -- actively participate in the DHT */
  static unsigned long long int next_time = 0;
  static int expire_count = 0;    /* when it reaches 10, expire old entries */
  static unsigned char my_address [ADDRESS_SIZE];
  static unsigned char zero_address [ADDRESS_SIZE];
  if (next_time == 0) {            /* initialize */
    routing_my_address (my_address);
    memset (zero_address, 0, sizeof (zero_address));
  }
  unsigned long long int now = allnet_time ();
  if (now < next_time) /* not time to send to my neighbors yet */
    return 0;
  /* compute the next time to execute, between 90% and 110% of two hours */
  next_time = now + ((ADHT_INTERVAL * (90 + (random () % 21))) / 100);
  char buffer [ADHT_MAX_PACKET_SIZE];
  memset (buffer, 0, sizeof (buffer));
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
  struct addr_info * entries = (struct addr_info *) (&(dhtp->nodes[0]));
  size_t total_header_bytes = (((char *) entries) - ((char *) hp));
  size_t possible = (sizeof (buffer) - total_header_bytes)
                  / sizeof (struct addr_info);
  int self = init_own_routing_entries (entries, 2, my_address, ADDRESS_BITS);
  if (self <= 0) { /* only send if we have one or more public IP addresses */
    snprintf (alog->b, alog->s,
              "no publically routable IP address, not sending\n");
    log_print (alog);
    print_dht (-1);
    print_ping_list (-1);
#ifdef DEBUG_PRINT
#endif /* DEBUG_PRINT */
    return 0;
  }
  int added = routing_table (entries + self, (int)(possible - self));
#ifdef DEBUG_PRINT
  if (added <= 0)
    printf ("adht: routing table returned %d\n", added);
#endif /* DEBUG_PRINT */
  int actual = self;
  if (added > 0)
    actual += added;
  mp->mgmt_type = ALLNET_MGMT_DHT;
  dhtp->num_sender = self;
  dhtp->num_dht_nodes = added;
  writeb64u (dhtp->timestamp, allnet_time ());
  size_t send_size = total_header_bytes + actual * sizeof (struct addr_info);
  size_t ip_offset = (((char *) (&dhtp->sending_to_ip)) - buffer);
  if (send_size > sizeof (buffer)) {
    printf ("dht_update send_size %zd > %zd, truncating\n", 
            send_size, sizeof (buffer));
    send_size = sizeof (buffer);
  }
  packet_to_string ((char *) hp, (int)send_size, "dht_update created", 1,
                    alog->b, alog->s);
  log_print (alog);
  *message = memcpy_malloc (buffer, (int) send_size, "dht_update");
  *iap = (struct internet_addr *) ((*message) + ip_offset);
#ifdef DEBUG_PRINT
  print_packet (*message, send_size, "dht_update packet", 1);
#endif /* DEBUG_PRINT */
  static struct ping_all_args ping_arg = { .finished = 1, .nbits = 0,
                                           .sockfd_v6 = -1, .sockfd_v4 = -1 };
  if (ping_arg.finished) {
    ping_arg = make_ping_args (s, my_address, ADDRESS_BITS);
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
#ifdef DEBUG_PRINT
  int off = snprintf (alog->b, alog->s, "got %d byte DHT packet: ", dsize);
  packet_to_string (dht_bytes, dsize, NULL, 1, alog->b + off, alog->s - off);
  log_print (alog);
#endif /* DEBUG_PRINT */
  struct allnet_mgmt_dht * dhtp = (struct allnet_mgmt_dht *) dht_bytes;

  int n_sender = (dhtp->num_sender & 0xff);
  int n_dht = (dhtp->num_dht_nodes & 0xff);
  int n = n_sender + n_dht;
#ifdef DEBUG_PRINT
  snprintf (alog->b, alog->s, "packet has %d entries, size %d\n", n, dsize);
  log_print (alog);
#endif /* DEBUG_PRINT */
  struct addr_info * aip = dhtp->nodes;
  unsigned int expected_size = sizeof (struct allnet_mgmt_dht) + 
                               n * sizeof (struct addr_info);
  if ((n < 1) || (dsize < expected_size)) {
    printf ("packet %d entries, %d/%d size, nothing to add to DHT/pings\n",
            n, dsize, expected_size);
    return;
  }

  /* found a valid dht packet */
  int i;
  for (i = 0; i < n_sender; i++) {
    struct addr_info ai = aip [i];
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
        struct addr_info sender_ai = ai;
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
    struct addr_info * ai = aip + n_sender + i;
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
