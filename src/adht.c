/* adht.c: maintain a Distributed Hash Table of connected nodes
 * every allnet daemon runs a DHT node.
 * nodes that are externally reachable cooperate to build the distributed
 *   hash table
 * each DHT node stores data for one or more ranges of the possible Allnet
 *   destination addresses, including particularly any of its own addresses,
 *   but also zero or more randomly selected addresses
 * together, all DHT nodes should span the space of AllNet addresses.
 *   Preferably, data for each AllNet address should be in multiple (at
 *   least 4) DHT nodes
 *   To do this, for each of its ranges, each node keeps track of the 3
 *   nodes after it in the AllNet address space, and stores all data for
 *   each of those nodes.  For example, if this node stores address 55,
 *   and the 4 successive nodes store addresses 63, 68, 72, and 99, this
 *   node will store all messages with any destination address
 *   between 55 and 98, inclusive.
 * a DHT node persistently stores all messages whose destination
 *   address is in one of the node's ranges.  These messages may be removed:
 *   - when a message is acked
 *   - once the disk quota for the DHT server is reached, according to priority
 * when a message is generated locally, or when the node receives a message
 *   from another DHT node, the node sends that message to other nodes:
 *   - for each of its own addresses a, each DHT node keeps track of up to
 *     256 other DHT nodes
 *     - specifically, for each n-bit (n in 0..63) prefix of a, the node
 *       tracks up to 4 other nodes that have selected an address x matching
 *       the n-bit prefix of a, but differing from a in bit n+1
 *   - when the node forwards a message for address b, it finds the
 *     four nodes with the longest match between b and x, and forwards to them
 *   - if the node is already responsible for address b, it forwards the
 *     message to the other 3 nodes responsible for address b
 * when a disconnected node comes online, it sends a message to the first node
 *   it hears from to request any new messages for its address(es) a.
 *   Each node that stores a replies with a bitmap of the hashes of the
 *   available messages.  the node then sends requests for individual
 *   messages matching some of these hashes.
 * when a node forwards a messages that matches a large number n > 4 of
 *   other DHT nodes, it may forward to each with probability 4 / n.
 *
 * to maintain knowledge of the DHT, periodically (at random once a day),
 *   each DHT sends to all the nodes it tracks a subset of the nodes it
 *   is tracking, including any new nodes since the last transmission, and
 *   a fraction of the older nodes.

2014/03/27 to do:
  - start by figuring out what data structures are needed, implementing
    them together with save and restore.  Then update these data
    structures when the underlying file changes, or update and save when
    new information is received
  - make sure aip does what is needed, or fix as required
    note: aip routes to the (5) destinations most closely matching the address,
          whereas our DHT scheme would have each pick a range from n1 to n2
  - send routing info to aip
      initially over /tmp/allnet-addresses, later maybe over a dedicated pipe
      - send it at initialization time
      - send it periodically to keep it alive in the cache
      - add DHT destinations as they become known
  - define dht messages
  - initialization by querying prior DHT peers, alnt.org, and local broadcast
      - if none available, keep broadcasting locally

note: ADHT has info about priority of data to save.  It might eventually
replace (or supplement) acache.
      

open questions:
  - do I need to answer all these questions before implementing the DHT?
  - how does adht tell aip where to send data?  does it send its own
    data? should it listen on a different port?  how much do I have to
    modify aip?  Should I take a bunch of stuff out, and put it into adht?
  - details of the message request headers
  - how do I initially locate DHT nodes?  alnt.org?  my friends, I think.
  - is it sufficient to say I want content for address a?
  - adht has to keep track of every message ever received, and maybe the
    acks, so it can send the acks to any DHT node that still offers to
    send me obsolete packets.
  - how to do priority?  Obviously, newer messages should be favored over
    older messages, and "my" messages over other messages.  Also, messages
    for more specific addresses should be favored, etc.  But how to combine
    these?
  - do we need a DHT at all?  Could we just distribute along friend-of-friend
    links?
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <ifaddrs.h>
#include <sys/types.h>
#include <net/if.h>

#include "lib/packet.h"
#include "lib/mgmt.h"
#include "lib/ai.h"
#include "lib/log.h"
#include "lib/app_util.h"
#include "lib/util.h"
#include "lib/pipemsg.h"
#include "lib/priority.h"
#include "routing.h"

/* #define ADHT_INTERVAL	86400 /* 24 * 60 * 60 seconds == 1 day */
/* #define EXPIRATION_MULT	10 /* wait 10 intervals to expire a route */
#define ADHT_INTERVAL	30    /* for debugging */
#define EXPIRATION_MULT	3    /* for debugging */

#if 0
/* returns the number of entries filled in, 0...max */
/* entry may be NULL, in which case nothing is filled in */
int init_own_routing_entries (struct addr_info * entry, int max,
                              const char * dest, int nbits)
{
  int result = 0;
  if (entry != NULL)
    bzero (entry, sizeof (struct addr_info) * max);

  struct ifaddrs * ifap;
  if (getifaddrs (&ifap) != 0) {
    perror ("getifaddrs");
    printf ("unable to obtain own IP addresses, ignoring\n");
    return 0;
  }
  struct ifaddrs * next = ifap;
  while ((max > 0) && (next != NULL)) {
    int valid = 0;
    if (next->ifa_flags & IFF_LOOPBACK) {
#ifdef DEBUG_PRINT
      printf ("skipping loopback address\n");
#endif /* DEBUG_PRINT */
    } else if (next->ifa_addr->sa_family == AF_INET) {
      struct sockaddr_in * sinp = (struct sockaddr_in *) (next->ifa_addr);
      int high_byte = ((char *) (&(sinp->sin_addr.s_addr))) [0] & 0xff;
      int next_byte = ((char *) (&(sinp->sin_addr.s_addr))) [1] & 0xff;
      if ((high_byte != 10) &&  /* anything beginning with 10 is private */
          ((high_byte != 172) || ((next_byte & 0xf0) != 16)) &&
          ((high_byte != 192) || (next_byte != 168))) {
        if (entry != NULL) {
/* the address is already zeroed.  Assign the IP address to the last four
 * bytes (entry->ip.ip.s6_addr + 12), and 0xff to the immediately preceding
 * two bytes */
          uint32_t s_addr = sinp->sin_addr.s_addr;
          * ((uint32_t *) (entry->ip.ip.s6_addr + 12)) = s_addr;
          entry->ip.ip.s6_addr [10] = entry->ip.ip.s6_addr [11] = 0xff;
          entry->ip.ip_version = 4;
        }
        valid = 1;
      }
    } else if (next->ifa_addr->sa_family == AF_INET6) {
      struct sockaddr_in6 * sinp = (struct sockaddr_in6 *) (next->ifa_addr);
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
    } else {
#ifdef DEBUG_PRINT
      printf ("interface %s, ignoring address family %d\n", next->ifa_name,
              next->ifa_addr->sa_family);
#endif /* DEBUG_PRINT */
    }
    if (valid) {
      if (entry != NULL) {
        entry->ip.port = ALLNET_PORT;
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
    next = next->ifa_next;
  }
  freeifaddrs (ifap);
  return result;
}

/* returns 1 if the given addr is one of mine, or matches my_address */
int is_own_address (struct addr_info * addr)
{
  char my_address [ADDRESS_SIZE];
  routing_my_address (my_address);
  if (memcmp (addr->destination, my_address, ADDRESS_SIZE) == 0)
    return 1;
#define MAX_MY_ADDRS	100
  struct addr_info mine [MAX_MY_ADDRS];
  int n = init_own_routing_entries (mine, addr->destination, MAX_MY_ADDRS);
#undef MAX_MY_ADDRS
  int i;
  for (i = 0; i < n; i++)
    if (same_ai (mine + i, addr))
      return 1;
  return 0;
}

#endif /* 0 */

static void ping_all_pending (int sock, char * my_address, int nbits)
{
#define MAX_MY_ADDRS	10
  int dsize = ALLNET_DHT_SIZE (0, MAX_MY_ADDRS);
  int msize;
/* for now, create a packet addressed to my own address.  In the loop,
 * replace this address with the actual address we are sending to */
  struct allnet_header * hp =
    create_packet (dsize - ALLNET_SIZE (0), ALLNET_TYPE_MGMT, 1,
                   ALLNET_SIGTYPE_NONE,
                   my_address, nbits, my_address, ADDRESS_BITS,
                   NULL, &msize);
  if (msize != dsize) {
    printf ("error: created message expected size %d, actual %d\n",
            dsize, msize);
    exit (1);  /* for now */
  }
  int t = hp->transport;
  char * message = (char *) hp;
  bzero (message + ALLNET_SIZE (t), msize - ALLNET_SIZE (t));
  struct allnet_mgmt_header * mhp = 
    (struct allnet_mgmt_header *) (message + ALLNET_SIZE (t));
  struct allnet_mgmt_dht * mdp = 
    (struct allnet_mgmt_dht *) (message + ALLNET_MGMT_HEADER_SIZE (t));
  mhp->mgmt_type = ALLNET_MGMT_DHT;
  int n = init_own_routing_entries (mdp->nodes, MAX_MY_ADDRS,
                                    my_address, ADDRESS_BITS);
  mdp->num_sender = n;
  mdp->num_dht_nodes = 0;
  writeb64 (mdp->timestamp, allnet_time ());
  if (n < MAX_MY_ADDRS)
    msize -= (MAX_MY_ADDRS - n) * sizeof (struct addr_info);
#undef MAX_MY_ADDRS
  int iter = 0;
  struct addr_info ai;
  while ((iter = routing_ping_iterator (iter, &ai)) >= 0) {
    memcpy (hp->destination, ai.destination, ADDRESS_SIZE);
    hp->dst_nbits = ai.nbits;
    packet_to_string (message, msize, "ping_all_pending sending", 1,
                      log_buf, LOG_SIZE);
    log_print ();
    if (! send_pipe_message (sock, message, msize,
                             ALLNET_PRIORITY_LOCAL_LOW)) {
      printf ("unable to send dht ping packet to socket %d\n", sock);
      exit (1);
    }
    sleep (1); /* sleep a bit between messages, to avoid oveflowing the pipe */
  }
  free (message);
}

/* sends parts of my DHT routing table to all my DHT peers */
static void * send_loop (void * a)
{
  int sock = *((int *) a);
  char packet [1024 /* ALLNET_MTU */ ];
  char dest [ADDRESS_SIZE];
  routing_my_address (dest);
  int expire_count = 0;    /* when it reaches 10, expire old entries */
  while (1) {
    memset (packet, 0, sizeof (packet));
    time_t ping_time = 0;
    struct allnet_header * hp =
      init_packet (packet, sizeof (packet),
                   ALLNET_TYPE_MGMT, 1, ALLNET_SIGTYPE_NONE,
                   dest, ADDRESS_BITS, dest, 0, NULL);
    int hsize = ALLNET_SIZE_HEADER (hp);
    struct allnet_mgmt_header * mp = 
      (struct allnet_mgmt_header *) (packet + hsize);
    int msize = ALLNET_MGMT_HEADER_SIZE (hp->transport);
    struct allnet_mgmt_dht * dhtp =
      (struct allnet_mgmt_dht *) (packet + msize);
    struct addr_info * entries = 
      (struct addr_info *)
        (((char *) dhtp) + sizeof (struct allnet_mgmt_dht));
    int total_header_bytes = (((char *) entries) - ((char *) hp));
    int possible = (sizeof (packet) - total_header_bytes)
                 / sizeof (struct addr_info);
    int self = init_own_routing_entries (entries, 2, dest, ADDRESS_BITS);
    if (self > 0) {  /* only send if we have one or more public IP addresses */
      int added = routing_table (entries + self, possible - self);
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
      writeb64 (dhtp->timestamp, allnet_time ());
      int send_size = total_header_bytes + actual * sizeof (struct addr_info);
      if (! send_pipe_message (sock, (char *) hp, send_size,
                               ALLNET_PRIORITY_LOCAL_LOW)) {
        printf ("unable to send dht packet\n");
        exit (1);
      }
#ifdef DEBUG_PRINT
      print_packet (packet, send_size, "sent packet", 1);
#endif /* DEBUG_PRINT */
    } else {
      snprintf (log_buf, LOG_SIZE,
                "no publically routable IP address, not sending\n");
      log_print ();
      print_dht (1);
      print_ping_list (1);
#ifdef DEBUG_PRINT
#endif /* DEBUG_PRINT */
    }
    ping_time = time (NULL);
    ping_all_pending (sock, dest, ADDRESS_BITS);
    ping_time = time (NULL) - ping_time; /* num seconds it took to ping */
    snprintf (log_buf, LOG_SIZE, "    expiration count %d\n", expire_count);
    log_print ();
    if (expire_count++ >= EXPIRATION_MULT) {
      routing_expire_dht ();
      expire_count = 0;
    }
    /* sleep for ADHT_INTERVAL +- 10%, and skipping the ping time */
    time_t interval = ((ADHT_INTERVAL * (90 + (random () % 21))) / 100)
                    - ping_time;
#ifdef DEBUG_PRINT
    printf ("sleep interval %ld\n", interval);
#endif /* DEBUG_PRINT */
    sleep (interval);
  }
}

static void respond_to_dht (int sock, char * message, int msize)
{
  /* ignore any packet other than valid dht packets */
  if (msize <= ALLNET_HEADER_SIZE)
    return;
  struct allnet_header * hp = (struct allnet_header *) message;
  if ((hp->message_type != ALLNET_TYPE_MGMT) ||
      (msize < ALLNET_MGMT_HEADER_SIZE(hp->transport) +
               sizeof (struct allnet_mgmt_dht) +
               sizeof (struct addr_info)))  /* only process if >= 1 entry */
    return;
/* snprintf (log_buf, LOG_SIZE, "survived msize %d/%zd\n", msize,
             ALLNET_MGMT_HEADER_SIZE(hp->transport) +
             sizeof (struct allnet_mgmt_dht) +
             sizeof (struct addr_info));
  log_print (); */
  struct allnet_mgmt_header * mp =
    (struct allnet_mgmt_header *) (message + ALLNET_SIZE (hp->transport));
  if (mp->mgmt_type != ALLNET_MGMT_DHT)
    return;
  struct allnet_mgmt_dht * dhtp =
    (struct allnet_mgmt_dht *)
      (message + ALLNET_MGMT_HEADER_SIZE (hp->transport));

  int off = snprintf (log_buf, LOG_SIZE, "got %d byte DHT packet: ", msize);
  packet_to_string (message, msize, NULL, 1, log_buf + off, LOG_SIZE - off);
  log_print ();
#ifdef DEBUG_PRINT
#endif /* DEBUG_PRINT */

  int n_sender = (dhtp->num_sender & 0xff);
  int n_dht = (dhtp->num_dht_nodes & 0xff);
  int n = n_sender + n_dht;
#ifdef DEBUG_PRINT
  snprintf (log_buf, LOG_SIZE, "packet has %d entries, size %d\n", n, msize);
  log_print ();
#endif /* DEBUG_PRINT */
  int expected_size = ALLNET_MGMT_HEADER_SIZE(hp->transport) + 
                      sizeof (struct allnet_mgmt_dht) + 
                      n * sizeof (struct addr_info);
  if ((n < 1) || (msize < expected_size)) {
    printf ("packet has %d entries, %d/%d size, nothing to add to DHT/pings\n",
            n, msize, expected_size);
    return;
  }

  /* found a valid dht packet */
  int i;
  for (i = 0; i < n_sender; i++)
    if (! is_own_address (dhtp->nodes + i))
      routing_add_dht (dhtp->nodes + i);
  print_dht (1);
#ifdef DEBUG_PRINT
#endif /* DEBUG_PRINT */
  for (i = 0; i < n_dht; i++)
    if (! is_own_address (dhtp->nodes + n_sender + i))
      routing_add_ping (dhtp->nodes + n_sender + i);
  print_ping_list (1);
#ifdef DEBUG_PRINT
#endif /* DEBUG_PRINT */
}

int main (int argc, char ** argv)
{
  /* connect to alocal */
  int sock = connect_to_local ("adht", argv [0]);
  if (sock < 0)
    return 1;

  pthread_t send_thread;
  if (pthread_create (&send_thread, NULL, send_loop, &sock) != 0) {
    perror ("pthread_create/addrs");
    return 1;
  }
  while (1) {
    char * message;
    int pipe, pri;
    int timeout = PIPE_MESSAGE_WAIT_FOREVER;
    int found = receive_pipe_message_any (timeout, &message, &pipe, &pri);
    if (found < 0) {
      printf ("adht: pipe closed, exiting\n");
      pthread_cancel (send_thread);
      exit (1);
    }
#ifdef DEBUG_PRINT
    print_packet (message, found, "received", 1);
#endif /* DEBUG_PRINT */
    respond_to_dht (sock, message, found);
    free (message);
  }
}
