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

#include "lib/packet.h"
#include "lib/mgmt.h"
#include "lib/ai.h"
#include "lib/log.h"
#include "lib/app_util.h"
#include "lib/util.h"
#include "lib/pipemsg.h"
#include "lib/priority.h"

#include "routing.h"

#define MAX_PEERS	(64 * 4)

struct addr_info peers [MAX_PEERS];

static void init_peers (int always)
{
  static int initialized = 0;
  if ((initialized) && (! always))
    return;
  /* an unused entry has nbits set to 0 -- and might as well clear the rest */
  bzero ((char *) (peers), sizeof (peers));
  initialized = 1;
}

static void save_peers ()
{
  init_peers (0);
  int fd = open_write_config ("adht", "peers", 1);
  if (fd < 0)
    return;
  int i;
  for (i = 0; i < MAX_PEERS; i++) {
    if (peers [i].nbits != 0) {
      char line [300];
      char buf [200];
      addr_info_to_string (peers + i, buf, sizeof (buf));
      snprintf (line, sizeof (line), "%d:%s", i, buf);
      write (fd, line, strlen (line));
    }
  }
  close (fd);
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
    buf [0] = strtol (in, &end, 16);
    if (end == in) {
      return in;
    }
    in = end;
    buf++;
    nbytes--;
  }
  return in;
}

static void load_peer (struct addr_info * peer, char * line)
{
  /* printf ("load_peer parsing line %s\n", line); */
  if (*line != ':')
    return;
  line++;
  if (*line != ' ')
    return;
  line++;
  char * end;
  int ptr = strtol (line, &end, 16);
  if (end == line)
    return;
  if ((end [0] != ' ') || (end [1] != '('))
    return;
  line = end + 2;
  int nbits = strtol (line, &end, 10);
  if (end == line)
    return;
  if ((end [0] != ')') || (end [1] != ' '))
    return;
  line = end + 2;
  strtol (line, &end, 10);
  if ((end == line) || (memcmp (end, " bytes: ", 8) != 0))
    return;
  line = end + 8;
  char address [ADDRESS_SIZE];
  bzero (address, sizeof (address));
  line = read_buffer (line, (nbits + 7) / 8, address, sizeof (address));
  if (memcmp (line, ", v ", 4) != 0)
    return;
  line += 4;
  int ipversion = strtol (line, &end, 10);
  if (end == line)
    return;
  if ((ipversion != 4) && (ipversion != 6)) {
    printf ("error: IP version %d\n", ipversion);
    return;
  }
  line = end;
  if (memcmp (line, ", port ", 7) != 0)
    return;
  line += 7;
  int port = strtol (line, &end, 10);
  if (end == line)
    return;
  line = end;
  if (memcmp (line, ", addr ", 7) != 0)
    return;
  line += 7;
  strtol (line, &end, 10);
  if ((end == line) || (memcmp (end, " bytes: ", 8) != 0))
    return;
  line = end + 8;
  char ip [16];   /* maximum size needed for IPv6 addresses */
  bzero (ip, sizeof (ip));
  ip [10] = 0xff;
  ip [11] = 0xff;
  if (ipversion == 4)
    line = read_buffer (line, 4, ip + 12, 4);
  else
    line = read_buffer (line, 16, ip, 16);
  bzero (((char *) (peer)), sizeof (struct addr_info));
  memcpy (((char *) (&(peer->ip.ip))), ip, sizeof (ip));
  peer->ip.port = htons (port);
  peer->ip.ip_version = ipversion;
  memcpy (peer->destination, address, ADDRESS_SIZE);
  peer->nbits = nbits;
}

static int load_peers ()
{
  init_peers (1);
  int fd = open_read_config ("adht", "peers", 1);
  if (fd < 0)
    return 0;
  char line [300];
  while (read_line (fd, line, sizeof (line))) {
    char * end;
    int peer = strtol (line, &end, 10);
    if ((end != line) && (peer >= 0) && (peer < MAX_PEERS))
      load_peer (peers + peer, end);
  }
  close (fd);
}

struct send_arg {
  int sock;
  unsigned char my_id [ADDRESS_SIZE];
  int my_bits;
};

static void * send_loop (void * a)
{
  struct send_arg * arg = (struct send_arg *) a;
  char packet [1024 /* ALLNET_MTU */ ];
  char dest [ADDRESS_SIZE];
  memset (dest, 0, sizeof (dest));
  while (1) {
    memset (packet, 0, sizeof (packet));
    sleep (30);  /* good for debugging.  later maybe sleep longer */
    struct allnet_header * hp =
      init_packet (packet, sizeof (packet),
                   ALLNET_TYPE_MGMT, 5, ALLNET_SIGTYPE_NONE,
                   arg->my_id, arg->my_bits, dest, 0, NULL);
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
    int actual = routing_table (entries, possible);
    if (actual <= 0) {
      printf ("adht: routing table returned %d\n", actual);
    } else {
      mp->mgmt_type = ALLNET_MGMT_DHT;
      dhtp->num_dht_nodes = actual;
      int send_size = total_header_bytes + actual * sizeof (struct addr_info);
      if (! send_pipe_message (arg->sock, (char *) hp, send_size,
                               ALLNET_PRIORITY_LOCAL_LOW)) {
        printf ("unable to send dht packet\n");
        exit (1);
      }
      print_packet (packet, send_size, "sent packet", 1);
    }
  }
}

static void respond_to_dht (int sock, char * message, int msize)
{
  /* ignore any packet other than valid dht packets */
  if (msize <= ALLNET_HEADER_SIZE)
    return;
  snprintf (log_buf, LOG_SIZE, "got %d bytes\n", msize);
  log_print ();
  packet_to_string (message, msize, "respond_to_dht", 1, log_buf, LOG_SIZE);
  log_print ();
  struct allnet_header * hp = (struct allnet_header *) message;
  if ((hp->message_type != ALLNET_TYPE_MGMT) ||
      (msize < ALLNET_MGMT_HEADER_SIZE(hp->transport) +
               sizeof (struct allnet_mgmt_dht) +
               sizeof (struct addr_info)))
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
  int n = (dhtp->num_dht_nodes & 0xff);
/* snprintf (log_buf, LOG_SIZE, "packet has %d entries, size %d\n", n, msize);
  log_print (); */
  int expected_size = ALLNET_MGMT_HEADER_SIZE(hp->transport) + 
                      sizeof (struct allnet_mgmt_dht) + 
                      n * sizeof (struct addr_info);
  if ((n < 1) || (msize < expected_size))
    return;

  /* found a valid dht packet */
  int i;
  for (i = 0; i < n; i++)
    routing_add_dht (dhtp->nodes + i);
}

int main (int argc, char ** argv)
{
  /* connect to alocal */
  int sock = connect_to_local ("adht", argv [0]);

  pthread_t send_thread;
  struct send_arg arg;
  arg.sock = sock;
  random_bytes (arg.my_id, sizeof (arg.my_id));
  arg.my_bits = 8;
  if (pthread_create (&send_thread, NULL, send_loop, &arg) != 0) {
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
    print_packet (message, found, "received", 1);
#ifdef DEBUG_PRINT
#endif /* DEBUG_PRINT */
    respond_to_dht (sock, message, found);
    free (message);
  }

#if 0  /* debugging */
  load_peers ();
  srandom (time (NULL));
  int p = random () % MAX_PEERS;
  random_bytes ((char *) (&(peers [p].ip.ip)), sizeof (peers [p].ip.ip));
  peers [p].ip.port = random () % 65536;
  peers [p].ip.ip_version = ((random () % 2) ? 4 : 6); 
  random_bytes (peers [p].destination, ADDRESS_SIZE);
  peers [p].nbits = random () % (ADDRESS_SIZE * 8 + 1);
  save_peers ();
/*  load_peers (); */
#endif /* 0 */
}
