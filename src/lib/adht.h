/* adht.h: maintain a Distributed Hash Table of connected nodes
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
 *  a day or less, changed this to send messages once every 30 minutes,
 *  and expire after 300 minutes = 5 hours)
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

#ifndef ADHT_H
#define ADHT_H

#include "sockets.h"

/* #define ADHT_INTERVAL	86400 */ /* 24 * 60 * 60 seconds == 1 day */
#define ADHT_INTERVAL	1800   /* 30 min -- IPv6 addresses expire every day */
#define EXPIRATION_MULT	10     /* wait 10 intervals to expire a route */

/* add information from a newly received DHT packet */
extern void dht_process (char * message, unsigned int msize,
                         const struct sockaddr * sap, socklen_t alen);

/* at the right time, create a DHT packet to send out my routing table */
extern int dht_update (struct socket_set * s, char ** message);

/* add into the socket set the addresses known from the DHT */
extern void dht_add_addrs (struct socket_set * s);

#endif /* ADHT_H */
