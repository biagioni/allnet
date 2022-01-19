/* routing.h: maintain routing tables for the AllNet Distributed Hash Table */

#ifndef ROUTING_H
#define ROUTING_H

#include "sockets.h"    /* struct socket_set */

/* limit sizes of dht packets */
#define ADHT_MAX_PACKET_SIZE	1024

/* fills in addr (of size at least ADDRESS_SIZE) with my address */
extern void routing_my_address (unsigned char * addr);

/* returns 1 and fills in result (if not NULL) if it finds an examct
 * match for this address (assumed to be of size ADDRESS_SIZE.
 * otherwise returns 0.  */
extern int routing_exact_match (const unsigned char * addr,
                                struct addr_info * result);
extern int ping_exact_match (const unsigned char * addr,
                             struct addr_info * result);

/* fills in an array of sockaddr_storage to the top internet addresses
 * (up to max_matches) for the given AllNet address.
 * returns the number of matches
 * returns zero if there are no matches */
extern int routing_top_dht_matches (const unsigned char * dest, int nbits,
                                    struct sockaddr_storage * result,
                                    socklen_t * alen, int max_matches);

/* either adds or refreshes a DHT entry/external IP address.
 * returns 1 for a new entry, 0 for an existing entry, -1 for errors */
extern int routing_add_dht (struct addr_info addr);
/* record our address as seen by our peers */
extern int routing_add_external (struct internet_addr ip);

/* expires old DHT entries that haven't been refreshed since the last call
 * and removes them from the socket set */
extern void routing_expire_dht (struct socket_set * s);

/* fills in the given array, which must have room for num_entries addr_infos,
 * with data to send.
 * returns the actual number of entries, which may be less than num_entries */
extern int routing_table (struct addr_info * data, int num_entries);

/* returns 1 if the address is in the routing table, 0 otherwise */
extern int is_in_routing_table (const struct sockaddr * addr, socklen_t alen);

/* as well as the DHT info, we also keep a list of nodes that we ping from
 * time to time, to see if we can add them to the DHT */

/* either adds or refreshes a ping entry.
 * returns 1 for a new entry, 0 for an existing entry, -1 for an entry that
 * is already in the DHT list, and -2 for other errors */
extern int routing_add_ping (struct addr_info * addr);

/* when iter is zero, initializes the iterator and fills in the first
 * value, if any.  Every subsequent call should use the prior return value > 0
 * When there are no more values to fill in, returns -1 */
extern int routing_ping_iterator (int iter, struct addr_info * ai);

/* for debugging */
/* fd is -1 to print to the log, 0 to print to stdout,
 * and a valid fd otherwise */
extern void print_dht (int fd);
extern void print_ping_list (int fd);

/* returns the number of entries filled in, 0...max */
/* entry may be NULL, in which case nothing is filled in */
extern int init_own_routing_entries (struct addr_info * entry, int max,
                                     const unsigned char * dest, int nbits);

/* returns 1 if the given addr is one of mine, or matches my_address */
extern int is_own_address (struct addr_info * addr);

/* save the peers file before shutting down */
extern void routing_save_peers (void);

/* if token is not NULL, this call fills its ALLNET_TOKEN_SIZE bytes */
/* if it is NULL, this call generates a new token */
/* tokens are saved in ~/.allnet/acache/local_token */
extern void routing_local_token (unsigned char * token);

#endif /* ROUTING_H */
