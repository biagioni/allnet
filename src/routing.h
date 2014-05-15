/* routing.h: maintain routing tables for the AllNet Distributed Hash Table */

#ifndef ROUTING_H
#define ROUTING_H

/* returns a malloc'd array containing the top matches (up to max_matches)
 * for the given address.
 * returns zero and sets *result to NULL if there are no matches */
extern int routing_top_dht_matches (struct addr_info * addr, int max_matches,
                                    struct addr_info ** result);

/* either adds or refreshes a DHT entry */
extern int routing_add_dht (struct addr_info * addr);

/* expires old DHT entries that haven't been refreshed since the last call */
extern int routing_expire_dht (struct addr_info * addr);

/* fills in the given array, which must have room for num_entries addr_infos,
 * with data to send.
 * returns the actual number of entries, which may be less than num_entries */
extern int routing_table (struct addr_info * data, int num_entries);

#endif /* ROUTING_H */
