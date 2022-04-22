/* ai.h: utility functions for struct addr_info and struct internet_addr */

#include "packet.h"
#include "mgmt.h"

#ifndef ALLNET_AI_H
#define ALLNET_AI_H

/* prints a newline at the end of the address info */
extern void print_addr_info (struct allnet_addr_info * ai);
/* includes a newline at the end of the address info */
extern int addr_info_to_string (struct allnet_addr_info * ai,
                                char * buf, size_t bsize);

/* sap must point to at least sizeof (struct sockaddr_in6) bytes */
/* returns 1 for success, 0 for failure */
/* if salen is not NULL, it is given the appropriate length (0 for failure) */
extern int ai_to_sockaddr (const struct allnet_addr_info * ai,
                           struct sockaddr_storage * sap, socklen_t * salen);

extern int sockaddr_to_ai (const struct sockaddr * sap, socklen_t addr_size,
                           struct allnet_addr_info * ai);

/* prints a newline at the end of the internet address */
extern void print_ia (struct allnet_internet_addr * ia);
/* includes a newline at the end of the internet address */
extern int ia_to_string (const struct allnet_internet_addr * ia,
                         char * buf, size_t bsize);

/* returns 1 for success, 0 for failure */
/* if salen is not NULL, it is given the appropriate length (0 for failure) */
extern int ia_to_sockaddr (const struct allnet_internet_addr * ia,
                           struct sockaddr_storage * sap, socklen_t * salen);

/* returns 1 for success, 0 for failure */
/* takes sas as input, and returns the result (if any) in sas and alen
 * ai_embed_v4_in_v6 is needed since apple OSX and perhaps other systems
 * don't support sending to IPv4 addresses on IPv6 sockets */
extern int ai_embed_v4_in_v6 (struct sockaddr_storage * sas, socklen_t * alen);

/* returns 1 for success, 0 for failure */
/* addr_size is only used for error checking, may be greater than the size
 * of sockaddr_in/6, and is ignored if it is 0 */
extern int sockaddr_to_ia (const struct sockaddr * sap, socklen_t addr_size,
                           struct allnet_internet_addr * ia);

/* addr must point to 4 bytes if af is AF_INET, 16 bytes for AF_INET6 */
/* if nbits > 0, dest should point to at least (nbits + 7) / 8 bytes */
/* returns 1 for success, 0 for failure */
extern int init_ai (int af, const unsigned char * addr, int port, int nbits,
                    const unsigned char * dest, struct allnet_addr_info * ai);

/* returns 1 if the two addresses are the same, 0 otherwise */
extern int same_ai (const struct allnet_addr_info * a,
                    const struct allnet_addr_info * b);
/* returns 1 if the two addresses and ports are the same, 0 otherwise */
extern int same_aip (const struct allnet_addr_info * a,
                     const struct allnet_addr_info * b);

/* if this is an IPv4-encoded-as-IPv6 address, make it an IPv4 address again */
extern void standardize_ip (struct sockaddr * ap, socklen_t asize);

/* is this address a local IP? */
extern int is_loopback_ip (const struct sockaddr * ap, socklen_t asize);

struct interface_addr {
  char * interface_name;
  int is_loopback;
  int is_broadcast;
  int is_up;
  int num_addresses;
  struct sockaddr_storage * addresses;
};

/* getifaddrs is not completely portable, so this is implemented in
 * any way the local system supports.
 * returns the number n of interface addresses.
 * if interfaces is not NULL, *interfaces is assigned to point to malloc'd
 * storage with n addresses, may be free'd (as a block -- interface_name
 * and addresses point to within *interfaces) */
extern int interface_addrs (struct interface_addr ** interfaces);

/* same, but only return all the valid broadcast addresses */
extern int interface_broadcast_addrs (struct sockaddr_storage ** addrs);

/* using getaddrinfo makes it hard or impossible to do static linking,
 * whereas static linking is useful for distributing the software as
 * self-contained binaries.
 * Also, getaddrinfo only queries one name at a time, when it would be much
 * easier to request all translations at once.
 * Finally, the response should be returned in real time.
 * allnet_dns sends a query for each of the names to each server
 *    in /etc/hosts.  When it gets a valid response, it calls the
 *    callback with the original name, the corresponding id, and the address.
 *    valid is all zeros if there is no address for the name (RCODE=3)
 *    allnet_dns itself returns after it gets all its responses, or when
 *    it times out, usually after 10-20s.
 *    allnet_dns returns the number of addresses found, or 0 for errors
 */
extern int allnet_dns (const char ** names, const int * callback_ids, int count,
                       void (* callback) (const char * name, int id, int valid,
                                          const struct sockaddr * addr));

/* test whether this address is syntactically valid address (e.g.
 * not all zeros), returning 1 if valid, -1 if it is an ipv4-in-ipv6
 * address, and 0 otherwise */
extern int is_valid_address (const struct allnet_internet_addr * ip);

/* as well as the obvious comparisons, returns true also for
 * an IPv4-embedded-in-IPv6 that matches a plain IPv4 address */
extern int same_sockaddr (const struct sockaddr_storage * a, socklen_t alen,
                          const struct sockaddr_storage * b, socklen_t blen);

#endif /* ALLNET_AI_H */
