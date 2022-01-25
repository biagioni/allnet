/* manage sockets, mostly for use by ad */

/* a program such as ad has a collection of unconnected sockets,
 * represented by file descriptors (which are integers meaningful to the OS)
 * each socket has one or more addresses to which it sends
 * each address may have a maximum number of packets to send and a maximum
 * time for which it is active.
 */

#ifndef ALLNET_SOCKETS_H
#define ALLNET_SOCKETS_H

#include <inttypes.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "mgmt.h"

/* since UDP doesn't tell us when peers have gone away, we send each peer
 * a message and require each active peer to send us a message every n
 * seconds, and we assume they are dead after n * m seconds.
 * For the sockets code, "time" is just a number -- the caller will typically
 * increase that number by 1 every n seconds (2018/04/15: n is 10 seconds).
 * For local  connections, typically m = 6.
 * For remote connections, typically m = 360 (and we send fewer keepalives).
 */
struct socket_address_validity {
  struct sockaddr_storage addr;
  socklen_t alen;
  long long int alive_rcvd;      /* the most recent time at which received */
  long long int alive_sent;      /* the most recent time at which sent */
  long long int time_limit;      /* time to delete, 0 if no time limit */
  int recv_limit;                /* num packets can recv, 0 if no recv limit */
  int send_limit;                /* num packets can send, 0 if no send limit */
  int send_limit_on_recv;        /* new send limit on recv, 0 to disable */
  char keepalive_auth [KEEPALIVE_AUTHENTICATION_SIZE];  /* send with keepalives */
};

struct socket_address_set {
  int sockfd;
  int is_local;                  /* true if used by local programs */
  int is_global_v6;              /* true if can send to any IPv6 address */; 
  int is_global_v4;              /* true if can send to any IPv4 address */; 
  int is_broadcast;              /* true if added to support broadcasts */; 
  int num_addrs;
  struct socket_address_validity * send_addrs;
};

struct socket_set {
  int num_sockets;
  struct socket_address_set * sockets;
  /* needed to send authentication in keepalives */
  char random_secret [KEEPALIVE_AUTHENTICATION_SIZE];
  uint64_t counter;
};

/* return 1 if was able to add, and 0 otherwise (e.g. if already in the set) */
extern int socket_add (struct socket_set * s, int sockfd, int is_local,
                       int is_global_v6, int is_global_v4, int is_bc);
/* returns a pointer to the new sav, or NULL in case of errors (e.g.
 * if this address is already in the structure, or if the socket isn't) */
extern struct socket_address_validity *
  socket_address_add (struct socket_set * s, int sockfd,
                      struct socket_address_validity sav);

/* the loop functions should return 1 if the socket/address should be kept,
 * and 0 if the socket/address should be deleted
 * ref is a reference to any data structure needed by the function */
typedef int (* socket_sock_loop_fun) (struct socket_address_set * sock,
                                      void * ref);
typedef int (* socket_addr_loop_fun) (struct socket_address_set * sock,
                                      struct socket_address_validity * sav,
                                      void * ref);
/* each of these return the number of records deleted */
extern int socket_sock_loop (struct socket_set * s,
                             socket_sock_loop_fun f, void * ref);
extern int socket_addr_loop (struct socket_set * s,
                             socket_addr_loop_fun f, void * ref);

/* only messages sent and received on a local socket have a priority */
struct socket_read_result {
  int success;                   /* other fields only valid if this is 1 */
  char * message;                /* points to the buffer passed as parameter */
  int msize;
  unsigned int priority;         /* valid for local messages, otherwise 1 */
  struct socket_address_set * sock;
  struct sockaddr_storage from;
  socklen_t alen;
  int socket_address_is_new;            /* 1 if address is not in socket set */
  struct socket_address_validity * sav; /* NULL if socket_address_is_new */
  int recv_limit_reached;               /* if recv_limit reached 1 */
};

#define SOCKETS_TIMEOUT_FOREVER		-1
/* if a message has been read by the given timeout (in milliseconds of
 * real time),
 * returns success = 1 and fields should be valid, and
 * updates the socket_address_validity's alive_rcvd to rcvd_time.
 * the pointers point into the socket_set or buffer, do not free.
 * the buffer must have size at least ALLNET_MTU + 4 (the + 4 is important!)
 * special cases of "success": 
 *   if the address is not found in the socket set, socket_address_is_new
 *   is 1 (otherwise 0) and sav is NULL.
 *   recv_limit_reached is 1 if the address is found in the socket set
 *   and has recv_limit of 1.  recv_limit is left unchanged if 0 or 1,
 *   and decreased by 1 otherwise.
 * if success is 0, the pointers are NULL and the call timed out.
 * if success is -1, the sock pointer is either NULL or points to a socket
 *   that is no longer valid, and the other pointers are NULL */
#define SOCKET_READ_MIN_BUFFER	(ALLNET_MTU + 4)
extern struct socket_read_result socket_read (struct socket_set * s,
                                              char * buffer, int timeout,
                                              long long int rcvd_time);
/* returns 1 if the receive limit was updated, 0 otherwise */
extern int socket_update_recv_limit (int new_recv_limit, struct socket_set * s,
                                     struct sockaddr_storage addr,
                                     socklen_t alen);
/* remove all socket addresses whose time is less than new_time.
 * return the number of records deleted */
extern int socket_update_time (struct socket_set * s, long long int new_time);

/* socket_send_{local,out} remove any address that has become invalid
 * due to send limit.
 * return 1 for success, 0 for at least some error */
extern int socket_send_local (struct socket_set * s, const char * message,
                              int msize, unsigned int priority,
                              unsigned long long int sent_time,
                              struct sockaddr_storage except_to,
                              socklen_t alen);
/* if sent_to and num_sent are not NULL, *num_sent should have the
 * number of available entries in sent_to.  These will be filled
 * with the addresses to which we send, and the number of these is
 * placed back in *num_sent
 * if save_dest_address is not NULL, the address to which we send is filled
 * in each time before the packet is sent -- this may be useful if
 * the outgoing address is to be sent as part of the message */
extern int socket_send_out (struct socket_set * s, const char * message,
                            int msize,
                            struct allnet_internet_addr * save_dest_address,
                            unsigned long long int sent_time,
                            struct sockaddr_storage except_to, socklen_t alen,
                            struct sockaddr_storage * sent_to, int * num_sent);
/* send only to the given socket and address */
extern int socket_send_to (const char * message, int msize,
                           unsigned int priority,
                           unsigned long long int sent_time,
                           struct socket_set * s,
                           struct socket_address_set * sock,
                           struct socket_address_validity * addr);
/* send to an address that may not even be in a socket set -- this is how
 * we can connect to new systems without receiving from them first */
extern int socket_send_to_ip (int sockfd, const char * message, int msize,
                              struct sockaddr_storage sas, socklen_t alen,
                              const char * debug);
/* send a keepalive to addresses whose sent time + local/remote <= current_time
 * returns the number of messages sent
 * if the keepalive is being sent through the internet,
 * sender and receiver authentications
 * are copied into each keepalive before it is sent
 * do NOT send keepalives to broadcast addresses */
extern int socket_send_keepalives (struct socket_set * s,
                                   long long int current_time,
                                   long long int local, long long int remote);

/* create a socket and bind it as appropriate for the given address
 * and add it to the given socket set
 * return the sockfd for success, -1 otherwise */
extern int socket_create_bind (struct socket_set * s, int is_local,
                               struct sockaddr_storage addr, socklen_t alen,
                               int quiet);

/* for debugging */
extern void print_socket_set (struct socket_set * s);
extern void print_socket_global_addrs (struct socket_set * s);
extern void close_socket_set (struct socket_set * s);

/* use result -100 to say we don't know the result */ 
extern void sockets_log_sr (int sent_not_received, const char * debug,
                            const char * message, int msize,
                            const struct sockaddr * sent, int alen,
                            ssize_t result);
extern void sockets_log_addresses (const char * debug,
                                   struct socket_set * sockets,
                                   const struct sockaddr_storage * addrs,
                                   int num_addrs, int priority_threshold);

#endif /* ALLNET_SOCKETS_H */
