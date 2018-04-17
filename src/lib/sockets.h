/* manage sockets, mostly for use by ad */

/* a program such as ad has a collection of unconnected sockets,
 * represented by file descriptors (which are integers meaningful to the OS)
 * each socket has one or more addresses to which it sends
 * each address may have a maximum number of packets to send and a maximum
 * time for which it is active.
 */

#include <sys/types.h>
#include <sys/socket.h>

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
};

struct socket_address_set {
  int sockfd;
  int is_local;
  int num_addrs;
  struct socket_address_validity * send_addrs;
};

struct socket_set {
  int num_sockets;
  struct socket_address_set * sockets;
};

/* return 1 if was able to add, and 0 otherwise (e.g. if already in the set) */
extern int socket_add (struct socket_set * s, int sockfd, int is_local);
/* returns a pointer to the new sav, or NULL in case of errors (e.g.
 * if this address is already in the structure, or if the socket isn't) */
extern struct socket_address_validity *
  socket_address_add (struct socket_set * s,
                      struct socket_address_set * sock,
                      struct socket_address_validity addr);
extern int socket_remove (struct socket_set * s, int sockfd);
extern int socket_address_remove (struct socket_set * s, int sockfd,
                                  struct sockaddr_storage addr, socklen_t alen);
/* send a keepalive to addresses whose sent time + local/remote <= current_time
 * returns the number of messages sent */
extern int socket_send_keepalives (struct socket_set * s,
                                   long long int current_time,
                                   long long int local, long long int remote,
                                   const char * message, int msize);
/* remove all socket addresses whose time is less than new_time */
extern int socket_update_time (struct socket_set * s, long long int new_time);
/* return 1 if the socket address has been removed due to
 * exceeding send/receive limit, 0 otherwise, -1 for errors */
extern int socket_dec_send (struct socket_set * s, int sockfd,
                            struct sockaddr_storage addr, socklen_t alen);
extern int socket_dec_recv (struct socket_set * s, int sockfd,
                            struct sockaddr_storage addr, socklen_t alen);

/* only messages sent and received on a local socket have a priority */
struct socket_read_result {
  int success;                   /* other fields only valid if this is 1 */
  char * message;
  int msize;
  unsigned int priority;         /* valid for local messages, otherwise 1 */
  struct socket_address_set * sock;
  struct sockaddr_storage from;
  socklen_t alen;
  int socket_address_is_new;            /* 1 if address is not in socket set */
  struct socket_address_validity * sav; /* NULL for new addresses */
  int recv_limit_reached;               /* if recv_limit reached 1 */
};

/* if a message has been read by the given timeout (in milliseconds of
 * real time),
 * returns success = 1 and fields should be valid, and
 * updates the socket_address_validity's alive_rcvd to rcvd_time.
 * the pointers point into the socket_set, do not free.
 * if success is 0, the pointers are NULL.
 * special cases of "success": 
 * if the address is not found in the socket set, socket_address_is_new
 * is 1 (otherwise 0) and sav is NULL.
 * recv_limit_reached is 1 if the address is found in the socket set
 * and has recv_limit of 1.  recv_limit is left unchanged if 0 or 1,
 * and decreased by 1 otherwise. */
extern struct socket_read_result
  socket_read (struct socket_set * s, unsigned int timeout,
               long long int rcvd_time);

/* socket_send may remove any address that has become invalid due to send limit
 * send to all {local,nonlocal} except not to the given address
 * e.g. to send to all local, have local = 1, nonlocal = 0.
 *      to only send to all nonlocal, have local = 0, nonlocal = 1
 * priority is only sent with messsages sent to local sockets */
extern int socket_send (struct socket_set * s, int local, int nonlocal,
                        const char * message, int msize, unsigned int priority,
                        unsigned long long int sent_time,
                        struct sockaddr_storage except_to, socklen_t alen);
/* send only to the given socket and address */
extern int socket_send_to (const char * message, int msize,
                           unsigned int priority,
                           unsigned long long int sent_time,
                           struct socket_address_set * sock,
                           struct socket_address_validity * addr);

/* create a socket and bind it as appropriate for the given address
 * and add it to the given socket set
 * return 1 for success, 0 otherwise */
extern int socket_create_bind (struct socket_set * s, int is_local,
                               struct sockaddr_storage addr, socklen_t alen,
                               int quiet);

/* create a socket and connect it as appropriate for the given address
 * and add it to the given socket set
 * return 1 for success, 0 otherwise */
extern int socket_create_connect (struct socket_set * s, int is_local,
                                  struct sockaddr_storage addr, socklen_t alen,
                                  int quiet);
