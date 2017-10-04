/* listen.c: thread to listen on a port and maintain connected fds */
/*   there is a finite maximum number of fds -- once more are connected, */
/*   old ones are closed */

#ifndef LISTEN_H
#define LISTEN_H

#include "lib/pipemsg.h"  /* pd */

/* this structure is declared in the caller and passed to every function.
 * Some of the fields should not be accessed by the caller */
struct listen_info {
  /* accessed by the caller as well as the code in listen.c */
  int num_fds;           /* counter for number of file descriptors in fds */
  int * fds;             /* array of ints for file descriptors */
  pthread_mutex_t mutex; /* mutex for accessing fds */
  pthread_t thread4;     /* listen thread for IPv4 */
  pthread_t thread6;     /* listen thread for IPv6 */
  int nodelay;           /* nodelay 1 on all local sockets, 0 on all other */
  /* the rest of these fields are for listen.c internal use only */
  int max_num_fds;       /* max number of elements with space in fds */
  char * program_name;   /* e.g. alocal, aip */
  int listen_fd4;        /* fd for listening for new connections on ipv4 */
  int listen_fd6;        /* fd for listening for new connections on ipv6 */
  int port;              /* TCP port number */
  int localhost_only;    /* immediately close connections not from local host */
  int add_remove_pipe;   /* call add_pipe and remove_pipe */
  /* if the ip version of a peer is 0, that fd does not have a peer address */
  struct addr_info * peers;  /* handled similar to fds, holds peer addrs */
  struct addr_info * reserved;  /* same size (max_num_fds) as peers,
                                   holds pending connections */
  unsigned long long int * reservation_times;  /* matches with reserved */
  /* for testing, make counter a char.  Normally, unsigned int */
  unsigned char counter;  /* cycle counter for least recently used */
  unsigned int * used;   /* array of most recent access times */
  void (* callback) (int);  /* may be NULL, otherwise called when new
                               fd added, parameter is fd */
  pd pipe_descriptor;
};

/* exits in case of errors, otherwise initializes info and starts the
 * listen thread */
/* ip version should be 4 or 6 */
/* port is in host byte order */
/* add_remove_pipe should be 1 if add_pipe and remove_pipe should be
 * called when adding or removing pipes */
extern void listen_init_info (struct listen_info * info, int max_fds,
                              char * name, int port, int local_only,
                              int add_remove_pipe, int nodelay,
                              void (* callback) (int), pd p);

/* call to close all connections and free the allocated memory */
extern void listen_shutdown (struct listen_info * info);

/* call to record that this fd was active at this time */
extern void listen_record_usage (struct listen_info * info, int fd);

/* call to add an fd to the data structure */
/* may close the least recently active fd, and if so, */
/* sends the list of peers before closing */
/* returns 1 if successfully added,
           0 if addr != NULL and add_only_if_unique_ip and
                a matching address already had an fd */
extern int listen_add_fd (struct listen_info * info, int fd,
                          struct addr_info * addr, int add_only_if_unique_ip,
                          const char * caller_description);

/* call to remove an fd from the data structure */
/* returns 1 if removed, 0 otherwise */
extern int listen_remove_fd (struct listen_info * info, int fd);

/* returned addr_info is statically allocated (until remove_fd is called),
 * do not modify in any way.  Returns NULL for no match */
extern struct addr_info * listen_fd_addr (struct listen_info * info, int fd);

/* mallocs and sets result to an n-element array of file descriptors
 * that are the best matches for the given destination */
/* returns the actual number of destinations found, or 0 */
extern int listen_top_destinations (struct listen_info * info, int max,
                                    unsigned char * dest, int nbits,
                                    int ** result);

/* returns the socket number if already listening,
   returns -1 and reserves the address if nobody else had reserved it,
   returns -2 if someone had reserved the address already. */
extern int already_listening (struct addr_info * ai,
                              struct listen_info * info);

/* clears a reservation that was set when already_listening returned -1 */
extern void listen_clear_reservation (struct addr_info * ai,
                                      struct listen_info * info);

#endif /* LISTEN_H */
