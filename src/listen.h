/* listen.c: thread to listen on a port and maintain connected fds */
/*   there is a finite maximum number of fds -- once more are connected, */
/*   old ones are closed */

#ifndef LISTEN_H
#define LISTEN_H

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
  int add_remove_pipe;   /* call add_pipe and remove_pipe */
  /* if the ip version of a peer is 0, that fd does not have a peer address */
  struct addr_info * peers;  /* handled similar to fds, holds peer addrs */
  /* for testing, make counter a char.  Normally, unsigned int */
  unsigned char counter;  /* cycle counter for least recently used */
  unsigned int * used;   /* array of most recent access times */
  void (* callback) (int);  /* may be NULL, otherwise called when new
                               fd added, parameter is fd */
};

/* exits in case of errors, otherwise initializes info and starts the
 * listen thread */
/* ip version should be 4 or 6 */
/* add_remove_pipe should be 1 if add_pipe and remove_pipe should be
 * called when adding or removing pipes */
extern void listen_init_info (struct listen_info * info, int max_fds,
                              char * name, int port, int local_only,
                              int add_remove_pipe, int nodelay,
                              void (* callback) (int));

/* call to record that this fd was active at this time */
extern void listen_record_usage (struct listen_info * info, int fd);

/* call to add an fd to the data structure */
/* may close the least recently active fd, and if so, */
/* sends the list of peers before closing */
extern void listen_add_fd (struct listen_info * info, int fd,
                           struct addr_info * addr);

/* call to remove an fd from the data structure */
extern void listen_remove_fd (struct listen_info * info, int fd);

/* returned addr_info is statically allocated (until remove_fd is called),
 * do not modify in any way.  Returns NULL for no match */
extern struct addr_info * listen_fd_addr (struct listen_info * info, int fd);

extern int already_listening (struct addr_info * ai,
                              struct listen_info * info);

#endif /* LISTEN_H */
