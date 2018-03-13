/* listen.c: thread to listen on a port and maintain connected fds */
/*   there is a finite maximum number of fds -- once more are connected, */
/*   old ones are closed */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include "listen.h"
#include "lib/packet.h"
#include "lib/pipemsg.h"
#include "lib/mgmt.h"
#include "lib/util.h"
#include "lib/pipemsg.h"
#include "lib/allnet_log.h"
#include "lib/ai.h"

static struct allnet_log * alog = NULL;

#ifdef DEBUG_PRINT
static void print_listen_info (struct listen_info * info)
{
  printf ("listen_info %p", info);
  printf (" (c %d) has %d fds %p", info->counter, info->num_fds, info->fds);
  int i;
  if (info->num_fds > 0) {
    for (i = 0; i < info->num_fds; i++)
      printf (", %d", info->fds [i]);
    printf ("\n");
    for (i = 0; i < info->num_fds; i++)
      print_addr_info (&(info->peers [i]));
  }
  printf ("\n");
}
#endif /* DEBUG_PRINT */

/* returns the fd of the new listen socket, or -1 in case of error */
static int init_listen_socket (int version, int port, int local)
{
  int isip6 = (version == 6);
  static int ipv6_supported = 1;   /* default */
  if (isip6 && (! ipv6_supported))
    return -1;
  int af = ((isip6) ? AF_INET6 : AF_INET);
  int fd = socket (af, SOCK_STREAM, 0);
  if (fd < 0) {
    if (isip6 && (errno == EAFNOSUPPORT))
      ipv6_supported = 0;   /* IPv6 is not supported */
    perror ("listen socket");
    return -1;
  }
  /* allow us to reuse the port number immediately, rather than wait */
  int option = 1;
  if (setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof (int)) != 0)
    perror ("listen setsockopt reuseaddr");
#ifdef SO_NOSIGPIPE
  option = 1;
  if (setsockopt (fd, SOL_SOCKET, SO_NOSIGPIPE, &option, sizeof (int)) != 0)
    perror ("listen setsockopt nosigpipe");
#endif /* SO_NOSIGPIPE */

  struct sockaddr_storage address;
  struct sockaddr     * ap  = (struct sockaddr     *) &address;
  struct sockaddr_in  * ap4 = (struct sockaddr_in  *) ap;
  struct sockaddr_in6 * ap6 = (struct sockaddr_in6 *) ap;
  socklen_t addr_size = sizeof (address);

  memset (&address, 0, addr_size);
  if (isip6) {
    ap6->sin6_family = AF_INET6;
    if (local)
      memcpy (&(ap6->sin6_addr), &(in6addr_loopback), sizeof (ap6->sin6_addr));
    else
      memcpy (&(ap6->sin6_addr), &(in6addr_any), sizeof (ap6->sin6_addr));
    ap6->sin6_port = port;
    addr_size = sizeof (struct sockaddr_in6);
  } else {
    ap4->sin_family = AF_INET;
    if (local)
      ap4->sin_addr.s_addr = htonl (INADDR_LOOPBACK);
    else
      ap4->sin_addr.s_addr = htonl (INADDR_ANY);
    ap4->sin_port = port;
    addr_size = sizeof (struct sockaddr_in);
  }
  int n = snprintf (alog->b, alog->s, "binding to ");
  n += print_sockaddr_str (ap, addr_size, 1, alog->b + n, alog->s - n);
  log_print (alog);
  if (bind (fd, ap, addr_size) < 0) {
    if (version == 6) {
      perror ("listen.c bind 6");
      n = snprintf (alog->b, alog->s,
                    "ipv%d unable to bind %d/%x(%d), maybe already running\n",
                    version, ntohs (port), ntohs (port), addr_size);
      n += snprintf (alog->b + n, alog->s - n, "bind address is ");
      n += print_sockaddr_str (ap, addr_size, 1, alog->b + n, alog->s - n);
      log_print (alog);
    } else {
      snprintf (alog->b, alog->s,
                "ipv%d unable to bind to %d/%x(%d), probably handled by ipv6\n",
                version, ntohs (port), ntohs (port), addr_size);
      log_print (alog);
    }
snprintf (alog->b, alog->s, "l i closing socket %d\n", fd); log_print (alog);
    close (fd);
    return -1;
  }
  /* specify the maximum queue length */
  if (listen (fd, 5) < 0) {
    perror("listen");
snprintf (alog->b, alog->s, "l i2 closing socket %d\n", fd); log_print (alog);
    close (fd);
    return -1;
  }
  snprintf (alog->b, alog->s, "opened accept socket fd = %d, ip version %d\n",
            fd, version);
  log_print (alog);
  return fd;
}

struct real_arg {
  struct listen_info * info;   /* struct listen_info is defined in listen.h */
  int version;                 /* IP version 6 or 4 */
};

static void * listen_loop (void * arg)
{
  struct real_arg * ra = (struct real_arg *) arg;
  struct listen_info * info = ra->info;
  int version = ra->version;
  int port = info->port;
  int local = info->localhost_only;
  free (ra);
  snprintf (alog->b, alog->s, "started listen_loop (v %d, p %d, l %d)\n",
            version, port, local);
  log_print (alog);

  /* allow the main thread to kill this thread at any time */
#ifndef ANDROID
#ifdef PTHREAD_CANCEL_ASYNCHRONOUS
  int notinteresting;
  pthread_setcanceltype (PTHREAD_CANCEL_ASYNCHRONOUS, &notinteresting);
#endif /* PTHREAD_CANCEL_ASYNCHRONOUS */
#endif /* ANDROID */

  int failure_count = 0;
  while (1) {   /* repeat, in case the listen socket is closed, e.g. in iOS */
    if (version == 4)
      usleep (100 * 1000);  /* give IPv6 a chance to bind the port first */
    int fd = init_listen_socket (version, port, local);
    if (fd >= 0) {
      failure_count = 0;
      if (version == 4)
        info->listen_fd4 = fd;
      else
        info->listen_fd6 = fd;

      struct sockaddr_storage address;
      struct sockaddr     * ap   = (struct sockaddr     *) &address;
      socklen_t addr_size = sizeof (address);

      /* listen for connections, add them to the data structure */
      int connection;
      while ((connection = accept (fd, ap, &addr_size)) >= 0) {
        int off = snprintf (alog->b, alog->s,
                            "opened connection socket fd = %d port %d from ",
                            connection, ntohs (info->port));
/* sometimes an incoming IPv4 connection is recorded as an IPv6 connection.
 * we want to record it as an IPv4 connection */
        standardize_ip (ap, addr_size);
#ifdef DEBUG_PRINT
        print_sockaddr_str (ap, addr_size, 1, alog->b + off, alog->s - off);
#else /* DEBUG_PRINT */
        snprintf (alog->b + off, alog->s - off, "\n");
#endif /* DEBUG_PRINT */
        log_print (alog);
        if ((info->localhost_only) && (! is_loopback_ip (ap, addr_size))) {
          snprintf (alog->b, alog->s, "warning: loopback got from nonlocal\n");
          log_print (alog);
snprintf (alog->b, alog->s, "l l closing socket %d\n", connection); log_print (alog);
          close (connection);
#ifdef DEBUG_EBADFD
snprintf (ebadbuf, EBADBUFS,
"listen_loop for local host got nonlocal, closing %d\n", connection);
record_message (info->pipe_descriptor);
#endif /* DEBUG_EBADFD */
          continue;   /* skip the rest of the inner while loop */
        }
        int option = 1;  /* nodelay disables Nagle algorithm */
        if ((info->nodelay) &&
            (setsockopt (connection, IPPROTO_TCP, TCP_NODELAY, &option,
                         sizeof (option)) != 0)) {
          snprintf (alog->b, alog->s, "unable to set nodelay socket option\n");
          log_print (alog);
        }

        struct addr_info addr;
        sockaddr_to_ai (ap, addr_size, &addr);  /* zero destination and nbits */
        if (listen_add_fd (info, connection, &addr, /* unique unless local IP */
                           ! is_loopback_ip (ap, addr_size),
                           "listen.c listen_loop")) {
          if (info->callback != NULL)
            info->callback (connection);
        } else {
#ifdef DEBUG_EBADFD
snprintf (ebadbuf, EBADBUFS, 
"listen_loop unable to listen_add_fd, closing %d\n", connection);
record_message (info->pipe_descriptor);
#endif /* DEBUG_EBADFD */
snprintf (alog->b, alog->s, "l l2 closing socket %d\n", connection); log_print (alog);
          close (connection);
        }
        addr_size = sizeof (address);  /* reset for next call to accept */
      }
      perror ("accept in listen.c listen_loop");
      printf ("error calling accept (%d)\n", fd);
snprintf (alog->b, alog->s, "l l3 closing socket %d\n", fd); log_print (alog);
      close (fd);    /* if still open */
    } else {  /* unable to create listen_socket: wait a while, try again */
      sleep (5);
      failure_count++;
      if ((failure_count > 20) || ((failure_count > 5) && (version == 4))) {
      /* give up.  Give up sooner for IPv4, since IPv4 bind may fail if
       * the IPv6 has already bound the port */
        return NULL;
      }
    }
  }
  return NULL;
}

/* port is in host byte order */
void listen_init_info (struct listen_info * info, int max_fds, char * name,
                       int port, int local_only, int add_remove_pipe,
                       int nodelay, void (* callback) (int), pd p)
{
  alog = pipemsg_log (p);
  if (max_fds > 1024) {
    printf ("using 1024 as the maximum number of open fds, %d is too large\n",
            max_fds);
    exit (1);
  }
  if (max_fds <= 0) {
    printf ("invalid %d for max open fds\n", max_fds);
    exit (1);
  }
  info->program_name = name;
  info->port = allnet_htons (port);
  info->add_remove_pipe = add_remove_pipe;
  info->localhost_only = local_only;
  info->num_fds = 0;
  info->max_num_fds = max_fds;
  info->fds = malloc_or_fail (max_fds * sizeof (int), "listen thread fds");
  int asize = max_fds * sizeof (struct addr_info);
  int atsize = max_fds * sizeof (unsigned long long int);
  info->peers = malloc_or_fail (asize, "listen thread peers");
  info->reserved = malloc_or_fail (asize, "listen reserved peers");
  info->reservation_times = malloc_or_fail (atsize, "listen reservation times");
  memset (info->reserved, 0, asize);
  memset (info->reservation_times, 0, atsize);
  info->used = malloc_or_fail (max_fds * sizeof (int), "listen thread used");
  info->callback = callback;
  info->pipe_descriptor = p;
  info->nodelay = nodelay;
  int i;
  for (i = 0; i < max_fds; i++)
    info->fds [i] = info->used [i] = info->peers [i].ip.ip_version = 0;
  info->counter = 0;
  pthread_mutex_init (&(info->mutex), NULL);
  info->listen_fd6 = -1;
  info->listen_fd4 = -1;
  struct real_arg * real_arg6 =
    malloc_or_fail (sizeof (struct real_arg), "ip6 real arg");
  real_arg6->info = info;
  real_arg6->version = 6;
  if (pthread_create (&(info->thread6), NULL, listen_loop, real_arg6) != 0) {
    perror ("listen6/pthread_create");
    snprintf (alog->b, alog->s,
              "unable to create listen thread for IP version 6, exiting\n");
    log_print (alog);
    exit (1);
  }
  /* printf ("allocating %ld bytes for 4\n", sizeof (struct real_arg));  */
  struct real_arg * real_arg4 =
    malloc_or_fail (sizeof (struct real_arg), "ip4 real arg");
  /* printf ("allocated %ld bytes\n", sizeof (struct real_arg)); */
  real_arg4->info = info;
  real_arg4->version = 4;
  if (pthread_create (&(info->thread4), NULL, listen_loop, real_arg4) != 0) {
    perror ("listen4/pthread_create");
    snprintf (alog->b, alog->s,
              "unable to create listen thread for IP version 4, exiting\n");
    log_print (alog);
    exit (1);
  }
}

#define FREE_NULL(p)	{ if (p != NULL) free (p); p = NULL; }

void listen_shutdown (struct listen_info * info)
{
  while (info->num_fds > 0) 
    listen_remove_fd (info, info->fds [0]);
  if (info->listen_fd6 >= 0) {
#ifdef DEBUG_EBADFD
snprintf (ebadbuf, EBADBUFS,
"listen_shutdown closing ipv6 listen socket %d\n", info->listen_fd6);
record_message (info->pipe_descriptor);
#endif /* DEBUG_EBADFD */
snprintf (alog->b, alog->s, "l s closing socket %d\n", info->listen_fd6); log_print (alog);
    close (info->listen_fd6);
#ifndef ANDROID   /* android doesn't have pthread_cancel */
    pthread_cancel (info->thread6);
#endif /* ANDROID */
  }
  if (info->listen_fd4 >= 0) {
#ifdef DEBUG_EBADFD
snprintf (ebadbuf, EBADBUFS,
"listen_shutdown closing ipv4 listen socket %d\n", info->listen_fd6);
record_message (info->pipe_descriptor);
#endif /* DEBUG_EBADFD */
snprintf (alog->b, alog->s, "l s2 closing socket %d\n", info->listen_fd4); log_print (alog);
    close (info->listen_fd4);
#ifndef ANDROID   /* android doesn't have pthread_cancel */
    pthread_cancel (info->thread4);
#endif /* ANDROID */
  }
  FREE_NULL (info->fds);
  FREE_NULL (info->peers);
  FREE_NULL (info->reserved);
  FREE_NULL (info->reservation_times);
  FREE_NULL (info->used);
}

void listen_record_usage (struct listen_info * info, int fd)
{
  int i;
  if (info->counter + 1 == 0) {  /* wrap around of counter value */
    unsigned int decrement = info->counter - (info->counter / 16);
    printf ("wrapping around counter values, decrement %d\n", decrement);
    for (i = 0; i < info->num_fds; i++) {
      printf ("%d: %d", i, info->used [i]);
      if (decrement < info->used [i])
        info->used [i] -= decrement;
      else
        info->used [i] = 0;
      printf (" -> %d\n", info->used [i]);
    }
    info->counter = info->counter - decrement;
  }
  info->counter++;
  for (i = 0; i < info->num_fds; i++)
    if (info->fds [i] == fd)
      info->used [i] = info->counter;
}

/* send a message describing my peers */
/* index is a peer to avoid sending, since it is itself */
static void send_peer_message (int fd, struct listen_info * info, int index)
{
  if (info->num_fds <= 1)  /* no peers to send */
    return;
  int npeers = info->num_fds;
  if (npeers > 255)
    npeers = 255;
printf ("sending peer message with %d/%d peers\n", npeers, info->num_fds);
  unsigned int size = ALLNET_PEER_SIZE (0, npeers);
  unsigned int hsize = ALLNET_SIZE (0);
  unsigned int dsize = size - hsize;

  unsigned int psize;
  struct allnet_header * hp =
    create_packet (dsize, ALLNET_TYPE_MGMT, 1, ALLNET_SIGTYPE_NONE,
                   NULL, 0, NULL, 0, NULL, NULL, &psize);
  if (psize != size) {
    snprintf (alog->b, alog->s,
              "likely error: send_peer_message size %d, psize %d\n",
              size, psize);
    log_print (alog);
    printf ("likely error: send_peer_message size %d, psize %d\n", size, psize);
    exit (1);   /* for now -- this should never happen! 2014/02/26 */
  }

  char * buffer = (char *) hp;

  struct allnet_mgmt_header * mp =
    (struct allnet_mgmt_header *) (buffer + ALLNET_SIZE (hp->transport));
  mp->mgmt_type = ALLNET_MGMT_PEERS;

  struct allnet_mgmt_peers * mpp =
    (struct allnet_mgmt_peers *)
       (((char *) mp) + sizeof (struct allnet_mgmt_header));

  mpp->num_peers = 0;
  int i;
  for (i = 0; (i < info->num_fds) && (mpp->num_peers < 255); i++) {
    if ((i != index) && (info->peers [i].ip.ip_version != 0)) {
      struct internet_addr * iap = mpp->peers + ((mpp->num_peers)++);
      *iap = info->peers [i].ip;
      memset (iap->pad, 0, sizeof (iap->pad));
    }
  }
  /* use priority 0 since ignored on messages from a different machine */
  if (! send_pipe_message (fd, buffer, size, 0, alog))
    printf ("unable to send peer message (%d bytes) for %d peers\n",
            size, npeers);
}

/* if some fds are still available, return the next */
/* otherwise, return the index of the oldest FD, after closing it */
/* called with lock held */
/* if closing connection, send the list of peers before closing */
static int close_oldest_fd (struct listen_info * info)
{
  if (info->num_fds < info->max_num_fds)
    return info->num_fds++;
  int i;
  int min_index = 0;
  for (i = 1; i < info->num_fds; i++)
    if (info->used [i] < info->used [min_index])
      min_index = i;
  int fd = info->fds [min_index];
  /* we are closing this FD, tell the peer about others they may connect to */
  send_peer_message (fd, info, min_index);
  if (info->add_remove_pipe) {
    if (! remove_pipe (info->pipe_descriptor, fd)) {
      snprintf (alog->b, alog->s, "close_oldest_fd error removing %d\n", fd);
      log_print (alog);
    }
  }
#ifdef DEBUG_EBADFD
snprintf (ebadbuf, EBADBUFS,
"close_oldest_fd closing %d, a_r %d\n", fd, info->add_remove_pipe);
record_message (info->pipe_descriptor);
#endif /* DEBUG_EBADFD */
snprintf (alog->b, alog->s, "l cof closing socket %d\n", fd); log_print (alog);
  close (fd);
  info->fds [min_index] = -1;
  return min_index;
}

static void listen_get_reservation_with_lock_held (struct addr_info * ai,
                                                   struct listen_info * info)
{
  int i;
  unsigned long long int now = allnet_time_us ();
  unsigned long long int oldest = now; /* should be nothing older than now */
  int use_index = 0;
  struct addr_info zero;
  memset (&zero, 0, sizeof (zero));
  for (i = 0; i < info->max_num_fds; i++) {
    if (same_ai (info->reserved + i, &zero)) {
      use_index = i;
      break;
    }
    if (info->reservation_times [i] < oldest) {
      oldest = info->reservation_times [i];
      use_index = i;
    }
  }
  info->reserved [use_index] = *ai;
  info->reservation_times [use_index] = now;
}

static void listen_clear_reservation_with_lock_held (struct addr_info * ai,
                                                     struct listen_info * info)
{
  int i;
  for (i = 0; i < info->max_num_fds; i++) {
    if (same_ai (info->reserved + i, ai)) {
      memset (info->reserved + i, 0, sizeof (struct addr_info));
      info->reservation_times [i] = 0;
    }
  }
}

/* returns 1 if successfully added, 
           0 if addr != NULL and add_only_if_unique_ip and
                a matching address already had an fd */
static int listen_add_fd_with_lock_held (struct listen_info * info,
                                         int fd, struct addr_info * addr,
                                         int add_only_if_unique_ip,
                                         const char * caller_description)
{
  int index = -1;
  if (addr != NULL) {
    if (add_only_if_unique_ip) {
      int i;
      for (i = 0; i < info->num_fds; i++) {
        if (same_ai (info->peers + i, addr)) {
#ifdef DEBUG_PRINT
          printf ("found address at index %d ", i);
          print_addr_info (info->peers + i);
          printf ("     ");
          print_addr_info (addr);
#endif /* DEBUG_PRINT */
          if (alog != NULL) {
            char b1 [1000];
            char b2 [1000];
            addr_info_to_string (info->peers + i, b1, sizeof (b1));
            if ((strlen (b1) > 0) && (b1 [strlen (b1) - 1] == '\n'))
              b1 [strlen (b1) - 1] = '\0';  /* eliminate final newline */
            addr_info_to_string (addr, b2, sizeof (b2));
            snprintf (alog->b, alog->s,
                      "%s: unable to add fd %d %d/%d/%d dup %s =? %s",
                      caller_description, fd, i, info->num_fds, info->fds [i],
                      b1, b2);
            log_print (alog);
          }
          index = i;  /* found, replace it with new fd */
          break;
        }
      }
    }  /* clear any reservation on this address */
    listen_clear_reservation_with_lock_held (addr, info);
  }
  if (index < 0)
    index = close_oldest_fd (info);
  else {
    int cfd = info->fds [index];  /* fd to close */
    if (info->add_remove_pipe) {
      if (! remove_pipe (info->pipe_descriptor, cfd)) {
        snprintf (alog->b, alog->s, "listen_add_fd error removing %d\n", cfd);
        log_print (alog);
      }
    }
snprintf (alog->b, alog->s, "l a closing socket %d [%d], replacing with %d\n", cfd, index, fd); log_print (alog);
    close (cfd);  /* because replacing with the new one */
  }
  info->fds [index] = fd;
  if (addr != NULL)
    info->peers [index] = *addr;
  else   /* clear the address */
    memset (&(info->peers [index]), 0, sizeof (info->peers [index]));
  if (info->add_remove_pipe) {
    char * desc = strcat_malloc (caller_description,
                                 "/listen_add_fd_with_lock_held",
                                 "listen_add_fd_with_lock_held");
    add_pipe (info->pipe_descriptor, fd, desc);
    free (desc);
  }
#ifdef DEBUG_PRINT
  printf ("added %d: ", fd);
  print_listen_info (info);
#endif /* DEBUG_PRINT */
  return 1;
}

/* call to add an fd to the data structure */
/* may close the least recently active fd, and if so, */
/* sends the list of peers before closing */
/* returns 1 if successfully added, 
           0 if addr != NULL and add_only_if_unique_ip and
                a matching address already had an fd */
int listen_add_fd (struct listen_info * info, int fd, struct addr_info * addr,
                   int add_only_if_unique_ip,
                   const char * caller_description)
{
  pthread_mutex_lock (&(info->mutex));
  if ((info->num_fds >= info->max_num_fds) && (random () >= RAND_MAX / 2)) {
    /* if full, half the time just send a peer message and close the fd */
#ifdef LOG_PACKETS
printf ("closing incoming fd, %d %d\n", info->num_fds, info->max_num_fds);
#endif /* LOG_PACKETS */
    send_peer_message (fd, info, -1);
    pthread_mutex_unlock (&(info->mutex));
#ifdef DEBUG_EBADFD
snprintf (ebadbuf, EBADBUFS, "listen_add_fd busy, closing fd %d\n", fd);
record_message (info->pipe_descriptor);
#endif /* DEBUG_EBADFD */
snprintf (alog->b, alog->s, "l laf closing socket %d\n", fd); log_print (alog);
    close (fd);
    return 0;
  }
  int result =
    listen_add_fd_with_lock_held (info, fd, addr, add_only_if_unique_ip,
                                  caller_description);
  pthread_mutex_unlock (&(info->mutex));
  return result;
}

/* returns 1 if removed, 0 otherwise */
int listen_remove_fd (struct listen_info * info, int fd)
{
  int result = 0;
  pthread_mutex_lock (&(info->mutex));
  if (info->add_remove_pipe) {
    if (! remove_pipe (info->pipe_descriptor, fd)) {
      snprintf (alog->b, alog->s, "listen_remove_fd error removing %d\n", fd);
      log_print (alog);
    }
#ifdef DEBUG_EBADFD
    snprintf (ebadbuf, EBADBUFS, "listen_remove_fd removed_pipe (%d)\n", fd);
    record_message (info->pipe_descriptor);
#endif /* DEBUG_EBADFD */
  }
  int i;
  for (i = 0; i < info->num_fds; i++) {
    if (info->fds [i] == fd) {
      info->num_fds--;
      if (i < info->num_fds)
        info->fds [i] = info->fds [info->num_fds];
      result = 1;
      break;      /* assume any fd only appears once */
    }
  }
  pthread_mutex_unlock (&(info->mutex));
  return result;
}

/* returned addr_info is statically allocated (until remove_fd is called),
 * do not modify in any way.  Returns NULL for no match */
struct addr_info * listen_fd_addr (struct listen_info * info, int fd)
{
  struct addr_info * result = NULL;
  pthread_mutex_lock (&(info->mutex));
  int i;
  for (i = 0; i < info->num_fds; i++) {
    if (info->fds [i] == fd)
      result = info->peers + i;
  }
  pthread_mutex_unlock (&(info->mutex));
  return result;
}

/* mallocs and sets result to an n-element array of file descriptors
 * that are the best matches for the given destination */
/* returns the actual number of destinations found, or 0 */
int listen_top_destinations (struct listen_info * info, int max,
                             unsigned char * dest, int nbits,
                             int ** result)
{
  *result = NULL;
  if (info == NULL)
    return 0;
  if (max <= 0)
    return 0;
  pthread_mutex_lock (&(info->mutex));
  int start = 0;
  /* the first peer usually added is the socket fd for communication with ad,
   * and it has an all-zeros sockaddr.  It should not be returned */
  if ((info->num_fds > 0) && (max > 0) &&
      (info->peers [0].ip.ip_version != 4) &&
      (info->peers [0].ip.ip_version != 6))
    start = 1;
  if ((info->num_fds <= 0) || (info->num_fds <= start)) {
    pthread_mutex_unlock (&(info->mutex));
    return 0;
  }
  int available = info->num_fds - start; /* num_fds > start, so available > 0 */
  if (max >= available) {   /* return all, order does not matter */
    size_t size = available * sizeof (int);
    *result = memcpy_malloc (info->fds + start, (int)size,
                             "listen_top_destinations returning all");
    pthread_mutex_unlock (&(info->mutex));
#ifdef DEBUG_PRINT
    printf ("max %d >= available %d, result buffer is ", max, available);
    for (int i = 0; i < available; i++) printf ("%d, ", (*result) [i]);
    printf ("\n");
#endif /* DEBUG_PRINT */
    return available;
  }
/* max < available: loop through the peers to find the max best destinations */
  size_t bits_size = sizeof (int) * max;
  *result = malloc_or_fail (bits_size, "listen_top_destinations result");
  int * bits = malloc_or_fail (bits_size, "listen_top_destinations bits");
  int i;
  for (i = 0; i < max; i++)
    bits [i] = -1;
#ifdef DEBUG_PRINT
    printf ("max %d, available %d, dest %d bits ", max, available, nbits);
    print_buffer ((char *) dest, (nbits + 7) / 8, NULL, nbits, 1);
#endif /* DEBUG_PRINT */
  for (i = 0; i < available; i++) {
    int index = i + start;
    int r = matching_bits (info->peers [index].destination,
                           info->peers [index].nbits, dest, nbits);
#ifdef DEBUG_PRINT
    printf ("peers [%d], fd %d, matches %d/%d bits ", index, info->fds [index],
            r, info->peers [index].nbits);
    print_buffer ((char *)(info->peers [index].destination),
                  (info->peers [index].nbits + 7) / 8, NULL, 100, 1);
#endif /* DEBUG_PRINT */
    /* insert into result/bits if there is room or if it is a better match */
    if ((i <= max) || (bits [max - 1] < r)) {
      /* insertion sort, with r as the key, saved in bits */
      int j = ((i > max) ? (max - 1) : (i - 1));
      while (j >= 0) {
        if (bits [j] >= r) /* found the place to insert */
          break;
        (*result) [j + 1] = (*result) [j]; /* shift up to make room to insert */
        bits      [j + 1] = bits      [j];
        j--;
      }
      /* here, j == -1 or bits [j] >= r, and 0 <= j + 1 <= i and j + 1 <= max */
      (*result) [j + 1] = info->fds [index];  /* insert */
      bits      [j + 1] = r;
    }
  }
  free (bits);
  pthread_mutex_unlock (&(info->mutex));
#ifdef DEBUG_PRINT
  printf ("result buffer is ");
  for (i = 0; i < max; i++) printf ("%d, ", (*result) [i]);
  printf ("\n");
#endif /* DEBUG_PRINT */
  return max;
}

/* returns the socket number if already listening,
   returns -1 and reserves the address if nobody else had reserved it,
   returns -2 if someone had reserved the address already. */
int already_listening (struct addr_info * ai, struct listen_info * info)
{
  pthread_mutex_lock (&(info->mutex));
  int i;
  for (i = 0; i < info->num_fds; i++) {
    if (same_ai (info->peers + i, ai)) {
      pthread_mutex_unlock (&(info->mutex));
      return info->fds [i];
    }
  }
  for (i = 0; i < info->max_num_fds; i++) {
    if (same_ai (info->reserved + i, ai)) {
      pthread_mutex_unlock (&(info->mutex));
      return -2;   /* reserved by someone else */
    }
  }
  /* reserve, return -1 */
  listen_get_reservation_with_lock_held (ai, info);
  pthread_mutex_unlock (&(info->mutex));
  return -1;
}

void listen_clear_reservation (struct addr_info * ai, struct listen_info * info)
{
  pthread_mutex_lock (&(info->mutex));
  listen_clear_reservation_with_lock_held (ai, info);
  pthread_mutex_unlock (&(info->mutex));
}

