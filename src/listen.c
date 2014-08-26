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
#include "lib/log.h"
#include "lib/ai.h"

/* returns the fd of the new listen socket, or -1 in case of error */
static int init_listen_socket (int version, int port, int local)
{
  int isip6 = (version == 6);
  int af = ((isip6) ? AF_INET6 : AF_INET);
  int fd = socket (af, SOCK_STREAM, 0);
  if (fd < 0) {
    perror ("listen socket");
    return -1;
  }
  /* allow us to reuse the port number immediately, rather than wait */
  int option = 1;
  if (setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof (int)) != 0)
    perror ("setsockopt");

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
  int n = snprintf (log_buf, LOG_SIZE, "binding to ");
  n += print_sockaddr_str (ap, addr_size, 1, log_buf + n, LOG_SIZE - n);
  log_print ();
  if (bind (fd, ap, addr_size) < 0) {
    if (version == 6) {
      perror ("bind");
      n = snprintf (log_buf, LOG_SIZE,
                    "ipv%d unable to bind %d/%x(%d), maybe already running\n",
                    version, ntohs (port), ntohs (port), addr_size);
      n += snprintf (log_buf + n, LOG_SIZE - n, "bind address is ");
      n += print_sockaddr_str (ap, addr_size, 1, log_buf + n, LOG_SIZE - n);
      log_print ();
    } else {
      snprintf (log_buf, LOG_SIZE,
                "ipv%d unable to bind to %d/%x(%d), probably handled by ipv6\n",
                version, ntohs (port), ntohs (port), addr_size);
      log_print ();
    }
    return -1;
  }
  /* specify the maximum queue length */
  if (listen (fd, 5) < 0) {
    perror("listen");
    return -1;
  }
  snprintf (log_buf, LOG_SIZE, "opened accept socket fd = %d, ip version %d\n",
            fd, version);
  log_print ();
  return fd;
}

struct real_arg {
  struct listen_info * info;   /* struct listen_info is defined in listen.h */
  int fd;  /* listen socket for opening new connections */
};

static void * listen_loop (void * arg)
{
  struct real_arg * ra = (struct real_arg *) arg;
  snprintf (log_buf, LOG_SIZE, "started listen_loop, listen socket is %d\n",
            ra->fd);
  log_print ();
  struct listen_info * info = ra->info;

  /* allow the main thread to kill this thread at any time */
  int notinteresting;
  pthread_setcanceltype (PTHREAD_CANCEL_ASYNCHRONOUS, &notinteresting);

  struct sockaddr_storage address;
  struct sockaddr     * ap   = (struct sockaddr     *) &address;
  socklen_t addr_size = sizeof (address);

  /* listen for connections, add them to the data structure */
  int connection;
  while ((connection = accept (ra->fd, ap, &addr_size)) >= 0) {
    int off = snprintf (log_buf, LOG_SIZE,
                        "opened connection socket fd = %d port %d from ",
                        connection, ntohs (info->port));
/* sometimes an incoming IPv4 connection is recorded as an IPv6 connection.
 * we want to record it as an IPv4 connection */
    standardize_ip (ap, addr_size);
#ifdef DEBUG_PRINT
    print_sockaddr_str (ap, addr_size, 1, log_buf + off, LOG_SIZE - off);
#else /* DEBUG_PRINT */
    snprintf (log_buf + off, LOG_SIZE - off, "\n");
#endif /* DEBUG_PRINT */
    log_print ();

    int option = 1;  /* disable Nagle algorithm if nodelay */
    if ((ra->info->nodelay) &&
        (setsockopt (connection, IPPROTO_TCP, TCP_NODELAY, &option,
                     sizeof (option)) != 0)) {
      snprintf (log_buf, LOG_SIZE, "unable to set nodelay socket option\n");
      log_print ();
    }

    struct addr_info addr;
    sockaddr_to_ai (ap, addr_size, &addr);
    listen_add_fd (info, connection, &addr);

    if (info->callback != NULL)
      info->callback (connection);

    addr_size = sizeof (address);  /* reset for next call to accept */
  }
  perror ("accept");
  printf ("error calling accept (%d)\n", ra->fd);
  return NULL;
}

void listen_init_info (struct listen_info * info, int max_fds, char * name,
                       int port, int local_only, int add_remove_pipe,
                       int nodelay, void (* callback) (int))
{
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
  info->port = port;
  info->add_remove_pipe = add_remove_pipe;
  info->num_fds = 0;
  info->max_num_fds = max_fds;
  info->fds = malloc_or_fail (max_fds * sizeof (int), "listen thread fds");
  info->peers = malloc_or_fail (max_fds * sizeof (struct addr_info),
                                "listen thread peers");
  info->used = malloc_or_fail (max_fds * sizeof (int), "listen thread used");
  info->callback = callback;
  info->nodelay = nodelay;
  int i;
  for (i = 0; i < max_fds; i++)
    info->fds [i] = info->used [i] = info->peers [i].ip.ip_version = 0;
  info->counter = 0;
  pthread_mutex_init (&(info->mutex), NULL);
  info->listen_fd6 = init_listen_socket (6, port, local_only);
  info->listen_fd4 = init_listen_socket (4, port, local_only);
  if (info->listen_fd6 < 0) {
    snprintf (log_buf, LOG_SIZE, "unable to open IPv6 listener, exiting\n");
    log_print ();
    exit (1);
  }
/*  ipv4 may be handled under ipv6
  if ((info->listen_fd4 < 0) || (info->listen_fd6 < 0)) {
    snprintf (log_buf, LOG_SIZE, "unable to open IPv6 listener, exiting\n");
    log_print ();
    exit (1);
  }
*/
  struct real_arg * real_arg6 =
    malloc_or_fail (sizeof (struct real_arg), "ip6 real arg");
  real_arg6->info = info;
  real_arg6->fd = info->listen_fd6;
  if (pthread_create (&(info->thread6), NULL, listen_loop, real_arg6) != 0) {
    perror ("listen6/pthread_create");
    snprintf (log_buf, LOG_SIZE,
              "unable to create listen thread for IP version 6, exiting\n");
    log_print ();
    exit (1);
  }
  if (info->listen_fd4 >= 0) {
  /* printf ("allocating %ld bytes for 4\n", sizeof (struct real_arg));  */
    struct real_arg * real_arg4 =
      malloc_or_fail (sizeof (struct real_arg), "ip4 real arg");
  /* printf ("allocated %ld bytes\n", sizeof (struct real_arg)); */
    real_arg4->info = info;
    real_arg4->fd = info->listen_fd4;
    if (pthread_create (&(info->thread4), NULL, listen_loop, real_arg4) != 0) {
      perror ("listen4/pthread_create");
      snprintf (log_buf, LOG_SIZE,
                "unable to create listen thread for IP version 4, exiting\n");
      log_print ();
      exit (1);
    }
  }
}

void listen_record_usage (struct listen_info * info, int fd)
{
  int i;
  if (info->counter + 1 == 0) {  /* wrap around of counter value */
    int decrement = info->counter - (info->counter / 16);
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
  int size = ALLNET_PEER_SIZE (0, npeers);
  int hsize = ALLNET_SIZE (0);
  int dsize = size - hsize;

  int psize;
  struct allnet_header * hp =
    create_packet (dsize, ALLNET_TYPE_MGMT, 1, ALLNET_SIGTYPE_NONE,
                   NULL, 0, NULL, 0, NULL, &psize);
  if (psize != size) {
    snprintf (log_buf, LOG_SIZE,
              "likely error: send_peer_message size %d, psize %d\n",
              size, psize);
    log_print ();
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
  /* set priority to 0 since ignored on messages from a different machine */
  if (! send_pipe_message (fd, buffer, size, 0))
    printf ("unable to send peer message for %d peers\n", npeers);
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
  send_peer_message (fd, info, min_index);
  if (info->add_remove_pipe)
    remove_pipe (fd);
  close (fd);
  info->fds [min_index] = -1;
  return min_index;
}

/* if closing connection, send the list of peers before closing */
void listen_add_fd (struct listen_info * info, int fd, struct addr_info * addr)
{
  if ((info->num_fds >= info->max_num_fds) && (random () >= RAND_MAX / 2)) {
    /* if full, half the time just send a peer message and close the fd */
    send_peer_message (fd, info, -1);
    close (fd);  /* never added the pipe, so no need to remove it */
  }
  pthread_mutex_lock (&(info->mutex));
  int index = close_oldest_fd (info);
  info->fds [index] = fd;
  if (addr != NULL)
    info->peers [index] = *addr;
  else
    info->peers [index].ip.ip_version = 0;
  if (info->add_remove_pipe)
    add_pipe (fd);
  pthread_mutex_unlock (&(info->mutex));
}

void listen_remove_fd (struct listen_info * info, int fd)
{
  pthread_mutex_lock (&(info->mutex));
  if (info->add_remove_pipe) {
    remove_pipe (fd);
    /* printf ("removed_pipe (%d)\n", fd); */
  }
  int i;
  for (i = 0; i < info->num_fds; i++) {
    if (info->fds [i] == fd) {
      info->num_fds--;
      if (i < info->num_fds)
        info->fds [i] = info->fds [info->num_fds];
      break;      /* assume any fd only appears once */
    }
  }
  pthread_mutex_unlock (&(info->mutex));
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

int already_listening (struct addr_info * ai, struct listen_info * info)
{
  int result = 0;
  pthread_mutex_lock (&(info->mutex));
  int i;
  for (i = 0; (i < info->num_fds) && (! result); i++) {
    if (same_ai (info->peers + i, ai))
      result = 1;
  }
  pthread_mutex_unlock (&(info->mutex));
  return result;
}


