/* manage sockets, mostly for use by ad */

#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>
#include <assert.h>
#include <sys/select.h>

#include "sockets.h"
#include "packet.h"
#include "util.h"
#include "priority.h"

static pthread_mutex_t global_mutex = PTHREAD_MUTEX_INITIALIZER;

static char * add_priority (const char * message, int msize, unsigned int p)
{
  int new_size = msize + 2;
  char * result = malloc_or_fail (new_size, "add_priority");
  memcpy (result, message, msize);
  writeb16 (result + msize, p);
  return result;
}

static int address_matches (struct sockaddr_storage * a, socklen_t alen,
                            struct sockaddr_storage * b, socklen_t blen)
{
  if (alen != blen)
    return 0;
  if (((struct sockaddr *) a)->sa_family != ((struct sockaddr *) b)->sa_family)
    return 0;
  if (memcmp (a, b, alen) == 0)
    return 1;
  return 0;
}

/* return 1 if was able to add, and 0 otherwise (e.g. if already in the set) */
static int socket_add_locked (struct socket_set * s, int sockfd, int is_local)
{
  int si;
  for (si = 0; si < s->num_sockets; si++)
    if (s->sockets [si].sockfd == sockfd)
      return 0;     /* already found */
  s->num_sockets++;
  int size = s->num_sockets * sizeof (struct socket_address_set);
  s->sockets = realloc (s->sockets, size);
  s->sockets [s->num_sockets - 1].sockfd = sockfd;
  s->sockets [s->num_sockets - 1].is_local = is_local;
  s->sockets [s->num_sockets - 1].num_addrs = 0;
  s->sockets [s->num_sockets - 1].send_addrs = NULL;
  return 1;
}
/* returns a pointer to the new sav, or NULL in case of errors (e.g.
 * if this address is already in the structure, or if the socket isn't) */
static struct socket_address_validity *
  socket_address_add_locked (struct socket_set * s,
                             struct socket_address_set * sock,
                             struct socket_address_validity addr)
{
  int ai;
  for (ai = 0; ai < sock->num_addrs; ai++) {
    struct socket_address_validity * sav = &(sock->send_addrs [ai]);
    if (address_matches (&(addr.addr), addr.alen, &(sav->addr), sav->alen))
{ print_buffer ((char *)&(addr.addr), addr.alen, "address", addr.alen, 0);
  print_buffer ((char *)&(sav->addr), sav->alen, " matches ", sav->alen, 1);
      return NULL;  /* already there, no need to add */
}
  }
  int index = sock->num_addrs;
  sock->num_addrs++;
  int size = sock->num_addrs * sizeof (struct socket_address_validity);
  sock->send_addrs = realloc (sock->send_addrs, size);
  sock->send_addrs [index] = addr;
  return sock->send_addrs + index;
}
static int socket_remove_locked (struct socket_set * s, int sockfd)
{
  int si;
  for (si = 0; si < s->num_sockets; si++) {
    if (s->sockets [si].sockfd == sockfd) {   /* found */
      if ((s->sockets [si].num_addrs > 0) &&
          (s->sockets [si].send_addrs != NULL))
        free (s->sockets [si].send_addrs);
      while (si < s->num_sockets) {   /* compress the array */
        s->sockets [si] = s->sockets [si + 1];
        si++;
      }
      s->num_sockets--;
      return 1;
    }
  }
  return 0;
}
static int socket_address_remove_locked (struct socket_set * s, int sockfd,
                                         struct sockaddr_storage addr,
                                         socklen_t alen)
{
  int si;
  for (si = 0; si < s->num_sockets; si++) {
    struct socket_address_set * sas = &(s->sockets [si]);
    if (sas->sockfd == sockfd) {   /* remove from here */
      int ai;
      for (ai = 0; ai < sas->num_addrs; ai++) {
        struct socket_address_validity * sav = &(sas->send_addrs [ai]);
        if (address_matches (&(addr), alen, &(sav->addr), sav->alen)) {
          while (ai < sas->num_addrs) {   /* compress the array */
            sas->send_addrs [ai] = sas->send_addrs [ai + 1];
            ai++;
          }
          sas->num_addrs--;
          return 1;
        }
      }
      return 0;  /* found socket, did not find address */
    }
  }
  return 0;
}
/* remove all socket addresses whose time is less than new_time */
/* returns the number of addresses removed */
static int socket_update_time_locked (struct socket_set * s,
                                       long long int new_time)
{
  int si;
  for (si = 0; si < s->num_sockets; si++) {
    struct socket_address_set * sas = &(s->sockets [si]);
    int ai;
    for (ai = 0; ai < sas->num_addrs; ai++) {
      struct socket_address_validity * sav = sas->send_addrs + ai;
      if ((sav->time_limit != 0) && (sav->time_limit < new_time)) {
        socket_address_remove_locked (s, sas->sockfd, sav->addr, sav->alen);
        /* also delete any other entries that have exceeded this time */
        /* do it with a recursive call, since indices have changed */
        return 1 + socket_update_time_locked (s, new_time);
      }
    }
  }
  return 0;
}
/* returns 1 if deleted the sav, 0 otherwise */
static int dec_sav_send_limit (struct socket_set * s, int sockfd,
                               struct socket_address_validity * sav)
{
  if (sav->send_limit > 0) {
    sav->send_limit--;
    if (sav->send_limit == 0)
      return socket_address_remove_locked (s, sockfd, sav->addr, sav->alen);
  }
  return 0;  /* no limit, or limit has not been exceeded */
}
/* return 1 if the socket address has been removed due to
 * exceeding send/receive limit, 0 otherwise, -1 for errors */
static int socket_dec_send_locked (struct socket_set * s, int sockfd,
                                   struct sockaddr_storage addr, socklen_t alen)
{
  int si;
  for (si = 0; si < s->num_sockets; si++) {
    struct socket_address_set * sas = &(s->sockets [si]);
    if (sas->sockfd == sockfd) {   /* remove from here */
      int ai;
      for (ai = 0; ai < sas->num_addrs; ai++) {
        struct socket_address_validity * sav = sas->send_addrs + ai;
        if (address_matches (&(addr), alen, &(sav->addr), sav->alen))
          return dec_sav_send_limit (s, sas->sockfd, sav);
      }
    }
  }
  return 0;
}
static int socket_dec_recv_locked (struct socket_set * s, int sockfd,
                                   struct sockaddr_storage addr, socklen_t alen)
{
  int si;
  for (si = 0; si < s->num_sockets; si++) {
    struct socket_address_set * sas = &(s->sockets [si]);
    if (sas->sockfd == sockfd) {   /* remove from here */
      int ai;
      for (ai = 0; ai < sas->num_addrs; ai++) {
        struct socket_address_validity * sav = sas->send_addrs + ai;
        if (address_matches (&(addr), alen, &(sav->addr), sav->alen)) {
          if (sav->recv_limit > 0) {
            sav->recv_limit--;
            if (sav->recv_limit == 0)
              return socket_address_remove_locked (s, sas->sockfd,
                                                   sav->addr, sav->alen);
          }
          return 0;  /* no limit, or limit has not been exceeded */
        }
      }
    }
  }
  return 0;
}

/* return 1 if was able to add, and 0 otherwise (e.g. if already in the set) */
int socket_add (struct socket_set * s, int socket, int is_local)
{
  pthread_mutex_lock (&global_mutex);
  int result = socket_add_locked (s, socket, is_local);
  pthread_mutex_unlock (&global_mutex);
  return result;
}
/* returns a pointer to the new sav, or NULL in case of errors (e.g.
 * if this address is already in the structure, or if the socket isn't) */
struct socket_address_validity *
  socket_address_add (struct socket_set * s,
                      struct socket_address_set * sock,
                      struct socket_address_validity addr)
{
  pthread_mutex_lock (&global_mutex);
  struct socket_address_validity * result =
    socket_address_add_locked (s, sock, addr);
  pthread_mutex_unlock (&global_mutex);
  return result;
}
int socket_remove (struct socket_set * s, int socket)
{
  pthread_mutex_lock (&global_mutex);
  int result = socket_remove_locked (s, socket);
  pthread_mutex_unlock (&global_mutex);
  return result;
}
int socket_address_remove (struct socket_set * s, int socket,
                           struct sockaddr_storage addr, socklen_t alen)
{
  pthread_mutex_lock (&global_mutex);
  int result = socket_address_remove_locked (s, socket, addr, alen);
  pthread_mutex_unlock (&global_mutex);
  return result;
}
/* remove all socket addresses whose time is less than new_time */
int socket_update_time (struct socket_set * s, long long int new_time)
{
  pthread_mutex_lock (&global_mutex);
  int result = socket_update_time_locked (s, new_time);
  pthread_mutex_unlock (&global_mutex);
  return result;
}
/* return 1 if the socket address has been removed due to
 * exceeding send/receive limit, 0 otherwise, -1 for errors */
int socket_dec_send (struct socket_set * s, int socket,
                     struct sockaddr_storage addr, socklen_t alen)
{
  pthread_mutex_lock (&global_mutex);
  int result = socket_dec_send_locked (s, socket, addr, alen);
  pthread_mutex_unlock (&global_mutex);
  return result;
}
int socket_dec_recv (struct socket_set * s, int socket,
                     struct sockaddr_storage addr, socklen_t alen)
{
  pthread_mutex_lock (&global_mutex);
  int result = socket_dec_recv_locked (s, socket, addr, alen);
  pthread_mutex_unlock (&global_mutex);
  return result;
}

static void add_fd_to_bitset (fd_set * set, int fd, int * max)
{
  FD_SET (fd, set);
  if (fd > *max)
    *max = fd + 1;
}
/* returns the max parameter to pass to select */
static int make_fdset (struct socket_set * s, fd_set * set)
{
  int i;
  int max_pipe = 0;
  FD_ZERO (set);
  for (i = 0; i < s->num_sockets; i++)
    add_fd_to_bitset (set, s->sockets [i].sockfd, &max_pipe);
  return max_pipe;
}

static void update_read (struct sockaddr_storage sas, socklen_t alen,
                         struct socket_address_set * sock,
                         long long int rcvd_time,
                         struct socket_address_validity ** savp,
                         int * is_new, int * recv_limit_reached)
{
  *savp = NULL;     /* in case we don't find it */
  *is_new = 1;      /* in case we don't find it */
  *recv_limit_reached = 0; /* in case we don't find it (and good default) */
  int i;
  for (i = 0; i < sock->num_addrs; i++) {
    struct socket_address_validity * sav = sock->send_addrs + i;
    if (address_matches (&sas, alen, &(sav->addr), sav->alen)) {  /* found! */
      *savp = sav;
      *is_new = 0;
      sav->alive_rcvd = rcvd_time;
      *recv_limit_reached = (sav->recv_limit == 1);
      if (sav->recv_limit > 1)
        sav->recv_limit--;
      if (sav->send_limit_on_recv != 0)
        sav->send_limit = sav->send_limit_on_recv;
      break;
    }
  }
}

/* called with the mutex locked, unlocks it before returning */
static struct socket_read_result
  record_message (struct socket_set * s, long long int rcvd_time,
                  struct socket_address_set * sock,
                  struct sockaddr_storage sas, socklen_t alen,
                  const char * buffer, ssize_t rcvd)
{
  int is_local = sock->is_local;
  int delta = (is_local ? 2 : 0);    /* local packets have priority also */
  if (rcvd < ((ssize_t) (ALLNET_HEADER_SIZE + delta)))
    printf ("error: rcvd %d, min %d + %d = %d\n", (int) rcvd,
            (int) ALLNET_HEADER_SIZE, delta, (int) ALLNET_HEADER_SIZE + delta);
  int msize = rcvd - delta;
  char * message = memcpy_malloc (buffer, msize, "sockets/get_message");
  int priority = (is_local ? readb16 (buffer + msize) : 1);
  int is_new = 0;
  int recv_limit_reached = 0;
  struct socket_address_validity * sav = NULL;
  update_read (sas, alen, sock, rcvd_time, &sav, &is_new, &recv_limit_reached);
  struct socket_read_result r =
    { .success = 1, .message = message, .msize = msize,
      .priority = priority, .sock = sock, .alen = alen,
      .socket_address_is_new = is_new, .sav = sav,
      .recv_limit_reached = recv_limit_reached };
  memset (&(r.from), 0, sizeof (r.from));
  memcpy (&(r.from), &sas, alen);
  pthread_mutex_unlock (&global_mutex);
  return r;
}

/* returns the max parameter to pass to select */
/* called with the mutex locked, unlocks it before returning */
static struct socket_read_result
  get_message (struct socket_set * s, fd_set * set,
               long long int rcvd_time,
               struct socket_read_result result)  /* result init'd by caller */
{
  int i;
  for (i = 0; i < s->num_sockets; i++) {
    struct socket_address_set * sock = s->sockets + i;
    if (FD_ISSET (sock->sockfd, set)) { 
      struct sockaddr_storage sas;
      struct sockaddr * sap = (struct sockaddr *) (&sas);
      socklen_t alen = sizeof (sas);
      char buffer [ALLNET_MTU + 2];  /* + 2 needed for local sockets */
      ssize_t rcvd = recvfrom (sock->sockfd, buffer, sizeof (buffer),
                                MSG_DONTWAIT, sap, &alen);
      if (rcvd > (ssize_t) (ALLNET_HEADER_SIZE + 2))
        return record_message (s, rcvd_time, sock, sas, alen, buffer, rcvd);
      perror ("get_message recvfrom");
printf ("get_message error %d receiving from socket %d\n", errno, sock->sockfd);
      /* TODO: should we close the socket? */
      break;
    }
  }
  pthread_mutex_unlock (&global_mutex);
  return result;
}

struct socket_read_result socket_read (struct socket_set * s,
                                       unsigned int timeout,
                                       long long int rcvd_time)
{
  struct socket_read_result r = { .success = 0, .message = NULL, .msize = 0,
                                  .priority = 0, .sock = NULL, .alen = 0,
                                  .socket_address_is_new = 0, .sav = NULL,
                                  .recv_limit_reached = 0 };
  memset (&(r.from), 0, sizeof (r.from));
  while (1) {
    pthread_mutex_lock (&global_mutex);
    fd_set receiving;
    int max_pipe = make_fdset (s, &receiving);
    /* set up the timeout, if any.  If timeout is zero, sleep for 10ms */
    struct timeval tv = { .tv_sec = timeout / 1000,
                          .tv_usec = 1000 * ((timeout != 0) ? (timeout % 1000)
                                                            : 10) };
    int result = select (max_pipe, &receiving, NULL, NULL, &tv);
    if (result > 0)      /* found something, get_message unlocks global_mutex */
      return get_message (s, &receiving, rcvd_time, r);
    pthread_mutex_unlock (&global_mutex);  /* allow other threads to execute */
    if (result < 0) {    /* some error */
      perror ("select");
      return r;
    } /* else: timed out */
    if (timeout != 0) /* can return, otherwise repeat */
      return r;
  }
  assert (0);  /* should never get here */
  return r;
}

static void send_on_socket (const char * desc, const char * message, int msize,
                            unsigned long long int sent_time,
                            int sockfd, struct socket_address_validity * sav)
{
  int flags = 0;
#ifdef MSG_NOSIGNAL
  flags = MSG_NOSIGNAL;
#endif /* MSG_NOSIGNAL */
  ssize_t result = sendto (sockfd, message, msize, flags,
                           (struct sockaddr *) (&(sav->addr)), sav->alen);
  if (result != msize) {
    char * desc2 = strcat_malloc (desc, " sendto", "send_on_socket");
    perror (message);
    printf ("%s: tried to send %d bytes to socket %d, sent %d, errno %d\n",
            desc2, msize, sockfd, (int) result, errno);
    free (desc2);
  } else {
    sav->alive_sent = sent_time;
  }
}

/* socket_send and socket_send_to may remove any address that has
 * become invalid due to send limit
 * send to all {local,nonlocal} except not to the given address
 * e.g. to send to all local, have local = 1, nonlocal = 0.
 *      to only send to all nonlocal, have local = 0, nonlocal = 1
 * priority is only sent with messages sent to local sockets */
int socket_send (struct socket_set * s, int local, int nonlocal,
                  const char * message, int msize, unsigned int priority,
                  unsigned long long int sent_time,
                  struct sockaddr_storage except_to, socklen_t alen)
{
  pthread_mutex_lock (&global_mutex);
  char * message_with_priority = NULL;
  if (local)
    message_with_priority = add_priority (message, msize, priority);
  int msize_local = msize + 2;
  int si;
  for (si = 0; si < s->num_sockets; si++) {
    struct socket_address_set * sas = s->sockets + si;
    const char * msg = message;
    int size = msize;
    if (sas->is_local) {
      msg = message_with_priority;
      size = msize_local;
    }
    if ((local && sas->is_local) || (nonlocal && (! sas->is_local))) {
      int ai;
      for (ai = 0; ai < sas->num_addrs; ai++) {
        struct socket_address_validity * sav = sas->send_addrs + ai;
        if (! address_matches (&except_to, alen, &(sav->addr), sav->alen)) {
          send_on_socket ("socket_send", msg, size,
                          sent_time, sas->sockfd, sav);
          sav->alive_sent = sent_time;
          /* dec_sav_send_limit may delete the sav, so should be called last */
          if (dec_sav_send_limit (s, sas->sockfd, sav))
            ai--; /* it was deleted, so look at this index again */
        }
      }
    }
  }
  if (local)
    free (message_with_priority);
  pthread_mutex_unlock (&global_mutex);
  return 1;
}

/* send only to the given address, adding the priority if it is a local msg */
int socket_send_to (const char * message, int msize, unsigned int priority,
                    unsigned long long int sent_time,
                    struct socket_address_set * sock,
                    struct socket_address_validity * addr)
{
  pthread_mutex_lock (&global_mutex);
  char * allocated = NULL;  /* message is const char *, so cannot be free'd */
  if (sock->is_local) {
    allocated = add_priority (message, msize, priority);
    message = allocated;
    msize += 2;
  }
  send_on_socket ("socket_send_to", message, msize,
                  sent_time, sock->sockfd, addr);
  if (allocated != NULL)
    free (allocated);
  pthread_mutex_unlock (&global_mutex);
  return 1;
}

/* send a keepalive to addresses whose sent time + local/remote <= current_time 
 * returns the number of messages sent */
int socket_send_keepalives (struct socket_set * s, long long int current_time,
                            long long int local, long long int remote,
                            const char * message, int msize)
{
  int count = 0;
  char * message_with_priority = NULL;
  if (local)
    message_with_priority =
      add_priority (message, msize, ALLNET_PRIORITY_EPSILON);
  int msize_local = msize + 2;
  int si;
  for (si = 0; si < s->num_sockets; si++) {
    struct socket_address_set * sas = &(s->sockets [si]);
    const char * msg = message;
    int size = msize;
    if (sas->is_local) {
      msg = message_with_priority;
      size = msize_local;
    }
    int ai;
    for (ai = 0; ai < sas->num_addrs; ai++) {
      struct socket_address_validity * sav = &(sas->send_addrs [ai]);
      long long int delta = ((sas->is_local) ? local : remote);
      if (sav->alive_sent + delta <= current_time) {
        send_on_socket ("socket_send_keepalives", msg, size,
                        current_time, sas->sockfd, sav);
        count++;
      }
    }
  }
  if (message_with_priority != NULL)
    free (message_with_priority);
  return count;
}

/* create a socket and bind it as appropriate for the given address
 * and add it to the given socket set
 * return 1 for success, 0 otherwise */
int socket_create_bind (struct socket_set * s, int is_local,
                        struct sockaddr_storage addr, socklen_t alen,
                        int quiet)
{
  struct sockaddr * sap = (struct sockaddr *) (&addr);
  int sockfd = socket (sap->sa_family, SOCK_DGRAM, 0);
  if (sockfd < 0) {
    if (! quiet) perror ("socket_create_bind: socket");
    return 0;
  }
  if (bind (sockfd, sap, alen) != 0) {
    if (! quiet) perror ("socket_create_bind: bind");
    return 0;
  }
  return socket_add (s, sockfd, is_local);
}

/* create a socket and connect it as appropriate for the given address
 * and add it to the given socket set
 * return 1 for success, 0 otherwise */
int socket_create_connect (struct socket_set * s, int is_local,
                           struct sockaddr_storage addr, socklen_t alen,
                           int quiet)
{
  struct sockaddr * sap = (struct sockaddr *) (&addr);
  int sockfd = socket (sap->sa_family, SOCK_DGRAM, 0);
  if (sockfd < 0) {
    if (! quiet) perror ("socket_create_connect: socket");
    return 0;
  }
  if (connect (sockfd, sap, alen) != 0) {
    if (! quiet) perror ("socket_create_connect: connect");
    return 0;
  }
  return socket_add (s, sockfd, is_local);
}
