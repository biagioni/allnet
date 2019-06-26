/* manage sockets, mostly for use by ad and app_util */

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>
#include <assert.h>
#include <sys/select.h>

#include <netinet/in.h>
#include <fcntl.h>

#include "sockets.h"
#include "packet.h"
#include "util.h"
#include "priority.h"
#include "ai.h"   /* same_sockaddr */
#include "configfiles.h"
#include "routing.h"   /* print_dht */

#ifdef ALLNET_NETPACKET_SUPPORT
#include <linux/if_packet.h>  /* sockaddr_ll */
#endif /* ALLNET_NETPACKET_SUPPORT */

static pthread_mutex_t global_mutex = PTHREAD_MUTEX_INITIALIZER;

static void lock (const char * caller)
{
  pthread_mutex_lock (&global_mutex);
}

static void unlock (const char * caller)
{
  pthread_mutex_unlock (&global_mutex);
}

static void debug_crash ()
{
  char * p = NULL;
  printf ("now crashing: %d\n", *p);
}

void print_sav_to_fd (struct socket_address_validity * sav, int fd)
{
   int limit = (sav->alen == 16 ? 8 : 24);
   char large_buffer [10000];
   buffer_to_string ((char *) (&sav->addr), sav->alen, NULL, limit, 0,
                     large_buffer, sizeof (large_buffer));
   dprintf (fd, "%s", large_buffer);
   dprintf (fd, ", alive %lld/%lld, time %lld, rl %d, sl %d/%d",
           sav->alive_rcvd, sav->alive_sent,
           sav->time_limit, sav->recv_limit, 
           sav->send_limit, sav->send_limit_on_recv); 
   int ks = KEEPALIVE_AUTHENTICATION_SIZE;
   buffer_to_string (sav->keepalive_auth, ks, ", ka", 8, 0,
                     large_buffer, sizeof (large_buffer));
   if (memget (sav->keepalive_auth, 0, ks))
     dprintf (fd, "\n");
   else
     dprintf (fd, "%s\n", large_buffer);
}
void print_sav (struct socket_address_validity * sav)
{
  print_sav_to_fd (sav, STDOUT_FILENO);
}

#ifdef DEBUG_SOCKETS
struct socket_set * debug_copy_socket_set (const struct socket_set * s)
{
  int si;
  int na = 0;
  for (si = 0; si < s->num_sockets; si++) {
    na += s->sockets [si].num_addrs;
  }
  char * p = malloc_or_fail (sizeof (struct socket_set) +
                             s->num_sockets
                                * sizeof (struct socket_address_set) +
                             na * sizeof (struct socket_address_validity),
                             "debug_copy_socket_set");
  struct socket_set * res = (struct socket_set *) p;
  struct socket_address_set * sasp = (struct socket_address_set *)
    (p + sizeof (struct socket_set));
  struct socket_address_validity * savp = (struct socket_address_validity *)
    (p + sizeof (struct socket_set) +
     s->num_sockets * sizeof (struct socket_address_set));
  *res = *s;
  res->sockets = sasp;
  for (si = 0; si < s->num_sockets; si++) {
    res->sockets [si] = s->sockets [si];
    res->sockets [si].send_addrs = savp;
    savp += s->sockets [si].num_addrs;
    int ai;
    for (ai = 0; ai < res->sockets [si].num_addrs; ai++) {
      res->sockets [si].send_addrs [ai] = s->sockets [si].send_addrs [ai];
    }
  }
  return res;
}
#endif /* DEBUG_SOCKETS */

void print_socket_set_to_fd (struct socket_set * s, int fd)
{
  if (s == NULL) {
    printf ("NULL socket set\n");
    return;
  }
  int si;
  for (si = 0; si < s->num_sockets; si++) {
    struct socket_address_set * sas = &(s->sockets [si]);
    dprintf (fd, "socket %d/%d: sockfd %d, %s%s%s%s%d addrs\n",
             si, s->num_sockets, sas->sockfd,
             ((sas->is_local) ? "local, " : ""),
             ((sas->is_global_v6) ? "globalv6, " : ""),
             ((sas->is_global_v4) ? "globalv4, " : ""),
             ((sas->is_broadcast) ? "bc, " : ""), sas->num_addrs);  
    int ai;
    for (ai = 0; ai < sas->num_addrs; ai++) {
      struct socket_address_validity * sav = &(sas->send_addrs [ai]);
      dprintf (fd, "  sav %d/%d: ", ai, sas->num_addrs);
      print_sav_to_fd (sav, fd);
    }
  }
}

void print_socket_set (struct socket_set * s)
{
  print_socket_set_to_fd (s, STDOUT_FILENO);
}

void print_socket_global_addrs_to_fd (struct socket_set * s, int fd)
{
  int si;
  for (si = 0; si < s->num_sockets; si++) {
    struct socket_address_set * sas = &(s->sockets [si]);
    if ((sas->is_global_v6) || (sas->is_global_v4)) {
      int ai;
      for (ai = 0; ai < sas->num_addrs; ai++) {
        char buffer [10000];
        struct socket_address_validity * sav = &(sas->send_addrs [ai]);
        print_sockaddr_str ((struct sockaddr *) (&(sav->addr)), sav->alen,
                            buffer, sizeof (buffer));
        dprintf (fd, "%s\n", buffer);
      }
    }
  }
}
void print_socket_global_addrs (struct socket_set * s)
{
  print_socket_global_addrs_to_fd (s, STDOUT_FILENO);
}

void check_sav (struct socket_address_validity * sav, const char * desc)
{
  if ((sav->alen > sizeof (sav->addr)) ||
      (sav->alen < sizeof (struct sockaddr_in)) ||
      (sav->alen == 18)) {
    printf ("%s: illegal alen ", desc);
    print_sav (sav);
    debug_crash ();
  }
}

static void add_priority (const char * message, int msize, unsigned int p,
                          char * buffer, int bsize)
{
  int new_size = msize + 4;
  if (new_size > bsize) {
    printf ("add_priority error: new size %d = %d + 4 > buffer size %d\n",
            new_size, msize, bsize);
    exit (1);
  }
  memcpy (buffer, message, msize);
  writeb32 (buffer + msize, p);
}

static int socket_sock_loop_locked (struct socket_set * s,
                                    socket_sock_loop_fun f, void * ref)
{
  int count = 0;
  int si;
  for (si = 0; si < s->num_sockets; si++) {
    struct socket_address_set * sas = &(s->sockets [si]);
    if (! f (sas, ref)) {  /* delete this element */
#ifdef DEBUG_PRINT
      if (! sas->is_broadcast)
        printf ("deleting socket %d, l %d, 4 %d, 6 %d, b %d, %d addrs\n",
                sas->sockfd, sas->is_local, sas->is_global_v4,
                sas->is_global_v6, sas->is_broadcast, sas->num_addrs);
#endif /* DEBUG_PRINT */
      close (sas->sockfd);
      count++;
      /* compress the array to replace the deleted element */
      int sim;
      for (sim = si; sim + 1 < s->num_sockets; sim++)
        s->sockets [sim] = s->sockets [sim + 1];
      s->num_sockets--;
      si--;   /* so the loop does the next element, which is now at si */
    }
  }
  return count;
}
int socket_sock_loop (struct socket_set * s, socket_sock_loop_fun f, void * ref)
{
  lock ("socket_sock_loop");
  int result = socket_sock_loop_locked (s, f, ref);
  unlock ("socket_sock_loop");
  return result;
}

static int socket_addr_loop_locked (struct socket_set * s,
                                    socket_addr_loop_fun f, void * ref)
{
  int count = 0;
  int si;
  for (si = 0; si < s->num_sockets; si++) {
    struct socket_address_set * sas = s->sockets + si;
    int ai;
    for (ai = 0; ai < sas->num_addrs; ai++) {
      struct socket_address_validity * sav = sas->send_addrs + ai;
check_sav (sav, "socket_addr_loop");
      if (! f (sas, sav, ref)) {  /* delete this element */
#ifdef DEBUG_PRINT
        printf ("deleting address: ");
        print_sockaddr ((struct sockaddr *) &(sav->addr), sav->alen);
        printf ("\n");
#endif /* DEBUG_PRINT */
        count++;
        /* compress the array to replace the deleted element */
        int aim;
        for (aim = ai; aim + 1 < sas->num_addrs; aim++)
          sas->send_addrs [aim] = sas->send_addrs [aim + 1];
        sas->num_addrs--;
        ai--;   /* so the loop does the next element, which now is at ai */
      }
    }
  }
  return count;
}
int socket_addr_loop (struct socket_set * s, socket_addr_loop_fun f, void * ref)
{
  lock ("socket_addr_loop");
  int result = socket_addr_loop_locked (s, f, ref);
  unlock ("socket_addr_loop");
  return result;
}

/* return 1 if was able to add, and 0 otherwise (e.g. if already in the set) */
static int socket_add_locked (struct socket_set * s, int sockfd, int is_local,
                              int is_global_v6, int is_global_v4, int is_bc)
{
  int si;
  for (si = 0; si < s->num_sockets; si++)
    if (s->sockets [si].sockfd == sockfd)
      return 0;     /* already found */
  int index = s->num_sockets;
  s->num_sockets++;
  int size = s->num_sockets * sizeof (struct socket_address_set);
  s->sockets = realloc (s->sockets, size);
  s->sockets [index].sockfd = sockfd;
  s->sockets [index].is_local = is_local;
  s->sockets [index].is_global_v6 = is_global_v6;
  s->sockets [index].is_global_v4 = is_global_v4;
  s->sockets [index].is_broadcast = is_bc;
  s->sockets [index].num_addrs = 0;
  s->sockets [index].send_addrs = NULL;
  return 1;
}
/* returns a pointer to the new sav, or NULL in case of errors (e.g.
 * if this address is already in the structure, or if the socket isn't) */
static struct socket_address_validity *
  socket_address_add_locked (struct socket_set * s, int sockfd,
                             struct socket_address_validity addr)
{
  struct socket_address_set * sock = NULL;
  int si;
  for (si = 0; si < s->num_sockets; si++) {
    if (s->sockets [si].sockfd == sockfd) {
      sock = s->sockets + si;
      break;
    }
  }
  if (sock == NULL) {  /* not found */
    printf ("unable to add sav to socket %d, sockets are:\n", sockfd);
    print_socket_set (s);
    return NULL;
  }
  int ai;
  for (ai = 0; ai < sock->num_addrs; ai++) {
    struct socket_address_validity * sav = &(sock->send_addrs [ai]);
    check_sav (sav, "socket_address_add_locked");
    if (same_sockaddr (&(addr.addr), addr.alen, &(sav->addr), sav->alen))
      return NULL;  /* already there, no need to add */
  }
  int index = sock->num_addrs;
  sock->num_addrs++;
  int size = sock->num_addrs * sizeof (struct socket_address_validity);
  sock->send_addrs = realloc (sock->send_addrs, size);
  sock->send_addrs [index] = addr;
  check_sav (sock->send_addrs + index, "return value from saal");
  return sock->send_addrs + index;
}

/* return 1 if was able to add, and 0 otherwise (e.g. if already in the set) */
int socket_add (struct socket_set * s, int socket, int is_local,
                int is_global_v6, int is_global_v4, int is_bc)
{
  lock ("socket_add");
  int result = socket_add_locked (s, socket, is_local,
                                  is_global_v6, is_global_v4, is_bc);
  unlock ("socket_add");
  return result;
}
/* returns a pointer to the new sav, or NULL in case of errors (e.g.
 * if this address is already in the structure, or if the socket isn't) */
struct socket_address_validity *
  socket_address_add (struct socket_set * s, int sockfd,
                      struct socket_address_validity addr)
{
  lock ("socket_address_add");
check_sav (&addr, "socket_address_add return value");
  struct socket_address_validity * result =
    socket_address_add_locked (s, sockfd, addr);
  unlock ("socket_address_add");
  return result;
}

struct recv_limit_data {
  int updated;
  int new_recv_limit;
  struct sockaddr_storage addr;
  socklen_t alen;
};

static int update_recv_limit_fun (struct socket_address_set * sock,
                                  struct socket_address_validity * sav,
                                  void * ref)
{
  struct recv_limit_data * rld = (struct recv_limit_data *) ref;
  if (same_sockaddr (&(rld->addr), rld->alen, &(sav->addr), sav->alen)) {
    rld->updated = 1; /* found! */
    sav->recv_limit = rld->new_recv_limit;
  }
  return 1;   /* keep the record */
}

/* returns 1 if the receive limit was updated, 0 otherwise */
int socket_update_recv_limit (int new_recv_limit, struct socket_set * s,
                              struct sockaddr_storage addr, socklen_t alen)
{
#ifdef DEBUG_SOCKETS
struct socket_set * debug_copy = debug_copy_socket_set (s);
#endif /* DEBUG_SOCKETS */
  struct recv_limit_data rld =
    { .updated = 0, .new_recv_limit = new_recv_limit, .alen = alen };
  memcpy (&(rld.addr), &addr, sizeof (addr));
  int del = socket_addr_loop (s, update_recv_limit_fun, &rld);
  if (del != 0) {
    printf ("error: update_recv_limit deleted %d addrs\n", del);
    exit (1);
  }
  if (! rld.updated) {   /* likely error -- report for now */
    char st [1000];
    print_sockaddr_str ((struct sockaddr *) &addr, alen, st, sizeof (st));
    printf ("warning: update_recv_limit %s did not update any addresses\n", st);
    print_socket_set (s);
#ifdef DEBUG_SOCKETS
    printf ("  was:\n");
    print_socket_set (debug_copy);
#endif /* DEBUG_SOCKETS */
  }
#ifdef DEBUG_SOCKETS
  if (debug_copy != NULL) free (debug_copy);
#endif /* DEBUG_SOCKETS */
  return rld.updated;
}

static int update_time_fun (struct socket_address_set * sock,
                            struct socket_address_validity * sav,
                            void * ref)
{
  long long int new_time = * ((long long int *) ref);
check_sav (sav, "update_time_fun");
#ifdef DEBUG_PRINT
  char timestring [ALLNET_TIME_STRING_SIZE];
  allnet_localtime_string (allnet_time (), timestring);
  if (! ((sav->time_limit == 0) || (sav->time_limit >= new_time)))
    printf ("%s: update_time_fun deleting record, time_limit %lld <? %lld\n",
            timestring, sav->time_limit, new_time);
#endif /* DEBUG_PRINT */
  return ((sav->time_limit == 0) || (sav->time_limit >= new_time));
}

/* remove all socket addresses whose time is less than new_time.
 * return the number of records deleted */
int socket_update_time (struct socket_set * s, long long int new_time)
{
  return socket_addr_loop (s, update_time_fun, &new_time);
}

static void add_fd_to_bitset (fd_set * set, int fd, int * max)
{
  FD_SET (fd, set);
  if (fd >= *max)
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
                         long long int rcvd_time, int auth,
                         struct socket_address_validity ** savp,
                         int * is_new, int * recv_limit_reached)
{
  *savp = NULL;     /* in case we don't find it */
  *is_new = 1;      /* in case we don't find it */
  *recv_limit_reached = 0; /* in case we don't find it (and good default) */
  int i;
  for (i = 0; i < sock->num_addrs; i++) {
    struct socket_address_validity * sav = sock->send_addrs + i;
check_sav (sav, "update_read");
    if (same_sockaddr (&sas, alen, &(sav->addr), sav->alen)) {  /* found! */
/* printf ("update_read %d found: ", sock->sockfd); print_sav(sav); */
      *savp = sav;
      *is_new = 0;
      sav->alive_rcvd = rcvd_time;
      if (sav->recv_limit >= 1)
        sav->recv_limit--;
      *recv_limit_reached = (sav->recv_limit == 0);
      if ((sav->send_limit_on_recv != 0) && auth)
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
                  char * buffer, int rcvd, int auth)
{
  int is_local = sock->is_local;
  int delta = (is_local ? 4 : 0);    /* local packets have priority also */
  assert (rcvd >= ((ssize_t) (ALLNET_HEADER_SIZE + delta)));
  int msize = rcvd - delta;
  int priority = (is_local ? ((int) readb32 (buffer + msize)) : 1);
  int is_new = 0;
  int recv_limit_reached = 0;
  struct socket_address_validity * sav = NULL;
#ifdef ALLNET_NETPACKET_SUPPORT
/* received packets on AF_PACKET have a size that reflects actual
 * bytes of hardware address but can't be used for sending */
  if ((sas.ss_family == AF_PACKET) && (alen < sizeof (struct sockaddr_ll))) {
    char * ptr = (char *) (&sas);   /* clear the last few bytes */
    memset (ptr + alen, 0, sizeof (struct sockaddr_ll) - alen);
    alen = sizeof (struct sockaddr_ll);
  }
#endif /* ALLNET_NETPACKET_SUPPORT */
  update_read (sas, alen, sock, rcvd_time, auth,
               &sav, &is_new, &recv_limit_reached);
if (! is_new) check_sav (sav, "update_read result");
  struct socket_read_result r =
    { .success = 1, .message = buffer, .msize = msize,
      .priority = priority, .sock = sock, .alen = alen,
      .socket_address_is_new = is_new, .sav = sav,
      .recv_limit_reached = recv_limit_reached };
  memset (&(r.from), 0, sizeof (r.from));
  memcpy (&(r.from), &sas, alen);
if (! is_new) check_sav (r.sav, "record_message result");
  unlock ("record_message");
  return r;
}

/* returns the max parameter to pass to select */
/* called with the mutex locked, unlocks it before returning */
static struct socket_read_result
  get_message (struct socket_set * s, char * buffer, fd_set * set,
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
      ssize_t rcvd = recvfrom (sock->sockfd, buffer, SOCKET_READ_MIN_BUFFER,
                               MSG_DONTWAIT, sap, &alen);
      int save_errno = errno;
      /* all packets must have a min header, local packets also have priority */
      int min = ALLNET_HEADER_SIZE + ((sock->is_local) ? 4 : 0);
      if ((rcvd >= (ssize_t) min) && (rcvd <= SOCKET_READ_MIN_BUFFER)) {
#ifdef ALLNET_NETPACKET_SUPPORT
        /* special handling for 40-byte ack packets sent on ethernet,
         * which get padded with 0s out to 46 bytes */
        if ((sap->sa_family == AF_PACKET) && (rcvd == 46) &&
            (buffer [1] == ALLNET_TYPE_ACK) && (memget (buffer + 40, 0, 6)))
          rcvd = 40;
#endif /* ALLNET_NETPACKET_SUPPORT */
        int auth = ((sock->is_global_v4 || sock->is_global_v6) ?
                    is_auth_keepalive (sas, s->random_secret, 
                                       sizeof (s->random_secret), s->counter,
                                       buffer, (int)rcvd) : 1);
        sockets_log_sr (0, "socket_read", buffer, (int)rcvd, sap, alen, -100);
        return record_message (s, rcvd_time, sock, sas, alen,
                               buffer, (int)rcvd, auth);
      }
if (rcvd >= 0) printf ("received illegal message of size %zd\n", rcvd);
      if (rcvd >= 0)  /* try the next socket */
        continue;
      static int error_count = 0;
      if (error_count++ < 30)
        perror ("get_message recvfrom");
      if (error_count < 10) {
        if (save_errno == ENODEV) { /* not sure. 2019/02/13 */
          printf ("errno %d on socket %d\n", save_errno, sock->sockfd);
          print_socket_set (s);
        } else if (save_errno != ECONNREFUSED) {
          printf ("error number %d on socket %d\n", save_errno, sock->sockfd);
        }
      }
      if ((error_count >= 10) || (save_errno == ECONNREFUSED)) {
        /* ECONNREFUSED: connected socket closed by peer */
        result.success = 0;    /* error on this socket */
        result.sock = sock;
        int zero = 0; result.success = error_count / zero;  /* crash */
      }
      break;
    }
  }
  unlock ("get_message");
  return result;
}

/* the buffer must have length at least SOCKET_READ_MIN_BUFFER = ALLNET_MTU+4 */
struct socket_read_result socket_read (struct socket_set * s,
                                       char * buffer, int timeout,
                                       long long int rcvd_time)
{
  struct socket_read_result r = { .success = 0, .message = NULL, .msize = 0,
                                  .priority = 0, .sock = NULL, .alen = 0,
                                  .socket_address_is_new = 0,
                                  .sav = NULL, .recv_limit_reached = 0 };
  memset (&(r.from), 0, sizeof (r.from));
  int remaining_time = timeout;
  while ((timeout == SOCKETS_TIMEOUT_FOREVER) || (remaining_time > 0)) {
    lock ("socket_read");
    fd_set receiving;
    int max_pipe = make_fdset (s, &receiving);
    /* always select for 10ms, since we are holding the lock */
    struct timeval tv = { .tv_sec = 0, .tv_usec = 10000 };
    int result = select (max_pipe, &receiving, NULL, NULL, &tv);
    if (result > 0)      /* found something, get_message unlocks global_mutex */
      return get_message (s, buffer, &receiving, rcvd_time, r);
    unlock ("socket_read");
    /* sleep a little while so others have a chance to acquire the lock.
     * otherwise, linux will not grant the lock to others until it
     * can see if we immediately re-acquire the lock (I am guessing this
     * is to avoid a context switch) which however leads to starvation */
    usleep (1);
    if (result < 0) {    /* some error */
      if (errno != EINTR)   /* it is normal to be killed during select */
        perror ("select");
      r.success = -1;    /* error */
      return r;
    } /* else: timed out */
    if (remaining_time > 0) remaining_time--;
  }
  return r;
}

/* any of these may be null, si and ai set to -1 if they are not known. */
static void send_error (const char * message, int msize, int flags, int res,
                        const struct sockaddr_storage sas, socklen_t alen,
                        const char * desc, struct socket_set * s,
                        int sockfd, struct socket_address_validity * sav,
                        int si, int ai)
{
  int e = errno;  /* save the value of errno */
  const char * es = strerror (e);
  printf ("%s sendto: %d (%s)\n", desc, e, es);
  char desc_addr [1000] = "";
  print_sockaddr_str ((struct sockaddr *) (&sas), alen,
                      desc_addr, sizeof (desc_addr));
  void * p = NULL;
  int alen2 = 0;
  if (sav != NULL) {
    p = (&(sav->addr));
    alen2 = sav->alen;
  }
  printf ("sendto (%d, %p, %d, %d, %p (%s), %d/%d) => %d\n",
          sockfd, message, msize, flags, p, desc_addr, alen, alen2, res);
  if ((si >= 0) && (ai >= 0))
    printf ("si %d, ai %d:\n", si, ai);
  if (s != NULL)
    print_socket_set (s);
  if (sav != NULL)
    print_sav (sav);
  print_buffer (message, msize, "message", 32, 0);
  if (msize > 32)
    print_buffer (message + msize - 4, 4, "...", 4, 1);
  /* no need to die for network or host unreachable or unavailable addrs
   * or message too long */
  if ((e != ENETUNREACH) && (e != EHOSTUNREACH) &&
      (e != EADDRNOTAVAIL) && (e != EMSGSIZE)) {
    char * q = NULL;
    printf ("now crashing: %d\n", *q);
  }
}

/* returns 1 for success, 0 for error */
static int send_on_socket (const char * message, int msize,
                           unsigned long long int sent_time,
                           int sockfd, struct socket_address_validity * sav,
                           /* debugging information: */
                           const char * desc, struct socket_set * s,
                           /* si and ai set to -1 if they are not known */
                           int si, int ai)
{
check_sav (sav, "send_on_socket");
  struct sockaddr * sap = (struct sockaddr *) (&(sav->addr));
  int flags = 0;
#ifdef MSG_NOSIGNAL
  flags = MSG_NOSIGNAL;
#endif /* MSG_NOSIGNAL */
#ifdef TEST_TCP_ONLY
  if ((msize > 3) && ((message [2] & 0xff) > (message [3] & 0xff))) {
    print_buffer (message, msize, "send_on_socket sending bad hops", 10, 1);
    printf ("sleeping 100, pid %d, hops %d > %d\n", getpid (),
            message [2], message [3]);
    sleep (100);
    printf ("done sleeping 100, pid %d\n", getpid ());
  }
#endif /* TEST_TCP_ONLY */
  ssize_t result = sendto (sockfd, message, msize, flags, sap, sav->alen);
  sockets_log_sr (1, "send_on_socket", message, msize, sap, sav->alen, result);
  if (result == msize) {
    sav->alive_sent = sent_time;
    return 1;
  }
  if ((errno != EADDRNOTAVAIL) && (errno != ENETUNREACH) &&
      (errno != EHOSTUNREACH) && (errno != EHOSTDOWN)) {
    char desc2 [1000];
    snprintf (desc2, sizeof (desc2), "%s send_on_socket", desc);
    /* some error, so the rest of this function is for debugging */
    send_error (message, msize, flags, (int)result,
                sav->addr, sav->alen, desc2, s, sockfd, sav, si, ai);
    print_socket_set (s);
  }
  return 0;
}

struct socket_send_data {
  int local_not_remote;
  const char * message;
  int msize;
  unsigned long long int sent_time;
  struct sockaddr_storage except_to;
  socklen_t alen;
  int error;
  struct sockaddr_storage * sent_addrs;  /* may be NULL */
  int sent_num;
  int sent_available;
};

static int socket_send_fun (struct socket_address_set * sock,
                            struct socket_address_validity * sav,
                            void * ref)
{
  struct socket_send_data * ssd = (struct socket_send_data *) ref;
check_sav (sav, "socket_send_fun");
  if ((sock->is_local == ssd->local_not_remote) &&
      (! same_sockaddr (&(ssd->except_to), ssd->alen,
                        &(sav->addr), sav->alen))) {
#ifdef TEST_TCP_ONLY
    if ((! sock->is_local) &&
        (! is_loopback_ip ((struct sockaddr *) &(sav->addr), sav->alen)))
    return 1;  /* debugging: only send to local sockets */
#endif /* TEST_TCP_ONLY */
    if (send_on_socket (ssd->message, ssd->msize, ssd->sent_time,
                        sock->sockfd, sav, "socket_send_fun", NULL, -1, -1)) {
      if ((ssd->sent_addrs != NULL) && (ssd->sent_num < ssd->sent_available))
        ssd->sent_addrs [ssd->sent_num] = sav->addr;
      ssd->sent_num++;
      sav->alive_sent = ssd->sent_time;
      if (sav->send_limit > 0) {
        sav->send_limit--;
#ifdef DEBUG_SOCKETS
        if (sav->send_limit == 0) {
          printf ("socket_send_fun (%d) reached 0 send limit, removing: ",
                  sock->sockfd);
          print_sav(sav);
        }
#endif /* DEBUG_SOCKETS */
        if (sav->send_limit == 0)  /* reached send limit */
          return 0;   /* send limit expired, delete the address */
      }
    } else {
      ssd->error = 1;
#ifdef DEBUG_SOCKETS
      printf ("socket_send_fun (%d) had an error, removing\n", sock->sockfd);
#endif /* DEBUG_SOCKETS */
      return 0;   /* some error, delete the address */
    }
  }
  return 1;         /* do not delete */
}

/* socket_send_{local,remote} remove any address that has become invalid 
 * due to send limit.
 * return 1 for success, 0 for at least some error */
int socket_send_local (struct socket_set * s, const char * message, int msize,
                       unsigned int priority, unsigned long long int sent_time,
                       struct sockaddr_storage except_to, socklen_t alen)
{
  char buffer [ALLNET_MTU + 4];
  add_priority (message, msize, priority, buffer, sizeof (buffer));
  struct socket_send_data ssd =
    { .message = buffer, .msize = msize + 4,
      .sent_time = sent_time, .alen = alen, .local_not_remote = 1, .error = 0,
      .sent_addrs = NULL, .sent_available = 0, .sent_num = 0 };
  memset (&(ssd.except_to), 0, sizeof (ssd.except_to));
  if ((alen > 0) && (alen < sizeof (except_to)))
    memcpy (&(ssd.except_to), &(except_to), alen);
  socket_addr_loop (s, socket_send_fun, &ssd);
  if (ssd.error)
    return 0;
  return 1;
}

/* if sent_to and num_sent are not NULL, *num_sent should have the
 * number of available entries in sent_to.  These will be filled
 * with the addresses to which we send, and the number of these is
 * placed back in *num_sent */
int socket_send_out (struct socket_set * s, const char * message,
                     int msize, unsigned long long int sent_time,
                     struct sockaddr_storage except_to, socklen_t alen,
                     struct sockaddr_storage * sent_to, int * num_sent)
{
  struct socket_send_data ssd =
    { .message = message, .msize = msize,
      .sent_time = sent_time, .alen = alen, .local_not_remote = 0, .error = 0,
      .sent_addrs = sent_to, .sent_num = 0,
      .sent_available = ((num_sent != NULL) ? *num_sent : 0) };
  if (num_sent != NULL) *num_sent = 0;
  memset (&(ssd.except_to), 0, sizeof (ssd.except_to));
  if ((alen > 0) && (alen < sizeof (except_to)))
    memcpy (&(ssd.except_to), &(except_to), alen);
  socket_addr_loop (s, socket_send_fun, &ssd);
  if (num_sent != NULL) *num_sent = ssd.sent_num;
  if (ssd.error)
    return 0;
  return 1;
}

struct dec_send_limit_data {
  struct sockaddr_storage addr;
  socklen_t alen;
};

static int socket_dec_send_limit (struct socket_address_set * sock,
                                  struct socket_address_validity * sav,
                                  void * ref)
{
  struct dec_send_limit_data * dsld = (struct dec_send_limit_data *) ref;
check_sav (sav, "socket_dec_send_limit");
  if ((same_sockaddr (&(dsld->addr), dsld->alen, &(sav->addr), sav->alen)) &&
      (sav->send_limit > 0)) {
    sav->send_limit--;
#ifdef DEBUG_SOCKETS
    if (sav->send_limit == 0) {
      printf ("socket_dec_send_limit (%d) reached 0 send limit, removing: ",
      sock->sockfd);
      print_sav(sav);
    }
#endif /* DEBUG_SOCKETS */
    return (sav->send_limit != 0);
  }
  return 1;  /* keep the record: no match, or no limit */
}

/* send only to the given address, adding the priority if it is a local msg */
int socket_send_to (const char * message, int msize, unsigned int priority,
                    unsigned long long int sent_time,
                    struct socket_set * s, struct socket_address_set * sock,
                    struct socket_address_validity * addr)
{
check_sav (addr, "socket_send_to");
  lock ("socket_send_to");
  char buffer [ALLNET_MTU + 4]; /* local: copy message to the buffer */
  if (sock->is_local) {
    add_priority (message, msize, priority, buffer, sizeof (buffer));
    message = buffer;
    msize += 4;
  }
  int result = send_on_socket (message, msize, sent_time, sock->sockfd, addr,
                               "socket_send_to", NULL, -1, -1);
  struct dec_send_limit_data dsld = { .alen = addr->alen };
  memcpy (&(dsld.addr), &(addr->addr), sizeof (addr->addr));
  socket_addr_loop_locked (s, socket_dec_send_limit, &dsld);
  unlock ("socket_send_to");
  return result;
}

/* send to an address that may not even be in a socket set -- this is how
 * we can connect to new systems without receiving from them first */
int socket_send_to_ip (int sockfd, const char * message, int msize,
                       struct sockaddr_storage sas, socklen_t alen,
                       const char * debug)
{
  struct sockaddr * sap = (struct sockaddr *) (&sas);
  int flags = 0;
#ifdef MSG_NOSIGNAL
  flags = MSG_NOSIGNAL;
#endif /* MSG_NOSIGNAL */
#ifdef TEST_TCP_ONLY
  if ((msize > 3) && ((message [2] & 0xff) > (message [3] & 0xff))) {
    print_buffer (message, msize, "socket_send_to_ip sending bad hops", 10, 1);
    printf ("sleeping 100, pid %d, hops %d > %d\n",
            getpid (), message [2], message [3]);
    sleep (100);
    printf ("done sleeping 100, pid %d\n", getpid ());
  }
#endif /* TEST_TCP_ONLY */
  ssize_t result = sendto (sockfd, message, msize, flags,
                           (struct sockaddr *) (&sas), alen);
  sockets_log_sr (1, "send_to_ip", message, msize, sap, alen, result);
  if (result == msize)
    return 1;
  if (errno != ENETUNREACH) {
    char desc [1000];
    snprintf (desc, sizeof (desc), "%s socket_send_to_ip", debug);
    send_error (message, msize, flags, (int)result, sas, alen,
                desc, NULL, sockfd, NULL, -1, -1);
  }
  return 0;
}

/* send a keepalive to addresses whose sent time + local/remote <= current_time
 * returns the number of messages sent
 * if the keepalive is being sent through the internet,
 * sender and receiver authentications
 * are copied into each keepalive before it is sent
 * do NOT send keepalives to broadcast addresses */
int socket_send_keepalives (struct socket_set * s, long long int current_time,
                            long long int local, long long int remote)
{
  int count = 0;
  unsigned int msize;
  /* the basic keepalive, only sent to local processes */
  const char * message = keepalive_packet (&msize); /* small, w/o auth */
  char message_with_priority [ALLNET_MTU + 4];
  if (local)
    add_priority (message, msize, ALLNET_PRIORITY_EPSILON,
                  message_with_priority, sizeof (message_with_priority));
  int msize_local = msize + 4;
  int si;
  for (si = 0; si < s->num_sockets; si++) {
    struct socket_address_set * sas = &(s->sockets [si]);
    if (sas->is_broadcast)
      continue;
    /* size and msg refer to either message (above) or auth_msg (below) */
    const char * msg = message;
    int size = msize;
    if (sas->is_local) {
      msg = message_with_priority;
      size = msize_local;
    }
    int ai;
    for (ai = 0; ai < sas->num_addrs; ai++) {
      struct socket_address_validity * sav = &(sas->send_addrs [ai]);
check_sav (sav, "socket_send_keepalives");
      char auth_msg [ALLNET_MTU];
      if (sas->is_global_v4 || sas->is_global_v6) {
        /* an authenticating keepalive, specific to this destination */
        size = keepalive_auth (auth_msg, sizeof (auth_msg),
                               sav->addr, s->random_secret,
                               sizeof (s->random_secret), s->counter,
                               sav->keepalive_auth);
        msg = auth_msg;
      }
      if (send_on_socket (msg, size, current_time, sas->sockfd, sav,
                          "socket_send_keepalives", s, si, ai))
        count++;
    }
  }
  return count;
}

/* create a socket and bind it as appropriate for the given address
 * and add it to the given socket set
 * return the sockfd for success, -1 otherwise */
int socket_create_bind (struct socket_set * s, int is_local,
                        struct sockaddr_storage addr, socklen_t alen,
                        int quiet)
{
  struct sockaddr * sap = (struct sockaddr *) (&addr);
  int is_global_v6 = ((! is_local) && (sap->sa_family == AF_INET6));
  int is_global_v4 = ((! is_local) && (sap->sa_family == AF_INET));
  int sockfd = socket (sap->sa_family, SOCK_DGRAM, 0);
  if (sockfd < 0) {
    if (! quiet) perror ("socket_create_bind: socket");
    return -1;
  }
  if (bind (sockfd, sap, alen) != 0) {
    if (! quiet) perror ("socket_create_bind: bind");
    return -1;
  }
  if (socket_add (s, sockfd, is_local, is_global_v6, is_global_v4, 0))
    return sockfd;
  if (! quiet) printf ("unable to add %d socket %d\n", sap->sa_family, sockfd);
  return -1;
}

#if defined(LOG_PACKETS) || defined(LOG_STATE)
static int sockets_open_file (const char * name, int trunc)
{
  char * fname = NULL;
  if ((config_file_name ("log", name, &fname) <= 0) || (fname == NULL)) {
    printf ("unable to open file log/%s\n", name);
    return -1;
  }
  int flags = O_WRONLY | O_CREAT;
  if (trunc)
    flags |= O_TRUNC;
  else
    flags |= O_APPEND;
  int fd = open (fname, flags, 0644);
  if (fd < 0) {
    perror ("open");
    printf ("error opening %s (%s)\n", name, fname);
    free (fname);
    return -1;
  }
  free (fname);
  return fd;
}
#endif /* LOG_PACKETS || LOG_STATE */

/* use result -100 to say we don't know the result */ 
void sockets_log_sr (int sent_not_received, const char * debug,
                     const char * message, int msize,
                     const struct sockaddr * sent, int alen, ssize_t result)
{
#ifdef LOG_PACKETS
#ifndef LOG_EVEN_LOCAL_KEEPALIVES
  if ((msize == 36) || (msize == 32))
    return;
#endif /* LOG_EVEN_LOCAL_KEEPALIVES */
  struct timeval tv;
  gettimeofday (&tv, NULL);
  int milli = tv.tv_usec / 1000;
  char * ct = ctime (&(tv.tv_sec));
  char * now_day_hour = ct + 8;
  char * now_min_sec = ct + 14;
  now_min_sec [5] = '\0';
  char addr_str [1000];
  print_sockaddr_str (sent, alen, addr_str, sizeof (addr_str));
  const char * sr = (sent_not_received ? "sent" : "rcvd");
  const char * sr_tf = (sent_not_received ? "to" : "from");
  char fname [100] = "sent_rcvd.0102.txt";
  memcpy (fname + 10, now_day_hour, 2);
  if (fname [10] == ' ')
    fname [10] = '0';
  memcpy (fname + 12, now_day_hour + 3, 2);
  int fd = sockets_open_file (fname, 0);
  if (fd < 0)
    return;
  if (result != -100)
    dprintf (fd, "%s.%03d %s %s %d bytes %s %s => %zd\n",
             now_min_sec, milli, debug, sr, msize, sr_tf, addr_str, result);
  else
    dprintf (fd, "%s.%03d %s %s %d bytes %s %s\n",
             now_min_sec, milli, debug, sr, msize, sr_tf, addr_str);
  close (fd);
#endif /* LOG_PACKETS */
}

void sockets_log_addresses (const char * debug, struct socket_set * s,
                            const struct sockaddr_storage * addrs,
                            int num_addrs, int priority_threshold)
{
#ifdef LOG_STATE
  time_t now = time (NULL);
  char * now_day_hour = ctime (&now) + 8;
  char fname [100] = "state.0102.txt";
  memcpy (fname + 6, now_day_hour, 2);
  if (fname [6] == ' ')
    fname [6] = '0';
  memcpy (fname + 8, now_day_hour + 3, 2);
  int fd = sockets_open_file (fname, 1);
  if (fd < 0)
    return;
  dprintf (fd, "%s:\n", debug);
  if (priority_threshold != 0)
    dprintf (fd, "priority threshold: %08x\n", priority_threshold);
  dprintf (fd, "dht is:\n");
  print_dht (fd);
  dprintf (fd, "global addresses in sockets:\n");
  print_socket_global_addrs_to_fd (s, fd);
#define MAX_SAVED_ADDRS	1000
  static struct sockaddr_storage saved_addrs [MAX_SAVED_ADDRS];
  static int num_saved_addrs = 0;
  if ((num_addrs == -1) && (num_saved_addrs > 0)) {
    addrs = saved_addrs;
    num_addrs = num_saved_addrs;
  }
  if ((addrs != NULL) && (num_addrs > 0)) {
    if (addrs != saved_addrs)
      num_saved_addrs = 0;
    dprintf (fd, "send_out sent to %d addresses:\n", num_addrs);
    int i;
    for (i = 0; i < num_addrs; i++) {
      char buffer [10000];
      int alen = sizeof (struct sockaddr_storage);
      struct sockaddr * sap = (struct sockaddr *) (addrs + i);
      if (sap->sa_family == AF_INET)
        alen = sizeof (struct sockaddr_in);
      else if (sap->sa_family == AF_INET6)
        alen = sizeof (struct sockaddr_in6);
#ifdef ALLNET_NETPACKET_SUPPORT
      else if (sap->sa_family == AF_PACKET)
        alen = sizeof (struct sockaddr_ll);
#endif /* ALLNET_NETPACKET_SUPPORT */
      print_sockaddr_str (sap, alen, buffer, sizeof (buffer));
      dprintf (fd, "%s\n", buffer);
      if ((addrs != saved_addrs) && (num_saved_addrs < MAX_SAVED_ADDRS))
        saved_addrs [num_saved_addrs++] = addrs [i];
    }
  }
  print_socket_set_to_fd (s, fd);
  close (fd);
#undef MAX_SAVED_ADDRS
#endif /* LOG_STATE */
}
