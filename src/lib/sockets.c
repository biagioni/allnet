/* manage sockets, mostly for use by ad and app_util */

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>
#include <assert.h>
#include <sys/select.h>

#include <netinet/in.h>

#include "sockets.h"
#include "packet.h"
#include "util.h"
#include "priority.h"
#include "ai.h"   /* same_sockaddr */

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
  int i = 3;
  i = i - i;  /* 0 */
    char * p = NULL;
  printf ("now crashing: %d\n", *p);
}

void print_sav (struct socket_address_validity * sav)
{
   int limit = (sav->alen == 16 ? 8 : 24);
   print_buffer ((char *) (&sav->addr), sav->alen, NULL, limit, 0);
   printf (", %lld/%lld, %lld, %d, %d/%d\n",
           sav->alive_rcvd, sav->alive_sent,
           sav->time_limit, sav->recv_limit, 
           sav->send_limit, sav->send_limit_on_recv); 
}

#ifdef DEBUG_SOCKETS
struct socket_set * debug_copy_socket_set (const struct socket_set * s)
{
  int si;
  int na = 0;
  for (si = 0; si < s->num_sockets; si++) {
    na += s->sockets [si].num_addrs;
  }
  char * p = malloc (sizeof (struct socket_set) +
                     s->num_sockets * sizeof (struct socket_address_set) +
                     na * sizeof (struct socket_address_validity));
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

void print_socket_set (struct socket_set * s)
{
  int si;
  for (si = 0; si < s->num_sockets; si++) {
    struct socket_address_set * sas = &(s->sockets [si]);
    printf ("socket %d/%d: sockfd %d, %s%s%s%d addrs\n",
            si, s->num_sockets, sas->sockfd,
            ((sas->is_local) ? "local, " : ""),
            ((sas->is_global_v6) ? "globalv6, " : ""),
            ((sas->is_global_v4) ? "globalv4, " : ""), sas->num_addrs);
    int ai;
    for (ai = 0; ai < sas->num_addrs; ai++) {
      struct socket_address_validity * sav = &(sas->send_addrs [ai]);
      printf ("  sav %d/%d: ", ai, sas->num_addrs);
      print_sav (sav);
    }
  }
}

void check_sav (struct socket_address_validity * sav, const char * desc)
{
  if ((sav->alen > sizeof (sav->addr)) ||
      (sav->alen < sizeof (struct sockaddr_in))) {
    printf ("%s: illegal alen ", desc);
    print_sav (sav);
    debug_crash ();
  }
}

static char * add_priority (const char * message, int msize, unsigned int p)
{
  int new_size = msize + 2;
  char * result = malloc_or_fail (new_size, "add_priority");
  memcpy (result, message, msize);
  writeb16 (result + msize, p);
  return result;
}

static int socket_sock_loop_locked (struct socket_set * s,
                                    socket_sock_loop_fun f, void * ref)
{
  int count = 0;
  int si;
  for (si = 0; si < s->num_sockets; si++) {
    struct socket_address_set * sas = &(s->sockets [si]);
    if (! f (sas, ref)) {  /* delete this element */
printf ("socket_sock_loop deleting socket %d\n", sas->sockfd);
      count++;
      /* compress the array to replace the deleted element */
      int sim;
      for (sim = si; sim + 1 < sas->num_addrs; sim++)
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
                              int is_global_v6, int is_global_v4)
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
  s->sockets [index].num_addrs = 0;
  s->sockets [index].send_addrs = NULL;
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
                int is_global_v6, int is_global_v4)
{
  lock ("socket_add");
  int result = socket_add_locked (s, socket, is_local,
                                  is_global_v6, is_global_v4);
  unlock ("socket_add");
  return result;
}
/* returns a pointer to the new sav, or NULL in case of errors (e.g.
 * if this address is already in the structure, or if the socket isn't) */
struct socket_address_validity *
  socket_address_add (struct socket_set * s,
                      struct socket_address_set * sock,
                      struct socket_address_validity addr)
{
  lock ("socket_address_add");
check_sav (&addr, "socket_address_add return value");
  struct socket_address_validity * result =
    socket_address_add_locked (s, sock, addr);
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
    print_sockaddr_str ((struct sockaddr *) &addr, alen, 0, st, sizeof (st));
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
check_sav (sav, "update_read");
    if (same_sockaddr (&sas, alen, &(sav->addr), sav->alen)) {  /* found! */
/* printf ("update_read %d found: ", sock->sockfd); print_sav(sav); */
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
                  const char * buffer, int rcvd)
{
  int is_local = sock->is_local;
  int delta = (is_local ? 2 : 0);    /* local packets have priority also */
  assert (rcvd >= ((ssize_t) (ALLNET_HEADER_SIZE + delta)));
  int msize = rcvd - delta;
  char * message = memcpy_malloc (buffer, msize, "sockets/record_message");
  int priority = (is_local ? readb16 (buffer + msize) : 1);
  int is_new = 0;
  int recv_limit_reached = 0;
  struct socket_address_validity * sav = NULL;
  update_read (sas, alen, sock, rcvd_time, &sav, &is_new, &recv_limit_reached);
if (! is_new) check_sav (sav, "update_read result");
  struct socket_read_result r =
    { .success = 1, .message = message, .msize = msize,
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
      /* all packets must have a min header, local packets also have priority */
      int min = ALLNET_HEADER_SIZE + ((sock->is_local) ? 2 : 0);
      if ((rcvd >= (ssize_t) min) && (rcvd <= sizeof (buffer)))
        return record_message (s, rcvd_time, sock, sas, alen, buffer, (int)rcvd);
      if (errno == ECONNREFUSED) {  /* connected socket was closed by peer */
        result.success = -1;    /* error on this socket */
        result.sock = sock;
      } else {
        perror ("get_message recvfrom");
        /* TODO: should we close the socket? */
      }
      break;
    }
  }
  unlock ("get_message");
  return result;
}

struct socket_read_result socket_read (struct socket_set * s,
                                       int timeout,
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
    /* always select for 1ms, since we are holding the lock */
    struct timeval tv = { .tv_sec = 0, .tv_usec = 1000 };
    int result = select (max_pipe, &receiving, NULL, NULL, &tv);
    if (result > 0)      /* found something, get_message unlocks global_mutex */
      return get_message (s, &receiving, rcvd_time, r);
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
  print_sockaddr_str ((struct sockaddr *) (&sas), alen, 0,
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
  /* no need to die for network or host unreachable or unavailable addrs */
  if ((e != ENETUNREACH) && (e != EHOSTUNREACH) &&
      (e != EADDRNOTAVAIL)) {
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
  int flags = 0;
#ifdef MSG_NOSIGNAL
  flags = MSG_NOSIGNAL;
#endif /* MSG_NOSIGNAL */
  ssize_t result = sendto (sockfd, message, msize, flags,
                           (struct sockaddr *) (&(sav->addr)), sav->alen);
  if (result == msize) {
    sav->alive_sent = sent_time;
    return 1;
  }
  char desc2 [1000];
  snprintf (desc2, sizeof (desc2), "%s send_on_socket", desc);
  /* some error, so the rest of this function is for debugging */
  send_error (message, msize, flags, (int)result,
              sav->addr, sav->alen, desc2, s, sockfd, sav, si, ai);
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
    if (send_on_socket (ssd->message, ssd->msize, ssd->sent_time,
                        sock->sockfd, sav, "socket_send_fun", NULL, -1, -1)) {
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
      printf ("socket_send_fun (%d) had an error, removing\n", sock->sockfd);
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
  struct socket_send_data ssd =
    { .message = add_priority (message, msize, priority), .msize = msize + 2,
      .sent_time = sent_time, .alen = alen, .local_not_remote = 1, .error = 0 };
  memset (&(ssd.except_to), 0, sizeof (ssd.except_to));
  if ((alen > 0) && (alen < sizeof (except_to)))
    memcpy (&(ssd.except_to), &(except_to), alen);
  socket_addr_loop (s, socket_send_fun, &ssd);
  if (ssd.error)
    return 0;
  return 1;
}

int socket_send_out (struct socket_set * s, const char * message, int msize,
                     unsigned long long int sent_time,
                     struct sockaddr_storage except_to, socklen_t alen)
{
  struct socket_send_data ssd =
    { .message = message, .msize = msize,
      .sent_time = sent_time, .alen = alen, .local_not_remote = 0, .error = 0 };
  memset (&(ssd.except_to), 0, sizeof (ssd.except_to));
  if ((alen > 0) && (alen < sizeof (except_to)))
    memcpy (&(ssd.except_to), &(except_to), alen);
  socket_addr_loop (s, socket_send_fun, &ssd);
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
  char * allocated = NULL;  /* local: copy message, then free after sending */
  if (sock->is_local) {
    allocated = add_priority (message, msize, priority);
    message = allocated;
    msize += 2;
  }
  int result = send_on_socket (message, msize, sent_time, sock->sockfd, addr,
                               "socket_send_to", NULL, -1, -1);
  if (allocated != NULL)
    free (allocated);
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
  int flags = 0;
#ifdef MSG_NOSIGNAL
  flags = MSG_NOSIGNAL;
#endif /* MSG_NOSIGNAL */
  ssize_t result = sendto (sockfd, message, msize, flags,
                           (struct sockaddr *) (&sas), alen);
  if (result == msize)
    return 1;
  char desc [1000];
  snprintf (desc, sizeof (desc), "%s socket_send_to_ip", debug);
  send_error (message, msize, flags, (int)result, sas, alen,
              desc, NULL, sockfd, NULL, -1, -1);
  return 0;
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
check_sav (sav, "socket_send_keepalives");
      long long int delta = ((sas->is_local) ? local : remote);
      if (sav->alive_sent + delta <= current_time) {
        if (send_on_socket (msg, size, current_time, sas->sockfd, sav,
                            "socket_send_keepalives", s, si, ai))
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
  if (socket_add (s, sockfd, is_local, is_global_v6, is_global_v4))
    return sockfd;
  if (! quiet) printf ("unable to add %d socket %d\n", sap->sa_family, sockfd);
  return -1;
}
