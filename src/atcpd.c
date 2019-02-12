/* atcpd.c: allnet TCP daemon, to maintain TCP connections */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <dirent.h>
#include <time.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>

#include "lib/packet.h"
#include "lib/media.h"
#include "lib/util.h"
#include "lib/app_util.h"
#include "lib/priority.h"
#include "lib/sha.h"
#include "lib/allnet_log.h"
#include "lib/cipher.h"
#include "lib/keys.h"
#include "lib/routing.h"

static struct allnet_log * alog = NULL;

/* format, defined up to version 3.3 is:
 * magic string, "MAGICPIE"  (8 bytes) -- magic pipe, squeezed into 8 chars
 * priority                  (4 bytes) -- not used, but part of format
 * length                    (4 bytes) -- big-endian order
 */
#define MAGIC_STRING		"MAGICPIE"
#define MAGIC_STRING_SIZE	8
#define PRIORITY_SIZE		4
#define LENGHT_SIZE		4
#define HEADER_FOR_TCP_SIZE    (MAGIC_STRING_SIZE + PRIORITY_SIZE + LENGHT_SIZE)

/* the first MAX_CONNECTIONS / 2 are ones that we open, i.e. connect.
 * The next  MAX_CONNECTIONS / 2 are ones that we accept. */
#define MAX_CONNECTIONS		64
#define BUFSIZE			(ALLNET_MTU + HEADER_FOR_TCP_SIZE)
static int tcp_fds [MAX_CONNECTIONS];
static char tcp_buffers [MAX_CONNECTIONS] [BUFSIZE];
static size_t tcp_bytes [MAX_CONNECTIONS];

struct atcp_thread_args {
  int running;   /* set to zero when the main thread terminates */
  int local_sock;
  pthread_mutex_t lock;
};

/* memmem is standard if _GNU_SOURCE is defined, but not otherwise */
/* invariant: returned value >= buffer, or is NULL */
static void * find_magic (char * buffer, size_t blen)
{
  while (blen >= MAGIC_STRING_SIZE) {
    if (memcmp (buffer, MAGIC_STRING, MAGIC_STRING_SIZE) == 0)
      return buffer;
    buffer++;
    blen--;
  }
  return NULL;
}

#if 0
static void * memmem (void * haystack, size_t haystacklen,
                      void * needle, size_t needlelen)
{
  if (haystacklen < needlelen)
    return NULL;
  int count = haystacklen - needlelen;
  int i;
  for (i = 0; i < count; i++)
    if (memcmp (haystack + count, needle, needlelen) == 0)
      return haystack + count;
  return NULL;
}
#endif /* 0 */

static void acquire (pthread_mutex_t * mutex, const char * message)
{
#ifdef DEBUG_PRINT
  printf ("~%s\n", message);
#endif /* DEBUG_PRINT */
  pthread_mutex_lock (mutex);
#ifdef DEBUG_PRINT
  printf ("+%s\n", message);
#endif /* DEBUG_PRINT */
}
static void release (pthread_mutex_t * mutex, const char * message)
{
  pthread_mutex_unlock (mutex);
#ifdef DEBUG_PRINT
  printf ("-%s\n", message);
#endif /* DEBUG_PRINT */
}

/* returns the number of bytes left in the buffer after processing */
/* if the buffer is full, removes at least 16 bytes from the buffer */
static size_t atcp_process (int fd, char * buffer, size_t bsize)
{
  if (bsize <= HEADER_FOR_TCP_SIZE)  /* no valid header or no data, continue */
    return bsize;
  if (memcmp (buffer, MAGIC_STRING, MAGIC_STRING_SIZE) == 0) {
    /* buffer starts with a valid header */
    unsigned long int length = readb32 (buffer + MAGIC_STRING_SIZE +
                                        PRIORITY_SIZE);
    if (length <= bsize) {   /* valid packet, send to ad */
      send (fd, buffer + HEADER_FOR_TCP_SIZE, length, MSG_DONTWAIT);
      if (length == bsize)   /* consumed everything */
        return 0;
      memmove (buffer, buffer + length, bsize - length);
      return bsize - length;
    }  /* else, length > bsize, continue to accept data */
    if (length <= ALLNET_MTU)  /* legal length > bsize, keep accumulating */
      return bsize;
    /* else: illegal length > MTU, look for the next header after
     * deleting the illegal one */
    bsize -= HEADER_FOR_TCP_SIZE;
    memmove (buffer, buffer + HEADER_FOR_TCP_SIZE, bsize);
  }  /* buffer does not begin with a magic string, look for one */
  if (bsize < MAGIC_STRING_SIZE)  /* nothing to do */
    return bsize;              /* if we do not return here, 8 <= bsize */
  /* find the magic string, if any -- it cannot be at the start of the buffer */
  char * magic = find_magic (buffer + 1, bsize - 1);
  if (magic == NULL)  /* save the last 7 bytes of the buffer */
    /* we know that bsize >= MAGIC_STRING_SIZE, so magic will be > buffer */
    magic = buffer + (bsize - (MAGIC_STRING_SIZE - 1)); /* magic=buf+bsize-7 */
  /* invariant: magic >= buffer (from the considerations above) */
  size_t delta = magic - buffer;
  /* invariant: 0 < delta <= bsize - 7          (given that 8 <= bsize)
     "if (magic is not NULL)", 8 < bsize, and 1 <= delta <= bsize - 8
     "if (magic == NULL)", sets delta to bsize - 7 (magic - buffer = bsize - 7):
     so 1 <= delta == bsize - 7. */
  size_t new_size = bsize - delta;
  /* invariant: 7 <= new_size < bsize */
  memmove (buffer, magic, new_size);
  return new_size;
}

/* receive from TCP, adding bytes to buffers until we have complete packets */
static void * atcp_recv_thread (void * arg)
{
  struct atcp_thread_args * args = ((struct atcp_thread_args *) arg);
  int local_sock = args->local_sock;
  char buffer [ALLNET_MTU + HEADER_FOR_TCP_SIZE];
  while (args->running) {   /* loop until main thread goes away */
    int i;
    acquire (&(args->lock), "r");
    for (i = 0; i < MAX_CONNECTIONS; i++) {
      if (tcp_fds [i] != -1) {
        ssize_t r = recv (tcp_fds [i], buffer, sizeof (buffer), MSG_DONTWAIT);
        if ((r < 0) && (errno != EAGAIN) && (errno != EWOULDBLOCK)) {
          if (errno == EBADF)
            close (tcp_fds [i]);
          tcp_fds [i] = -1;
        }
        if (r <= 0)
          continue;   /* got nothing, continue with the next fd */
        while (r > 0) {
          if (r + tcp_bytes [i] <= BUFSIZE) {
            memcpy (((char *) tcp_buffers [i]) + tcp_bytes [i], buffer, r);
            tcp_bytes [i] += r;
            r = 0;
          } else {  /* received bytes don't fit in buffer */
            memcpy (((char *) tcp_buffers [i]) + tcp_bytes [i], buffer,
                    BUFSIZE - tcp_bytes [i]);
            r -= BUFSIZE - tcp_bytes [i];
            tcp_bytes [i] = BUFSIZE;
          }
          tcp_bytes [i] = atcp_process (local_sock, tcp_buffers [i],
                                        tcp_bytes [i]);
        }
        break;   /* each time we lock, receive from at most one socket */
      }
    }
    release (&(args->lock), "r");
    usleep (30000);  /* sleep 1/30s */
  }
  return NULL;
}

static size_t atcp_make (const char * message, int msize, char * buffer)
{
  if ((msize <= 0) || (msize > ALLNET_MTU))
    return 0;
  memcpy (buffer, MAGIC_STRING, MAGIC_STRING_SIZE);
  writeb32 (buffer + MAGIC_STRING_SIZE, 0);  /* priority */
  writeb32 (buffer + MAGIC_STRING_SIZE + PRIORITY_SIZE, msize);
  memcpy (buffer + HEADER_FOR_TCP_SIZE, message, msize);
  return (msize + HEADER_FOR_TCP_SIZE);
}

/* returns true if this was a packet that we should not forward */
static int respond_to_keepalive (int fd, const char * message, int msize,
                                 struct sockaddr_storage addr)
{
  if (msize <= ALLNET_HEADER_SIZE)
    return 1;   /* not a valid packet */
  const struct allnet_header * hp = (const struct allnet_header *) message;
  if ((hp->message_type != ALLNET_TYPE_MGMT) ||
      (msize < ALLNET_MGMT_HEADER_SIZE (hp->transport)))
    return 0;   /* not a valid keepalive */
  const struct allnet_mgmt_header * mhp =
    (const struct allnet_mgmt_header *) (message + ALLNET_SIZE (hp->transport));
  if (mhp->mgmt_type != ALLNET_MGMT_KEEPALIVE)
    return 0;   /* not a valid keepalive */
  /* it is a valid keepalive.  Respond appropriately */
  static int skip = 0;   /* only respond to one out of every 4 keepalives */
  if (skip++ < 3)
    return 1;            /* because it is a valid keepalive */
  skip = 0;
  if (msize == ALLNET_MGMT_HEADER_SIZE (hp->transport)) {
    /* simple keepalive, send back the same */
    send (fd, message, msize, MSG_DONTWAIT);
    return 1;
  }
  char secret [KEEPALIVE_AUTHENTICATION_SIZE];
  static int initialized = 0;
  if (! initialized)
    random_bytes (secret, sizeof (secret));
  initialized = 1;
  const char * receiver_auth = NULL;
  if (msize >= ALLNET_MGMT_HEADER_SIZE (hp->transport) +
               KEEPALIVE_AUTHENTICATION_SIZE)
    receiver_auth = message + ALLNET_MGMT_HEADER_SIZE (hp->transport);
  char buffer [ALLNET_MTU];
  int send_len = keepalive_auth (buffer, sizeof (buffer), addr,
                                 secret, sizeof (secret), 1, receiver_auth);
  send (fd, buffer, send_len, MSG_DONTWAIT);
  return 1;
}

/* send most packets out on all the TCP connections, respond to keepalives */
static void atcp_handle_local_packet (int fd, const char * message, int msize,
                                      pthread_mutex_t * mutex,
                                      struct sockaddr_storage addr)
{
  /* do not forward keepalives.  Instead, respond to them */
  if (respond_to_keepalive (fd, message, msize, addr))
    return;
  /* not a keepalive, forward to all the valid tcp sockets */
  char buffer [ALLNET_MTU + HEADER_FOR_TCP_SIZE];
  size_t send_len = atcp_make (message, msize, buffer);
  acquire (mutex, "h");
  if (send_len > 0) {
    int i;
    for (i = 0; i < MAX_CONNECTIONS; i++) {
      if (tcp_fds [i] != -1) {
        if (send (tcp_fds [i], buffer, send_len, MSG_DONTWAIT) != send_len) {
          close (tcp_fds [i]);
          tcp_fds [i] = -1;
        }
      }
    }
  }
  release (mutex, "h");
}

static void * atcp_accept_thread (void * arg)
{
  struct atcp_thread_args * args = ((struct atcp_thread_args *) arg);
  int listen_socket = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (listen_socket < 0) {
    perror ("atcp_accept_thread socket");
    return NULL;
  }
  struct sockaddr_in sin = { .sin_family = AF_INET,
                             .sin_port = allnet_htons (ALLNET_PORT)};
  sin.sin_addr.s_addr = allnet_htonl (INADDR_ANY);
  if (bind (listen_socket, (struct sockaddr *) (&sin), sizeof (sin)) != 0) {
    perror ("atcp_accept_thread bind");
    sleep (240);  /* wait for long enough for the port to be released */
    if (bind (listen_socket, (struct sockaddr *) (&sin), sizeof (sin)) != 0) {
      perror ("atcp_accept_thread bind again");
      printf ("another atcpd already running, quitting this one\n");
      args->running = 0;
      return NULL;
    }
  }
  if (listen (listen_socket, 5) != 0) {
    perror ("atcp_accept_thread listen");
    return NULL;
  }
  while (args->running) {   /* loop until main thread goes away */
    struct sockaddr_storage sas;
    socklen_t alen = sizeof (sas);
    int new_socket = accept (listen_socket, (struct sockaddr *) &sas, &alen);
    if (new_socket >= 0) {  /* save the new socket */
      int i;
      int index = -1;
      acquire (&(args->lock), "a");  /* find a free fd slot, save the socket */
      for (i = MAX_CONNECTIONS / 2; i < MAX_CONNECTIONS; i++)
        if (tcp_fds [i] == -1)
          index = i;
      if (index < 0) {   /* no free fds, close a random connection */
        index = random_int (MAX_CONNECTIONS / 2, MAX_CONNECTIONS - 1);
        close (tcp_fds [index]);
        tcp_fds [index] = -1;
      }
      tcp_fds [index] = new_socket;
      release (&(args->lock), "a");
    }
  }
  return NULL;
}

static void * atcp_connect_thread (void * arg)
{
  struct atcp_thread_args * args = ((struct atcp_thread_args *) arg);
  routing_init_is_complete (1);
  struct sockaddr_storage addrs [MAX_CONNECTIONS / 2];
  socklen_t addr_lengths [MAX_CONNECTIONS / 2];
  /* since we never update the routing info, there is no point
   * in reading it more than once */
  unsigned char dest [ADDRESS_SIZE];
  memset (dest, 0, ADDRESS_SIZE);
  int sleep_time = KEEPALIVE_SECONDS;           /* initial interval */
  int n = routing_top_dht_matches (dest, 0, addrs, addr_lengths,
                                   MAX_CONNECTIONS / 2);
  if (n <= 0)
    printf ("atcp_connect_thread: no peers (%d) to connect to\n", n);
  if (n <= 0)
    return NULL;            /* nothing to connect to */
  while (args->running) {   /* loop until main thread goes away */
    acquire (&(args->lock), "c");
    unsigned long long int i = random_int (0, n - 1);
    if (tcp_fds [i] < 0) {   /* try to connect this random socket */
      struct sockaddr * sap = (struct sockaddr *) (addrs + i);
      int sock = socket (sap->sa_family, SOCK_STREAM, IPPROTO_TCP);
      if (sock < 0) {
perror ("atcpd TCP socket");
        snprintf (alog->b, alog->s, "atcpd unable to open TCP socket\n");
        log_print (alog);
      } else {
        if (connect (sock, sap, addr_lengths [i]) != 0) {
          snprintf (alog->b, alog->s, "atcpd unable to connect TCP socket\n");
          log_print (alog);
          close (sock);
        } else {  /* success! */
          tcp_fds [i] = sock;
        }
      }
    }
    release (&(args->lock), "c");
    sleep (sleep_time);
    sleep_time = sleep_time * 12 / 10;          /* gradual increase, 20%/loop */
#define MAX_SLEEP_TIME (KEEPALIVE_SECONDS * 24) /* try at least every 4min */
    if (sleep_time > MAX_SLEEP_TIME)
      sleep_time = MAX_SLEEP_TIME;
#undef MAX_SLEEP_TIME
  }
  return NULL;
}

static void * atcp_keepalive_thread (void * arg)
{
  struct atcp_thread_args * args = ((struct atcp_thread_args *) arg);
  int local_sock = args->local_sock;
  unsigned int size_to_send = 0;
  const char * packet = keepalive_packet (&size_to_send);
  while (args->running) {   /* loop until main thread goes away */
    send (local_sock, packet, size_to_send, MSG_DONTWAIT);
    sleep (KEEPALIVE_SECONDS);
  }
  return NULL;
}

static int local_socket ()
{
  int result = socket (AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (result < 0) {
    perror ("atcpd UDP socket");
    snprintf (alog->b, alog->s, "atcpd unable to open UDP port, exiting\n");
    log_print (alog);
    return -1;
  }
  struct sockaddr_in sin = { .sin_family = AF_INET,
                             .sin_port = allnet_htons (ALLNET_PORT)};
  sin.sin_addr.s_addr = allnet_htonl (INADDR_LOOPBACK);
  if (connect (result, (struct sockaddr *) (&sin), sizeof (sin)) != 0) {
    perror ("atcpd UDP connect");
    print_sockaddr ((struct sockaddr *) (&sin), sizeof (sin));
    snprintf (alog->b, alog->s, "atcpd unable to connect UDP port, exiting\n");
    log_print (alog);
    return -1;
  }
  return result;
}

void * atcpd_main (char * arg)
{
  alog = init_log ("atcpd");
  struct atcp_thread_args * thread_args =
    malloc_or_fail (sizeof (struct atcp_thread_args), "atcpd_main");
  thread_args->local_sock = local_socket ();
  int i;
  for (i = 0; i < MAX_CONNECTIONS; i++) {
    tcp_fds [i] = -1;
    tcp_bytes [i] = 0;
  }
  pthread_mutex_init (&(thread_args->lock), NULL);
  thread_args->running = 1;
  pthread_t thr;
  pthread_create (&thr, NULL, atcp_connect_thread, (void *) thread_args);
  pthread_create (&thr, NULL, atcp_recv_thread, (void *) thread_args);
  pthread_create (&thr, NULL, atcp_keepalive_thread, (void *) thread_args);
  pthread_create (&thr, NULL, atcp_accept_thread, (void *) thread_args);
  while (thread_args->running) {  /* loop until an error occurs */
    char buffer [ALLNET_MTU];
    struct sockaddr_storage sas;
    struct sockaddr * sap = (struct sockaddr *) (&sas);
    socklen_t addr_len = sizeof (sas);
    ssize_t r = recvfrom (thread_args->local_sock, buffer, sizeof (buffer), 0,
                          sap, &addr_len);
    if (r < 0) {   /* some error */
      snprintf (alog->b, alog->s, "atcpd pipe closed, restarting\n");
      log_print (alog);
      close (thread_args->local_sock);
      thread_args->local_sock = local_socket ();
    } else if (r > 0) {           /* got a packet */
      atcp_handle_local_packet (thread_args->local_sock, buffer, (int) r,
                                &(thread_args->lock), sas);
    }
  }
  snprintf (alog->b, alog->s, "keyd infinite loop ended, exiting\n");
  log_print (alog);
  return NULL;
}

