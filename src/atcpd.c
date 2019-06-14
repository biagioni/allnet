/* atcpd.c: allnet TCP daemon, to maintain TCP connections */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <dirent.h>
#include <time.h>
#include <fcntl.h>
#include <errno.h>
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
#include "lib/ai.h"

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
static struct sockaddr_storage tcp_addrs [MAX_CONNECTIONS];

/* used to terminate the program if the keepalives stop */
static unsigned long long int last_udp_received_time = 0;

struct atcp_thread_args {
  int running;   /* set to zero when the main thread terminates */
  int local_sock;
  pthread_mutex_t lock;
  unsigned long long int last_keepalive_sent_time;
  char * authenticating_keepalive;
  unsigned int aksize;
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

/* if running becomes false, exit immediately, otherwise sleep */
static void sleep_while_running (struct atcp_thread_args * args, int ms)
{
  while ((args->running) && (ms > 0)) {
    usleep (10000);
    ms -= 10;
  }
}

/* returns 1 if an open connection to the new address is in tcp_addrs */
static int addr_in_list (struct sockaddr_storage * new_addr)
{
  int i;
  socklen_t new_len = sizeof (struct sockaddr_in);
  if (new_addr->ss_family == AF_INET6)
    new_len = sizeof (struct sockaddr_in6);
  for (i = 0; i < MAX_CONNECTIONS; i++) {
    if (tcp_fds [i] != -1) {
      socklen_t this_len = sizeof (struct sockaddr_in);
      if (tcp_addrs [i].ss_family == AF_INET6)
        this_len = sizeof (struct sockaddr_in6);
      if (same_sockaddr (new_addr, new_len, tcp_addrs + i, this_len))
        return 1;
    }
  }
  return 0;
}

static struct sockaddr_storage tcp_addrs [MAX_CONNECTIONS];

/* returns the number of bytes left in the buffer after processing */
/* if the buffer is full, removes at least 16 bytes from the buffer */
static size_t atcp_process (int fd, char * buffer, size_t bsize, int dbg)
{
  if (bsize > ALLNET_MTU + HEADER_FOR_TCP_SIZE) {  /* sanity check */
    printf ("error in atcp_process: bsize %zd\n", bsize);
    return 0;
  }
  while (bsize > HEADER_FOR_TCP_SIZE) {
    if (memcmp (buffer, MAGIC_STRING, MAGIC_STRING_SIZE) == 0) {
      /* buffer starts with a valid magic string.  Check the length */
      unsigned long int length = readb32 (buffer + MAGIC_STRING_SIZE +
                                          PRIORITY_SIZE);
      if ((length > ALLNET_HEADER_SIZE) && (length <= ALLNET_MTU)) {
        unsigned long int total = length + HEADER_FOR_TCP_SIZE;
        if (total > bsize)     /* we don't have all the data yet, */
          return bsize;        /* continue to receive new data */
        const char * message = buffer + HEADER_FOR_TCP_SIZE;
        char * errs = "unknown error";
        if (is_valid_message (buffer + HEADER_FOR_TCP_SIZE,
                              (unsigned int) length, &errs)) {
          /* valid length and valid message, send to ad */
          send (fd, message, length, 0);
          if (total == bsize)  /* consumed everything */
            return 0;
          /* else: move remaining bytes to front of the array */
          bsize -= total;
          memmove (buffer, buffer + total, bsize);
        } else {
          if (strcmp (errs, "expired packet") != 0) {
#undef DEBUG_FOR_DEVELOPER
#ifdef DEBUG_FOR_DEVELOPER
            printf ("atcpd fd %d bad %ld-byte message, %s, ", fd, length, errs);
            print_buffer (buffer, HEADER_FOR_TCP_SIZE, "header", 32, 0);
            printf ("  from: ");
            print_sockaddr ((struct sockaddr *) (tcp_addrs + dbg),
                            sizeof (struct sockaddr_storage));
            print_buffer (buffer + HEADER_FOR_TCP_SIZE, length, ", msg", 40, 0);
            printf ("\r\n");
#endif /* DEBUG_FOR_DEVELOPER */
          } /* invalid packet: delete the magic string, then look for another */
          bsize -= MAGIC_STRING_SIZE; /* remove magic string, try again */
          memmove (buffer, buffer + MAGIC_STRING_SIZE, bsize);
        }
      } else {  /* insane length, ignore: delete the magic string */
        bsize -= MAGIC_STRING_SIZE; /* remove magic string, try again */
        memmove (buffer, buffer + MAGIC_STRING_SIZE, bsize);
      } 
    } /* else: no magic string at start, search for it in what follows */
    /* find the first magic string in the buffer, if any */
    if (bsize >= MAGIC_STRING_SIZE) {
      char * magic = find_magic (buffer, bsize);
      if (magic == NULL) {   /* no magic string, keep the last 7 bytes */
        size_t new_size = MAGIC_STRING_SIZE - 1;
        size_t offset = bsize - new_size;
        memmove (buffer, buffer + offset, new_size);
        return new_size;               /* receive more data */
      }   /* else: found magic string, loop again */
      bsize -= (magic - buffer);
      memmove (buffer, magic, bsize);  /* then loop again */
    }
  }
  /* bsize <= HEADER_FOR_TCP_SIZE, return whatever size is left */
  return bsize;
}

/* receive from TCP, adding bytes to buffers until we have complete packets */
static void * atcp_recv_thread (void * arg)
{
  struct atcp_thread_args * args = ((struct atcp_thread_args *) arg);
  int local_sock = args->local_sock;
  while (args->running) {   /* loop until main thread goes away */
    int i;
    acquire (&(args->lock), "r");
    for (i = 0; i < MAX_CONNECTIONS; i++) {
      if (tcp_fds [i] != -1) {
        if (tcp_bytes [i] >= sizeof (tcp_buffers [i])) {
          /* == should be exceedingly rare, > should never happen */
          printf ("error: tcp_bytes [%d] is %zd >= %d (%zd)\n",
                  i, tcp_bytes [i], BUFSIZE, sizeof (tcp_buffers [i]));
          tcp_bytes [i] = atcp_process (local_sock, tcp_buffers [i],
                                        sizeof (tcp_buffers [i]), i);
        } else {
          char * p = &(tcp_buffers [i] [tcp_bytes [i]]);
          size_t free = sizeof (tcp_buffers [i]) - tcp_bytes [i];
unsigned long long int start = allnet_time ();
          ssize_t r = recv (tcp_fds [i], p, free, 0);
if (allnet_time () > start + 1)
printf ("receive took %lld seconds\n", allnet_time () - start);
          if (r > 0) {
            tcp_bytes [i] = atcp_process (local_sock, tcp_buffers [i],
                                          tcp_bytes [i] + r, i);
          } else if ((r < 0) && (errno != EAGAIN) && (errno != EWOULDBLOCK)) {
            if (errno == EBADF) {
#ifdef TEST_TCP_ONLY
printf ("receive error badf, closing socket %d to: ", tcp_fds [i]);
print_sockaddr ((struct sockaddr *) (tcp_addrs + i),
sizeof (struct sockaddr_storage)); printf ("\n");
#endif /* TEST_TCP_ONLY */
              close (tcp_fds [i]);
            }
            tcp_fds [i] = -1;
            tcp_bytes [i] = 0;
            memset (tcp_addrs + i, 0, sizeof (tcp_addrs [i]));
          }
        }
      }
    }
    release (&(args->lock), "r");
    sleep_while_running (args, 100);  /* sleep 1/10s */
  }
  printf ("%lld: atcpd_recv_thread %p ending\n", allnet_time (), arg);
  return NULL;
}

/* assumes buffer has length at least ALLNET_MTU + HEADER_FOR_TCP_SIZE */
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
static int respond_to_keepalive (struct atcp_thread_args * args,
                                 const char * message, int msize,
                                 struct sockaddr_storage addr)
{
/* print_buffer (message, msize, "respond_to_keepalive", 10, 1); */
  if (msize <= ALLNET_HEADER_SIZE)
    return 1;   /* not a valid packet */
  const struct allnet_header * hp = (const struct allnet_header *) message;
  if ((hp->message_type != ALLNET_TYPE_MGMT) ||
      (msize < ALLNET_MGMT_HEADER_SIZE (hp->transport)))
    return 0;   /* a valid message, but not a valid keepalive -- respond */
  const struct allnet_mgmt_header * mhp =
    (const struct allnet_mgmt_header *) (message + ALLNET_SIZE (hp->transport));
  if (mhp->mgmt_type != ALLNET_MGMT_KEEPALIVE)
    return 0;   /* a valid message, but not a valid keepalive -- respond */
  /* it is a valid keepalive.  Respond here if at all, and always return 1 */
  unsigned int hdr_size = ALLNET_MGMT_HEADER_SIZE (hp->transport);
  if (hdr_size != ALLNET_MGMT_HEADER_SIZE (0)) {
    printf ("possible error: header size %u (%d) != %zd\n",
            hdr_size, hp->transport, ALLNET_MGMT_HEADER_SIZE (0));
    return 1;
  }
  unsigned int min_size = hdr_size + KEEPALIVE_AUTHENTICATION_SIZE;
  unsigned int max_size = min_size + KEEPALIVE_AUTHENTICATION_SIZE;
  if (msize < min_size) {    /* simple keepalive, send back the same */
    printf ("unusual: atcpd responding to simple keepalive\n");
    send (args->local_sock, message, msize, 0);
    return 1;
  }
  acquire (&(args->lock), "q");
  if ((args->authenticating_keepalive == NULL) || (args->aksize < min_size) ||
      (args->last_keepalive_sent_time + KEEPALIVE_SECONDS <= allnet_time ())) {
    /* no authenticating keepalive sent in the last 10 seconds */
    args->last_keepalive_sent_time = allnet_time ();
    const char * ad_auth = message + hdr_size;
    if ((args->authenticating_keepalive == NULL) || (args->aksize < max_size)) {
      static char secret [KEEPALIVE_AUTHENTICATION_SIZE];
      static int initialized = 0;
      if (! initialized)
        random_bytes (secret, sizeof (secret));
      initialized = 1;
      args->authenticating_keepalive = malloc_or_fail (max_size, "atcpd rtk");
      args->aksize = keepalive_auth (args->authenticating_keepalive, max_size,
                                     addr, secret, sizeof (secret), 1,
                                     ad_auth);
    }
    char * auth = args->authenticating_keepalive + min_size;
    if (memcmp (ad_auth, auth, KEEPALIVE_AUTHENTICATION_SIZE) != 0) {
print_buffer (auth, KEEPALIVE_AUTHENTICATION_SIZE, "ad changed auth", 32, 1);
print_buffer (ad_auth, KEEPALIVE_AUTHENTICATION_SIZE, "to", 32, 1);
      memcpy (auth, ad_auth, KEEPALIVE_AUTHENTICATION_SIZE);
    }
    send (args->local_sock, args->authenticating_keepalive, args->aksize, 0);
  }
  release (&(args->lock), "q");
  return 1;
}

/* send most packets out on all the TCP connections, respond to keepalives */
static void atcp_handle_local_packet (struct atcp_thread_args * args,
                                      const char * message, int msize,
                                      struct sockaddr_storage addr)
{
  /* do not forward keepalives.  Instead, respond to them */
  if (respond_to_keepalive (args, message, msize, addr))
    return;
/* printf ("not a keepalive\n"); */
  /* not a keepalive, forward to all the valid tcp sockets */
  char buffer [ALLNET_MTU + HEADER_FOR_TCP_SIZE];
  size_t send_len = atcp_make (message, msize, buffer);
  acquire (&(args->lock), "h");
  if (send_len > 0) {
    int i;
    for (i = 0; i < MAX_CONNECTIONS; i++) {
      if (tcp_fds [i] != -1) {
        size_t sent = 0;
        if ((sent = send (tcp_fds [i], buffer, send_len, 0)) != send_len) {
#ifdef TEST_TCP_ONLY
printf ("send error %zd != %zd, closing socket to: ", send_len, sent);
print_sockaddr ((struct sockaddr *) (tcp_addrs + i),
sizeof (struct sockaddr_storage)); printf ("\n");
#endif /* TEST_TCP_ONLY */
          close (tcp_fds [i]);
          tcp_fds [i] = -1;
          tcp_bytes [i] = 0;
          memset (tcp_addrs + i, 0, sizeof (tcp_addrs [0]));
        }
      }
    }
  }
  release (&(args->lock), "h");
}

static void make_socket_nonblocking (int fd, const char * desc)
{
  char err_buf [1000];
  snprintf (err_buf, sizeof (err_buf), "%s fcntl (%d, F_GETFL)", desc, fd);
  int flags = fcntl (fd, F_GETFL);
  if (flags == -1) {
    perror (err_buf);
    return;
  }
  flags |= O_NONBLOCK;
  snprintf (err_buf, sizeof (err_buf), "%s fcntl (%d, F_SETFL, %04x)",
            desc, fd, flags);
  if (fcntl (fd, F_SETFL, flags) != 0)
    perror (err_buf);
}

/* select IPv4 the first time called, IPv6 the second time.
 * return the address family, or 0 for errors */
static int atcp_accept_common (struct atcp_thread_args * args,
                               struct sockaddr_storage * addr,
                               socklen_t * alen, char ** ipv)
{
  static int count = 0;
  int result = 0;
  memset (addr, 0, sizeof (struct sockaddr_storage));
  *alen = 0;
  *ipv = "not IP";
  acquire (&(args->lock), "x");
  if (count == 1) {
    struct sockaddr_in * sin = (struct sockaddr_in *) addr;
    sin->sin_family = AF_INET;
    sin->sin_addr.s_addr = allnet_htonl (INADDR_ANY);
    sin->sin_port = allnet_htons (ALLNET_PORT);
    *alen = sizeof (struct sockaddr_in);
    *ipv = "IPv4";
    result = AF_INET;
  } else if (count == 0) {
    struct sockaddr_in6 * sin = (struct sockaddr_in6 *) addr;
    sin->sin6_family = AF_INET6;
    sin->sin6_addr = in6addr_any;
    sin->sin6_port = allnet_htons (ALLNET_PORT);
    *alen = sizeof (struct sockaddr_in6);
    *ipv = "IPv6";
    result = AF_INET6;
  } /* else: result is 0 */
  count++;
  release (&(args->lock), "x");
  return result;
}

static void perror2 (const char * first, const char * second)
{
  char buffer [1000];
  snprintf (buffer, sizeof (buffer), "%s (%s)", first, second);
  perror (buffer);
}

static void * atcp_accept_thread (void * arg)
{
  static int success = 0;
  struct atcp_thread_args * args = ((struct atcp_thread_args *) arg);
  struct sockaddr_storage addr;
  socklen_t balen;  /* address length for the binding address */
  char * ipv = "unknown";
  int af = atcp_accept_common (args, &addr, &balen, &ipv);
  struct sockaddr * sap = (struct sockaddr *) &addr;
  if (af == AF_INET)  /* wait 10s for IPv6 to succeed */
    sleep_while_running (args, 10000);
  int listen_socket = socket (af, SOCK_STREAM, IPPROTO_TCP);
  if (listen_socket < 0) {
    perror2 ("atcp_accept_thread socket", ipv);
    return NULL;
  }
  if (bind (listen_socket, sap, balen) != 0) {
    if (! success)
      perror2 ("atcp_accept_thread bind", ipv);
    /* wait 240s, long enough for the port to be released
     * ipv4 should be 10s behind ipv6, to give it a chance to succeed first */
    sleep_while_running (args, 240000);
    if (bind (listen_socket, sap, balen) != 0) {
      if (! success)
        perror2 ("atcp_accept_thread bind again", ipv);
      if ((af == AF_INET) && (! success)) {
        printf ("another atcpd already running, quitting this one\n");
        args->running = 0;
      }
      close (listen_socket);
      return NULL;
    } else printf ("second bind successful\n");
  }
  success = 1;  /* to be seen by the other thread */
  if (listen (listen_socket, 5) != 0) {
    perror2 ("atcp_accept_thread listen", ipv);
    return NULL;
  }
  make_socket_nonblocking (listen_socket, "accept_thread listen_socket");

  while (args->running) {   /* loop until main thread goes away */
    struct sockaddr_storage sas;
    socklen_t aalen = sizeof (sas);  /* length of accept address */
    int new_socket = accept (listen_socket, (struct sockaddr *) &sas, &aalen);
    if ((new_socket >= 0) && (! addr_in_list (&sas))) {/* save the new socket */
#ifdef TEST_TCP_ONLY
printf ("accepted connection from: ");
print_sockaddr ((struct sockaddr *) &sas, aalen); printf ("\n");
#endif /* TEST_TCP_ONLY */
      make_socket_nonblocking (new_socket, "accept_thread new_socket");
      int i;
      int index = -1;
      acquire (&(args->lock), "a"); /* find a free fd slot, save the socket */
      for (i = MAX_CONNECTIONS / 2; i < MAX_CONNECTIONS; i++)
        if (tcp_fds [i] == -1)
          index = i;
      if (index < 0) {   /* no free fds, close a random connection */
        index = (int) (random_int (MAX_CONNECTIONS / 2, MAX_CONNECTIONS - 1));
#ifdef TEST_TCP_ONLY
printf ("accept randomly closing socket to: ");
print_sockaddr ((struct sockaddr *) (tcp_addrs + index),
sizeof (struct sockaddr_storage)); printf ("\n");
#endif /* TEST_TCP_ONLY */
        close (tcp_fds [index]);
        tcp_fds [index] = -1;
      }
      tcp_fds [index] = new_socket;
      tcp_bytes [index] = 0;
      memcpy (tcp_addrs + index, &sas, aalen);
      release (&(args->lock), "a");
    } else if (new_socket >= 0) {  /* address is in the list */
#ifdef TEST_TCP_ONLY
printf ("refusing connection, address already in list: ");
print_sockaddr ((struct sockaddr *) &sas, aalen); printf ("\n");
#endif /* TEST_TCP_ONLY */
      close (new_socket);
      sleep_while_running (args, 1000);
    } else if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) {
      sleep_while_running (args, 1000);
    } else {
      perror2 ("atcpd accept", ipv);
      args->running = 0;
    }
  }
  printf ("%lld: atcpd_accept_thread %p ending\n", allnet_time (), arg);
  close (listen_socket);
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
  sleep_time = 2;
  int n = routing_top_dht_matches (dest, 0, addrs, addr_lengths,
                                   MAX_CONNECTIONS / 2);
#ifdef TEST_TCP_ONLY
printf ("atcp_connect_thread: %d peers\n", n);
#endif /* TEST_TCP_ONLY */
  if (n <= 0)
    printf ("atcp_connect_thread: no peers (%d) to connect to\n", n);
  if (n <= 0)
    return NULL;            /* nothing to connect to */
  int count = 0;
  while (args->running) {   /* loop until main thread goes away */
    acquire (&(args->lock), "c");
    unsigned long long int i = random_int (0, n - 1);
    if ((! addr_in_list (addrs + i)) && (tcp_fds [i] < 0)) {
      /* try to connect this random socket */
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
#ifdef TEST_TCP_ONLY
printf ("connected to: ");
print_sockaddr (sap, addr_lengths [i]); printf ("\n");
#endif /* TEST_TCP_ONLY */
          make_socket_nonblocking (sock, "connect_thread new socket");
          tcp_fds [i] = sock;
          tcp_bytes [i] = 0;
          memcpy (tcp_addrs + i, sap, addr_lengths [i]);
        }
      }
    }
    release (&(args->lock), "c");
    sleep_while_running (args, sleep_time * 1000);
    if (count++ > n)
      sleep_time = sleep_time * 12 / 10 + 1;  /* gradual increase, ~20%/loop */
#define MAX_SLEEP_TIME (KEEPALIVE_SECONDS * 24) /* try at least every 4min */
    if (sleep_time > MAX_SLEEP_TIME)
      sleep_time = MAX_SLEEP_TIME;
#undef MAX_SLEEP_TIME
  }
  printf ("%lld: atcpd_connect_thread %p ending\n", allnet_time (), arg);
  int i;
  for (i = 0; i < MAX_CONNECTIONS; i++) {
    if (tcp_fds [i] != -1)
      close (tcp_fds [i]);
    tcp_bytes [i] = 0;
  }
  memset (tcp_addrs, 0, sizeof (tcp_addrs));
  return NULL;
}

static void * atcp_keepalive_thread (void * arg)
{
  struct atcp_thread_args * args = ((struct atcp_thread_args *) arg);
  int local_sock = args->local_sock;
  unsigned int size_to_send = 0;
  const char * packet = keepalive_packet (&size_to_send);
  while (args->running) {   /* loop until main thread goes away */
    acquire (&(args->lock), "k");
    if (args->last_keepalive_sent_time + KEEPALIVE_SECONDS * 10 <
        allnet_time ()) {
      if ((args->authenticating_keepalive != NULL) &&
          (args->aksize > 0))
        send (local_sock, args->authenticating_keepalive, args->aksize, 0);
      else
        send (local_sock, packet, size_to_send, 0);
      args->last_keepalive_sent_time = allnet_time ();
    }
    release (&(args->lock), "k");
    sleep_while_running (args, KEEPALIVE_SECONDS * 100);
  }
  printf ("%lld: atcpd_keepalive_thread %p ending\n", allnet_time (), arg);
  return NULL;
}

static void * atcp_timer_thread (void * arg)
{
  struct atcp_thread_args * args = ((struct atcp_thread_args *) arg);
  int missed_count = 0;
  do {
    sleep_while_running (args, KEEPALIVE_SECONDS * 3 * 1000);
    while (args->running &&
           (last_udp_received_time + KEEPALIVE_SECONDS * 50 > allnet_time ())) {
      missed_count = 0;  /* recently received */
      sleep_while_running (args, KEEPALIVE_SECONDS * 1000);
    }
    printf ("last_udp_receive_time %lld, current time %lld (k %d, m %d)\n",
            last_udp_received_time, allnet_time (),
            (int) KEEPALIVE_SECONDS, missed_count);
  } while (args->running && (missed_count++ < 3));
  printf ("%lld: atcpd_timer_thread %p ending %d\n", allnet_time (), arg,
          args->running);
  args->running = 0;  /* gracefully stop all the other threads */
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
  int restart_count = 0;
  while (restart_count++ < 3) {
    int new_sock = local_socket ();
    last_udp_received_time = allnet_time (); /* start all the timers now */
    if (new_sock < 0) {
      sleep (2);
      continue;  /* start over, after a two-second pause */
    }
    struct atcp_thread_args * thread_args =
      malloc_or_fail (sizeof (struct atcp_thread_args), "atcpd_main");
    thread_args->local_sock = new_sock;
    int i;
    for (i = 0; i < MAX_CONNECTIONS; i++) {
      tcp_fds [i] = -1;
      tcp_bytes [i] = 0;
    }
    memset (tcp_addrs, 0, sizeof (tcp_addrs));
    pthread_mutex_init (&(thread_args->lock), NULL);
    thread_args->running = 1;
    thread_args->last_keepalive_sent_time = 0; /* we have sent no keepalives */
    thread_args->authenticating_keepalive = NULL;
    thread_args->aksize = 0;
    pthread_t thr1, thr2, thr3, thr4, thr5, thr6;
    pthread_create (&thr1, NULL, atcp_connect_thread, (void *) thread_args);
    pthread_create (&thr2, NULL, atcp_recv_thread, (void *) thread_args);
    pthread_create (&thr3, NULL, atcp_keepalive_thread, (void *) thread_args);
    /* two accept threads, one each for IPv4 and IPv6. */
    pthread_create (&thr4, NULL, atcp_accept_thread, (void *) thread_args);
    pthread_create (&thr5, NULL, atcp_accept_thread, (void *) thread_args);
    pthread_create (&thr6, NULL, atcp_timer_thread, (void *) thread_args);
    while (thread_args->running) {  /* loop until an error occurs */
      char buffer [ALLNET_MTU];
      struct sockaddr_storage sas;
      struct sockaddr * sap = (struct sockaddr *) (&sas);
      socklen_t addr_len = sizeof (sas);
      ssize_t r = recvfrom (thread_args->local_sock, buffer, sizeof (buffer),
                            0, sap, &addr_len);
      if ((r < 0) &&   /* some error, or timeout */
          (errno != EAGAIN) && (errno != EWOULDBLOCK)) {  /* not a timeout */
        if (errno == ECONNREFUSED)
          snprintf (alog->b, alog->s,
                    "atcpd socket %d connection refused, %p\n",
                    thread_args->local_sock, thread_args);
        else
          snprintf (alog->b, alog->s,
                    "atcpd socket closed, socket %d, errno %d, restarting %p\n",
                    thread_args->local_sock, errno, thread_args);
        printf ("%s", alog->b);
        log_print (alog);
        close (thread_args->local_sock);
        thread_args->running = 0;  /* kill off all the other threads, if any */
      } else if (r > 0) {           /* got a packet */
        atcp_handle_local_packet (thread_args, buffer, (int) r, sas);
        last_udp_received_time = allnet_time ();
        restart_count = 0; /* successful, doesn't count as a restart any more */
/* printf ("received %d bytes, time %lld\n", (int) r, last_udp_received_time); */
      }
      sleep_while_running (thread_args, 30);  /* sleep 1/30s */
    }
    pthread_join (thr1, NULL);
    pthread_join (thr2, NULL);
    pthread_join (thr3, NULL);
    pthread_join (thr4, NULL);
    pthread_join (thr5, NULL);
    free (thread_args);
    printf ("%lld: atcpd_main restarting %d\n", allnet_time (), restart_count);
    snprintf (alog->b, alog->s, "atcpd_main restarting\n");
    log_print (alog);
  }
  return NULL;
}

