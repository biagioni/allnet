/* aip.c: get allnet messages from ad, send them to DHT and known hosts */
/*        get allnet messages from the internet, forward them to ad */
/* aip stands for A(llNet) IP interface */
/* main thread uses select to check the pipe from ad and the sockets */
/* secondary threads:
 * - listen and open TCP connections
 * - listen on the unix socket for allnet-destination-address to IP mappings
 */
/* arguments are:
  - the fd number of the pipe from ad
  - the fd number of the pipe to ad
  - the name of the Unix socket
 */
/* config file "aip" "speed" (e.g. ~/.allnet/aip/speed)
 * gives the maximum speed to send over the internet, in bytes/second
 * this speed limit only applies to messages with priority 0.5 or less,
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>
#include <netdb.h>
#include <limits.h> 		/* HOST_NAME_MAX */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "packet.h"
#include "listen.h"
#include "ai.h"
#include "lib/pipemsg.h"
#include "lib/priority.h"
#include "lib/util.h"
#include "lib/dcache.h"
#include "lib/log.h"

/* UDPv4 messages are limited to less than 2^16 bytes */
#define MAX_RECEIVE_BUFFER	ALLNET_MAX_UDP_SIZE

static int init_unix_socket (char * addr_socket_name)
{
  int addr_socket = socket (AF_UNIX, SOCK_DGRAM, 0);
  if (addr_socket < 0) {
    perror ("af_unix socket");
    exit (1);    /* not sure what this error would mean */
  }
  struct sockaddr_un sun;
  sun.sun_family = AF_UNIX;
  snprintf (sun.sun_path, sizeof (sun.sun_path), "%s", addr_socket_name);
  if (bind (addr_socket, (struct sockaddr *) (&sun), sizeof (sun)) < 0) {
    perror ("af_unix bind");
    printf ("unable to bind to unix socket ");
    print_sockaddr ((struct sockaddr *) (&sun), sizeof (sun), -1);
    printf ("\nmake sure no other aip is running and delete %s\n",
            addr_socket_name);
    exit (1);
  }
  return addr_socket;
}

struct receive_arg {
  char * socket_name;
  void * cache;
};

static void * receive_addrs (void * arg)
{
  struct receive_arg * ra = (struct receive_arg *) arg;
  int addr_socket = init_unix_socket (ra->socket_name);
  snprintf (log_buf, LOG_SIZE, "receive_addrs, socket is %d\n", addr_socket);
  log_print ();

  int size = sizeof (struct addr_info);
  while (1) {
    struct addr_info * ai = malloc_or_fail (size, "receive_addrs");
    int bytes = recv (addr_socket, (char *) ai, size, 0);
    if (bytes < 0)
      perror ("recv");
    if (bytes <= 0) {
      printf ("error: address socket %d closed, thread exiting\n", addr_socket);
      free (ai);
      return NULL;
    }
    /* error checking, print if find inconsistencies */
    if ((ai->ip.ip_version == 4) && (bytes != size))
      printf ("ip version 4, expected %d, got %d\n", size, bytes);
    if ((ai->ip.ip_version == 6) && (bytes != size))
      printf ("ip version 6, expected %d, got %d\n", size, bytes);

    printf ("receive_addrs got %d bytes, ", bytes);
    print_addr_info (ai);
    cache_add (ra->cache, ai);   /* if already in cache, records usage */
  }
}

struct match_arg {
  /* arguments */
  unsigned char destination [ADDRESS_SIZE];
  unsigned char nbits;    /* how many bits of the destination are given */
};

/* matching_bits should return nonzero for a matching entry (higher
 * values for a better match), and 0 for no match */
static int matching_bits (void * a, void * data)
{
  struct match_arg * ma = (struct match_arg *) a;
  struct addr_info * ai = (struct addr_info *) data;
  int r = matches (ma->destination, ma->nbits, ai->destination, ai->nbits);
/*
  printf ("matching %d bits of ", ma->nbits);
  print_buffer (ma->destination, (ma->nbits + 7) / 8, NULL, 8, 0);
  printf (" to %d bits of ", ai->nbits);
  print_buffer (ai->destination, (ai->nbits + 7) / 8, NULL, 8, 0);
  printf (", result %d\n", r);
*/
  return r;
}

/* mallocs and sets result to an n-element array of addr_infos that are the
 * best matches for the given destination */
/* returns the actual number of destinations found, or 0 */
static int top_destinations (void * addr_cache, int max, unsigned char * dest,
                             int nbits, struct sockaddr_in6 ** result)
{
  void ** matches;
  struct match_arg dest_arg;
  memcpy (dest_arg.destination, dest, (nbits + 7) / 8); 
  dest_arg.nbits = nbits;
  int num_matches = cache_all_matches (addr_cache, matching_bits, &dest_arg,
                                       &matches);
/*
  printf ("top_destination (");
  print_buffer (dest, (nbits + 7) / 8, NULL, 100, 0);
  printf (" (%d), %d)\n", nbits, num_matches);
*/
  struct sockaddr_in6 * new =
    malloc_or_fail (sizeof (struct sockaddr_in6) * max, "top_destinations");
  if (num_matches > max)
    num_matches = max;    /* only return the first n matches */
  int i;
  for (i = 0; i < num_matches; i++) {
/* print_addr_info ((struct addr_info *) (matches [i])); */
    if (! ai_to_sockaddr (((struct addr_info *) (matches [i])),
                          (struct sockaddr *) (new + i))) {
      printf ("coding error: match %d of %d could not be made a sockaddr\n",
              i, num_matches); 
      exit (1);
    }
  }
  *result = new;
  return num_matches;
}

static int same_sockaddr (void * arg1, void * arg2)
{
  struct sockaddr_in6 * a1 = (struct sockaddr_in6 *) arg1;
  struct sockaddr_in6 * a2 = (struct sockaddr_in6 *) arg2;
  if (a1->sin6_family != a2->sin6_family)
    return 0;
  if (a1->sin6_family == AF_INET6) {
    if ((a1->sin6_port == a2->sin6_port) &&
        (memcmp (a1->sin6_addr.s6_addr, a2->sin6_addr.s6_addr,
                 sizeof (a1->sin6_addr)) == 0))
      return 1;
    return 0;
  }
  if (a1->sin6_family == AF_INET) {
    struct sockaddr_in * sin1 = (struct sockaddr_in  *) arg1;
    struct sockaddr_in * sin2 = (struct sockaddr_in  *) arg2;
    if ((sin1->sin_port == sin2->sin_port) &&
        (sin1->sin_addr.s_addr == sin2->sin_addr.s_addr))
      return 1;
    return 0;
  }
  printf ("same_sockaddr: unknown address family %d\n", a1->sin6_family);
  return 0;
}

/* save the IP address of the sender, unless it is already there */
static void add_sockaddr_to_cache (void * cache, struct sockaddr * addr,
                                   socklen_t sasize, char * log, int lsize)
{
  int off = print_sockaddr_str (addr, sasize, 0, log, lsize);
  snprintf (log + off, lsize - off, "\n");
  /* found and addr are different pointers, so cannot rely on cache_add
   * detecting that this is a duplicate */
  void * found = cache_get_match (cache, same_sockaddr, addr);
  if (found != NULL) {  /* found */
    /* printf (" (already in cache)\n"); */
    cache_record_usage (cache, found); /* found, addr are different pointers */
    return;
  }
  /* else, add to cache.  cannot use caller's pointer, so allocate new space */
  struct sockaddr * copy = memcpy_malloc (addr, sasize, "add_sockaddr_cache");
  cache_add (cache, copy);
}

static void send_udp (int udp, char * message, int msize, struct sockaddr * sa)
{
  socklen_t addr_len = sizeof (struct sockaddr_in6);
  if (sa->sa_family == AF_INET)
    addr_len = sizeof (struct sockaddr_in);
  int s = sendto (udp, message, msize, 0, sa, addr_len);
  if (s < msize) {
    int n = snprintf (log_buf, LOG_SIZE,
                      "error sending %d (sent %d) on udp %d to ", msize, s, udp);
    n += print_sockaddr_str (sa, 0, 0, log_buf + n, LOG_SIZE - n);
    log_error ("sendto");
  } else {
/*
    int n = snprintf (log_buf, LOG_SIZE, "sent %d bytes to ", msize);
    n += print_sockaddr_str (sa, 0, 0, log_buf + n, LOG_SIZE - n);
    log_print ();
*/
  }
}

/* send up to about max_send/2 of the UDPs for which we have matching
 * translations, then the rest to a random permutation of other udps
 * we have heard from and tcps we are connected to */
static void forward_message (int * fds, int num_fds, int udp, void * udp_cache,
                             void * addr_cache, char * message, int msize,
                             int priority, int max_send)
{
  if (! is_valid_message (message, msize))
    return;

  struct allnet_header * hp = (struct allnet_header *) message;
  int i;
  struct sockaddr_in6 * destinations;
  int max_translations = max_send / 2 + 1;
  int translations =
    top_destinations (addr_cache, max_translations, hp->destination,
                      hp->dst_nbits, &destinations);
  for (i = 0; i < translations; i++)  /* send here first */
    send_udp (udp, message, msize, (struct sockaddr *) (destinations + i));
  if (translations > 0) free (destinations);
  if (translations > 1) {
    snprintf (log_buf, LOG_SIZE, "forwarded to %d mappings\n", translations);
    log_print ();
  }

  int sent_fds = 0;
  int sent_udps = 0;
  int remaining = max_send - translations;
#define FORWARDING_UDPS	100
  void * udps [FORWARDING_UDPS];
  int nudps = cache_random (udp_cache, FORWARDING_UDPS, udps);
#undef FORWARDING_UDPS
  int size = num_fds + nudps;
  if (size > 0) {
    int * random_selection = random_permute (size);
    for (i = 0; i < size && i < remaining; i++) {
      int index = random_selection [i];
      if (index < num_fds) {
        if (! send_pipe_message (fds [index], message, msize, ONE_HALF)) {
          snprintf (log_buf, LOG_SIZE,
                    "aip error sending to socket %d at %d\n",
                    fds [index], i);
          log_print ();
        }
        snprintf (log_buf, LOG_SIZE, "aip sent %d bytes to TCP socket %d\n",
                  msize, fds [index]);
        log_print ();
        sent_fds++;
      } else {
        /* udp cache contains sockaddrs */
        send_udp (udp, message, msize,
                  (struct sockaddr *) (udps [index - num_fds]));
        sent_udps++;
      }
    }
    free (random_selection);
  }
  snprintf (log_buf, LOG_SIZE, "forwarded to %d TCP and %d UDP\n",
            sent_fds, sent_udps);
  log_print ();
}

static int udp_socket ()
{
  int udp = socket (AF_INET6, SOCK_DGRAM, 0);
  if (udp < 0) {
    snprintf (log_buf, LOG_SIZE, "unable to open UDP socket, exiting");
    log_error ("main loop socket");
    exit (1);
  }
  struct sockaddr_storage address;
  struct sockaddr     * ap  = (struct sockaddr     *) &address;
  struct sockaddr_in  * ap4 = (struct sockaddr_in  *) ap;
  struct sockaddr_in6 * ap6 = (struct sockaddr_in6 *) ap;
  int addr_size = sizeof (address);

  memset (&address, 0, addr_size);
  ap6->sin6_family = AF_INET6;
  memcpy (&(ap6->sin6_addr), &(in6addr_any), sizeof (ap6->sin6_addr));
  ap6->sin6_port = ALLNET_PORT;
  if (bind (udp, ap, addr_size) < 0) {
    perror ("bind");
    printf ("aip unable to bind to UDP %d/%x, probably already running\n",
            ntohs (ALLNET_PORT), ntohs (ALLNET_PORT));
    exit (1);
  }
  snprintf (log_buf, LOG_SIZE, "opened UDP socket %d\n", udp);
  log_print ();
  return udp;
}

static void print_gethostbyname_error (char * hostname)
{
  switch (h_errno) {
  case HOST_NOT_FOUND:
    snprintf (log_buf, LOG_SIZE,
              "error resolving host name %s: host not found\n", hostname);
    break;
  case NO_ADDRESS:  /* same as NO_DATA */
    snprintf (log_buf, LOG_SIZE,
              "error resolving host name %s: no address/no data\n", hostname);
    break;
  case NO_RECOVERY:
    snprintf (log_buf, LOG_SIZE,
              "error resolving host name %s: unrecoverable error\n", hostname);
    break;
  case TRY_AGAIN:
    snprintf (log_buf, LOG_SIZE,
              "error resolving host name %s: try again\n", hostname);
    break;
  default:
    snprintf (log_buf, LOG_SIZE,
              "error resolving host name %s: unknown %d\n", hostname, h_errno);
    break;
  }
  log_print ();
}

int make_listener (struct listen_info * info, void * addr_cache)
{
#define NO_DHT_YET_USE_ALNT_ORG
#ifdef NO_DHT_YET_USE_ALNT_ORG
  char my_name [HOST_NAME_MAX + 1];
  if ((gethostname (my_name, sizeof (my_name)) == 0) &&
      (strcmp (my_name, "alnt.org") == 0))
    return -1;
/* open a connection to alnt.org as a listener */
  struct hostent * he = gethostbyname ("alnt.org");
  if (he == NULL) {
    print_gethostbyname_error ("alnt.org");
    return -1;
  }
  int size = sizeof (struct addr_info);
  struct addr_info * ai = malloc_or_fail (size, "receive_addrs");
  init_ai (he->h_addrtype, he->h_addr_list [0], ALLNET_PORT, 0, NULL, ai);
  struct sockaddr_storage sas;
  struct sockaddr * sap = (struct sockaddr *) (&sas);
  if (! ai_to_sockaddr (ai, sap)) {
    printf ("error converting address to sockaddr\n");
    return -1;
  }
  int listener = socket (he->h_addrtype, SOCK_STREAM, 0);
  if (listener < 0) {
    perror ("listener socket");
    return -1;
  }
  /* add a mapping to alnt.org for any destination -- only until DHT */
  if (connect (listener, sap, sizeof (sas)) < 0) {
    snprintf (log_buf, LOG_SIZE, "error connecting listener socket %d\n",
              listener);
    log_error ("make_listener/connect");
    close (listener);
    return -1;
  }
  cache_add (addr_cache, ai);
  listen_add_fd (info, listener, ai);
  int offset = snprintf (log_buf, LOG_SIZE,
                         "listening to alnt.org on socket %d at ", listener);
  offset += addr_info_to_string (ai, log_buf + offset, LOG_SIZE - offset);
  log_print ();
  return listener;
#else /* NO_DHT_YET_USE_ALNT_ORG */
  return -1;
#endif /* NO_DHT_YET_USE_ALNT_ORG */
}

/* if it is a peer message, changes the listener to listen to one of
 * the peers instead */
/* returns 1 if it is a valid peer message, 0 otherwise */
static int handle_peer_packet (int * listener, int peer,
                               char * message, int msize)
{
  if (*listener < 0)
    return 0;
  if (msize < ALLNET_HEADER_SIZE)
    return 0;
  struct allnet_header * hp = (struct allnet_header *) message;
  if (msize < ALLNET_PEER_SIZE (hp->transport, 1))
    return 0;
  struct allnet_mgmt_header * mp =
    (struct allnet_mgmt_header *) (message + ALLNET_SIZE (hp->transport));
  if ((hp->message_type != ALLNET_TYPE_MGMT) ||
      (mp->mgmt_type != ALLNET_MGMT_PEERS))
    return 0;
  if (*listener != peer) {
    printf ("unsolicited peer message fd %d, expected %d\n", peer, *listener);
    return 0;
  }
  struct allnet_mgmt_peers * mpp =
    (struct allnet_mgmt_peers *)
      (message + ALLNET_MGMT_HEADER_SIZE (hp->transport));
  int npeers = mpp->num_peers & 0xff;
  if (msize < ALLNET_PEER_SIZE(hp->transport, npeers))
    return 0;
  int index;
  for (index = 0; index < npeers; index++) {
    struct internet_addr * ia = mpp->peers + index;
    struct sockaddr_storage * sas;
    struct sockaddr * sap = (struct sockaddr *) &sas;
    if (ia_to_sockaddr (ia, sap)) {
      int af = (ia->ip_version == 4) ? AF_INET : AF_INET6;
      int new_sock = socket (af, SOCK_STREAM, 0);
      if (connect (new_sock, sap, sizeof (sas)) < 0) {
        close (*listener);
        *listener = new_sock;
        return 1;
      } else {
        perror ("warning: connect/listener");  /* not really an error */
      }
    }
  }
  if (npeers > 0) {
    printf ("error: none of the %d peers given were valid:\n", npeers);
    for (index = 0; index < npeers; index++)
      print_ia (mpp->peers + index);
  }
  return 0;   /* no connection established */
}

static void main_loop (int rpipe, int wpipe, struct listen_info * info,
                       void * addr_cache)
{
  int udp = udp_socket ();
  void * udp_cache = NULL;
  udp_cache = cache_init (128, free);
  int listener = -1;
  time_t last_listen = 0;
  while (1) {
    if ((listener == -1) &&
        ((last_listen == 0) || (time (NULL) - last_listen > 60)))  {
      listener = make_listener (info, addr_cache);
      last_listen = time (NULL);
    }
    int fd = 0;
    int priority;
    char * message;
    struct sockaddr_storage sockaddr;
    struct sockaddr * sap = (struct sockaddr *) (&sockaddr);
    socklen_t sasize = sizeof (sockaddr);
    int result = receive_pipe_message_fd (1000, &message, udp, sap, &sasize,
                                          &fd, &priority);
    if (result < 0) {
      if ((fd == rpipe) || (fd == udp)) {
        printf ("aip %s %d closed\n",
                ((fd == rpipe) ? "ad pipe" : "udp socket"), fd);
        break;  /* exit the loop and the program */
      }
      printf ("aip: error on file descriptor %d, closing\n", fd);
      listen_remove_fd (info, fd); /* remove from data structures */
      close (fd);       /* remove from kernel */
      if (fd == listener)
        listener = -1;
    } else if (result > 0) {
      if (fd == rpipe) {    /* message from ad, send to IP neighbors */
        /* snprintf (log_buf, LOG_SIZE, "message from ad\n");
        log_print (); */
        forward_message (info->fds + 1, info->num_fds - 1, udp, udp_cache,
                         addr_cache, message, result, priority, 10);
      } else if (handle_peer_packet (&listener, fd, message, result)) {
        /* handled, no action needed */
      } else {              /* message from a client, send to ad */
        int off = snprintf (log_buf, LOG_SIZE,
                            "got %d bytes from Internet on fd %d", result, fd);
        if (fd == udp) {
          off += snprintf (log_buf + off, LOG_SIZE - off, "/udp, saving ");
          add_sockaddr_to_cache (udp_cache, sap, sasize,
                                 log_buf + off, LOG_SIZE - off);
        } else {
          off += snprintf (log_buf + off, LOG_SIZE - off, "\n");
        }
        log_print ();
        /* often will just get message back from ad, with a new priority */
        if (! send_pipe_message (wpipe, message, result, EPSILON)) {
          snprintf (log_buf, LOG_SIZE, "error sending to ad pipe %d\n", wpipe);
          log_print ();
          break;
        }
        listen_record_usage (info, fd);   /* this fd was used */
      }  /* else -- result is zero, try again */
      free (message);   /* allocated by receive_pipe_message_fd */
    }   /* else result is zero, timed out, try again */
  }
}

int main (int argc, char ** argv)
{
  init_log ("aip");
  if (argc != 4) {
    printf ("aip: arguments are read pipe from ad and write pipe to ad,\n");
    printf (" and a unix domain socket for address info (argc == 4)\n");
    printf (" but argc == %d\n", argc);
    return -1;
  }

  int rpipe = atoi (argv [1]);  /* read pipe */
  int wpipe = atoi (argv [2]);  /* write pipe */
  char * addr_socket_name = argv [3];

  snprintf (log_buf, LOG_SIZE,
            "read pipe is fd %d, write pipe fd %d, socket %s\n",
            rpipe, wpipe, addr_socket_name);
  log_print ();

  pthread_t addr_thread;
  struct receive_arg ra;
  ra.socket_name = addr_socket_name;
  ra.cache = cache_init (128, free);
  if (pthread_create (&addr_thread, NULL, receive_addrs, &ra) != 0) {
    perror ("pthread_create/addrs");
    return 1;
  }
  struct listen_info info;
  listen_init_info (&info, 256, "aip", ALLNET_PORT, 0, 1);

  listen_add_fd (&info, rpipe, NULL);

  srandom (time (NULL));
  main_loop (rpipe, wpipe, &info, ra.cache);

  snprintf (log_buf, LOG_SIZE,
            "end of aip main thread, deleting %s\n", addr_socket_name);
  log_print ();
  if (unlink (addr_socket_name) < 0)
    perror ("unlink");
}
