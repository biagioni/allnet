/* app_util.c: utility functions for applications */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <netdb.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>   /* inet_addr */

#include "app_util.h"
#include "packet.h"
#include "util.h"
#include "sha.h"
#include "priority.h"
#include "crypt_sel.h"

#ifdef ALLNET_USE_FORK
static void find_path (char * arg, char ** path, char ** program)
{
  char * slash = strrchr (arg, '/');
  if (slash == NULL) {
    *path = ".";
    *program = arg;
  } else {
    *slash = '\0';
    *path = arg;
    *program = slash + 1;
  }
}

/* changes the contents of the argument string, iff the substring is found */
static void del_string (char * string, char * substring)
{
  char * found = strstr (string, substring);
  if (found == NULL)
    return;
  int slen = strlen (substring);
  int len = strlen (found) - slen;
  memmove (found, found + slen, len + 1);
}

/* returned value is malloc'd. */
static char * make_program_path (char * path, char * program,
                                 const char * debug)
{
  char * result = strcat3_malloc (path, "/", program,
                                  "app_util/make_program_path");
  del_string (result, "/.libs"); /* /.libs added to path by dynamic linking */
  if (access (result, X_OK) != 0) {
    char pwdbuf [10000];
    printf ("error: unable to find executable %s/%s or %s (pwd %s, arg %s), aborting\n",
            path, program, result, getcwd (pwdbuf, sizeof (pwdbuf)), debug);
    free (result);
    return NULL;
  }
  return result;
}

static void exec_allnet (const char * arg, const char * config_path)
{
  pid_t child = fork ();
  if (child < 0) {
    perror ("fork");
    printf ("exec_allnet unable to fork, errno %d\n", errno);
    exit (1);  /* no point continuing */
  }
  if (child == 0) {  /* all this code is in the child process */
    char * path;
    char * pname;
    char * arg_copy = strcpy_malloc (arg, "exec_allnet");
    find_path (arg_copy, &path, &pname);
    char * astart = make_program_path (path, "allnetd", arg);
    if ((astart == NULL) || (access (astart, X_OK) != 0)) {
      perror ("access, unable to find allnetd executable");
      printf ("unable to start AllNet daemon %s\n", astart);
      exit (1);   /* only exits the child */
    }
    /* put extra spaces in "default" so we can see more of the arguments */
#define DEFAULT_STRING	"default                     "
    char * args [] = { astart, "-d", NULL, DEFAULT_STRING, NULL };
    if (config_path == NULL) {
      args [1] = DEFAULT_STRING;  /* replace "-d" */
    } else {                 /* replace the NULL with the path */
      args [2] = strcpy_malloc (config_path, "exec_allnet thread path");
    }
#ifdef DEBUG_PRINT
    printf ("calling");
    int i;
    for (i = 0; args [i] != NULL; i++)
      printf (" %s", args [i]);
    printf (" (%d args)\n", i);
#endif /* DEBUG_PRINT */
    execv (astart, args);
    perror ("execv");
    printf ("error: exec allnet [interfaces] failed\nallnet");
    int a;
    for (a = 0; args [a] != NULL; a++)
      printf (" %s", args [a]);
    printf ("\n");
    exit (1);
  }
  setpgid (child, 0);  /* put the child process in its own process group */
}

#endif /* ALLNET_USE_FORK */

static int internal_sockfd = -1;
static struct sockaddr_storage sas;
static struct sockaddr * sap = (struct sockaddr *) (&sas);
static struct sockaddr_in * sinp = (struct sockaddr_in *) (&sas);
static const socklen_t alen = sizeof (struct sockaddr_in);
static long long int last_sent = 0;
static long long int last_rcvd = 0;
static int internal_print_send_errors = 1;

static int send_with_priority (const char * message, int msize, unsigned int p)
{
  if (internal_sockfd < 0) {
    printf ("send_with_priority: unininitialzed socket %d, ls %lld\n",
            internal_sockfd, last_sent);
    char * pq = NULL;
    printf ("crashing %d\n", *pq);
    return 0;
  }
  char * copy = malloc_or_fail (msize + 2, "app_util.c send_with_priority");
  memcpy (copy, message, msize);
  writeb16 (copy + msize, p);
  ssize_t s = sendto (internal_sockfd, copy, msize + 2, 0, sap, alen);
  if ((s < 0) && (internal_print_send_errors)) {
int e = errno;
    perror ("send_with_priority send");
printf ("send (%d, %p, %d, 0): result %zd, errno %d\n",
internal_sockfd, copy, msize + 2, s, e);
  }
  free (copy);
  return (s == (msize + 2));
}

/* send a keepalive unless we have sent messages in the last 5s */
void local_send_keepalive (int override)
{
  long long int now = allnet_time ();
  if ((! override) && (last_sent + (KEEPALIVE_SECONDS / 2) > now))
    return;  /* do nothing */
#if 0
struct sockaddr_storage local_sas; socklen_t local_alen = sizeof (local_sas);
getsockname(internal_sockfd, (struct sockaddr *)(&local_sas), &local_alen);
int port = htons (local_sas.ss_family == AF_INET
                  ? ((struct sockaddr_in *) (&local_sas))->sin_port
                  : ((struct sockaddr_in6 *) (&local_sas))->sin6_port);
printf ("local_send_keepalive from port %04x\n", port);
#endif /* 0 */
  last_sent = now;
  unsigned int msize;
  const char * message = keepalive_packet (&msize);
  send_with_priority (message, msize, ALLNET_PRIORITY_EPSILON);
}

static int connect_once (int print_error)
{
  memset (&sas, 0, sizeof (sas));
  sinp->sin_family = AF_INET;
  sinp->sin_addr.s_addr = allnet_htonl (INADDR_LOOPBACK);
  sinp->sin_port = allnet_htons (ALLNET_LOCAL_PORT);
  const char * error_desc = "connect_once socket";
  internal_sockfd = socket (sinp->sin_family, SOCK_DGRAM, IPPROTO_UDP);
int debug_recv_count = 0;
  if (internal_sockfd >= 0) {
    error_desc = NULL;  /* timeout */
    long long int start = allnet_time ();
    int flags = MSG_DONTWAIT;
    while (allnet_time () < start + 2) {
      /* send a keepalive to start the flow of data */
      local_send_keepalive (1);
      /* now read a response (hopefully) */
      char buffer [ALLNET_MTU + 2];
debug_recv_count++;
      ssize_t r = recv (internal_sockfd, buffer, sizeof (buffer), flags);
if ((r < 0) && (errno != EAGAIN) && (errno != EWOULDBLOCK)) {
printf ("connect_once received %d, errno %d, s %d, count %d\n",
        (int)r, errno, internal_sockfd, debug_recv_count);
printf ("refused %d, reset %d, notconn %d, badf %d, notsock %d\n",
ECONNREFUSED, ECONNRESET, ENOTCONN, EBADF, ENOTSOCK);
}
      if (r > 2) { /* received an initial packet, which we will discard */
        last_rcvd = allnet_time ();
        return internal_sockfd;  /* success! */
      }
      if ((r < 0) && (errno != EAGAIN) && (errno != EWOULDBLOCK)) {
        error_desc = "connect_once recv";
        char * pq = NULL;
        printf ("%d\n", *pq);
        break;
      }
      usleep (50000);  /* wait for 50ms */
    }
  }
  if (print_error && (errno != 0) && (error_desc != NULL))
    { printf ("error %d/%d,%d,%d,%d,%d, s %d count %d\n", errno,
              ECONNREFUSED, ECONNRESET, ENOTCONN, EBADF, ENOTSOCK,
              internal_sockfd, debug_recv_count);
      perror (error_desc); }
  else if (print_error)  /* timed out */
    printf ("no response after connecting to allnet\n");
  close (internal_sockfd);
  internal_sockfd = -1;
  return -1;
}

#ifndef ANDROID  /* android doesn't support initstate */
static void read_n_bytes (int fd, char * buffer, int bsize)
{
  memset (buffer, 0, bsize);
  int i;
  for (i = 0; i < bsize; i++) {
    if (read (fd, buffer + i, 1) != 1) {
      if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) {
        i--;
        usleep (50000);
      } else
        perror ("unable to read /dev/urandom");
    }
  }
}

/* if cannot read /dev/urandom, use the system clock as a generator of bytes */
static void weak_seed_rng (char * buffer, int bsize)
{
  char results [12]; 
  char rcopy [12]; 
  memset (results, 0, sizeof (results));

  /* the number of microseconds in the current hour or so should give
   * 4 fairly random bytes -- actually use slightly more than an hour,
   * specifically, the maximum possible range (approx 4294s). */
  struct timeval tv;
  gettimeofday (&tv, NULL);
  /* usually overflows, and the low-order 32 bits should be random */
  int rt = (int)(tv.tv_sec * 1000 * 1000 + tv.tv_usec);
  writeb32 (results, rt);

  /* it would be good to have additional entropy (true randomness).
   * to get that, we loop 64 times (SHA512_size), computing the sha()
   * of the intermediate result and doing a system call (usleep) over and
   * over until 1000 clocks (1ms) have passed.  Since the number of clocks
   * should vary (1000 to 1008 have been observed), each loop should add
   * one or maybe a few bits of randomness.
   */
  int i;
  clock_t old_clock = 0;
  int max = (int)(SHA512_SIZE - sizeof (results));
  if (max < 0)  /* unlikely as long as sizeof (results) < 64 */
    max = 0;
  for (i = 0; i < max; i++) {
    do {
      memcpy (rcopy, results, sizeof (results));
      sha512_bytes (rcopy, sizeof (results), results, sizeof (results));
      usleep (1);
    } while (old_clock + 1000 > clock ());  /* continue for 1000 clocks */
    old_clock = clock ();
    /* XOR the clock value into the mix */
    writeb32 (results + 4, old_clock ^ readb32 (results + 4));
  }
  /* combine the bits */
  sha512_bytes (results, sizeof (results), buffer, bsize);
}

/* to the extent possible, add randomness to the SSL Random Number Generator */
/* see http://wiki.openssl.org/index.php/Random_Numbers for details */
static void seed_rng ()
{
  char buffer [sizeof (unsigned int) + 8];
  int fd = open ("/dev/urandom", O_RDONLY | O_NONBLOCK);
  int has_dev_urandom = (fd >= 0);
  if (has_dev_urandom) { /* don't need to seed openssl rng, only standard rng */
    read_n_bytes (fd, buffer, sizeof (unsigned int));
    close (fd);
  } else {
    weak_seed_rng (buffer, sizeof (buffer));  /* seed both */
    /* even though the seed is weak, it is still better to seed openssl RNG */
    allnet_rsa_seed_rng (buffer + sizeof (unsigned int), 8);
  }
  /* seed standard rng */
  static char state [128];
  unsigned int seed = (unsigned int)readb32 (buffer);
  initstate (seed, state, sizeof (state));
}
#endif /* ANDROID */

static void * keepalive_thread (void * arg)
{
  while (1) {
    local_send_keepalive (0);
    sleep (KEEPALIVE_SECONDS);
  }
  return NULL;
}

/* returns a UDP socket used to send messages to the allnet daemon
 * or receive messages from the allnet daemon
 * returns -1 in case of failure
 * arg0 is the first argument that main gets -- useful for finding binaries
 * path, if not NULL, tells allnet what path to use for config files
 * the application MUST receive messages, even if it ignores them all.
 * otherwise, after a while (once the buffer is full) allnet/alocal
 * will close the socket.
 * NOTICE: this can only be called ONCE in any given process, so if
 * there is no fork, there still should only be one call to this function. */
int connect_to_local (const char * program_name, const char * arg0,
                      const char * path, int start_allnet_if_needed,
                      int start_keepalive_thread)
{
  static int first_call = 1;
  if (! first_call)
    close (internal_sockfd);
  internal_sockfd = -1;
  internal_print_send_errors = 0;
#ifndef ANDROID
  seed_rng ();
#endif /* ANDROID */
#ifdef ALLNET_USE_FORK
  int sock = connect_once (! start_allnet_if_needed);
  if ((sock < 0) && start_allnet_if_needed) {
    printf ("%s", program_name);
    if (strcmp (program_name, arg0) != 0)
      printf ("(%s)", arg0);
    printf (" unable to connect, starting allnet\n");
    exec_allnet (strcpy_malloc (arg0, "connect_to_local exec_allnet"),
                 path);
    sleep (1);
    sock = connect_once (1);
    if (sock < 0)
      printf ("unable to start allnet daemon, giving up\n");
  }
#else /* ! ALLNET_USE_FORK */
  int sock = connect_once (1);
#endif /* ALLNET_USE_FORK */
  internal_print_send_errors = 1;
  if (sock < 0)
    return -1;
  /* else, success! */
  if (first_call && start_keepalive_thread) {
    pthread_t ignored;
    pthread_create (&ignored, NULL, keepalive_thread, NULL);
    pthread_detach (ignored);
  }
  first_call = 0;
  return sock;
}

/* return 1 for success, 0 otherwise */
int local_send (const char * message, int msize, unsigned int priority)
{
  if (send_with_priority (message, msize, priority)) {
    last_sent = allnet_time ();
    return 1;
  }
  return 0;
}

/* return the message size > 0 for success, 0 otherwise. timeout in ms */
int local_receive (unsigned int timeout,
                   char ** message, unsigned int * priority)
{
  *message = NULL;
  *priority = 0;
  static int keepalive_count = 0;   /* send a keepalive every 5 rcvd messages */
  if (keepalive_count <= 0) {
    local_send_keepalive (1);
    keepalive_count = 5;
  } else {               /* keepalive_count > 0 */
    keepalive_count--;
  }
  char buffer [ALLNET_MTU + 2];
  int flags = MSG_DONTWAIT;
  unsigned long long int loop_count = 0;
  while (allnet_time () < last_rcvd + 10 * KEEPALIVE_SECONDS) {
    loop_count++;
    ssize_t r = recv (internal_sockfd, buffer, sizeof (buffer), flags);
    if ((r > 2) && (r <= ALLNET_MTU + 2)) {
      *message = memcpy_malloc (buffer, r - 2, "local_receive");
      *priority = readb16 (buffer + (r - 2));
      last_rcvd = allnet_time ();
      return (int)(r - 2);
    }
    if ((r < 0) && (errno != EAGAIN) && (errno != EWOULDBLOCK)) {
      perror ("local_receive recv");
      printf ("the local allnet is no longer responding\n");
      exit (0);
    }
    usleep (1000);
    if (timeout <= 1)
      return 0;
    timeout--;
  }
  if (loop_count == 0) {
    printf ("no response from the local allnet\n");
    exit (0);
  }
  return 0;
}

static int ok_for_speculative_computation = 1;
/* since allnet may run on devices with limited power, some things
 * (speculative computation, i.e. stuff that is not needed immediately)
 * may be postponed if we are not plugged in to power */
int speculative_computation_is_ok ()
{
  return ok_for_speculative_computation;
}

void set_speculative_computation (int ok)
{
  ok_for_speculative_computation = ok;
}

#ifdef GET_BCKEY_IS_IMPLEMENTED
/* retrieve or request a public key.
 *
 * if successful returns the key length and sets *key to point to
 * statically allocated storage for the key (do not modify in any way)
 * if not successful, returns 0.
 *
 * max_time_ms and max_hops are only used if the address has not
 * been seen before.  If so, a key request is sent with max_hops, and
 * we wait at most max_time_ms (or quit after receiving max_keys).
 */
unsigned int get_bckey (char * address, char ** key,
                        int max_time_ms, int max_keys, int max_hops)
{
  struct timeval finish;
  gettimeofday (&finish, NULL);
  add_us (&finish, max_time_ms);

  printf ("please implement get_bckey\n");
  exit (1);

/*
  int keys_found = 0;
  static char result [512];
  while ((is_before (&finish)) && (keys_found < max_keys)) {
    
  }
*/
}
#endif /* GET_BCKEY_IS_IMPLEMENTED */


