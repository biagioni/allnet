/* app_util.c: utility functions for applications */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <netdb.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include "app_util.h"
#include "packet.h"
#include "pipemsg.h"
#include "util.h"
#include "sha.h"
#include "priority.h"
#include "log.h"
#include "crypt_sel.h"

#ifndef __IPHONE_OS_VERSION_MIN_REQUIRED
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

/* returned value is malloc'd. */
static char * make_program_path (char * path, char * program)
{
  int size = strlen (path) + 1 + strlen (program) + 1;
  char * result = malloc (size);
  if (result == NULL) {
    printf ("error: unable to allocate %d bytes for %s/%s, aborting\n",
            size, path, program);
    exit (1);
  }
  snprintf (result, size, "%s/%s", path, program);
  return result;
}

static void exec_allnet (char * arg)
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
    find_path (arg, &path, &pname);
    char * astart = make_program_path (path, "allnet");
    if (access (astart, X_OK) != 0) {
      perror ("access, unable to find allnet executable");
      printf ("unable to start AllNet daemon %s\n", astart);
      exit (1);   /* only exits the child */
    }
    char * args [] = { astart, "default", NULL };
    printf ("calling ");
    int i;
    for (i = 0; args [i] != NULL; i++)
    printf (" %s", args [i]);
    printf ("\n");
#ifdef DEBUG_PRINT
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
  waitpid (child, NULL, 0);
}

#else /* __IPHONE_OS_VERSION_MIN_REQUIRED */

extern int astart_main (int, char **);

static void * call_allnet_main (void * unused_arg)
{
  if (unused_arg != NULL)  /* check arg to prevent warnings */
    printf ("error: argument to call_allnet_main should be NULL\n");
  char * args [] = { "allnet", NULL };
  /* could be: char * args [] = { "allnet", "def", NULL }; */
  astart_main (1, args);
  return NULL;
}

static void exec_allnet (char * arg)  /* iOS version, threads instead of fork */
{
  pthread_t thread;
  int error = pthread_create (&thread, NULL, call_allnet_main, NULL);
  if (error) {
    printf ("ios exec_allnet unable to create thread for allnet main\n");
    exit (1);  /* no point continuing */
  }
}
#endif /* __IPHONE_OS_VERSION_MIN_REQUIRED */

static int connect_once (int print_error)
{
  int sock = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
  /* disable Nagle algorithm on sockets to alocal, because it delays
   * successive sends and, since the communication is local, doesn't
   * substantially improve performance anyway */
  int option = 1;  /* disable Nagle algorithm */
  if (setsockopt (sock, IPPROTO_TCP, TCP_NODELAY, &option, sizeof (option))
      != 0) {
    snprintf (log_buf, LOG_SIZE, "unable to set nodelay TCP socket option\n");
    log_print ();
  }
  struct sockaddr_in sin;
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = inet_addr ("127.0.0.1");
  sin.sin_port = ALLNET_LOCAL_PORT;
  if (connect (sock, (struct sockaddr *) &sin, sizeof (sin)) == 0)
    return sock;
  if (print_error)
    perror ("connect to alocal");
  close (sock);
  return -1;
}

static void read_n_bytes (int fd, char * buffer, int bsize)
{
  bzero (buffer, bsize);
  int i;
  for (i = 0; i < bsize; i++) {
    if (read (fd, buffer + i, 1) != 1) {
      if (errno == EAGAIN) {
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
  bzero (results, sizeof (results));

  /* the number of microseconds in the current hour or so should give
   * 4 fairly random bytes -- actually use slightly more than an hour,
   * specifically, the maximum possible range (approx 4294s). */
  struct timeval tv;
  gettimeofday (&tv, NULL);
  /* usually overflows, and the low-order 32 bits should be random */
  int rt = tv.tv_sec * 1000 * 1000 + tv.tv_usec;
  writeb32 (results, rt);

  /* it would be good to have additional entropy (true randomness).
   * to get that, we loop 64 times (SHA512_size), computing the sha()
   * of the intermediate result and doing a system call (usleep) over and
   * over until 1000 clocks (1ms) have passed.  Since the number of clocks
   * should vary (1000 to 1008 have been observed), each loop should add
   * one or maybe a few bits of randomness.
   */
  int i;
  int old_clock = 0;
  for (i = 0; i < SHA512_SIZE - sizeof (results); i++) {
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
  unsigned int seed = readb32 (buffer);
  initstate (seed, state, sizeof (state));
}

#ifdef CREATE_READ_IGNORE_THREAD   /* including requires apps to -lpthread */
/* need to keep reading and emptying the socket buffer, otherwise
 * it will fill and alocal will get an error from sending to us,
 * and so close the socket. */
static void * receive_ignore (void * arg)
{
  int * sockp = (int *) arg;
  while (1) {
    char * message;
    int priority;
    int n = receive_pipe_message (*sockp, &message, &priority);
    /* ignore the message and recycle the storage */
    free (message);
    if (n < 0)
      break;
  }
  return NULL;  /* returns if the pipe is closed */
}
#endif /* CREATE_READ_IGNORE_THREAD */

/* returns the socket, or -1 in case of failure */
/* arg0 is the first argument that main gets -- useful for finding binaries */
int connect_to_local (char * program_name, char * arg0)
{
  seed_rng ();
  int sock = connect_once (0);
  if (sock < 0) {
    /* printf ("%s(%s) unable to connect to alocal, starting allnet\n",
            program_name, arg0); */
    exec_allnet (arg0);
    sleep (1);
    sock = connect_once (1);
    if (sock < 0) {
      printf ("unable to start allnet daemon, giving up\n");
      return -1;
    }
  }
  add_pipe (sock);   /* tell pipe_msg to listen to this socket */
#ifdef CREATE_READ_IGNORE_THREAD   /* including requires apps to -lpthread */
  if (send_only == 1) {
    int * arg = malloc_or_fail (sizeof (int), "connect_to_local");
    *arg = sock;
    pthread_t receive_thread;
    if (pthread_create (&receive_thread, NULL, receive_ignore, (void *) arg)) {
      perror ("connect_to_local pthread_create/receive");
      return -1;
    }
  }
#endif /* CREATE_READ_IGNORE_THREAD */
  /* it takes alocal up to 50ms to update the list of sockets it listens on. 
   * here we wait 60ms so that by the time we return, alocal is listening
   * on this new socket. */
  struct timespec sleep;
  sleep.tv_sec = 0;
  sleep.tv_nsec = 60 * 1000 * 1000;
  struct timespec left;
  while ((nanosleep (&sleep, &left)) != 0)
    sleep = left;
  /* finally we can register with the log module.  We do this only
   * after we are sure that allnet is running, since starting allnet
   * might create a new log file. */
  init_log (program_name);
  return sock;
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


