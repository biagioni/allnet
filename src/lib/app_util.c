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
#include "pipemsg.h"
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
    char * astart = make_program_path (path, "allnet", arg);
    if ((astart == NULL) || (access (astart, X_OK) != 0)) {
      perror ("access, unable to find allnet executable");
      printf ("unable to start AllNet daemon %s\n", astart);
      exit (1);   /* only exits the child */
    }
    /* put extra spaces in "default" so we can see more of the arguments */
#define DEFAULT_STRING	"default        "
    char * args [] = { astart, "-d", NULL, DEFAULT_STRING, NULL };
    if (config_path == NULL) {
      args [1] = DEFAULT_STRING;  /* replace "-d" */
    } else {                 /* replace the NULL with the path */
      args [2] = strcpy_malloc (config_path, "exec_allnet thread path");
    }
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

#else /* ALLNET_USE_FORK */

extern int astart_main (int, char **);

static void * call_allnet_main (void * path)
{
  if (path == NULL) {
    char * args [] = { "allnet", NULL };
    astart_main (1, args);
  } else {
    char * args [] = { "allnet", "-d", path, NULL };
    astart_main (3, args);
  }
  return NULL;
}

static void exec_allnet (char * arg, const char * const_path)
/* iOS/android version, threads instead of fork */
{
  pthread_t thread;
  char * path = NULL;
  if (const_path != NULL)
    path = strcpy_malloc (const_path, "exec_allnet path");
  int error = pthread_create (&thread, NULL, call_allnet_main, (void *)path);
  if (error) {
    printf ("ios exec_allnet unable to create thread for allnet main\n");
    exit (1);  /* no point continuing */
  }
}
#endif /* ALLNET_USE_FORK */

static int connect_once (int print_error)
{
  int sock = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
  /* disable Nagle algorithm on sockets to alocal, because it delays
   * successive sends and, since the communication is local, doesn't
   * substantially improve performance anyway */
  int option = 1;  /* disable Nagle algorithm */
  if (setsockopt (sock, IPPROTO_TCP, TCP_NODELAY,
                  &option, sizeof (option)) != 0)
    printf ("unable to set nodelay TCP socket option\n");
  struct sockaddr_in sin;
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = inet_addr ("127.0.0.1");
  sin.sin_port = allnet_htons (ALLNET_LOCAL_PORT);
  usleep (200 * 1000); /* listen.c now sleeps 100ms to allow IPv6 to go first */
  if (connect (sock, (struct sockaddr *) &sin, sizeof (sin)) == 0)
    return sock;
  if (print_error)
    perror ("connect to alocal");
  close (sock);
  return -1;
}

#ifndef ANDROID  /* android doesn't support initstate */
static void read_n_bytes (int fd, char * buffer, int bsize)
{
  memset (buffer, 0, bsize);
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

#ifdef CREATE_READ_IGNORE_THREAD   /* including requires apps to -lpthread */
/* need to keep reading and emptying the socket buffer, otherwise
 * it will fill and alocal will get an error from sending to us,
 * and so close the socket. */
static void * receive_ignore (void * arg)
{
  int sockp = * (int *) arg;
  pd p = init_pipe_descriptor (init_log ("app_util.c receive_ignore thread"));
  while (1) {
    char * message;
    int priority;
    int n = receive_pipe_message (p, sockp, &message, &priority);
    /* ignore the message and recycle the storage */
    if (n > 0)
      free (message);
    if (n < 0)
      break;
  }
  return NULL;  /* returns if the pipe is closed */
}
#endif /* CREATE_READ_IGNORE_THREAD */

/* returns a TCP socket used to send messages to the allnet daemon
 * (specifically, alocal) or receive messages from alocal
 * returns -1 in case of failure
 * arg0 is the first argument that main gets -- useful for finding binaries
 * path, if not NULL, tells allnet what path to use for config files
 * the application MUST receive messages, even if it ignores them all.
 * otherwise, after a while (once the buffer is full) allnet/alocal
 * will close the socket. */
int connect_to_local (const char * program_name, const char * arg0,
                      const char * path, pd p)
{
#ifndef ANDROID
  seed_rng ();
#endif /* ANDROID */
  int sock = connect_once (0);
  if (sock < 0) {
    /* printf ("%s(%s) unable to connect to alocal, starting allnet\n",
            program_name, arg0); */
    exec_allnet (strcpy_malloc (arg0, "connect_to_local exec_allnet"),
                 path);
    sleep (1);
    sock = connect_once (1);
    if (sock < 0) {
      printf ("unable to start allnet daemon, giving up\n");
      return -1;
    }
  }
  /* tell pipe_msg to listen to this socket */
  add_pipe (p, sock, "app_util/connect_to_local");
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
  return sock;
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


