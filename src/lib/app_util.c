/* app_util.c: utility functions for applications */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <netdb.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <openssl/rand.h>

#include "app_util.h"
#include "packet.h"
#include "pipemsg.h"
#include "util.h"
#include "sha.h"
#include "priority.h"
#include "log.h"

static void find_path (char * arg, char ** path, char ** program)
{
  char * slash = rindex (arg, '/');
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
  if (fork () == 0) {
    char * path;
    char * pname;
    find_path (arg, &path, &pname);
    char * astart = make_program_path (path, "astart");
    if (access (astart, R_OK) != 0) {
      perror ("access");
      printf ("unable to start AllNet daemon\n");
      exit (1);   /* only exits the child */
    }
    execl (astart, astart, "wlan0", (char *) NULL);
    perror ("execl");
    printf ("error: exec astart failed\n");
    exit (1);
  }
  sleep (2);  /* pause the caller for a couple of seconds to get allnet going */
}

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

/* to the extent possible, add randomness to the SSL Random Number Generator */
/* see http://wiki.openssl.org/index.php/Random_Numbers for details */
static void seed_rng ()
{
  int fd = open ("/dev/random", O_RDONLY | O_NONBLOCK);
  if (fd < 0)
    return;
  int isize = sizeof (unsigned int);
  /* SSL won't need any more than 128, initstate can't use more than isize */
  char buffer [128 + 4];
  int count = 0;
  while (count < sizeof (buffer)) {
    int n = read (fd, buffer + count, 1);
    if (n <= 0)  /* presumably, nothing more to read from /dev/random */
      break;
    count++;
  }
  close (fd);
  if (count >= isize) {
    static char state [128];
    unsigned int seed = readb32 (buffer);
    initstate (seed, state, sizeof (state));
  }
  if (count > isize)
    RAND_seed (buffer + isize, count - isize);
/* if (count > 0) printf ("added %d bytes to entropy pool\n", count); */
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
    printf ("%s/%s unable to connect to alocal, starting allnet\n",
            program_name, arg0);
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
    if (pthread_create (&receive_thread, NULL, receive_ignore, (void *) arg)
        != 0) {
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


