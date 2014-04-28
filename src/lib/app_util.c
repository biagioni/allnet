/* app_util.c: utility functions for applications */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "app_util.h"
#include "packet.h"
#include "sha.h"
#include "priority.h"

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
    execl (astart, "astart", "wlan0", (char *) NULL);
    perror ("execl");
    printf ("error: exec astart failed\n");
    exit (1);
  }
  sleep (2);  /* pause the caller for a couple of seconds to get allnet going */
}

static int connect_once (int print_error)
{
  int sock = socket (AF_INET, SOCK_STREAM, 0);
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

/* returns the socket, or -1 in case of failure */
/* arg0 is the first argument that main gets -- useful for finding binaries */
int connect_to_local (char * program_name, char * arg0)
{
#if 0 /* apparently this is already done by openssl.  Should double-check */
  /* RSA encryption uses the random number generator */
  unsigned int seed = time (NULL);
  int rfd = open ("/dev/random", O_RDONLY);
  if (rfd < 0) {
    printf ("using weak random number generator, may be insecure\n");
  } else {
    /* wish I could initialize the whole rstate!!! */
    read (rfd, ((char *) (&seed)), sizeof (unsigned int));
    close (rfd);
  }
  static char rstate [256];
  initstate (seed, rstate, sizeof (rstate));
#endif /* 0 */

  init_log (program_name);
  int sock = connect_once (0);
  if (sock < 0) {
    exec_allnet (arg0);
    sleep (1);
    sock = connect_once (1);
    if (sock < 0) {
      printf ("unable to start allnet daemon, giving up\n");
      return -1;
    }
  }
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
  static char result [512];
  struct timeval finish;
  gettimeofday (&finish, NULL);
  add_us (&finish, max_time_ms);
  int keys_found = 0;

  printf ("please implement get_bckey\n");
  exit (1);

  while ((is_before (&finish)) && (keys_found < max_keys)) {
    
  }
}


