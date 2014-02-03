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
#include "../packet.h"
#include "sha.h"
#include "priority.h"

static void exec_allnet ()
{
  if (fork () == 0) {
    if ((chdir ("../bin") < 0) || (access ("./astart", X_OK) < 0)) {
      char * home = getenv ("HOME");
      if (home == NULL) {
        printf ("unable to find environment variable HOME\n");
        exit (1);
      }
      if ((chdir (home) < 0) || (chdir (".purple/plugins/xchat") < 0)) {
        printf ("unable to change directory to $HOME/.purple/plugins/xchat\n");
        exit (1);
      }
      if (access ("./astart", X_OK) < 0) {
        printf ("unable to exec $HOME/.purple/plugins/xchat/astart\n");
        exit (1);
      }
    }
    execl ("./astart", "astart", "wlan0", (char *) NULL);
    perror ("execl");
    printf ("error: exec astart failed\n");
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
int connect_to_local (char * program_name)
{
  init_log (program_name);
  int sock = connect_once (0);
  if (sock < 0) {
    exec_allnet ();
    sleep (1);
    sock = connect_once (1);
    if (sock < 0) {
      printf ("unable to start allnet daemon, giving up\n");
      return -1;
    }
  }
  return sock;
}

#if 0

/* only really works within 24 hours -- otherwise, too complicated */
/* should use mktime, but does not translate GMT/UTC time */
static int delta_minutes (struct tm * local, struct tm * gm)
{
  int delta_hour = local->tm_hour - gm->tm_hour;
  if (local->tm_wday == ((gm->tm_wday + 8) % 7)) {
    delta_hour += 24;
  } else if (local->tm_wday == ((gm->tm_wday + 6) % 7)) {
    delta_hour -= 24;
  } else if (local->tm_wday != gm->tm_wday) {
    printf ("assertion error: weekday %d != %d +- 1\n",
            local->tm_wday, gm->tm_wday);
    exit (1);
  }
  int delta_min = local->tm_min - gm->tm_min;
  if (delta_min < 0) {
    delta_hour -= 1;
    delta_min += 60;
  }
  int result = delta_hour * 60 + delta_min;
  /* 
  printf ("delta minutes is %02d:%02d = %d\n", delta_hour, delta_min, result);
  */
  return result;
}


void write_big_endian16 (char * array, int value)
{
  writeb64 (array
  array [0] = (value >>  8) & 0xff; array [1] =  value        & 0xff;
}

void write_big_endian32 (char * array, long int value)
{
  array [0] = (value >> 24) & 0xff; array [1] = (value >> 16) & 0xff;
  array [2] = (value >>  8) & 0xff; array [3] =  value        & 0xff;
}

void write_big_endian48 (char * array, long long int value)
{
  array [0] = (value >> 40) & 0xff; array [1] = (value >> 32) & 0xff;
  array [2] = (value >> 24) & 0xff; array [3] = (value >> 16) & 0xff;
  array [4] = (value >>  8) & 0xff; array [5] =  value        & 0xff;
}

void write_big_endian64 (char * array, long long int value)
{
  array [0] = (value >> 56) & 0xff; array [1] = (value >> 48) & 0xff;
  array [2] = (value >> 40) & 0xff; array [3] = (value >> 32) & 0xff;
  array [4] = (value >> 24) & 0xff; array [5] = (value >> 16) & 0xff;
  array [6] = (value >>  8) & 0xff; array [7] =  value        & 0xff;
}

int read_big_endian16 (char * array)
{
/*
  printf ("array is %02x %02x, result is %d\n",
          (array [0] & 0xff), (array [1] & 0xff),
          (array [0] & 0xff) <<  8 | (array [1] & 0xff));
*/
  return ((array [0] & 0xff) <<  8 | (array [1] & 0xff));
}

long int read_big_endian32 (char * array)
{
  return ((array [0] & 0xffL) << 24 | (array [1] & 0xffL) << 16 |
          (array [2] & 0xffL) <<  8 | (array [3] & 0xffL));
}

long long int read_big_endian48 (char * array)
{
  return ((array [0] & 0xffLL) << 40 | (array [1] & 0xffLL) << 32 |
          (array [2] & 0xffLL) << 24 | (array [3] & 0xffLL) << 16 |
          (array [4] & 0xffLL) <<  8 | (array [5] & 0xffLL));
}

long long int read_big_endian64 (char * array)
{
  return ((array [0] & 0xffLL) << 56 | (array [1] & 0xffLL) << 48 |
          (array [2] & 0xffLL) << 40 | (array [3] & 0xffLL) << 32 |
          (array [4] & 0xffLL) << 24 | (array [5] & 0xffLL) << 16 |
          (array [6] & 0xffLL) <<  8 | (array [7] & 0xffLL));
}

#endif /* 0 */
