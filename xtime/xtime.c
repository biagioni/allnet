/* xtime.c: send periodic (every hour, on the hour) time broadcast messages */
/* the argument to the call determines how many hops the messages are sent */
/* if no argument is specified, the default is 10 hops */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "packet.h"
#include "pipemsg.h"
#include "priority.h"
#include "cipher.h"

static void exec_allnet ()
{
  if (fork () == 0) {
    chdir ("../v2");   /* no error checking... */
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
int connect_to_local ()
{
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

static int init_xtime ()
{
  int sock = connect_to_local ();
  if (sock < 0)
    return -1;
  add_pipe (sock);
  return sock;
}

static time_t compute_next (time_t from, time_t granularity, int immediate_ok)
{
  time_t delta = from % granularity;
  if ((immediate_ok) && (delta == 0))
    /* already at the beginning of the interval */
    return from;
/*
  printf ("compute_next returning %ld = %ld + (%ld - %ld)\n",
          from + (granularity - delta), from, granularity, delta);
*/
  return from + (granularity - delta);
}

static void wait_until (time_t end_time)
{
  /* compute how long to wait for */
  struct timeval tv;
  gettimeofday (&tv, NULL);
  if (end_time <= tv.tv_sec)  /* already finished */
    return;
  /* from here, end_time > tv.tv_sec */
  /* how many seconds/microseconds until the time? */
  int full_seconds_till_end = end_time - tv.tv_sec;
  /* normally, the number of microseconds will not be zero */
  int seconds_till_end = full_seconds_till_end;
  if (tv.tv_usec != 0)
    seconds_till_end--;

  /* we should sleep until the end time */
  struct timespec sleep;
  sleep.tv_sec = seconds_till_end;
  sleep.tv_nsec = 1000 * (1000000 - tv.tv_usec);
#ifdef DEBUG_PRINT
  /* note that printing changes the accuracy of the sleep, since
   * printing takes time */
  printf ("starting time %ld.%06ld, sleep time %ld.%09ld\n",
          tv.tv_sec, tv.tv_usec, sleep.tv_sec, sleep.tv_nsec);
#endif /* DEBUG_PRINT */

  /* now actually wait */
  struct timespec left;
  left.tv_sec = 0;
  left.tv_nsec = 0;
  while ((nanosleep (&sleep, &left) < 0) &&
         (errno == EINTR) && (left.tv_sec > 0) && (left.tv_nsec > 0)) {
    sleep = left;
    left.tv_sec = 0;
    left.tv_nsec = 0;
  }
  /* struct timeval rt;
  gettimeofday (&rt, NULL); */
  /* printf ("returning at time %ld.%06ld\n", rt.tv_sec, rt.tv_usec); */
  /* printf ("returning at time %ld, stop time is %ld\n", now, stop); */
  return;
}

static void binary_time_to_buf (time_t t, char * dp, int n)
{
  /* printf ("binary time %ld, dp is %p, n is %d\n", t, dp, n); */
  int i;
  int tsize = sizeof (t);
  for (i = 0; i < n; i++) {
    /* big-endian, most significant byte first */
    int shift = (n - i - 1) * 8;
    if (n - i > tsize)
      dp [i] = 0;
    else
      dp [i] = ((t >> shift) & 0xff);
  }
#ifdef DEBUG_PRINT
  printf ("time %lx, timestamp %02x.%02x.%02x.%02x.%02x.%02x.%02x.%02x\n", t,
          dp [0] & 0xff, dp [1] & 0xff, dp [2] & 0xff, dp [3] & 0xff,
          dp [4] & 0xff, dp [5] & 0xff, dp [6] & 0xff, dp [7] & 0xff);
#endif /* DEBUG_PRINT */
}

/* the unix times, used in wait_until, are seconds since 01/01/1970.
   allnet times are seconds since 01/01/2000.
   the difference is 946720800 */
#define TIMEBASE_DELTA	946720800

/* sent as string, followed by null char, followed by 8 bytes of binary time
 * in big-endian format */
#define TIMESTAMP_SIZE 	(25 + 4 + 8)  /* ctime requires 26, plus " UTC" */
/* we remove the \n that ctime returns, so the actual size is one less */
/* returns the number of bytes to send */

static int time_to_buf (time_t t, char * dp, int n)
{
  /* printf ("time %ld, dp is %p, n is %d\n", t, dp, n); */
  memset (dp, 0, n);
  if (n < TIMESTAMP_SIZE) {
    binary_time_to_buf (t, dp + 1, n - 1);
    /* best we can do -- empty binary string */
    return 9;
  }
  time_t unix_time = t + TIMEBASE_DELTA;              /* restore unix time */
  struct tm details;
  gmtime_r (&unix_time, &details);
  asctime_r (&details, dp);
  char * pos = index (dp, '\n');
  snprintf (pos, n - (pos - dp), " UTC");
  pos = index (dp, '\0') + 1;
  /* printf ("time is '%s', offset %ld\n", dp, pos - dp); */
  binary_time_to_buf (t, pos, n - (pos - dp));
  /* printf ("final time is '%s'\n", dp); */
  return TIMESTAMP_SIZE;
}

static int make_announcement (char * buffer, int n,
                              time_t send, time_t expiration, int hops,
                              char * key, int ksize,
                              char * source, int sbits,
                              char * dest, int dbits)
{
  if (n < ALLNET_HEADER_CLEAR_SIZE + TIMESTAMP_SIZE) {
    printf ("error: n %d should be at least %zd + %d\n",
            n, ALLNET_HEADER_CLEAR_SIZE, TIMESTAMP_SIZE);
    exit (1);
  }
  struct allnet_header_clear * hp = (struct allnet_header_clear *) buffer;
  char * dp = buffer + ALLNET_HEADER_CLEAR_SIZE;
  int sig_algo = ALLNET_SIGTYPE_NONE;
  int ssize = 0;
  int dsize = time_to_buf (send, dp, TIMESTAMP_SIZE);
  if (ksize > 0) {
    char * sig;
    ssize = sign (dp, TIMESTAMP_SIZE, key, ksize, &sig);
    if (ssize > 0) {
      int size = ALLNET_HEADER_CLEAR_SIZE + TIMESTAMP_SIZE + ssize + 2;
      if (size > n) {
        printf ("error, buffer size %d, wanted %d, not adding sig\n", n, size);
        ssize = 0;
      } else {
        sig_algo = ALLNET_SIGTYPE_RSA_PKCS1;
        char * sp = dp + dsize;
        memcpy (sp, sig, ssize);
        sp [ssize    ] = (ssize >> 8) & 0xff;
        sp [ssize + 1] = (ssize & 0xff);
        ssize += 2;
      }
      free (sig);
    }
  }

  hp->version = ALLNET_VERSION;
  hp->packet_type = ALLNET_TYPE_CLEAR;
  hp->hops = 0;
  hp->max_hops = hops;
  hp->src_nbits = ADDRESS_BITS;
  hp->dst_nbits = ADDRESS_BITS;
  hp->sig_algo = sig_algo;
  hp->pad = 0;
  memcpy (hp->source, source, ADDRESS_SIZE);
  memcpy (hp->destination, dest, ADDRESS_SIZE);
  binary_time_to_buf (expiration, hp->expiration, EXPIRATION_TIME_SIZE);
  return ALLNET_HEADER_CLEAR_SIZE + dsize + ssize;
}

static void announce (time_t interval, int sock,
                      int hops, char * key, int ksize,
                      char * source, int sbits, char * dest, int dbits)
{
  static int called_before = 0;
  struct timeval now;
  gettimeofday (&now, NULL);
  time_t announce_time = compute_next (now.tv_sec, interval, called_before);
  called_before = 0;   /* on next loop, don't send right away even if we
                          are on the same second */

  static char buffer [ALLNET_MTU];

  int blen = make_announcement (buffer, sizeof (buffer),
                                announce_time - TIMEBASE_DELTA,
                                announce_time + interval - TIMEBASE_DELTA,
                                hops, key, ksize, source, sbits, dest, dbits);

  wait_until (announce_time);

  /* send with fairly low priority */
  send_pipe_message (sock, buffer, blen, ONE_HALF);

  struct timeval tv;
  gettimeofday (&tv, NULL);
  printf ("sent at %ld.%06ld: ", tv.tv_sec, tv.tv_usec);
  print_buffer (buffer, blen, "packet", 36, 1);
}

int main (int argc, char ** argv)
{
  int hops = 10;
  if (argc > 1)
    hops = atoi (argv [1]);
  int interval = 3600;
  if (argc > 2)
    interval = atoi (argv [2]);
  char * name = "edo";
  if (argc > 3)
    name = argv [3];
  create_keys (name, "broadcast time server", 0);
  int sock = init_xtime ();
  char * key = NULL;
  char source [ADDRESS_SIZE];
  char dest [ADDRESS_SIZE];
  int sbits, dbits;
  char * printable;
  int ksize = get_my_privkey (&key, source, &sbits, dest, &dbits, &printable);
  if (ksize > 0)
    printf ("found %d-byte key file\n", ksize);
  else
    printf ("key not found, sending unsigned messages\n");
  while (1)
    announce (interval, sock, hops, key, ksize, source, sbits, dest, dbits);
}
