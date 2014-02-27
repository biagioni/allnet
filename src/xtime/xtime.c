/* xtime.c: send periodic (every hour, on the hour) time broadcast messages */
/* the first argument to the call is the key for signing messages */
/* the second argument determines how many hops the messages are sent */
/* if no argument is specified, the default is 10 hops */
/* the third argument is the time interval, default 1 hour */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "packet.h"
#include "lib/util.h"
#include "lib/app_util.h"
#include "lib/pipemsg.h"
#include "lib/priority.h"
#include "lib/cipher.h"
#include "lib/keys.h"

static int init_xtime ()
{
  int sock = connect_to_local ("xtime");
  if (sock < 0)
    exit (1);
  add_pipe (sock);
  return sock;
}

#if 0   /* now in util.c */
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
#endif /* 0 -- now in util.c */

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
#ifdef DEBUG_PRINT
  printf ("binary time %ld, dp is %p, n is %d\n", t, dp, n);
#endif /* DEBUG_PRINT */
  if (n < 8)
    return;
  unsigned long long int tll = t;
  writeb64 (dp, tll);
#ifdef DEBUG_PRINT
  printf ("time %lx, timestamp %02x.%02x.%02x.%02x.%02x.%02x.%02x.%02x\n", t,
          dp [0] & 0xff, dp [1] & 0xff, dp [2] & 0xff, dp [3] & 0xff,
          dp [4] & 0xff, dp [5] & 0xff, dp [6] & 0xff, dp [7] & 0xff);
#endif /* DEBUG_PRINT */
}

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
  time_t unix_time = t + ALLNET_Y2K_SECONDS_IN_UNIX;  /* restore unix time */
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
  if (n < ALLNET_HEADER_SIZE + ALLNET_TIME_SIZE) {
    printf ("error: n %d should be at least %zd + %d\n",
            n, ALLNET_HEADER_SIZE, ALLNET_TIME_SIZE);
    exit (1);
  }
  /* the signature type will be changed later when we sign the message */
  struct allnet_header * hp =
    init_packet (buffer, n, ALLNET_TYPE_CLEAR, hops, ALLNET_SIGTYPE_NONE,
                 source, sbits, dest, dbits, NULL);
  if (hp == NULL)
    return;
  hp->transport |= ALLNET_TRANSPORT_EXPIRATION;

  int hsize = ALLNET_SIZE (hp->transport);
  if (hsize > n) {
    printf ("error: header size %d, buffer size %d\n", hsize, n);
    return;
  }
  char * dp = buffer + hsize;

  int sig_algo = ALLNET_SIGTYPE_NONE;
  int ssize = 0;
  int dsize = time_to_buf (send, dp, TIMESTAMP_SIZE);
  if (sig_algo != ALLNET_SIGTYPE_NONE) {
    char * sig;
    ssize = sign (dp, TIMESTAMP_SIZE, key, ksize, &sig);
    if (ssize > 0) {
      int size = hsize + TIMESTAMP_SIZE + ssize + 2;
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
  hp->sig_algo = sig_algo;

  char * e = ALLNET_EXPIRATION(hp, hp->transport, n);
  if (e != NULL)
    binary_time_to_buf (expiration, e, ALLNET_TIME_SIZE);
  return hsize + dsize + ssize;
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
  bzero (buffer, sizeof (buffer));

  int blen = make_announcement (buffer, sizeof (buffer),
                                announce_time - ALLNET_Y2K_SECONDS_IN_UNIX,
                                announce_time + interval -
                                  ALLNET_Y2K_SECONDS_IN_UNIX,
                                hops, key, ksize, source, sbits, dest, dbits);

  wait_until (announce_time);

  /* send with fairly low priority */
  send_pipe_message (sock, buffer, blen, ALLNET_PRIORITY_LOCAL_LOW);

  struct timeval tv;
  gettimeofday (&tv, NULL);
  printf ("sent at %ld.%06ld: ", tv.tv_sec, tv.tv_usec);
  print_buffer (buffer, blen, "packet", 36, 1);
}

int main (int argc, char ** argv)
{
  int hops = 10;
  if (argc < 2) {
    printf ("%s: needs at least a signing address\n", argv [0]);
    exit (1);
  }
  char * address = argv [1];
  if (argc > 2)
    hops = atoi (argv [2]);
  int interval = 3600;
  if (argc > 3)
    interval = atoi (argv [3]);
  struct bc_key_info * key = get_own_key (address);
  if (key == NULL) {
    printf ("key '%s' not found\n", address);
    exit (1);
  }
  printf ("xtime: got %d-byte public, %d-byte private key, address %02x.%02x\n",
          key->pub_klen, key->priv_klen, key->address [0] & 0xff,
          key->address [1] & 0xff);
  
  int sock = init_xtime ();

  while (1)
    announce (interval, sock, hops, key->priv_key, key->priv_klen,
              key->address, ADDRESS_BITS, key->address, ADDRESS_BITS);
}
