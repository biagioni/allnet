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
#include <pthread.h>

#include "lib/packet.h"
#include "lib/media.h"
#include "lib/util.h"
#include "lib/app_util.h"
#include "lib/pipemsg.h"
#include "lib/priority.h"
#include "lib/cipher.h"
#include "lib/keys.h"
#include "lib/log.h"

static int init_xtime (char * arg0)
{
  int sock = connect_to_local ("xtime", arg0);
  if (sock < 0)
    exit (1);
  return sock;
}

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
    if (n > 0)    /* ignore the message and recycle the storage */
      free (message);
    else          /* some error -- quit */
      return NULL;
  }
  return NULL;
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
#define TIMESTAMP_SIZE 	(25 + 4 + 8 +  /* ctime requires 26, plus " UTC" */ \
                         sizeof (struct allnet_app_media_header))
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
  struct allnet_app_media_header * amhp = (struct allnet_app_media_header *) dp;
  writeb32u (amhp->app, 0x7874696d /* xtim */ );
  writeb32u (amhp->media, ALLNET_MEDIA_TIME_TEXT_BIN);
  dp += sizeof (struct allnet_app_media_header);
  n -= sizeof (struct allnet_app_media_header);

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

/* returns -1 for errors, otherwise the size of the announcement */
static int make_announcement (char * buffer, int n,
                              time_t send, time_t expiration, int hops,
                              char * key, int ksize,
                              unsigned char * source, int sbits,
                              unsigned char * dest, int dbits)
{
  int hsize = ALLNET_SIZE (ALLNET_TRANSPORT_EXPIRATION);
  int h2size = sizeof (struct allnet_app_media_header);
  if (n < hsize + h2size + ALLNET_TIME_SIZE) {
    printf ("error: n %d should be at least %d + %d + %d\n",
            n, hsize, h2size, ALLNET_TIME_SIZE);
    exit (1);
  }
  /* the signature type will be changed later when we sign the message */
  struct allnet_header * hp =
    init_packet (buffer, n, ALLNET_TYPE_CLEAR, hops, ALLNET_SIGTYPE_NONE,
                 source, sbits, dest, dbits, NULL);
  if (hp == NULL) {
    snprintf (log_buf, LOG_SIZE, "error: unable to create announcement\n");
    log_print ();
    return -1;
  }
  hp->transport |= ALLNET_TRANSPORT_EXPIRATION;

  hsize = ALLNET_SIZE (hp->transport); /* there may be other transport fields */
  if (n < hsize + h2size + ALLNET_TIME_SIZE) {
    printf ("error2: n %d should be at least %d + %d + %d\n",
            n, hsize, h2size, ALLNET_TIME_SIZE);
    snprintf (log_buf, LOG_SIZE,
              "error: sizes %d + %d, buffer size %d\n", hsize, h2size, n);
    log_print ();
    return -1;
  }
  char * dp = buffer + hsize;

  int sig_algo = ALLNET_SIGTYPE_NONE;
  int ssize = 0;
  int dsize = time_to_buf (send, dp, TIMESTAMP_SIZE);
  if ((key != NULL) && (ksize > 0)) {
    char * sig;
    ssize = allnet_sign (dp, TIMESTAMP_SIZE, key, ksize, &sig);
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
                      unsigned char * source, int sbits,
                      unsigned char * dest, int dbits)
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
  if (blen <= 0) {
    printf ("unknown error: make_announcement returned %d\n", blen);
    snprintf (log_buf, LOG_SIZE,
              "make_announcement returned %d, aborting\n", blen);
    log_print ();
    exit (1);
  }

  wait_until (announce_time);

  /* send with fairly low priority */
  send_pipe_message (sock, buffer, blen, ALLNET_PRIORITY_LOCAL_LOW);

  struct timeval tv;
  gettimeofday (&tv, NULL);
  printf ("sent at %ld.%06ld: ", tv.tv_sec, tv.tv_usec);
  print_buffer (buffer, blen, "packet", 36, 1);
}

/* global debugging variable -- if 1, expect more debugging output */
/* set in main */
int allnet_global_debugging = 0;

int main (int argc, char ** argv)
{
  int verbose = get_option ('v', &argc, argv);
  if (verbose)
    allnet_global_debugging = verbose;

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
  struct bc_key_info * key = get_own_bc_key (address);
  if (key == NULL) {
    printf ("key '%s' not found\n", address);
    exit (1);
  }
  printf ("xtime: got %d-byte public, %d-byte private key, address %02x.%02x\n",
          key->pub_klen, key->priv_klen, key->address [0] & 0xff,
          key->address [1] & 0xff);
  
  int sock = init_xtime (argv [0]);
  pthread_t receive_thread;
  if (pthread_create (&receive_thread, NULL, receive_ignore, &sock) != 0) {
    perror ("xtime pthread_create/receive");
    return 1;
  }

  while (1)
    announce (interval, sock, hops, key->priv_key, key->priv_klen,
              key->address, ADDRESS_BITS, key->address, ADDRESS_BITS);
}
