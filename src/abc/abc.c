/* abc.c: get allnet messages from ad, broadcast them to one interface */
/*        get allnet messages from the interface, forward them to ad */
/* abc stands for (A)llNet (B)road(C)ast */
/* single-threaded, uses select to check the pipe from ad and the interface */
/* must be run with supervisory privileges */
/* arguments are:
  - the fd number of the pipe from ad
  - the fd number of the pipe to ad
  - the interface name
 */
/* config file "abc" "interface-name" (e.g. ~/.allnet/abc/wlan0)
 * gives the maximum fraction of time the interface should be turned
 * on for allnet ad-hoc traffic.
 * if not found, the maximum fraction is 1 percent, i.e. 0.01
 * this fraction only applies to messages with priority <= 0.5.
 *
 * there is a 5s basic cycle and two modes:
 * - sending data I care about (priority greater than 0.5)
 * - energy saving mode
 *
 * In either mode, I send a beacon at a random point in time during
 * each cycle, then listen (for fraction * basic cycle time) for senders
 * to contact me.
 *
 * When sending high priority data, I keep the iface on, and forward
 * all the data I can (within their time limit) to anyone who sends
 * me a beacon.
 *
 * I leave send mode as soon as I no longer have high priority data to send.
 *
 * In energy saving mode, the iface is turned on right before sending the
 * beacon.  If someone has contacted us during our beacon interval, and
 * sends us a beacon, we then send them our own queued data (even low
 * priority).  Either way, the iface is then turned off.
 * If we have low priority data to send, then once every 2/fraction cycles,
 * the iface is turned on for two full cycles, and during that time we
 * behave as if we had high priority data to send.
 *
 * packets are removed from the queue after being forwarded for at least
 * two basic cycles.
 */

#include <assert.h>
#include <errno.h>
#include <signal.h>           /* signal */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>           /* usleep */
#include <sys/socket.h>       /* sockaddr */

#include "abc-iface.h"        /* sockaddr_t */
#include "abc-wifi.h"         /* abc_iface_wifi */
#include "../social.h"        /* UNKNOWN_SOCIAL_TIER */
#include "lib/mgmt.h"         /* struct allnet_mgmt_header */
#include "lib/log.h"
#include "lib/packet.h"       /* struct allnet_header */
#include "lib/pipemsg.h"      /* receive_pipe_message_fd, receive_pipe_message_any */
#include "lib/priority.h"     /* ALLNET_PRIORITY_FRIENDS_LOW */
#include "lib/util.h"         /* delta_us */
#include "lib/pqueue.h"       /* queue_max_priority */
#include "lib/sha.h"          /* sha512_bytes */


/* we don't know how big messages will be on the interface until we get them */
#define MAX_RECEIVE_BUFFER	ALLNET_MTU

#define BASIC_CYCLE_SEC		5	/* 5s in a basic cycle */
/* a beacon time is 1/100 of a basic cycle */
#define	BEACON_MS		(BASIC_CYCLE_SEC * 1000 / 100)
/* maximum amount of time to wait for a beacon grant */
#define BEACON_MAX_COMPLETION_US	2000    /* 0.002s */

/** exit flag set by TERM signal. Set by term_handler. */
static volatile sig_atomic_t term = 0;

static unsigned long long int bits_per_s = 1000 * 1000;  /* 1Mb/s default */

/* The state machine has two modes, high priority (keep interface on,
 * and send whenever possible) and low priority (turn on interface only
 * about 1% of the time to send or receive packets */
static int high_priority = 0;   /* start out in low priority mode */

/* when we receive high priority packets, we want to stay in high
 * priority mode one more cycle, in case there are any more packets to
 * receive */
static int received_high_priority = 0;

static int lan_is_on = 0; /* if on, we should never be in high priority mode */

static int sockfd_global = -1;  /* -1 means not initialized yet */

/* cycles we skipped because of interface activation delay.
 * This is also the number of cycles we leave the interface on
 * in low priority mode to compensate for the delay */
static unsigned if_cycles_skiped = 0;

static char my_beacon_rnonce [NONCE_SIZE];
static char my_beacon_snonce [NONCE_SIZE];
static char other_beacon_snonce [NONCE_SIZE];
static char other_beacon_rnonce [NONCE_SIZE];
static char zero_nonce [NONCE_SIZE];

/** array of broadcast interface types (wifi, ethernet, ...) */
static abc_iface * iface_types[] = {
  &abc_iface_wifi
};
/* must match length and order of iface_types[] */
static const char * iface_type_strings[] = {
  "wifi"
};
static abc_iface * iface = NULL; /* used interface ptr */

static void term_handler (int sig) {
  term = 1;
}

static void clear_nonces (int mine, int other)
{
  if (mine) {
    bzero (my_beacon_rnonce, NONCE_SIZE);
    bzero (my_beacon_snonce, NONCE_SIZE);
  }
  if (other) {
    bzero (other_beacon_rnonce, NONCE_SIZE);
    bzero (other_beacon_snonce, NONCE_SIZE);
  }
}

/**
 * sets the high priority variable
 * returns the sockfd if we are in high priority, and -1 otherwise
 */
static int check_priority_mode ()
{
  if ((! lan_is_on) && (! high_priority) &&
      ((received_high_priority) ||
       (queue_max_priority () >= ALLNET_PRIORITY_FRIENDS_LOW))) {
    /* enter high priority mode */
    high_priority = 1;
  } else if ((high_priority) &&
             ((lan_is_on) ||
              ((! received_high_priority) &&
               (queue_max_priority () < ALLNET_PRIORITY_FRIENDS_LOW)))) {
    /* leave high priority mode */
    high_priority = 0;
  }
  if (high_priority)
    return sockfd_global;
  return -1;
}

#ifdef WAIT_UNTIL_USED
static void wait_until (struct timeval * t)
{
  do {
    struct timeval now;
    gettimeofday (&now, NULL);
    unsigned long long int wait = delta_us (t, &now);
    usleep (wait);
  } while (is_before (t));
}
#endif /* WAIT_UNTIL_USED */

/* returns -1 in case of error, 0 for timeout, and message size otherwise */
/* may return earlier than t if a packet is received or there is an error */
/* if sockfd < 0, only receives from ad, otherwise from both ad and sockfd */
static int receive_until (struct timeval * t, char ** message, int sockfd,
                          int * fd, int * priority)
{
  struct timeval now;
  gettimeofday (&now, NULL);
  unsigned long long int us_to_wait = delta_us (t, &now);  /* 0 or more */
  int timeout_ms = us_to_wait / 1000LL;

  /* we don't actually care what address the packet was received from */
  struct sockaddr_storage recv_addr;
  struct sockaddr * sap = (struct sockaddr *) (&recv_addr);
  socklen_t al = sizeof (recv_addr);

  int msize;
  if (sockfd >= 0) {
    msize = receive_pipe_message_fd (timeout_ms, message, sockfd, sap, &al,
                                     fd, priority);
  } else {
    msize = receive_pipe_message_any (timeout_ms, message, fd, priority);
  }
  return msize;  /* -1 (error), zero (timeout) or positive, the value is correct */
}

static void update_quiet (struct timeval * quiet_end,
                          unsigned long long int quiet_us)
{
  /* do not allow a sender to monopolize the medium too easily */
  if (quiet_us > 50000)  /* 0.05s, 50ms */
    quiet_us = 50000;
  struct timeval new_quiet;
  gettimeofday (&new_quiet, NULL);
  add_us (&new_quiet, quiet_us);
  if (delta_us (&new_quiet, quiet_end) > 0)
    *quiet_end = new_quiet;
}

static void send_beacon (int awake_ms, const char * interface,
                         struct sockaddr * addr, socklen_t addrlen)
{
  char buf [ALLNET_BEACON_SIZE (0)];
  int size = sizeof (buf);
  bzero (buf, size);
  struct allnet_mgmt_header * mp =
    (struct allnet_mgmt_header *) (buf + ALLNET_SIZE (0));
  struct allnet_mgmt_beacon * mbp =
    (struct allnet_mgmt_beacon *) (buf + ALLNET_MGMT_HEADER_SIZE (0));

  init_packet (buf, size, ALLNET_TYPE_MGMT, 1, ALLNET_SIGTYPE_NONE,
               NULL, 0, NULL, 0, NULL);

  mp->mgmt_type = ALLNET_MGMT_BEACON;
  clear_nonces (1, 0);   /* mark new cycle -- should not be needed, but safe */
  random_bytes (my_beacon_rnonce, NONCE_SIZE);
  memcpy (mbp->receiver_nonce, my_beacon_rnonce, NONCE_SIZE);
  writeb64u (mbp->awake_time,
             ((unsigned long long int) awake_ms) * 1000LL * 1000LL);
  if (sendto (sockfd_global, buf, size, MSG_DONTWAIT, addr, addrlen) < size) {
    int e = errno;
    /* retry, first packet is sometimes dropped */
    if (sendto (sockfd_global, buf, size, MSG_DONTWAIT, addr, addrlen) < size) {
      perror ("beacon sendto (2nd try)");
      if (errno != e)
        printf ("...different error on 2nd try, first was %d\n", e);
    }
  }
}

static void make_beacon_reply (char * buffer, int bsize)
{
  assert (bsize >= ALLNET_MGMT_HEADER_SIZE (0) +
               sizeof (struct allnet_mgmt_beacon_reply));
  /* struct allnet_header * hp = */
  init_packet (buffer, bsize, ALLNET_TYPE_MGMT, 1, ALLNET_SIGTYPE_NONE,
               NULL, 0, NULL, 0, NULL);

  struct allnet_mgmt_header * mp =
    (struct allnet_mgmt_header *) (buffer + ALLNET_SIZE (0));
  struct allnet_mgmt_beacon_reply * mbrp =
    (struct allnet_mgmt_beacon_reply *) (buffer + ALLNET_MGMT_HEADER_SIZE (0));

  mp->mgmt_type = ALLNET_MGMT_BEACON_REPLY;
  memcpy (mbrp->receiver_nonce, other_beacon_rnonce, NONCE_SIZE);
  random_bytes (other_beacon_snonce, NONCE_SIZE);
  memcpy (mbrp->sender_nonce, other_beacon_snonce, NONCE_SIZE);
}

static void make_beacon_grant (char * buffer, int bsize,
                               unsigned long long int send_time_ns)
{
  assert (bsize >= ALLNET_MGMT_HEADER_SIZE (0) +
               sizeof (struct allnet_mgmt_beacon_grant));
  init_packet (buffer, bsize, ALLNET_TYPE_MGMT, 1, ALLNET_SIGTYPE_NONE,
               NULL, 0, NULL, 0, NULL);

  struct allnet_mgmt_header * mp =
    (struct allnet_mgmt_header *) (buffer + ALLNET_SIZE (0));
  struct allnet_mgmt_beacon_grant * mbgp =
    (struct allnet_mgmt_beacon_grant *)
      (buffer + ALLNET_MGMT_HEADER_SIZE (0));

  mp->mgmt_type = ALLNET_MGMT_BEACON_GRANT;
  memcpy (mbgp->receiver_nonce, my_beacon_rnonce, NONCE_SIZE);
  memcpy (mbgp->sender_nonce  , my_beacon_snonce, NONCE_SIZE);
  writeb64u (mbgp->send_time, send_time_ns);
}

/* if type is 1, sends the message */
/* if type is 2, sends the specified number of bytes from the queue,
 * ignoring message */
static void send_pending (int type, int size, char * message, int sockfd,
                          struct sockaddr * bc_addr, socklen_t alen)
{
  if (type == 1) {
    if (sendto (sockfd, message, size, MSG_DONTWAIT, bc_addr, alen) < size)
      perror ("sendto for type 1");
  } else if (type == 2) {
    int total_sent = 0;
    char * my_message = NULL;
    int nsize;
    int priority;
    while ((queue_iter_next (&my_message, &nsize, &priority)) &&
           (total_sent + nsize <= size)) {
      if (sendto (sockfd, my_message, nsize, MSG_DONTWAIT, bc_addr, alen)
            != nsize)
        perror ("sendto for type 2");
      total_sent += nsize;
    }
  } else if (type != 0) {
    printf ("error: send_pending type %d not supported\n", type);
  }
}

/* return 1 if message is a beacon (not a regular packet), 0 otherwise.
 * does no work, expect identifying packet type, when quiet is set.
 *
 * Sets *send_type to 1, *send_size to the message size, and send_message
 * (which must have size ALLNET_MTU) to the message to send, if there
 * is a message to be sent after the quiet time.
 * sets *send_type to 2, *send_size to the number of bytes that can be
 * sent if we have been granted permission to send that many bytes.
 * if there is nothing to send, sets *send_type to 0
 */
static int handle_beacon (char * message, int msize, int sockfd,
                          struct timeval ** beacon_deadline,
                          struct timeval * time_buffer,
                          struct timeval * quiet_end,
                          int * send_type, int * send_size, char * send_message,
                          int quiet)
{
  *send_type = 0;  /* don't send anything unless we say otherwise */
  struct allnet_header * hp = (struct allnet_header *) message;
  if (hp->message_type != ALLNET_TYPE_MGMT)
    return 0;
  if (msize < ALLNET_MGMT_HEADER_SIZE (hp->transport))
    return 0;
  if (quiet)
    return 1;
  struct allnet_mgmt_header * mp =
    (struct allnet_mgmt_header *) (message + ALLNET_SIZE (hp->transport));
  char * beaconp = message + ALLNET_BEACON_SIZE (hp->transport);
  if (mp->mgmt_type == ALLNET_MGMT_BEACON) {
    if (*beacon_deadline != NULL)  /* already waiting for another grant */
      return 1;
    if (memcmp (other_beacon_rnonce, zero_nonce, NONCE_SIZE) != 0) /* same */
      return 1;
    struct allnet_mgmt_beacon * mbp = (struct allnet_mgmt_beacon *) beaconp;

    /* compute when to send the reply */
    struct timeval now;
    gettimeofday (&now, NULL);
    unsigned long long awake_us = readb64u (mbp->awake_time) / 1000LL;
    unsigned long long quiet_end_us = delta_us (quiet_end, &now);
    long long int diff_us = awake_us - quiet_end_us;
    if (diff_us <= 0 && awake_us != 0) {
      /* reply instantly and violate silence period */
      diff_us = 0;
      *quiet_end = now;
    } else if (diff_us < 100000 && awake_us != 0) {
      /* send in first half */
      diff_us /= 2;
    } else {
      /* not given, unreasonable or irrelevant, assume 50-99ms / 2 */
      diff_us = 25000 + (random () % 24000);
    }

    if (diff_us)
      add_us (quiet_end, random () % diff_us);

    /* create the reply */
    memcpy (other_beacon_rnonce, mbp->receiver_nonce, NONCE_SIZE);
    *send_type = 1;
    *send_size = ALLNET_MGMT_HEADER_SIZE (0) +
                 sizeof (struct allnet_mgmt_beacon_reply);
    /* make the beacon which will be sent by caller (handle_until()) */
    make_beacon_reply (send_message, ALLNET_MTU);

    *beacon_deadline = time_buffer;
    gettimeofday (*beacon_deadline, NULL);
    add_us (*beacon_deadline, BEACON_MAX_COMPLETION_US);
    return 1;

  } else if (mp->mgmt_type == ALLNET_MGMT_BEACON_REPLY) {
    struct allnet_mgmt_beacon_reply * mbrp =
      (struct allnet_mgmt_beacon_reply *) beaconp;
    /* make sure we are in the right state.  We should have sent a beacon
     * (my_beacon_rnonce not zero) matching this reply, but we should not
     * yet have sent a grant (my_beacon_snonce should be zero) */
    if (memcmp (my_beacon_rnonce, zero_nonce, NONCE_SIZE) == 0)
      return 1;
    if (memcmp (mbrp->receiver_nonce, my_beacon_rnonce, NONCE_SIZE) != 0)
      return 1;
    if (memcmp (my_beacon_snonce, zero_nonce, NONCE_SIZE) != 0)
      return 1;
    /* grant this sender exclusive permission to send */
    memcpy (my_beacon_snonce, mbrp->sender_nonce, NONCE_SIZE);
    *send_type = 1;
    *send_size = ALLNET_MGMT_HEADER_SIZE (0) +
                 sizeof (struct allnet_mgmt_beacon_grant);
    /* make the beacon grant which will be sent by caller (handle_until()) */
    make_beacon_grant (send_message, ALLNET_MTU, BEACON_MS * 1000LL * 1000LL);
    return 1;
  } else if (mp->mgmt_type == ALLNET_MGMT_BEACON_GRANT) {
    struct allnet_mgmt_beacon_grant * mbgp =
      (struct allnet_mgmt_beacon_grant *) beaconp;
    /* make sure this is a grant for something we signed up for */
    if (memcmp (mbgp->receiver_nonce, other_beacon_rnonce, NONCE_SIZE) == 0) {
      if (memcmp (mbgp->sender_nonce, other_beacon_snonce, NONCE_SIZE) == 0) {
        /* granted to me, so send now */
        *send_type = 2;   /* send from the queue */
        unsigned long long int bytes_to_send = queue_total_bytes ();
        unsigned long long int send_ns = readb64u (mbgp->send_time);
        /* bytes/second = bits/second / 8
           bytes/nanosecond = bits/second / 8,000,000,000
           bytes I may send = ns I may send * bits/second / 8,000,000,000 */
        unsigned long long int may_send =
          bits_per_s * send_ns / (8 * 1000LL * 1000LL * 1000LL);
        if (bytes_to_send > may_send)
          bytes_to_send = may_send;
printf ("sending %lld (%d/%lld) bytes, max time is %lld ns, %lld b/s\n",
bytes_to_send, queue_total_bytes (), may_send, send_ns, bits_per_s);
        *send_size = bytes_to_send;
#if 0
        wait_until (quiet_end);  /* but only after a prior sender finishes */
        char * next = NULL;
        int nsize;
        int priority;
        while (queue_iter_next (&next, &nsize, &priority)) {
          if (sendto (sockfd, next, nsize, MSG_DONTWAIT, bc_addr, alen) < nsize)
            perror ("beacon data sendto");
        }
#endif /* 0 */
      } else { /* granted to somebody else, so start listening again */
        /* should keep quiet while they send */
        update_quiet (quiet_end, readb64u (mbgp->send_time) / 1000LL);
      }
      clear_nonces (0, 1);      /* be open to new beacon messages */
      *beacon_deadline = NULL;
    }
    return 1;
  }
  /* else: not a beacon packet */
  return 0;
}

static void remove_acked (char * ack)
{
  char hashed_ack [MESSAGE_ID_SIZE];
  sha512_bytes (ack, MESSAGE_ID_SIZE, hashed_ack, MESSAGE_ID_SIZE);
  char * element = NULL;
  int size;
  int priority;
  queue_iter_start ();
  while (queue_iter_next (&element, &size, &priority)) {
    if (size > ALLNET_HEADER_SIZE) {
      struct allnet_header * hp = (struct allnet_header *) element;
      char * message_id = ALLNET_MESSAGE_ID (hp, hp->transport, size);
      char * packet_id = ALLNET_PACKET_ID (hp, hp->transport, size);
      if (((message_id != NULL) &&
           (memcmp (hashed_ack, message_id, MESSAGE_ID_SIZE) == 0)) ||
          ((packet_id != NULL) &&
           (memcmp (hashed_ack, packet_id, MESSAGE_ID_SIZE) == 0))) {
        queue_iter_remove ();
      }
    }
  }
}

static void remove_acks (char * message, char * end)
{
  struct allnet_header * hp = (struct allnet_header *) message;
  if (hp->message_type == ALLNET_TYPE_ACK) {
    char * ack;
    for (ack = message + ALLNET_SIZE (hp->transport);
           ack < end; ack += MESSAGE_ID_SIZE)
      remove_acked (ack);
  }
}

static void handle_ad_message (char * message, int msize, int priority)
{
  queue_add (message, msize, priority);
  remove_acks (message, message + msize);
}

static void handle_network_message (char * message, int msize,
                                    int ad_pipe, int sockfd,
                                    struct timeval ** beacon_deadline,
                                    struct timeval * time_buffer,
                                    struct timeval * quiet_end,
                                    int * send_type, int * send_size,
                                    char * send_message, int quiet)
{
  if (! handle_beacon (message, msize, sockfd, beacon_deadline, time_buffer,
                       quiet_end, send_type, send_size, send_message, quiet)) {
    /* check for high-priority message */
    struct allnet_header * hp = (struct allnet_header *) message;
    int cacheable = ((hp->transport & ALLNET_TRANSPORT_DO_NOT_CACHE) == 0);
    int msgpriority = compute_priority (msize, hp->src_nbits, hp->dst_nbits,
                                        hp->hops, hp->max_hops,
                                        UNKNOWN_SOCIAL_TIER, 1, cacheable);
    if (msgpriority >= ALLNET_PRIORITY_DEFAULT_HIGH)
      received_high_priority = 1;

    /* send the message to ad */
    send_pipe_message (ad_pipe, message, msize, ALLNET_PRIORITY_EPSILON);
    /* remove any messages that this message acks */
    remove_acks (message, message + msize);
  }
}

/* same as handle_until, but does not send any messages or change any
 * global state other than possibly quiet_end */
static void handle_quiet (struct timeval * quiet_end,
                          const char * interface, int rpipe, int wpipe)
{
  int sockfd = check_priority_mode ();
  while (is_before (quiet_end) && !term) {
    char * message;
    int fd;
    int priority;
    int msize = receive_until (quiet_end, &message, sockfd, &fd, &priority);
    if ((msize > 0) && (is_valid_message (message, msize))) {
      if (fd == rpipe)
        handle_ad_message (message, msize, priority);
      else
        handle_network_message (message, msize, wpipe, sockfd,
                                NULL, NULL, NULL, NULL, NULL, NULL, 1);
      free (message);
      /* see if priority has changed */
      sockfd = check_priority_mode ();
    } else {
      usleep (10 * 1000); /* 10ms */
    }
  }
}

/* handle incoming packets until time t.  Do not send before quiet_end */
static void handle_until (struct timeval * t, struct timeval * quiet_end,
                          const char * interface, int rpipe, int wpipe,
                          struct sockaddr * bc_addr, socklen_t alen)
{
  int sockfd = check_priority_mode ();
  struct timeval * beacon_deadline = NULL;
  struct timeval time_buffer;   /* beacon_deadline sometimes points here */
  while (is_before (t) && !term) {
    char * message;
    int fd;
    int priority;
    struct timeval * deadline = t;
    if ((beacon_deadline != NULL) && (delta_us (t, beacon_deadline) > 0))
      deadline = beacon_deadline;
    int msize = receive_until (deadline, &message, sockfd, &fd, &priority);
    int send_type = 0;
    int send_size = 0;
    static char send_message [ALLNET_MTU];
    if (msize > 0) {
      if (fd == rpipe)
        handle_ad_message (message, msize, priority);
      else
        handle_network_message (message, msize, wpipe, sockfd,
                                &beacon_deadline, &time_buffer, quiet_end,
                                &send_type, &send_size, send_message, 0);
      free (message);
      /* forward any pending messages */
      if (send_type != 0) {
        handle_quiet (quiet_end, interface, rpipe, wpipe);
        send_pending (send_type, send_size, send_message, sockfd,
                      bc_addr, alen);
      }
      /* see if priority has changed */
      sockfd = check_priority_mode ();
    } else {
      usleep (10 * 1000); /* 10ms */
    }
    if ((beacon_deadline != NULL) && (! is_before (beacon_deadline))) {
      /* we have not been granted permission to send, allow new beacons */
      beacon_deadline = NULL;
      clear_nonces (0, 1); /* we have not been granted permission to send */
    }
  }
}

/* sets bstart to a random time between bstart and (bfinish - beacon_ms),
 * and bfinish to beacon_ms ms later
 * parameters are in ms, computation is in us (sec/1,000,000) */
static void beacon_interval (struct timeval * bstart, struct timeval * bfinish,
                             const struct timeval * start, const struct timeval * finish,
                             int beacon_ms)
{
  unsigned long long int interval_us = delta_us (finish, start);
  unsigned long long int beacon_us = beacon_ms * 1000LL;
  unsigned long long int at_end_us = beacon_us;
  *bstart = *start;
  if (interval_us > at_end_us)
    set_time_random (start, 0LL, interval_us - at_end_us, bstart);
  *bfinish = *bstart;
  add_us (bfinish, beacon_us);
  printf ("b_int (%ld.%06ld, %ld.%06ld + %d) => %ld.%06ld, %ld.%06ld\n",
          start->tv_sec, start->tv_usec, finish->tv_sec, finish->tv_usec,
          beacon_ms,
          bstart->tv_sec, bstart->tv_usec, bfinish->tv_sec, bfinish->tv_usec);
}

/* do one basic 5s cycle */
static void one_cycle (const char * interface, int rpipe, int wpipe,
                       struct sockaddr * addr, socklen_t alen,
                       struct timeval * quiet_end)
{
  struct timeval if_off, if_on, start, finish, beacon_time, beacon_stop;
  if (if_cycles_skiped-- == 0) {
    gettimeofday (&if_off, NULL);
    /* enabling the iface might take some time causing us to miss a cycle */
    iface->iface_set_enabled_cb (1);
    gettimeofday (&if_on, NULL);

    unsigned long long ds = delta_us (&if_on, &if_off) / (1000LLU * 1000LLU);
    if_cycles_skiped = ds / BASIC_CYCLE_SEC;
    printf ("skipped %d\n", if_cycles_skiped);
  }

  gettimeofday (&start, NULL);
  finish.tv_sec = compute_next (start.tv_sec, BASIC_CYCLE_SEC, 0);
  finish.tv_usec = 0;
  beacon_interval (&beacon_time, &beacon_stop, &start, &finish, BEACON_MS);

  clear_nonces (1, 1);   /* start a new cycle */

  handle_until (&beacon_time, quiet_end, interface, rpipe, wpipe, addr, alen);
  send_beacon (BEACON_MS, interface, addr, alen);
  handle_until (&beacon_stop, quiet_end, interface, rpipe, wpipe, addr, alen);
  /* clear_nonces (1, 0);  -- if we stay on, denying beacon replies is
   * not really helpful.  If we are off, we will get no beacon replies
   * anyway, so it doesn't matter */
  if (! high_priority && if_cycles_skiped == 0) /* skipped cycle compensation */
    iface->iface_set_enabled_cb (0);
  handle_until (&finish, quiet_end, interface, rpipe, wpipe, addr, alen);
  received_high_priority = 0;
}

static void main_loop (const char * interface, int rpipe, int wpipe)
{
  sockaddr_t if_address; /* the address of the interface */
  sockaddr_t bc_address; /* broacast address of the interface */
  struct sockaddr  * bc_sap = (struct sockaddr *) (&bc_address);

  struct timeval quiet_end;   /* should we keep quiet? */
  gettimeofday (&quiet_end, NULL);  /* not until we overhear a beacon grant */
  /* init sockfd and set global variable sockfd_global */
  if (!iface->init_iface_cb (interface, &sockfd_global, &if_address, &bc_address)) {
    snprintf (log_buf, LOG_SIZE,
              "abc: unable to initialize interface %s\n", interface);
    log_print ();
    goto iface_cleanup;
  }
  int is_on = iface->iface_is_enabled_cb ();
  if ((is_on < 0) || ((is_on == 0) && (iface->iface_set_enabled_cb (1) != 1))) {
    snprintf (log_buf, LOG_SIZE,
              "abc: unable to bring up interface %s\n", interface);
    log_print ();
    goto iface_cleanup;
  }
  add_pipe (rpipe);      /* tell pipemsg that we want to receive from ad */
  bzero (zero_nonce, NONCE_SIZE);
  while (!term)
    one_cycle (interface, rpipe, wpipe, bc_sap, sizeof (sockaddr_t), &quiet_end);

iface_cleanup:
  iface->iface_cleanup_cb ();
}

void abc_main (int rpipe, int wpipe, const char * interface,
                const char * iface_type, const char * iface_type_args)
{
  init_log ("abc");
  queue_init (16 * 1024 * 1024);  /* 16MBi */

  if (iface_type != NULL) {
    int i;
    for (i = 0; i < sizeof (iface_types); ++i) {
      if (strcmp (iface_type_strings[i], iface_type) == 0) {
        iface = iface_types[i];
        iface->iface_type_args = iface_type_args;
        break;
      }
    }
  }
  if (iface == NULL)
    iface = iface_types[0];

  snprintf (log_buf, LOG_SIZE,
            "read pipe is fd %d, write pipe fd %d, interface is '%s'\n",
            rpipe, wpipe, interface);
  log_print ();
  struct sigaction sa;
  sa.sa_handler = term_handler;
  sa.sa_flags = 0;
  sigemptyset (&sa.sa_mask);
  sigaction (SIGINT, &sa, NULL);
  sigaction (SIGTERM, &sa, NULL);
  main_loop (interface, rpipe, wpipe);
  snprintf (log_buf, LOG_SIZE, "end of abc (%s) main thread\n", interface);
  log_print ();
}

#ifndef NO_MAIN_FUNCTION
/* global debugging variable -- if 1, expect more debugging output */
/* set in main */
int allnet_global_debugging = 0;

int main (int argc, char ** argv)
{
  int verbose = get_option ('v', &argc, argv);
  if (verbose)
    allnet_global_debugging = verbose;

  if (argc != 4) {
    printf ("arguments must be a read pipe, a write pipe, and an interface\n");
    printf ("argc == %d\n", argc);
    print_usage (argc, argv, 0, 1);
    return -1;
  }
  int rpipe = atoi (argv [1]);  /* read pipe */
  int wpipe = atoi (argv [2]);  /* write pipe */
  const char * interface = argv [3];
  const char * iface_type = (argc > 3 ? argv [4] : NULL);
  const char * iface_type_args = (argc > 4 ? argv [5] : NULL);
  abc_main (rpipe, wpipe, interface, iface_type, iface_type_args);
  return 1;
}
#endif /* NO_MAIN_FUNCTION */
