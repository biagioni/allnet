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
 * When sending high priority data, I keep the radio on, and forward
 * all the data I can (within their time limit) to anyone who sends
 * me a beacon.
 *
 * I leave send mode as soon as I no longer have high priority data to send.
 *
 * In energy saving mode, the radio is turned on right before sending the
 * beacon.  If someone has contacted us during our beacon interval, and
 * sends us a beacon, we then send them our own queued data (even low
 * priority).  Either way, the radio is then turned off.
 * If we have low priority data to send, then once every 2/fraction cycles,
 * the radio is turned on for two full cycles, and during that time we
 * behave as if we had high priority data to send.
 *
 * packets are removed from the queue after being forwarded for at least
 * two basic cycles.
 *
 * to do: If the interface is on and connected to a wireless LAN, I never
 * enter send mode.  Instead, I use energy saving mode to receive once
 * every basic cycle, and transmit once every 200 cycles.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ifaddrs.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netpacket/packet.h>   /* sockaddr_ll */
#include <net/if.h>   		/* ifa_flags */

#include "packet.h"
#include "mgmt.h"
#include "lib/pipemsg.h"
#include "lib/priority.h"
#include "lib/util.h"
#include "lib/log.h"
#include "lib/pqueue.h"


/* we don't know how big messages will be on the interface until we get them */
#define MAX_RECEIVE_BUFFER	ALLNET_MTU

#define BASIC_CYCLE_SEC		5	/* 5s in a basic cycle */
/* a beacon time is 1/100 of a basic cycle */
#define	BEACON_MS		(BASIC_CYCLE_SEC * 1000 / 100)
/* maximum amount of time to wait for a beacon grant */
#define BEACON_MAX_COMPLETION_US	2000    /* 0.002s */

/* similar to system(3), but more control over what gets printed */
static int my_system (char * command)
{
  pid_t pid = fork ();
  if (pid < 0) {
    perror ("fork");
    printf ("error forking for command '%s'\n", command);
    return -1;
  }
  if (pid == 0) {   /* child */
    int num_args = 1;
    char * argv [100];
    char * p = command;
    int found_blank = 0;
    argv [0] = command;
    while (*p != '\0') {
      if (found_blank) {
        if (*p != ' ') {
          argv [num_args] = p;
          num_args++;
          found_blank = 0;
        }
      } else if (*p == ' ') {
        found_blank = 1;
        *p = '\0';
      }
      p++;
    }
    argv [num_args] = NULL;
/*
    printf ("executing ");
    char ** debug_p = argv;
    while (*debug_p != NULL) {
      printf ("%s ", *debug_p);
      debug_p++;
    }
    printf ("\n");
*/
    dup2 (1, 2);   /* make stderr be a copy of stdout */
    execvp (argv [0], argv);
    perror ("execvp");
    exit (1);
  }
  /* parent */
  int status;
  do {
    waitpid (pid, &status, 0);
  } while (! WIFEXITED (status));
/*
  printf ("child process (%s) exited, status is %d\n",
          command, WEXITSTATUS (status));
*/
  return (WEXITSTATUS (status));
}

/* return 1 if successful, 0 otherwise */
/* return 2 if failed, but returned status matches wireless_status */
static int if_command (char * basic_command, char * interface,
                       int wireless_status, char * fail_wireless,
                       char * fail_other)
{
  static int printed_success = 0;
  int size = strlen (basic_command) + strlen (interface) + 1;
  char * command = malloc (size);
  if (command == NULL) {
    printf ("abc: unable to allocate %d bytes for command:\n", size);
    printf (basic_command, interface);
    return 0;
  }
  snprintf (command, size, basic_command, interface);
  int sys_result = my_system (command);
  int max_print_success = 0;
#ifdef DEBUG_PRINT
  max_print_success = 4;
#endif /* DEBUG_PRINT */
  if ((sys_result != 0) || (printed_success++ < max_print_success))
    printf ("abc: result of calling '%s' was %d\n", command, sys_result);
  if (sys_result != 0) {
    if (sys_result != -1)
      printf ("abc: program exit status for %s was %d\n",
              command, sys_result);
    if (sys_result != wireless_status) {
      if (fail_other != NULL)
        printf ("abc: call to '%s' failed, %s\n", command, fail_other);
      else
        printf ("abc: call to '%s' failed\n", command);
    } else {
      printf ("abc: call to '%s' failed, %s\n", command, fail_wireless);
      return 2;
    }
    return 0;
  }
  return 1;
}

/* returns 1 if successful, 2 if already up, 0 for failure */
static int wireless_up (char * interface)
{
#ifdef DEBUG_PRINT
  printf ("abc: opening interface %s\n", interface);
#endif /* DEBUG_PRINT */
/* need to execute the commands:
      sudo iw dev $if set type ibss
      sudo ifconfig $if up
      sudo iw dev $if ibss join allnet 2412
 */
  char * mess = "probably a wired or configured interface";
  if (geteuid () != 0)
    mess = "probably need to be root";
  int r = if_command ("iw dev %s set type ibss", interface, 240,
                      "wireless interface not available for ad-hoc mode",
                      mess);
  if (r == 0)
    return 0;
  if (r == 2) /* already up, no need to bring up the interface */
    return 2;
  /* continue with the other commands, which should succeed */
  if (! if_command ("ifconfig %s up", interface, 0, NULL, NULL))
    return 0;
  r = if_command ("iw dev %s ibss join allnet 2412", interface,
                  142, "allnet ad-hoc mode already set", "unknown problem");
  /* if (r == 0)
    return 0; */
  if (r == 0)
    return 2;
  return 1;
}

/* returns 1 if successful, 0 for failure */
static int wireless_down (char * interface)
{
#ifdef DEBUG_PRINT
  printf ("taking down interface %s\n", interface);
#endif /* DEBUG_PRINT */
/* doesn't seem to be necessary or helpful
  if (! if_command ("iw dev %s set type managed", interface, NULL))
    return 0;
*/
  if (! if_command ("ifconfig %s down", interface, 0, NULL, NULL))
    return 0;
  return 1;
}

static void default_broadcast_address (struct sockaddr_ll * bc)
{
  bc->sll_family = AF_PACKET;
  bc->sll_protocol = ALLNET_WIFI_PROTOCOL;
  bc->sll_hatype = 1;   /* used? */
  bc->sll_pkttype = 0;  /* not used */
  bc->sll_halen = 6;
  bc->sll_addr [0] = 0xff;
  bc->sll_addr [1] = 0xff;
  bc->sll_addr [2] = 0xff;
  bc->sll_addr [3] = 0xff;
  bc->sll_addr [4] = 0xff;
  bc->sll_addr [5] = 0xff;
  printf ("set default broadcast address\n");
}

static void print_sll_addr (struct sockaddr_ll * a, char * desc)
{
  if (desc != NULL)
    printf ("%s: ", desc);
  if (a->sll_family != AF_PACKET) {
    printf ("unknown address family %d\n", a->sll_family);
    return;
  }
  printf ("proto %d, ha %d pkt %d halen %d ", a->sll_protocol, a->sll_hatype,
          a->sll_pkttype, a->sll_halen);
  int i;
  for (i = 0; i < a->sll_halen; i++) {
    if (i > 0) printf (":");
    printf ("%02x", a->sll_addr [0]);
  }
  if (desc != NULL)
    printf ("\n");
}

static unsigned long long int wireless_on_off_ms = 150;  /* default */
static unsigned long long int bits_per_s = 1000 * 1000;  /* 1Mb/s default */

/* returns -1 if the interface is not found */
/* returns 0 if the interface is off, and 1 if it is on already */
/* if returning 0 or 1, fills in the socket and the address */
/* to do: figure out how to set bits_per_s in init_wireless */
static int init_wireless (char * interface, int * sock,
                          struct sockaddr_ll * address, struct sockaddr_ll * bc)
{
  struct ifaddrs * ifa;
  if (getifaddrs (&ifa) != 0) {
    perror ("getifaddrs");
    exit (1);
  }
  struct ifaddrs * ifa_loop = ifa;
  while (ifa_loop != NULL) {
    if ((ifa_loop->ifa_addr->sa_family == AF_PACKET) &&
        (strcmp (ifa_loop->ifa_name, interface) == 0)) {
      struct timeval start;
      gettimeofday (&start, NULL);
      int is_up = wireless_up (interface);
      int in_use = (is_up == 2);
      if (is_up) {
        struct timeval midtime;
        gettimeofday (&midtime, NULL);
        long long mtime = delta_us (&midtime, &start);
        if (! in_use) {
          wireless_down (interface);
          struct timeval finish;
          gettimeofday (&finish, NULL);
          long long time = delta_us (&finish, &start);
          printf ("abc: %s is wireless, %lld.%03lld ms to turn on+off\n",
                  interface, time / 1000LL, time % 1000LL);
          printf ("  (%lld.%03lld ms to turn on)\n",
                  mtime / 1000LL, mtime % 1000LL);
          wireless_on_off_ms = time;
        }
        /* create the socket and initialize the address */
        *sock = socket (AF_PACKET, SOCK_DGRAM, ALLNET_WIFI_PROTOCOL);
        *address = *((struct sockaddr_ll *) (ifa_loop->ifa_addr));
        if (ifa_loop->ifa_flags & IFF_BROADCAST)
          *bc = *((struct sockaddr_ll *) (ifa_loop->ifa_broadaddr));
        else if (ifa_loop->ifa_flags & IFF_POINTOPOINT)
          *bc = *((struct sockaddr_ll *) (ifa_loop->ifa_dstaddr));
        else
          default_broadcast_address (bc);
        bc->sll_protocol = ALLNET_WIFI_PROTOCOL;  /* otherwise not set */
        print_sll_addr (address, "interface address");
        print_sll_addr (bc,      "broadcast address");
        freeifaddrs (ifa);
        return in_use;
      }
    }
    ifa_loop = ifa_loop->ifa_next;
  }
  freeifaddrs (ifa);
  return -1;  /* interface not found */
}

static void old_send_beacon (int fd, unsigned char * dest, int nbits, int hops,
                         struct sockaddr * addr, socklen_t addrlen, int ms)
{
  static struct timeval send_next = {0, 0};
  struct timeval now;
  gettimeofday (&now, NULL);
  if (send_next.tv_sec == 0)  /* seed the random number generator */
    srandom (now.tv_sec);
  else if (delta_us (&now, &send_next) == 0LL)   /* do not send yet */
    return;
  /* send the next beacon at a random time between 0.5s and 1.5s from now */
  set_time_random (&now, HALF_SECOND, ONE_SECOND + HALF_SECOND, &send_next);
/*
  printf ("%ld.%06ld sending beacon, next %ld.%06ld delta %lld.%06lld\n",
          now.tv_sec, now.tv_usec, send_next.tv_sec, send_next.tv_usec,
          delta_us (&send_next, &now) / US_PER_S,
          delta_us (&send_next, &now) % US_PER_S);
*/
  if (nbits > 8 * ADDRESS_SIZE)
    nbits = 8 * ADDRESS_SIZE; /* defensive programming, should not be needed */
  char buffer [ALLNET_BEACON_HEADER_SIZE (0)];
  int bhs = ALLNET_BEACON_HEADER_SIZE (0);
  /* by default, set all fields to zero */
  bzero (buffer, bhs);
  struct allnet_header * hp = (struct allnet_header *) buffer;
  struct allnet_header_mgmt * mp =
    (struct allnet_header_mgmt *) (buffer + ALLNET_HEADER_SIZE);
  struct allnet_mgmt_beacon * bp =
    (struct allnet_mgmt_beacon *) (buffer + ALLNET_MGMT_HEADER_SIZE (0));
  hp->version = ALLNET_VERSION;
  hp->message_type = ALLNET_TYPE_MGMT;
  hp->max_hops = hops;
  hp->dst_nbits = nbits;
  if (nbits > 0)
    memcpy (hp->destination, dest, (nbits + 7) / 8);
  hp->sig_algo = ALLNET_SIGTYPE_NONE;
  mp->mgmt_type = ALLNET_MGMT_BEACON;
  random_bytes (bp->receiver_nonce, NONCE_SIZE);
  writeb32 (bp->awake_time, ms * 1000 * 1000);
  if (sendto (fd, buffer, bhs, MSG_DONTWAIT, addr, addrlen) < bhs)
    perror ("beacon sendto");
}

/* returns 1 if all is well, 0 if we need to exit */
static int inner_wireless_loop (int rpipe, int wpipe, int sockfd,
                                struct sockaddr * bc_sap, socklen_t addrlen,
                                int ms, char * interface)
{
  char * buffer;
  int priority;
  int fd;
  int r = receive_pipe_message_fd (ms, &buffer, sockfd, bc_sap,
                                   &addrlen, &fd, &priority);
  if (r < 0) {  /* one of the fds was closed, time to shut down */
    printf ("abc: pipe %d (%s) closed, shutting down\n",
            fd, (fd == sockfd) ? "raw socket" : "pipe from ad");
    return 0;
  }
  if (r == 0) {
    return 0;   /* timeout, quit the loop */
  }
  /* r > 0, got some data */
  if (fd == sockfd) {  /* send to ad */
    if (! send_pipe_message (wpipe, buffer, r, ONE_EIGHT)) {
      printf ("abc: unable to send message to ad, shutting down\n");
      return 0;
    }
  } else {  /* fd == rpipe */
/*    printf ("abc: ad message with %d bytes, priority ", r);
      print_fraction (priority, NULL);
      printf ("\n");
      print_buffer (buffer, r);
*/
    /* send the packet on the interface */
    int s = sendto (sockfd, buffer, r, MSG_DONTWAIT, bc_sap, addrlen);
    if (s < r)
      perror ("abc: sendto");
    int debug = 0;
    if ((s < r) || (debug)) {
      printf ("abc: sent %d bytes on interface %s, result %d\n",
              r, interface, s);
      /* print_sll_addr (&bc_address, NULL); */
    }
    if (s < r)
      return 0;
  }
  /* printf ("abc main loop freeing buffer %p\n", buffer); */
  free (buffer);
}

/* returns 1 if all is well, 0 if we need to exit */
static int inner_ad_loop (int rpipe, int ms, char ** pending_message,
                          int * message_size)
{
  char * buffer;
  int priority;
  int fd;
  /* only receiving packets from ad */
  int r = receive_pipe_message_any (ms, &buffer, &fd, &priority);
  if (r < 0) {  /* one of the fds was closed, time to shut down */
    printf ("abc: pipe %d (from ad?) closed, shutting down\n", fd);
    return 0;
  }
  if (r == 0)
    return 0;
  if (*pending_message != NULL)
    free (*pending_message);
  *pending_message = buffer;
  *message_size = r;
  if (priority >= THREE_QUARTERS)     /* worth waking up for */
    return 0;   /* start the "awake" time again */
  return 1;   /* repeat the loop */
}

static int timed_out (struct timeval * expiration, int * remaining_ms)
{
  struct timeval now;
  gettimeofday (&now, NULL);
  if ((now.tv_sec > expiration->tv_sec) ||
      ((now.tv_sec == expiration->tv_sec) &&
       (now.tv_usec >= expiration->tv_usec))) {
    *remaining_ms = 0;
    return 1;
  }
  *remaining_ms = (now.tv_sec  - expiration->tv_sec ) * 1000 +
                  (now.tv_usec - expiration->tv_usec) / 1000;
  return 0;
}

static void old_main_loop (int rpipe, int wpipe, char * interface)
{
  int sockfd;
  struct sockaddr_ll if_address; /* the address of the interface */
  struct sockaddr  * if_sap = (struct sockaddr *) (&if_address);
  struct sockaddr_ll bc_address; /* broacast address of the interface */
  struct sockaddr  * bc_sap = (struct sockaddr *) (&bc_address);
  socklen_t addrlen = sizeof (struct sockaddr_ll);
  int in_use;                    /* if in use, no need to bring up and down */

  /* init sockfd */
  in_use = init_wireless (interface, &sockfd, &if_address, &bc_address);
  if (in_use < 0) {
    snprintf (log_buf, LOG_SIZE,
              "unable to bring up interface %s, for now aborting\n", interface);
    log_print ();
    return;
  }
  add_pipe (rpipe);
  char * message_buffer = NULL;
  int message_size = 0;
#define BEACON_INTERVAL		100   /* 0.1 second */
#define INTER_BEACON_INTERVAL	(BEACON_INTERVAL * 99)   /* 9.9 seconds */
#define SEND_INTERVAL		(BEACON_INTERVAL * 101)  /* 990s, 16.5min */
#define SLEEP_INTERVAL		(BEACON_INTERVAL * 101)  /* 990s, 16.5min */
  while (1) {
    wireless_up (interface);
    add_pipe (sockfd);
    printf ("wireless interface %s is up\n", interface);
    if (message_buffer != NULL) {
      addrlen = sizeof (struct sockaddr_ll);
      if (sendto (sockfd, message_buffer, message_size, MSG_DONTWAIT,
                  bc_sap, addrlen) < message_size)
        perror ("pending message sendto");
      message_buffer = NULL;
      message_size = 0;
    }
    old_send_beacon (sockfd, NULL, 0, 1, bc_sap, addrlen, BEACON_INTERVAL);
    struct timeval now;
    gettimeofday (&now, NULL);
    int new_usec = now.tv_usec + BEACON_INTERVAL * 1000;
    struct timeval expire;
    expire.tv_sec = now.tv_sec + new_usec / 1000000;
    expire.tv_usec = new_usec % 1000000;
    int ms = BEACON_INTERVAL;
    while ((inner_wireless_loop (rpipe, wpipe, sockfd, bc_sap,
                                 sizeof (struct sockaddr_ll), ms,
                                 interface)) &&
           (! timed_out (&expire, &ms))) { 
    }
    wireless_down (interface);
    remove_pipe (sockfd);
    gettimeofday (&now, NULL);
    new_usec = now.tv_usec + SLEEP_INTERVAL * 1000;
    expire.tv_sec = now.tv_sec + new_usec / 1000000;
    expire.tv_usec = new_usec % 1000000;
    ms = SLEEP_INTERVAL;
    while ((inner_ad_loop (rpipe, ms, &message_buffer, &message_size)) &&
           (! timed_out (&expire, &ms))) { 
    }
  }
}

/* The state machine has two modes, high priority (keep interface on,
 * and send whenever possible) and low priority (turn on interface only
 * about 1% of the time to send or receive packets */
static int high_priority = 0;   /* start out in low priority mode */

/* when we receive high priority packets, we want to stay in high
 * priority mode one more cycle, in case there are any more packets to
 * receive */
/* todo: never set.  Should be set in handle_network_message */
/* todo: no connection between cycles and setting this.  Should probably
 * be reset in one_cycle */
static int received_high_priority = 0;

static int lan_is_on = 0; /* if on, we should never be in high priority mode */

static int sockfd_global = -1;  /* -1 means not initialized yet */
static int interface_is_on = 0;

static char my_beacon_rnonce [NONCE_SIZE];
static char my_beacon_snonce [NONCE_SIZE];
static char other_beacon_snonce [NONCE_SIZE];
static char other_beacon_rnonce [NONCE_SIZE];
static char zero_nonce [NONCE_SIZE];

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
  bzero (zero_nonce, NONCE_SIZE);
}

static int wireless_on (char * interface)
{
  if (! interface_is_on) {
    wireless_up (interface);
    interface_is_on = 1;
  }
  return sockfd_global;
}

static void wireless_off (char * interface)
{
  if (interface_is_on) {
    wireless_down (interface);
    interface_is_on = 0;
  }
}

/* sets the high priority variable, and turns on the interface if
 * we are now in high priority mode */
/* returns the sockfd if we are in high priority, and -1 otherwise */
static int check_priority_mode (char * interface)
{
  if ((! lan_is_on) && (! high_priority) &&
      ((received_high_priority) || (queue_max_priority () > ONE_HALF))) {
    /* enter high priority mode */
    high_priority = 1;
  } else if ((high_priority) &&
             ((lan_is_on) || ((! received_high_priority) &&
                              (queue_max_priority () <= ONE_HALF)))) {
    /* leave high priority mode */
    high_priority = 0;
  }
  if (high_priority)
    return wireless_on (interface);
  return -1;
}

static void jitter_deadline (struct timeval * t)
{
  struct timeval now;
  gettimeofday (&now, NULL);
  unsigned long long int delta = delta_us (t, &now);
  if (delta > 0) {
    *t = now;
    add_us (t, random () % delta);
  }
}

static void jitter_deadline_from_now (struct timeval * t, int us)
{
  struct timeval now;
  gettimeofday (&now, NULL);
  add_us (&now, random () % us);
  *t = now;
}

static void wait_until (struct timeval * t)
{
  do {
    struct timeval now;
    gettimeofday (&now, NULL);
    unsigned long long int wait = delta_us (t, &now);
    usleep (wait);
  } while (is_before (t));
}

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

  int msize = -1;
  if (sockfd >= 0) {
    msize = receive_pipe_message_fd (timeout_ms, message, sockfd, sap, &al,
                                     fd, priority);
  } else {
    msize = receive_pipe_message_any (timeout_ms, message, fd, priority);
  }
  if (msize < 0) /* error */
    return -1;
  return msize;  /* zero or positive, the value is correct */
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

static void send_beacon (int awake_ms, char * interface,
                         struct sockaddr * addr, socklen_t addrlen)
{
  int sockfd = wireless_on (interface);
  char buf [ALLNET_BEACON_HEADER_SIZE (0)];
  int size = ALLNET_BEACON_HEADER_SIZE (0);
  bzero (buf, size);
  struct allnet_header * hp = (struct allnet_header *) buf;
  struct allnet_header_mgmt * mp =
    (struct allnet_header_mgmt *) (buf + ALLNET_SIZE (0));
  struct allnet_mgmt_beacon * mbp =
    (struct allnet_mgmt_beacon *) (buf + ALLNET_MGMT_HEADER_SIZE (0));

  hp->version = ALLNET_VERSION;
  hp->message_type = ALLNET_TYPE_MGMT;
  hp->max_hops = 1;
  mp->mgmt_type = ALLNET_MGMT_BEACON;
  clear_nonces (1, 0);   /* mark new cycle -- should not be needed, but safe */
  random_bytes (my_beacon_rnonce, NONCE_SIZE);
  memcpy (mbp->receiver_nonce, my_beacon_rnonce, NONCE_SIZE);
  writeb64 (mbp->awake_time,
            ((unsigned long long int) awake_ms) * 1000LL * 1000LL);
  if (sendto (sockfd, buf, size, MSG_DONTWAIT, addr, addrlen) < size)
    perror ("beacon sendto");
}

static void make_beacon_reply (char * buffer, int bsize)
{
  if (bsize != ALLNET_MGMT_HEADER_SIZE (0) +
               sizeof (struct allnet_mgmt_beacon_reply)) {
    snprintf (log_buf, LOG_SIZE,
              "coding error in make_beacon_reply: expected %zd, got %d\n",
              ALLNET_MGMT_HEADER_SIZE (0) +
              sizeof (struct allnet_mgmt_beacon_reply), bsize);
    exit (1);
  }
  bzero (buffer, bsize);
  struct allnet_header * hp = (struct allnet_header *) buffer;
  struct allnet_header_mgmt * mp =
    (struct allnet_header_mgmt *) (buffer + ALLNET_SIZE (0));
  struct allnet_mgmt_beacon_reply * mbrp =
    (struct allnet_mgmt_beacon_reply *) (buffer + ALLNET_MGMT_HEADER_SIZE (0));
  hp->version = ALLNET_VERSION;
  hp->message_type = ALLNET_TYPE_MGMT;
  hp->max_hops = 1;
  mp->mgmt_type = ALLNET_MGMT_BEACON_REPLY;
  memcpy (mbrp->receiver_nonce, other_beacon_rnonce, NONCE_SIZE);
  random_bytes (other_beacon_snonce, NONCE_SIZE);
  memcpy (mbrp->sender_nonce, other_beacon_snonce, NONCE_SIZE);
}

static void make_beacon_grant (char * buffer, int bsize,
                               unsigned long long int send_time_ns)
{
  if (bsize != ALLNET_MGMT_HEADER_SIZE (0) +
               sizeof (struct allnet_mgmt_beacon_grant)) {
    snprintf (log_buf, LOG_SIZE,
              "coding error in make_beacon_grant: expected %zd, got %d\n",
              ALLNET_MGMT_HEADER_SIZE (0) +
              sizeof (struct allnet_mgmt_beacon_grant), bsize);
    exit (1);
  }
  bzero (buffer, bsize);
  struct allnet_header * hp = (struct allnet_header *) buffer;
  struct allnet_header_mgmt * mp =
    (struct allnet_header_mgmt *) (buffer + ALLNET_SIZE (0));
  struct allnet_mgmt_beacon_grant * mbgp =
    (struct allnet_mgmt_beacon_grant *)
      (buffer + ALLNET_MGMT_HEADER_SIZE (0));
  hp->version = ALLNET_VERSION;
  hp->message_type = ALLNET_TYPE_MGMT;
  hp->max_hops = 1;
  mp->mgmt_type = ALLNET_MGMT_BEACON_GRANT;
  memcpy (mbgp->receiver_nonce, my_beacon_rnonce, NONCE_SIZE);
  memcpy (mbgp->sender_nonce  , my_beacon_snonce, NONCE_SIZE);
  writeb64 (mbgp->send_time, send_time_ns);
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

/* return 1 if it is a beacon (not a regular packet), 0 otherwise */
/* sets *send_type to 1, *send_size to the message size, and send_message
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
                          int * send_type, int * send_size, char * send_message)
{
  *send_type = 0;  /* don't send anything unless we say otherwise */
  if (msize < ALLNET_HEADER_SIZE)
    return 0;
  struct allnet_header * hp = (struct allnet_header *) message;
  if (hp->message_type != ALLNET_TYPE_MGMT)
    return 0;
  if (msize < ALLNET_MGMT_HEADER_SIZE (hp->transport))
    return 0;
  struct allnet_header_mgmt * mp =
    (struct allnet_header_mgmt *) (message + ALLNET_SIZE (hp->transport));
  char * beaconp = message + ALLNET_BEACON_HEADER_SIZE (hp->transport);
  if (mp->mgmt_type == ALLNET_MGMT_BEACON) {
    if (*beacon_deadline != NULL)  /* already waiting for another grant */
      return 1;
    if (memcmp (other_beacon_rnonce, zero_nonce, NONCE_SIZE) != 0) /* same */
      return 1;
    struct allnet_mgmt_beacon * mbp = (struct allnet_mgmt_beacon *) beaconp;

    /* compute when to send the reply */
    unsigned long long int awake_us = readb64 (mbp->awake_time) / 1000LL;
    if (awake_us == 0)   /* not given, use 50ms */
      awake_us = 50 * 1000;
    struct timeval deadline;  /* send in the first 1/2 of the awake time */
    jitter_deadline_from_now (&deadline, awake_us / 2);
    if (delta_us (&deadline, quiet_end) > 0)  /* wait until deadline */
      *quiet_end = deadline;

    /* create the reply */
    memcpy (other_beacon_rnonce, mbp->receiver_nonce, NONCE_SIZE);
    *send_type = 1;
    *send_size = ALLNET_MGMT_HEADER_SIZE (0) +
                 sizeof (struct allnet_mgmt_beacon_reply);
    make_beacon_reply (send_message, ALLNET_MTU);

#if 0
    /* wait until the reply time, then send */
    wait_until (&deadline);
    /* others may issue beacon grants while we sleep.  Handling it would
     * require handling packets in wait_until, while if we do violate the
     * quiet time, it is not really the end of the world.  So here we
     * just wait until we have permission to send from any prior beacon
     * grants */
    wait_until (quiet_end);
    if (sendto (sockfd, reply, rsize, MSG_DONTWAIT, bc_addr, alen) < rsize)
      perror ("beacon reply sendto");
#endif /* 0*/

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
    make_beacon_grant (send_message, ALLNET_MTU, BEACON_MS * 1000LL * 1000LL);
#if 0
    char reply [ALLNET_MGMT_HEADER_SIZE (0) +
                sizeof (struct allnet_mgmt_beacon_grant)];
    int rsize = sizeof (reply);
    wait_until (quiet_end);
    if (sendto (sockfd, reply, rsize, MSG_DONTWAIT, bc_addr, alen) < rsize)
      perror ("beacon grant sendto");
#endif /* 0 */
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
        unsigned long long int send_ns = readb64 (mbgp->send_time);
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
        update_quiet (quiet_end, readb64 (mbgp->send_time) / 1000LL);
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

static void handle_ad_message (char * message, int msize, int priority,
                               int sockfd)
{
  if (msize >= ALLNET_HEADER_SIZE) {
    queue_add (message, msize, priority);
    remove_acks (message, message + msize);
  }
}

static void handle_network_message (char * message, int msize,
                                    int ad_pipe, int sockfd,
                                    struct timeval ** beacon_deadline,
                                    struct timeval * time_buffer,
                                    struct timeval * quiet_end,
                                    int * send_type, int * send_size,
                                    char * send_message)
{
  if (msize >= ALLNET_HEADER_SIZE) {
    if (! handle_beacon (message, msize, sockfd, beacon_deadline, time_buffer,
                         quiet_end, send_type, send_size, send_message)) {
      /* send the message to ad */
      send_pipe_message (ad_pipe, message, msize, ONE_HALF);
      /* remove any messages that this message acks */
      remove_acks (message, message + msize);
    }
  }
}

/* same as handle_until, but does not send any messages or change any
 * global state other than possibly quiet_end */
static void handle_quiet (struct timeval * quiet_end,
                          char * interface, int rpipe, int wpipe)
{
  int sockfd = check_priority_mode (interface);
  while (is_before (quiet_end)) {
    char * message;
    int fd;
    int priority;
    int msize = receive_until (quiet_end, &message, sockfd, &fd, &priority);
    int fake_type = 0;
    int fake_size = 0;
    static char fake_message [ALLNET_MTU];
    struct timeval * fake_timep;
    struct timeval fake_time;
    if (msize > 0) {
      if (fd == rpipe)
        handle_ad_message (message, msize, priority, sockfd);
      else
        handle_network_message (message, msize, wpipe, sockfd,
                                &fake_timep, &fake_time, quiet_end,
                                &fake_type, &fake_size, fake_message);
      free (message);
      /* see if priority has changed */
      sockfd = check_priority_mode (interface);
    }
  } 
}

/* handle incoming packets until time t.  Do not send before quiet_end */
static void handle_until (struct timeval * t, struct timeval * quiet_end,
                          char * interface, int rpipe, int wpipe,
                          struct sockaddr * bc_addr, socklen_t alen)
{
  int sockfd = check_priority_mode (interface);
  struct timeval * beacon_deadline = NULL;
  struct timeval time_buffer;   /* beacon_deadline sometimes points here */
  while (is_before (t)) {
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
        handle_ad_message (message, msize, priority, sockfd);
      else
        handle_network_message (message, msize, wpipe, sockfd,
                                &beacon_deadline, &time_buffer, quiet_end,
                                &send_type, &send_size, send_message);
      free (message);
      /* forward any pending messages */
      if (send_type != 0) {
        handle_quiet (quiet_end, interface, rpipe, wpipe);
        send_pending (send_type, send_size, send_message, sockfd,
                      bc_addr, alen);
      }
      /* see if priority has changed */
      sockfd = check_priority_mode (interface);
    }
    if ((beacon_deadline != NULL) && (! is_before (beacon_deadline))) {
      /* we have not been granted permission to send, allow new beacons */
      beacon_deadline = NULL;
      clear_nonces (0, 1); /* we have not been granted permission to send */
    }
  } 
}

/* sets bstart to a random time between bstart and
 * (bfinish - beacon_ms - extra_ms), and bfinish to beacon_ms ms later */
/* parameters are in ms (sec/1,000), computation is in us (sec/1,000,000) */
static void beacon_interval (struct timeval * bstart, struct timeval * bfinish,
                             struct timeval * start, struct timeval * finish,
                             int beacon_ms, int extra_ms)
{
  unsigned long long int interval_us = delta_us (finish, start);
  unsigned long long int beacon_us = beacon_ms * 1000LL;
  unsigned long long int at_end_us = beacon_us + (extra_ms * 1000LL);
  *bstart = *start;
  if (interval_us > at_end_us)
    set_time_random (start, 0LL, interval_us - at_end_us, bstart);
  *bfinish = *bstart;
  add_us (bfinish, beacon_us);
  printf ("b_int (%ld.%06ld, %ld.%06ld + %d, %d) => %ld.%06ld, %ld.%06ld\n",
          start->tv_sec, start->tv_usec, finish->tv_sec, finish->tv_usec,
          beacon_ms, extra_ms,
          bstart->tv_sec, bstart->tv_usec, bfinish->tv_sec, bfinish->tv_usec);
}

/* do one basic 5s cycle */
static void one_cycle (char * interface, int rpipe, int wpipe,
                       struct sockaddr * addr, socklen_t alen,
                       struct timeval * quiet_end)
{
  struct timeval start, finish, beacon_time, beacon_stop;
  gettimeofday (&start, NULL);
  finish.tv_sec = compute_next (start.tv_sec, BASIC_CYCLE_SEC, 0);
  finish.tv_usec = 0;
  beacon_interval (&beacon_time, &beacon_stop, &start, &finish,
                   BEACON_MS, wireless_on_off_ms * 2);

  clear_nonces (1, 1);   /* start a new cycle */

  handle_until (&beacon_time, quiet_end, interface, rpipe, wpipe, addr, alen);
  send_beacon (BEACON_MS, interface, addr, alen);
  handle_until (&beacon_stop, quiet_end, interface, rpipe, wpipe, addr, alen);
  /* clear_nonces (1, 0);  -- if we stay on, denying beacon replies is
   * not really helpful.  If we are off, we will get no beacon replies
   * anyway, so it doesn't matter */
  if (! high_priority)
    wireless_off (interface);
  handle_until (&finish, quiet_end, interface, rpipe, wpipe, addr, alen);
}

static void main_loop (char * interface, int rpipe, int wpipe)
{
  struct sockaddr_ll if_address; /* the address of the interface */
  struct sockaddr  * if_sap = (struct sockaddr *) (&if_address);
  struct sockaddr_ll bc_address; /* broacast address of the interface */
  struct sockaddr  * bc_sap = (struct sockaddr *) (&bc_address);

  struct timeval quiet_end;   /* should we keep quiet? */
  gettimeofday (&quiet_end, NULL);  /* not until we overhear a beacon grant */
  /* init sockfd and set two globals: &sockfd_global and interface_is_on */
  interface_is_on =
    init_wireless (interface, &sockfd_global, &if_address, &bc_address);
  if (interface_is_on < 0) {
    snprintf (log_buf, LOG_SIZE,
              "unable to bring up interface %s, for now aborting\n", interface);
    log_print ();
    return;
  }
  add_pipe (rpipe);      /* tell pipemsg that we want to receive from ad */
  /* check_priority_mode (interface); called by handle_until */
  while (1)
    one_cycle (interface, rpipe, wpipe, bc_sap, sizeof (struct sockaddr_ll),
               &quiet_end);
}

int main (int argc, char ** argv)
{
  init_log ("abc");
  queue_init (16 * 1024 * 1024);  /* 16MBi */
  if (argc != 4) {
    printf ("arguments must be a read pipe, a write pipe, and an interface\n");
    printf ("argc == %d\n", argc);
    return -1;
  }
  int rpipe = atoi (argv [1]);  /* read pipe */
  int wpipe = atoi (argv [2]);  /* write pipe */
  char * interface = argv [3];

  snprintf (log_buf, LOG_SIZE,
            "read pipe is fd %d, write pipe fd %d, interface is '%s'\n",
            rpipe, wpipe, interface);
  log_print ();
  main_loop (interface, rpipe, wpipe);
  snprintf (log_buf, LOG_SIZE, "end of abc (%s) main thread\n", interface);
  log_print ();
}
