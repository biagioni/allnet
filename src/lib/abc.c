/* abc.c: broadcast messages on local interfaces */
/* wireless interfaces are placed in ad-hoc mode if they are up,
 * but there is no IP address assigned to them */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/wait.h>    /* waitpid */
#include <arpa/inet.h>   /* inet_pton */

#include "abc.h"
#include "util.h"
#include "sockets.h"
#include "ai.h"

#ifdef TEST_ABC_ADHOC
#define DEBUG_PRINT
#endif /* TEST_ABC_ADHOC */


#ifdef ALLNET_NETPACKET_SUPPORT
#include <ifaddrs.h>
#include <net/if.h>      /* IFF_ values */
#include <linux/if_packet.h>
#endif /* ALLNET_NETPACKET_SUPPORT */

static void add_v4 (struct socket_set * sockets,
                    struct sockaddr_storage * bc_addrs, int num_bc)
{
  int s = socket (PF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (s < 0) {
    perror ("add_local_broadcast_sockets v4 socket");
    return;
  }
#ifdef DEBUG_PRINT
  printf ("add_v4 created socket %d, %d broadcast addresses\n", s, num_bc);
#endif /* DEBUG_PRINT */
  /* first bind the socket to the local port */
  struct sockaddr_in sin;
  memset (&sin, 0, sizeof (sin));
  sin.sin_family = AF_INET;
  sin.sin_port = htons (ALLNET_IPV4_BROADCAST_PORT);
  sin.sin_addr.s_addr = INADDR_ANY;
  socklen_t alen = sizeof (sin);
#ifdef DEBUG_PRINT
  print_buffer (&sin, 16, "bind address", 16, 1);
#endif /* DEBUG_PRINT */
  if (bind (s, (struct sockaddr *) (&sin), alen) != 0) {
    if (errno != EADDRINUSE)
      perror ("add_local_broadcast_sockets v4 bind");
    close (s);
    return;
  }
  int bc = 1;     /* enable broadcasts */
  setsockopt (s, SOL_SOCKET, SO_BROADCAST, &bc, sizeof(bc));
  int hops = 1;  /* set outgoing ttl to 1 */
  if (setsockopt (s, IPPROTO_IP, IP_TTL, &hops, sizeof(hops)))
    perror ("add_local_broadcast_sockets v4 setsockopt hops");
  if (! socket_add (sockets, s, 0, 0, 0, 1)) {
    printf ("add_local_broadcast_sockets unable to add socket %d\n", s);
    return;
  }
  int i;
  for (i = 0; i < num_bc; i++) {
    struct socket_address_validity sav =
      {  .alen = alen, .alive_rcvd = 0, .alive_sent = 0, .time_limit = 0,
         .recv_limit = 0, .send_limit = 0, .send_limit_on_recv = 0 };
    memset (&(sav.keepalive_auth), 0, sizeof (sav.keepalive_auth));
    memset (&(sav.addr), 0, sizeof (sav.addr));
    memcpy (&(sav.addr), bc_addrs + i, sizeof (struct sockaddr_in));
    ((struct sockaddr_in *) (&sav.addr))->sin_port =
      htons (ALLNET_IPV4_BROADCAST_PORT);
#ifdef DEBUG_PRINT
    printf ("interface %d has broadcast address ", i);
    socklen_t alen = sizeof (struct sockaddr_in);
    print_sockaddr ((struct sockaddr *) (bc_addrs + i), alen);
    printf ("\n");
#endif /* DEBUG_PRINT */
    if (socket_address_add (sockets, s, sav) == NULL)
      printf ("add_local_broadcast_sockets error adding socket address\n");
  }
}

#if 0  /* I think we have to bind to one interface per address! */
/* if possible, we should bind to a local IPv6 adddress, rather than
 * the generic in6addr_any.  Otherwise, the address from which we
 * send may change over time, which leads to problems with authentication */
static struct in6_addr get_local_ipv6_address ()
{
  struct in6_addr result = in6addr_any;
  struct interface_addr * interfaces = NULL;
  int n = interface_addrs (&interfaces);
  if ((interfaces == NULL) || (n <= 0)) {
    if (interfaces != NULL)
      free (interfaces);
    return result;
  }
  int i;
  for (i = 0; i < n; i++) {
    if ((! interfaces [i].is_loopback) && (! interfaces [i].is_broadcast)) {
      int j;
      for (j = 0; j < interfaces [i].num_addresses; j++) {
        if (interfaces [i].addresses [j].ss_family == AF_INET6) {
          struct sockaddr_in6 * sin = 
            (struct sockaddr_in6 *) (&(interfaces [i].addresses [j]));
          result = sin.sin6_addr;
        }
      }
    }
  }
  if (interfaces != NULL)
    free (interfaces);
  return result;
}
#endif /* 0 */

static void add_v6 (struct socket_set * sockets)
{
  int s = socket (PF_INET6, SOCK_DGRAM, IPPROTO_UDP);
  if (s < 0) {
    perror ("add_local_broadcast_sockets v6 socket");
    return;
  }
#ifdef DEBUG_PRINT
  printf ("add_v6 created socket %d\n", s);
#endif /* DEBUG_PRINT */
  /* first bind the socket to the local port */
  struct sockaddr_in6 sin;
  memset (&sin, 0, sizeof (sin));
  sin.sin6_family = AF_INET6;
  sin.sin6_port = htons (ALLNET_IPV6_BROADCAST_PORT);
  sin.sin6_addr = in6addr_any;
  socklen_t alen = sizeof (sin);
  if (bind (s, (struct sockaddr *) (&sin), alen) != 0) {
#ifdef DEBUG_PRINT  /* a normal error when the v4 socket shares with v6 */
    perror ("add_local_broadcast_sockets v6 bind");
#endif /* DEBUG_PRINT */
    close (s);
    return;
  }
  int mhops = 1;   /* set outgoing max hops to 1 */
  if (setsockopt (s, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &mhops, sizeof(mhops)))
    perror ("add_local_broadcast_sockets v6 setsockopt multicast hops");
  /* tell the OS that we are interested in multicast packets */
  struct in6_addr mcast;
  memset (&mcast, 0, sizeof (mcast));
  inet_pton (AF_INET6, ALLNET_IPV6_MCAST, &mcast);
  struct ipv6_mreq mreq = { .ipv6mr_multiaddr = mcast,
                            .ipv6mr_interface = 0 };
  if (setsockopt (s, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq, sizeof(mreq))) {
    if ((errno == ENODEV) ||
        (errno == EADDRNOTAVAIL)) {
      /* cannot join the group, do not add the socket */
#ifdef DEBUG_PRINT
      printf ("disabling ipv6 multicast on local networks\n");
#endif /* DEBUG_PRINT */
      close (s);
      return;
    }
    perror ("add_local_broadcast_sockets v6 setsockopt multicast receive");
  }
  if (! socket_add (sockets, s, 0, 0, 0, 1)) {
    printf ("add_local_broadcast_sockets unable to add v6 socket %d\n", s);
    close (s);
    return;
  }
  struct socket_address_validity sav =
    {  .alen = alen, .alive_rcvd = 0, .alive_sent = 0, .time_limit = 0,
       .recv_limit = 0, .send_limit = 0, .send_limit_on_recv = 0 };
  memset (&(sav.keepalive_auth), 0, sizeof (sav.keepalive_auth));
  memset (&(sav.addr), 0, sizeof (sav.addr));
  struct sockaddr_in6 * sinp = (struct sockaddr_in6 *) (&sav.addr);
  sinp->sin6_family = AF_INET6;
  sinp->sin6_addr = mcast;
  sinp->sin6_port = htons (ALLNET_IPV6_BROADCAST_PORT);
  if (socket_address_add (sockets, s, sav) == NULL)
    printf ("add_local_broadcast_sockets error adding v6 socket address\n");
}

#ifdef ALLNET_NETPACKET_SUPPORT

static int is_routable_ipv6 (struct sockaddr * addr)
{
  if (addr->sa_family != AF_INET6)
    return 0;
  struct sockaddr_in6 * sin = (struct sockaddr_in6 *) addr;
  if (memget (sin->sin6_addr.s6_addr, 0, 8)) /* begins with 8 zero bytes */
    return 0;
  if ((sin->sin6_addr.s6_addr [0] == 0xfe) || /* link-local address */
      (sin->sin6_addr.s6_addr [0] == 0xff))   /* multicast address */
    return 0;
  return 1;
}

static int has_ip_address (const char * name, const struct ifaddrs * ifa)
{
  const struct ifaddrs * ifa_loop = ifa;
  while (ifa_loop != NULL) {
    if ((strcmp (name, ifa_loop->ifa_name) == 0) &&
        ((ifa_loop->ifa_addr->sa_family == AF_INET) ||
         (is_routable_ipv6 (ifa_loop->ifa_addr))))
      return 1;
    ifa_loop = ifa_loop->ifa_next;
  }
  return 0;
}

static void broadcast_addr (const char * ifname, const struct ifaddrs * ifa,
                            struct socket_address_validity * sav)
{ 
  /* initialize all fields to 0 */
  memset (sav, 0, sizeof (struct socket_address_validity));
  const struct sockaddr_ll * ifsll = 
    (const struct sockaddr_ll *) (((ifa->ifa_flags & IFF_BROADCAST) != 0) ?
                                  (ifa->ifa_broadaddr) : (ifa->ifa_dstaddr));
  /* set the send address */
  sav->alen = sizeof (struct sockaddr_ll);
  struct sockaddr_ll * sll = (struct sockaddr_ll *) &(sav->addr);
  /* Setting 5 fields as specified by man 7 packet */
  sll->sll_family = AF_PACKET;
  sll->sll_protocol = allnet_htons (ALLNET_WIFI_PROTOCOL);
  sll->sll_ifindex = ifsll->sll_ifindex;
  sll->sll_halen = ifsll->sll_halen;
  memcpy (sll->sll_addr, ifsll->sll_addr, sizeof (sll->sll_addr));
}

/* similar to system(3), but suppresses output 
 * modifies 'command' by replacing blanks with null characters
 * returns -1 in case of error, and otherwise the exit status of the command */
static int my_system (char * command)
{
  pid_t pid = fork ();
  if (pid < 0) {
    perror ("fork");
    printf ("error forking command '%s'\n", command);
    return -1;
  }
  if (pid == 0) {   /* child, actually execute the command */
    int num_args = 1;
#define MAX_ARGS	1000
    char * argv [MAX_ARGS];
    char * p = command;
    int found_blank = 0;
    argv [0] = command;
    while ((*p != '\0') && (num_args + 1 < MAX_ARGS)) {
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
    if (num_args + 1 >= MAX_ARGS)
      printf ("error: reading beyond argv %d\n", num_args);
    else
      argv [num_args] = NULL;
    argv [MAX_ARGS - 1] = NULL;
#undef MAX_ARGS
#ifdef DEBUG_PRINT
    printf ("executing ");
    char ** debug_p = argv;
    while (*debug_p != NULL) {
      printf ("%s ", *debug_p);
      debug_p++;
    }
    printf ("\n");
    dup2 (1, 2);   /* make stderr be a copy of stdout */
#else /* DEBUG_PRINT */
    close (0);  /* close stdin */
    close (1);  /* close stdout */
    close (2);  /* close stderr */
#endif /* DEBUG_PRINT */
    execvp (argv [0], argv);
    perror ("execvp");
    exit (1);
  }
  /* parent */
  int status;
  do {
    waitpid (pid, &status, 0);
  } while (! WIFEXITED (status));
  return (WEXITSTATUS (status));
}

/**
 * Execute an iw command
 * @param basic_command Command with %s where interface is to be replaced
 * @param interface wireless interface (e.g. wlan0)
 * @param wireless_status alternate expected return status. If matched this
 *           function returns 2.
 * @param fail_wireless Error message when wireless_status is encountered
 *           (may be NULL)
 * @param fail_other Error message for unexpected errors or NULL.
 * @return 1 if successful (command returned 0), 2 if command status matches
 *           wireless_status, 0 otherwise */
static int if_command (const char * basic_command, const char * interface,
                       int wireless_status, const char * fail_wireless,
                       const char * fail_other)
{
  static int printed_success = 0;
  char command [1000];
  int ilen = 0;
  if (interface != NULL)
    ilen = (int)strlen (interface);
  if (strlen (basic_command) + ilen + 1 >= sizeof (command)) {
    printf ("abc.c: command %d+interface %d + 1 >= %d\n",
            (int) (strlen (basic_command)), ilen, (int) (sizeof (command)));
    printf (basic_command, interface);
    return 0;
  }
  if (interface != NULL)
    snprintf (command, sizeof (command), basic_command, interface);
  else
    snprintf (command, sizeof (command), "%s", basic_command);
  int sys_result = my_system (command);
  int max_print_success = 0;
#ifdef DEBUG_PRINT
  max_print_success = 4;
#endif /* DEBUG_PRINT */
  if ((sys_result == 0) && (printed_success++ < max_print_success))
    printf ("abc.c: result of calling '%s' was %d\n", command, sys_result);
  if (sys_result != 0) {
    if (sys_result != -1)
      printf ("if_command: program exit status for %s was %d, status %d\n",
              command, sys_result, wireless_status);
    if (sys_result != wireless_status) {
      if (fail_other != NULL)
        printf ("if_command: call to '%s' failed %d, %s\n",
                command, sys_result, fail_other);
      else
        printf ("if_command: call to '%s' failed %d\n", command, sys_result);
    } else {  /* sys_result == wireless_status */
      if (fail_wireless == NULL) {
        printf ("abc.c: result of calling '%s' was %d\n", command, sys_result);
      } else if (strlen (fail_wireless) > 0) {
        printf ("%s: %s\n", interface, fail_wireless);
      }
      return 2;
    }
    return 0;
  }
  return 1;
}

/*
sudo rfkill unblock wifi   -- should not be needed, but sometimes helpful
sudo iw dev wlan2 set type ibss
  -- 'sudo ifconfig wlan2 up' is not needed, since the interface is already up
sudo iw dev wlan2 ibss join 60:a4:4c:e8:bc:9c 2412 fixed-freq
  as SSID we use the MAC address of an existing Etherent card,
  which should not be in use by anyone else in the world
   see also https://wireless.wiki.kernel.org/en/users/documentation/iw/vif

esb@laptop:~/src/allnet/v3$ iw dev wlan2 info
Interface wlan2
	ifindex 2
	wdev 0x1
	addr 5c:f9:38:8f:ec:08
	ssid 60:a4:4c:e8:bc:9c
	type IBSS
	wiphy 0
*/

/* if this is a wireless interface and not already connected, start it */
static void start_wireless (const char * name, const struct ifaddrs * ifa)
{
  /* 2018/07/11: as far as I know, the wireless interfaces begin with w:
   * wlan, wlx, wlo, and likely more */
  if (name [0] != 'w')
    return;
  if (has_ip_address (name, ifa))
    return;
#ifdef DEBUG_PRINT
  printf ("(re)starting wireless for interface %s\n", name);
#endif /* DEBUG_PRINT */
  static char * mess = "unknown error";
  if (! if_command ("rfkill unblock wifi", NULL, 1, "", mess))
    printf ("rfkill failed\n");
  int iwret = if_command ("iw dev %s set type ibss", name, 240, "", mess);
  if (iwret == 2) { /* this happens if iface is up and in managed mode */
    printf ("bringing the interface %s down, then back up\n", name);
    /* so we bring the interface down and back up */
    if (! if_command ("ifconfig %s down", name, 0, NULL,
                      "unable to turn off interface"))
      return;
    if (! if_command ("iw dev %s set type ibss", name, 0, NULL, mess))
      return;
    if (! if_command ("ifconfig %s up", name, 255,
                      "interface already up", mess))
      return;
  }
/* it is better to leave first, in case it is set incorrectly -- otherwise
 * sometimes the next command fails but we are not on allnet */
  char * leave_cmd = "iw dev %s ibss leave";
  if (! if_command (leave_cmd, name, 67, "", mess)) {
    /* whether it succeeds or not, we are OK */
  }
#if 0
/* giving a specific BSSID (60:a4:4c:e8:bc:9c) on one trial sped up the
 * time to turn on the interface from over 5s to less than 1/2s, because
 * the driver no longer scans to see if somebody else is already offering
 * this ssid on a different bssid.  This also keeps different allnets
 * from trying to use different bssids, which prevents communication.
 * This BSSID is the MAC address of an existing Ethernet card,
 * so should not be in use by anyone else in the world. */
/* On the other hand, in 2019, using a fixed bssid caused the ad-hoc
 * to fail altogether, so disabled */
  char * cmd = "iw dev %s ibss join allnet 2412 fixed-freq 60:a4:4c:e8:bc:9c";
#endif /* 0 */
  char * cmd = "iw dev %s ibss join allnet 2412 fixed-freq";
  if (! if_command (cmd, name, 142, "interface already on allnet", mess))
    return;
}

static void add_adhoc (struct socket_set * sockets)
{
  int s = socket (AF_PACKET, SOCK_DGRAM, allnet_htons (ALLNET_WIFI_PROTOCOL));
  if (s < 0) {
    if ((geteuid () == 0) || (errno != EPERM)) {
      perror ("add_adhoc socket");
      printf ("unable to open ad-hoc socket, probably need to be root\n");
    }
    return;
  }
#ifdef DEBUG_PRINT
  printf ("add_adhoc created socket %d\n", s);
#endif /* DEBUG_PRINT */
  if (! socket_add (sockets, s, 0, 0, 0, 1)) {
    printf ("add_adhoc unable to add socket %d\n", s);
    close (s);
    return;
  }
  struct ifaddrs * ifa = NULL;
  if ((getifaddrs (&ifa) != 0) || (ifa == NULL)) {
    perror ("abc: getifaddrs");
    close (s);
    return;
  }
  struct ifaddrs * ifa_loop = ifa;
  while (ifa_loop != NULL) {
#ifdef DEBUG_PRINT
    printf ("ifa %s addr %p (%d), %x/%x,%x\n", ifa_loop->ifa_name,
            ifa_loop->ifa_addr, 
            ((ifa_loop->ifa_addr == NULL) ? 0 : ifa_loop->ifa_addr->sa_family),
            ifa_loop->ifa_flags, IFF_LOOPBACK, IFF_UP);
#endif /* DEBUG_PRINT */
/* only consider networks that are up, not loopback, and have a
 * hardware address */
    if ((ifa_loop->ifa_addr != NULL) &&
        (ifa_loop->ifa_addr->sa_family == AF_PACKET) &&
        ((ifa_loop->ifa_flags & IFF_LOOPBACK) == 0) &&
        ((ifa_loop->ifa_flags & IFF_UP) == IFF_UP)) {
      start_wireless (ifa_loop->ifa_name, ifa);
      struct socket_address_validity sav;
      broadcast_addr (ifa_loop->ifa_name, ifa_loop, &sav);
      if (socket_address_add (sockets, s, sav) == NULL)
        printf ("add_local_broadcast_sockets error adding adhoc address\n");
    }
    ifa_loop = ifa_loop->ifa_next;
  }
  freeifaddrs (ifa);
}
#endif /* ALLNET_NETPACKET_SUPPORT */

/* return 0 if this is a broadcast socket */
static int delete_bc (struct socket_address_set * sock, void * ref)
{
#ifdef DEBUG_PRINT
  if (sock->is_broadcast)
    printf ("delete_bc deleting socket %d\n", sock->sockfd);
#endif /* DEBUG_PRINT */
  if (sock->is_broadcast)
    return 0;  /* delete */
  return 1;    /* keep */
}

int add_local_broadcast_sockets (struct socket_set * sockets)
{
#ifdef DEBUG_PRINT
  print_socket_set (sockets);
#endif /* DEBUG_PRINT */
  /* start by deleting any previously added broadcast sockets */
  socket_sock_loop (sockets, &delete_bc, NULL);
  /* now add all broadcast addresses as appropriate */
  struct sockaddr_storage * bc_addrs = NULL;
  int num_bc = interface_broadcast_addrs (&bc_addrs);
  if (num_bc > 0)
    add_v4 (sockets, bc_addrs, num_bc);
  if (bc_addrs != NULL)
    free (bc_addrs);
  add_v6 (sockets);
#ifdef ALLNET_NETPACKET_SUPPORT
  add_adhoc (sockets);
#endif /* ALLNET_NETPACKET_SUPPORT */
  return (num_bc > 0);
}

#ifdef TEST_ABC_ADHOC
/* compile with: gcc -o test_adhoc -DTEST_ABC_ADHOC abc.c sockets.c util.c ai.c sha.c allnet_log.c */
int main (int argc, char ** argv)
{
  struct socket_set sockets = { .num_sockets = 0, .sockets = NULL };
  add_adhoc (&sockets);
  print_socket_set (&sockets);
  int timeout = 1000;   /* initial timeout is 1s */
  while (1) {
    static char buffer [SOCKET_READ_MIN_BUFFER];
    struct socket_read_result res = socket_read (&sockets, buffer, timeout, 1);
    if (res.success) {
      printf ("read a packet of size %d\n", res.msize);
    } else {
      printf ("timeout %3lld (%d)\n", allnet_time () % 1000, timeout / 1000);
      if (timeout < 3600 * 1000)
        timeout += timeout;   /* subsequent timeouts double each time */
      char message [32] = { 0x03, 0x07, 0x00, 0x01, };
      struct sockaddr_storage except;
      if (! socket_send_out (&sockets, message, sizeof (message), 1,
                             except, 0, NULL, NULL))
        print_buffer (message, sizeof (message), "unable to send", 10000, 1);
    }
  }
}
#endif /* TEST_ABC_ADHOC */
