/* abc.c: broadcast messages on local interfaces */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>   /* inet_pton */

#include "abc.h"
#include "util.h"
#include "sockets.h"
#include "ai.h"

#ifdef ALLNET_NETPACKET_SUPPORT
#include <ifaddrs.h>
#include <net/if.h>      /* IFF_ values */
#include <linux/if_packet.h>
#endif /* ALLNET_NETPACKET_SUPPORT */

static void add_v4 (struct socket_set * sockets, struct sockaddr_storage * a)
{
  int s = socket (PF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (s < 0) {
    perror ("add_local_broadcast_sockets v4 socket");
    return;
  }
  /* first bind the socket to the local port */
  struct sockaddr_in sin;
  memset (&sin, 0, sizeof (sin));
  sin.sin_family = AF_INET;
  sin.sin_port = htons (ALLNET_IPV4_BROADCAST_PORT);
  sin.sin_addr.s_addr = INADDR_ANY;
  socklen_t alen = sizeof (sin);
  if (bind (s, (struct sockaddr *) (&sin), alen) != 0) {
    if (errno != EADDRINUSE)
      perror ("add_local_broadcast_sockets v4 bind");
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
  struct socket_address_validity sav =
    {  .alen = alen, .alive_rcvd = 0, .alive_sent = 0, .time_limit = 0,
       .recv_limit = 0, .send_limit = 0, .send_limit_on_recv = 0 };
  memset (&(sav.addr), 0, sizeof (sav.addr));
  memcpy (&(sav.addr), a, sizeof (struct sockaddr_in));
  ((struct sockaddr_in *) (&sav.addr))->sin_port =
    htons (ALLNET_IPV4_BROADCAST_PORT);
  if (socket_address_add (sockets, s, sav) == NULL)
    printf ("add_local_broadcast_sockets error adding socket address\n");
}

static void add_v6 (struct socket_set * sockets)
{
  int s = socket (PF_INET6, SOCK_DGRAM, IPPROTO_UDP);
  if (s < 0) {
    perror ("add_local_broadcast_sockets v6 socket");
    return;
  }
  /* first bind the socket to the local port */
  struct sockaddr_in6 sin;
  memset (&sin, 0, sizeof (sin));
  sin.sin6_family = AF_INET6;
  sin.sin6_port = htons (ALLNET_IPV6_BROADCAST_PORT);
  sin.sin6_addr = in6addr_any;
  socklen_t alen = sizeof (sin);
  if (bind (s, (struct sockaddr *) (&sin), alen) != 0) {
    static int printed = 0;
    if (! printed)
      perror ("add_local_broadcast_sockets v6 bind");
    printed = 1;
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
  memset (&(sav.addr), 0, sizeof (sav.addr));
  struct sockaddr_in6 * sinp = (struct sockaddr_in6 *) (&sav.addr);
  sinp->sin6_family = AF_INET6;
  sinp->sin6_addr = mcast;
  sinp->sin6_port = htons (ALLNET_IPV6_BROADCAST_PORT);
  if (socket_address_add (sockets, s, sav) == NULL)
    printf ("add_local_broadcast_sockets error adding v6 socket address\n");
}

#ifdef ALLNET_NETPACKET_SUPPORT

/*
sudo rfkill unblock wifi
sudo ifconfig wlan2 up
sudo iw dev wlan2 ibss join allnet 2412 fixed-freq

esb@laptop:~/src/allnet/v3$ sudo iw dev wlan2 info

Interface wlan2
	ifindex 2
	wdev 0x1
	addr 5c:f9:38:8f:ec:08
	ssid allnet
	type IBSS
	wiphy 0
*/

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
  if (! socket_add (sockets, s, 0, 0, 0, 1)) {
    printf ("add_adhoc unable to add socket %d\n", s);
    close (s);
    return;
  }
  struct ifaddrs * ifa = NULL;
  if ((getifaddrs (&ifa) != 0) || (ifa == NULL)) {
    perror ("abc: getifaddrs");
    return;
  }
  struct ifaddrs * ifa_loop = ifa;
  while (ifa_loop != NULL) {
    if ((ifa_loop->ifa_addr != NULL) &&
        (ifa_loop->ifa_addr->sa_family == AF_PACKET) &&
        ((ifa_loop->ifa_flags & IFF_LOOPBACK) == 0)) {
static int printed = 0;
if (++printed < 10) { printf ("found interface %s, packet %x, bc %x ",
ifa_loop->ifa_name, AF_PACKET, ifa_loop->ifa_flags & IFF_BROADCAST);
print_buffer ((char *) (ifa->ifa_broadaddr), sizeof (struct sockaddr_ll),
              "bcast address", 20, 1); }
      struct sockaddr_ll * ifsll = 
        (struct sockaddr_ll *) (((ifa_loop->ifa_flags & IFF_BROADCAST) != 0) ?
                                (ifa->ifa_broadaddr) : (ifa->ifa_dstaddr));
      /* add a send address */
      struct socket_address_validity sav;
      memset (&sav, 0, sizeof (sav));  /* set all fields to 0 */
      sav.alen = sizeof (struct sockaddr_ll);
      struct sockaddr_ll * sll = (struct sockaddr_ll *) &(sav.addr);
      /* Setting 5 fields as specified by man 7 packet */
      sll->sll_family = AF_PACKET;
      sll->sll_protocol = allnet_htons (ALLNET_WIFI_PROTOCOL);
      sll->sll_ifindex = ifsll->sll_ifindex;
      sll->sll_halen = ifsll->sll_halen;
      if (sll->sll_halen <= sizeof (sll->sll_addr))
        memset (sll->sll_addr, 0xff, sll->sll_halen);
      if (socket_address_add (sockets, s, sav) == NULL)
        printf ("add_local_broacast_sockets error adding adhoc address\n");
    }
    ifa_loop = ifa_loop->ifa_next;
  }
  freeifaddrs (ifa);
printf ("addresses are:\n");
print_socket_set (sockets);
}
#endif /* ALLNET_NETPACKET_SUPPORT */

/* return 0 if this is a broadcast socket */
static int delete_bc (struct socket_address_set * sock, void * ref)
{
  if (sock->is_broadcast)
    return 0;  /* delete */
  return 1;    /* keep */
}

int add_local_broadcast_sockets (struct socket_set * sockets)
{
  /* start by deleting any previously added broadcast sockets */
  socket_sock_loop (sockets, &delete_bc, NULL);
  /* now add all broadcast addresses as appropriate */
  struct sockaddr_storage * bc_addrs = NULL;
  int num_bc = interface_broadcast_addrs (&bc_addrs);
  int i;
  for (i = 0; i < num_bc; i++) {
#ifdef DEBUG_PRINT
    printf ("interface %d has broadcast address ", i);
    socklen_t alen = sizeof (struct sockaddr_in);
    print_sockaddr ((struct sockaddr *) (bc_addrs + i), alen, 0);
    printf ("\n");
#endif /* DEBUG_PRINT */
    add_v4 (sockets, bc_addrs + i);
  }
  if ((num_bc > 0) && (bc_addrs != NULL))
    free (bc_addrs);
  add_v6 (sockets);
  add_adhoc (sockets);
  return (num_bc > 0);
}
