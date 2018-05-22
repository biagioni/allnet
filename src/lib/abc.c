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
  if (! socket_add (sockets, s, 0, 0, 0)) {
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
  int i;
  for (i = 0; i < sockets->num_sockets; i++) {
    if (sockets->sockets [i].sockfd == s) {
      if (socket_address_add (sockets, sockets->sockets + i, sav) == NULL) {
        printf ("add_local_broadcast_sockets error adding socket address\n");
        return;
      }
    }
  }
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
    perror ("add_local_broadcast_sockets v6 bind");
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
  if (! socket_add (sockets, s, 0, 0, 0)) {
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
  int i;
  for (i = 0; i < sockets->num_sockets; i++) {
    if (sockets->sockets [i].sockfd == s) {
      if (socket_address_add (sockets, sockets->sockets + i, sav) == NULL) {
        printf ("add_local_broadcast_sockets error adding v6 socket address\n");
        return;
      }
    }
  }
}

int add_local_broadcast_sockets (struct socket_set * sockets)
{
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
  return (num_bc > 0);
}
