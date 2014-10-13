/* abc-ip.c: Bradcast abc messages onto a generic ip interface */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ifaddrs.h>
#include <net/if.h>           /* ifa_flags */
#include <sys/socket.h>       /* struct sockaddr */
#include <sys/time.h>         /* gettimeofday */

#include "lib/packet.h"       /* ALLNET_WIFI_PROTOCOL */
#include "lib/util.h"         /* delta_us */

#include "abc-iface.h"        /* sockaddr_t */

#include "abc-ip.h"

/* forward declarations */
static int abc_ip_init (const char * interface);
static int abc_ip_is_enabled ();
static int abc_ip_set_enabled (int state);
static int abc_ip_cleanup ();


abc_iface abc_iface_ip = {
  .iface_type = ABC_IFACE_TYPE_IP,
  .iface_type_args = NULL,
  .iface_sockfd = -1,
  .if_address = {},
  .bc_address = {},
  .init_iface_cb = abc_ip_init,
  .iface_on_off_ms = 0, /* assume always on iface */
  .iface_is_enabled_cb = abc_ip_is_enabled,
  .iface_set_enabled_cb = abc_ip_set_enabled,
  .iface_cleanup_cb = abc_ip_cleanup
};

static int abc_ip_is_enabled ()
{
  return 1;
}

static int abc_ip_set_enabled (int state)
{
  return 1;
}

/* returns 0 if the interface is not found, 1 otherwise */
static int abc_ip_init (const char * interface)
{
  struct ifaddrs * ifa;
  if (getifaddrs (&ifa) != 0) {
    perror ("getifaddrs");
    return 0;
  }
  struct ifaddrs * ifa_loop = ifa;
  while (ifa_loop != NULL) {
#ifndef __APPLE__  /* not sure how to do this for apple */
    if ((ifa_loop->ifa_addr->sa_family == AF_PACKET) &&
        (strcmp (ifa_loop->ifa_name, interface) == 0)) {
#ifdef TRACKING_TIME
      struct timeval start;
      gettimeofday (&start, NULL);
#endif /* TRACKING_TIME */
      int is_up = abc_ip_is_enabled ();
      printf ("abc-ip: interface is enabled: %s (%d)\n",
                is_up > 0 ? "yes" : "no", is_up);
      if (is_up == 0)
        abc_ip_set_enabled (1);

#ifdef TRACKING_TIME
      struct timeval midtime;
      gettimeofday (&midtime, NULL);
      long long mtime = delta_us (&midtime, &start);
#endif /* TRACKING_TIME */
      /* create the socket and initialize the address */
      abc_iface_ip.iface_sockfd = socket (AF_PACKET, SOCK_DGRAM, ALLNET_WIFI_PROTOCOL);
      abc_iface_ip.if_address = *((struct sockaddr_ll *) (ifa_loop->ifa_addr));
      if (bind (abc_iface_ip.iface_sockfd, (const struct sockaddr *) &abc_iface_ip.if_address, sizeof (sockaddr_t)) == -1)
        printf ("abc-ip: error binding interface %s, continuing without..\n", interface);
      if (ifa_loop->ifa_flags & IFF_BROADCAST) {
        abc_iface_ip.bc_address = *((struct sockaddr_ll *) (ifa_loop->ifa_broadaddr));
      } else if (ifa_loop->ifa_flags & IFF_POINTOPOINT) {
        abc_iface_ip.bc_address = *((struct sockaddr_ll *) (ifa_loop->ifa_dstaddr));
      } else {
        abc_iface_set_default_broadcast_address (&abc_iface_ip.bc_address);
        printf ("abc-ip: set default broadcast address on %s\n", interface);
      }
      abc_iface_ip.bc_address.sll_protocol = ALLNET_WIFI_PROTOCOL;  /* otherwise not set */
      abc_iface_ip.bc_address.sll_ifindex = abc_iface_ip.if_address.sll_ifindex;
      abc_iface_print_sll_addr (&abc_iface_ip.if_address, "interface address");
      abc_iface_print_sll_addr (&abc_iface_ip.if_address, "broadcast address");
      freeifaddrs (ifa);
      return 1;
    }
#endif /* __APPLE__ */
    ifa_loop = ifa_loop->ifa_next;
  }
  freeifaddrs (ifa);
  return 0;  /* interface not found */
}

static int abc_ip_cleanup () {
  return 1;
}
