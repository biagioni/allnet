/* abc-ip.c: Bradcast abc messages onto a generic ip interface */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ifaddrs.h>
#include <net/if.h>           /* ifa_flags */
#include <netinet/in.h>       /* struct sockaddr_in */
#include <netpacket/packet.h>
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

struct abc_iface_ip_priv {
  struct ifaddrs * ifa;
} abc_iface_ip_priv;

abc_iface abc_iface_ip = {
  .iface_type = ABC_IFACE_TYPE_IP,
  .iface_is_managed = 0,
  .iface_type_args = NULL,
  .iface_sockfd = -1,
  .if_address = {},
  .bc_address = {},
  .sockaddr_size = sizeof (struct sockaddr_in),
  .init_iface_cb = abc_ip_init,
  .iface_on_off_ms = 0, /* always on iface */
  .iface_is_enabled_cb = abc_ip_is_enabled,
  .iface_set_enabled_cb = abc_ip_set_enabled,
  .iface_cleanup_cb = abc_ip_cleanup,
  .priv = NULL
};

static int abc_ip_is_enabled ()
{
  return ((struct abc_iface_ip_priv *)abc_iface_ip.priv)->ifa->ifa_flags & IFF_UP;
}

static int abc_ip_set_enabled (int state)
{
  return 0;
}

/* returns 0 if the interface is not found, 1 otherwise */
static int abc_ip_init (const char * interface)
{
  abc_iface_ip.priv = &abc_iface_ip_priv;
  struct ifaddrs * ifa;
  if (getifaddrs (&ifa) != 0) {
    perror ("getifaddrs");
    return 0;
  }
  struct ifaddrs * ifa_loop = ifa;
  while (ifa_loop != NULL) {
    if ((ifa_loop->ifa_addr->sa_family == AF_INET) &&
        (strcmp (ifa_loop->ifa_name, interface) == 0)) {
      ((struct abc_iface_ip_priv *)abc_iface_ip.priv)->ifa = ifa_loop;
#ifdef TRACKING_TIME
      struct timeval start;
      gettimeofday (&start, NULL);
#endif /* TRACKING_TIME */
      if (abc_ip_is_enabled () == 0)
        abc_ip_set_enabled (1);
#ifdef TRACKING_TIME
      struct timeval midtime;
      gettimeofday (&midtime, NULL);
      long long mtime = delta_us (&midtime, &start);
#endif /* TRACKING_TIME */
      /* create the socket and initialize the address */
      abc_iface_ip.iface_sockfd = socket (AF_INET, SOCK_DGRAM, 0);
      int flag = 1;
      setsockopt (abc_iface_ip.iface_sockfd, SOL_SOCKET, SO_BROADCAST, &flag, sizeof (flag));
      abc_iface_ip.if_address.sa = *(ifa_loop->ifa_addr);
      abc_iface_ip.if_address.in.sin_port = htons (ALLNET_ABC_IP_PORT);
      if (bind (abc_iface_ip.iface_sockfd, &abc_iface_ip.if_address.sa, sizeof (struct sockaddr_in)) == -1)
        printf ("abc-ip: error binding interface %s, continuing without..\n", interface);
      if (ifa_loop->ifa_flags & IFF_BROADCAST) {
        abc_iface_ip.bc_address.sa = *(ifa_loop->ifa_broadaddr);
      } else {
        abc_iface_ip.bc_address.in.sin_addr.s_addr = inet_addr ("255.255.255.255");
        printf ("abc-ip: set default broadcast address on %s\n", interface);
      }
      abc_iface_ip.bc_address.in.sin_family = AF_INET;
      abc_iface_ip.bc_address.in.sin_port = htons (ALLNET_ABC_IP_PORT);
      memset (&abc_iface_ip.bc_address.in.sin_zero, 0, sizeof (abc_iface_ip.bc_address.in.sin_zero));
      freeifaddrs (ifa);
      return 1;
    }
    ifa_loop = ifa_loop->ifa_next;
  }
  freeifaddrs (ifa);
  return 0;  /* interface not found */
}

static int abc_ip_cleanup () {
  return 1;
}
