/* abc-iw.c: Bradcast abc messages onto a wireless interface
 *
 * to do: If the interface is on and connected to a wireless LAN, I never
 * enter send mode.  Instead, I use energy saving mode to receive once
 * every basic cycle, and transmit once every 200 cycles.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ifaddrs.h>
#include <net/if.h>           /* ifa_flags */
#include <sys/socket.h>       /* struct sockaddr */
#include <sys/time.h>         /* gettimeofday */

#include "lib/packet.h"       /* ALLNET_WIFI_PROTOCOL */
#include "lib/util.h"         /* delta_us */

#include "abc-iface.h"        /* sockaddr_t, abc_iface_* */

#define NUM_WIFI_CONFIG_IFACES 1
#ifdef USE_NETWORK_MANAGER
#undef NUM_WIFI_CONFIG_IFACES /* get rid of redef. warning */
#define NUM_WIFI_CONFIG_IFACES 2
#include "abc-networkmanager.h"
#endif /* USE_NETWORK_MANAGER */

#include "abc-iw.h"
#include "abc-wifi.h"

/* Maintain abc_wifi_config_t length and order */
const char * abc_wifi_config_type_strings[] = {
    "iw",
    "nm"
};

/* forward declarations */
static int abc_wifi_init (const char * interface);
static int abc_wifi_is_enabled ();
static int abc_wifi_set_enabled (int state);
static int abc_wifi_cleanup ();


abc_iface abc_iface_wifi = {
  .iface_type = ABC_IFACE_TYPE_WIFI,
  .iface_type_args = NULL,
  .iface_sockfd = -1,
  .if_address = {},
  .bc_address = {},
  .init_iface_cb = abc_wifi_init,
  .iface_on_off_ms = 150, /* default value, updated on runtime */
  .iface_is_enabled_cb = abc_wifi_is_enabled,
  .iface_set_enabled_cb = abc_wifi_set_enabled,
  .iface_cleanup_cb = abc_wifi_cleanup
};

static abc_wifi_config_iface * wifi_config_types[] = {
  &abc_wifi_config_iw,
#ifdef USE_NETWORK_MANAGER
  &abc_wifi_config_nm_wlan,
#endif /* USE_NETWORK_MANAGER */
  NULL
};
static abc_wifi_config_iface * wifi_config_iface = NULL;

static int abc_wifi_is_enabled ()
{
  return wifi_config_iface->iface_is_enabled_cb () &&
         wifi_config_iface->iface_is_connected_cb ();
}

static int abc_wifi_set_enabled (int state)
{
  printf ("abc-wifi: %s wifi\n", state ? "enable" : "disable");
  int ret = wifi_config_iface->iface_set_enabled_cb (state);
  if (ret == 1 && state) {
    printf ("abc-wifi: connecting\n");
    return wifi_config_iface->iface_connect_cb ();
  }
  return ret;
}

/* returns 0 if the interface is not found, 1 otherwise */
static int abc_wifi_init (const char * interface)
{
  if (abc_iface_wifi.iface_type_args != NULL) {
    int i;
    for (i = 0; i < sizeof (wifi_config_types); ++i) {
      if (strcmp (abc_wifi_config_type_strings[i], abc_iface_wifi.iface_type_args) == 0) {
        wifi_config_iface = wifi_config_types[i];
        break;
      }
    }
  }
  if (!wifi_config_iface)
    wifi_config_iface = wifi_config_types[0];

  if (!wifi_config_iface->init_iface_cb (interface))
    return 0;

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
      struct timeval start;
      gettimeofday (&start, NULL);
      int is_up = wifi_config_iface->iface_is_enabled_cb ();
      int in_use = (is_up == 2);
      printf ("abc-wifi: interface is enabled: %s (%d)\n",
        in_use ? "yes, but busy" : (is_up > 0 ? "yes" : "no"), is_up);
      if (is_up == 0)
        wifi_config_iface->iface_set_enabled_cb (1);

      struct timeval midtime;
      gettimeofday (&midtime, NULL);
      long long mtime = delta_us (&midtime, &start);
      if (! in_use) {
        if (!wifi_config_iface->iface_is_connected_cb ())
          wifi_config_iface->iface_connect_cb (1);
        struct timeval finish;
        gettimeofday (&finish, NULL);
        long long time = delta_us (&finish, &start);
        printf ("abc: %s is wireless, %lld.%03lld ms to turn on+connect\n",
                interface, time / 1000LL, time % 1000LL);
        printf ("  (%lld.%03lld ms to turn on)\n",
                mtime / 1000LL, mtime % 1000LL);
        abc_iface_wifi.iface_on_off_ms = time;
      }
      /* create the socket and initialize the address */
      abc_iface_wifi.iface_sockfd = socket (AF_PACKET, SOCK_DGRAM, ALLNET_WIFI_PROTOCOL);
      abc_iface_wifi.if_address = *((struct sockaddr_ll *) (ifa_loop->ifa_addr));
      if (bind (abc_iface_wifi.iface_sockfd, (const struct sockaddr *) &abc_iface_wifi.if_address, sizeof (sockaddr_t)) == -1)
        printf ("abc-wifi: error binding interface, continuing without..\n");
      if (ifa_loop->ifa_flags & IFF_BROADCAST)
        abc_iface_wifi.bc_address = *((struct sockaddr_ll *) (ifa_loop->ifa_broadaddr));
      else if (ifa_loop->ifa_flags & IFF_POINTOPOINT)
        abc_iface_wifi.bc_address = *((struct sockaddr_ll *) (ifa_loop->ifa_dstaddr));
      else
        abc_iface_set_default_broadcast_address (&abc_iface_wifi.bc_address);
      abc_iface_wifi.bc_address.sll_protocol = ALLNET_WIFI_PROTOCOL;  /* otherwise not set */
      abc_iface_wifi.bc_address.sll_ifindex = abc_iface_wifi.if_address.sll_ifindex;
      abc_iface_print_sll_addr (&abc_iface_wifi.if_address, "interface address");
      abc_iface_print_sll_addr (&abc_iface_wifi.bc_address, "broadcast address");
      freeifaddrs (ifa);
      return 1;
    }
#endif /* __APPLE__ */
    ifa_loop = ifa_loop->ifa_next;
  }
  freeifaddrs (ifa);
  return 0;  /* interface not found */
}

static int abc_wifi_cleanup () {
  return wifi_config_iface->iface_cleanup_cb ();
}
