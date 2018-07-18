/* abc-wifi.c: Broadcast abc messages onto a wireless interface
 *
 * to do: If the interface is on and connected to a wireless LAN, I never
 * enter send mode.  Instead, I use energy saving mode to receive once
 * every basic cycle, and transmit once every 200 cycles.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>           /* close */
#include <ifaddrs.h>
#include <sys/socket.h>       /* struct sockaddr */
#include <net/if.h>           /* ifa_flags */
#include <sys/time.h>         /* gettimeofday */

#include "lib/packet.h"       /* ALLNET_WIFI_PROTOCOL */
#include "lib/util.h"         /* delta_us */

#include "abc-iface.h"        /* sockaddr_t, abc_iface_* */

#ifdef ALLNET_NETPACKET_SUPPORT  /* not sure how to do this without netpacket */

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
static int abc_wifi_init (const char * interface, struct allnet_log * log);
static int abc_wifi_is_enabled ();
static int abc_wifi_set_enabled (int state);
static int abc_wifi_cleanup ();


abc_iface abc_iface_wifi = {
  .iface_name = NULL,
  .iface_type = ABC_IFACE_TYPE_WIFI,
  .iface_is_managed = 1,
  .iface_type_args = NULL,
  .iface_sockfd = -1,
  .if_family = AF_PACKET,
  .if_address = {},
  .bc_address = {},
  .sockaddr_size = sizeof (struct sockaddr_ll),
  .init_iface_cb = abc_wifi_init,
  .iface_on_off_ms = 150, /* default value, updated on runtime */
  .iface_is_enabled_cb = abc_wifi_is_enabled,
  .iface_set_enabled_cb = abc_wifi_set_enabled,
  .iface_cleanup_cb = abc_wifi_cleanup,
  .accept_sender_cb = abc_iface_accept_sender,
  .priv = NULL
};

static abc_wifi_config_iface * wifi_config_types[] = {
  &abc_wifi_config_iw,
#ifdef USE_NETWORK_MANAGER
  &abc_wifi_config_nm_wlan,
#endif /* USE_NETWORK_MANAGER */
  NULL
};
static abc_wifi_config_iface * wifi_config_iface = NULL;

static struct allnet_log * alog = NULL;

static int abc_wifi_is_enabled ()
{
  return wifi_config_iface->iface_is_enabled_cb () &&
         wifi_config_iface->iface_is_connected_cb ();
}

static int abc_wifi_set_enabled (int state)
{
#ifdef DEBUG_PRINT
  char * pstate = state ? "enable" : "disable";
  snprintf (alog->b, alog->s, "abc-wifi: %s wifi\n", pstate);
  log_print (alog);
  printf ("abc-wifi: %s wifi\n", pstate);
#endif /* DEBUG_PRINT */
  int ret = wifi_config_iface->iface_set_enabled_cb (state);
  if (ret == 1 && state) {
#ifdef DEBUG_PRINT
    snprintf (alog->b, alog->s, "abc-wifi: connecting\n");
    log_print (alog);
    printf ("abc-wifi: connecting\n");
#endif /* DEBUG_PRINT */
    return wifi_config_iface->iface_connect_cb ();
  }
  return ret;
}

/* even though the parameters are declared as sockaddrs, the actual
 * length to copy depends on from->sa_family.  Only a few families supported */
static void copy_addr (struct sockaddr * to, struct sockaddr * from)
{
  socklen_t len = 0;
  switch (from->sa_family) {
  case AF_INET: len = sizeof (struct sockaddr_in); break;
  case AF_INET6: len = sizeof (struct sockaddr_in6); break;
  case AF_PACKET: len = sizeof (struct sockaddr_ll); break;
  default: printf ("abc-wifi: address family %d\n", from->sa_family); return;
  }
  memcpy (to, from, len);
}

static int init_socket (struct ifaddrs * ifa)
{
  if (ifa->ifa_addr == NULL)  /* can happen */
    return 0;
  abc_iface_wifi.iface_sockfd = socket (AF_PACKET, SOCK_DGRAM,
                                        allnet_htons (ALLNET_WIFI_PROTOCOL));
  if (abc_iface_wifi.iface_sockfd == -1) {
    perror ("abc-wifi: error creating socket");
    return 0;
  }
  copy_addr ((struct sockaddr *) &abc_iface_wifi.if_address.ll, ifa->ifa_addr);
  if (bind (abc_iface_wifi.iface_sockfd, &abc_iface_wifi.if_address.sa,
            sizeof (struct sockaddr_ll)) == -1) {
    perror ("abc-wifi: error binding interface (continuing without)");
    printf ("error binding interface %s\n", ifa->ifa_name);
  }
  if (ifa->ifa_flags & IFF_BROADCAST)
    copy_addr (&(abc_iface_wifi.bc_address.sa), ifa->ifa_broadaddr);
  else if (ifa->ifa_flags & IFF_POINTOPOINT)
    copy_addr (&(abc_iface_wifi.bc_address.sa), ifa->ifa_dstaddr);
  else
    abc_iface_set_default_sll_broadcast_address (&abc_iface_wifi.bc_address.ll);
  /* must set sll_protocol, otherwise it is not set */
  abc_iface_wifi.bc_address.ll.sll_protocol =
    allnet_htons (ALLNET_WIFI_PROTOCOL);
  abc_iface_wifi.bc_address.ll.sll_hatype = 0;  /* packet(7) says to set to 0 */
  abc_iface_wifi.bc_address.ll.sll_pkttype = 0; /* packet(7) says to set to 0 */
  if (abc_iface_wifi.bc_address.ll.sll_ifindex !=
      abc_iface_wifi.if_address.ll.sll_ifindex) { /* does thie ever happen? */
    snprintf (alog->b, alog->s, "abc-wifi error: indices %d != %d\n",
              abc_iface_wifi.bc_address.ll.sll_ifindex,
              abc_iface_wifi.if_address.ll.sll_ifindex);
    log_print (alog);
    abc_iface_wifi.bc_address.ll.sll_ifindex =
      abc_iface_wifi.if_address.ll.sll_ifindex;
  }
  abc_iface_print_sll_addr (&abc_iface_wifi.if_address.ll,
                            "interface address", 0, alog);
  abc_iface_print_sll_addr (&abc_iface_wifi.bc_address.ll,
                            "broadcast address", 0, alog);
  return 1;
}

/* returns 0 if the interface is not found, 1 otherwise */
static int abc_wifi_init (const char * interface, struct allnet_log * log)
{
  alog = log;
  if (abc_iface_wifi.iface_type_args != NULL) {
    int i;
    for (i = 0; i < (int) (sizeof (wifi_config_types)); ++i) {
      if (strcmp (abc_wifi_config_type_strings [i],
                  abc_iface_wifi.iface_type_args) == 0) {
        wifi_config_iface = wifi_config_types [i];
        break;
      }
    }
  }
  if (! wifi_config_iface)
    wifi_config_iface = wifi_config_types [0];

  if (! wifi_config_iface->init_iface_cb (interface, alog))
    return 0;

  struct ifaddrs * ifa;
  if (getifaddrs (&ifa) != 0) {
    perror ("abc-wifi: getifaddrs");
    return 0;
  }
  struct ifaddrs * ifa_loop = ifa;
  while (ifa_loop != NULL) {
    if ((ifa_loop->ifa_addr != NULL) &&
        (ifa_loop->ifa_addr->sa_family == AF_PACKET) &&
        (strcmp (ifa_loop->ifa_name, interface) == 0)) {
      struct timeval start;
      gettimeofday (&start, NULL);
      int is_up = wifi_config_iface->iface_is_enabled_cb ();
      int in_use = (is_up == 2);
      snprintf (alog->b, alog->s,
                "abc-wifi: interface %s is enabled: %s (%d)\n", interface,
                in_use ? "yes, but busy" : (is_up > 0 ? "yes" : "no"), is_up);
      log_print (alog);
#ifdef DEBUG_PRINT
      printf ("abc-wifi: interface %s is enabled: %s (%d)\n", interface,
              in_use ? "yes, but busy" : (is_up > 0 ? "yes" : "no"), is_up);
#endif /* DEBUG_PRINT */
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
#ifdef DEBUG_PRINT
        printf ("abc: %s is wireless, %lld.%03lld ms to turn on+connect ",
                interface, time / 1000LL, time % 1000LL);
        printf ("(%lld.%03lld ms to turn on)\n",
                mtime / 1000LL, mtime % 1000LL);
#endif /* DEBUG_PRINT */
        snprintf (alog->b, alog->s,
                  "%s: %lld.%03lld ms on, %lld.%03lld ms on+connect",
                  interface, mtime / 1000LL, mtime % 1000LL,
                  time / 1000LL, time % 1000LL);
        log_print (alog);
        abc_iface_wifi.iface_on_off_ms = time;
      }
      /* create the socket and initialize the address */
      int n = init_socket (ifa_loop);
      freeifaddrs (ifa);
      return n;
    }
    ifa_loop = ifa_loop->ifa_next;
  }
  freeifaddrs (ifa);
  return 0;
}

static int abc_wifi_cleanup () {
  if (abc_iface_wifi.iface_sockfd != -1) {
    if (close (abc_iface_wifi.iface_sockfd) != 0)
      perror ("abc-wifi: error closing socket");
    else
      abc_iface_wifi.iface_sockfd = -1;
  }
  return wifi_config_iface->iface_cleanup_cb ();
}
#endif /* ALLNET_NETPACKET_SUPPORT */
