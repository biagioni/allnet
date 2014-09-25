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
static int abc_ip_init (const char * interface, int * sock,
                        sockaddr_t * address,
                        sockaddr_t * bc);
static int abc_ip_is_enabled ();
static int abc_ip_set_enabled (int state);
static int abc_ip_cleanup ();


abc_iface abc_iface_ip = {
  .iface_type = ABC_IFACE_TYPE_IP,
  .iface_type_args = NULL,
  .init_iface_cb = abc_ip_init,
  .iface_on_off_ms = 0, /* assume always on iface */
  .iface_is_enabled_cb = abc_ip_is_enabled,
  .iface_set_enabled_cb = abc_ip_set_enabled,
  .iface_cleanup_cb = abc_ip_cleanup
};

#ifndef __APPLE__  /* not sure what replaces the sll addresses for apple */
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
#endif /* __APPLE__ */

static int abc_ip_is_enabled ()
{
  return 1;
}

static int abc_ip_set_enabled (int state)
{
  return 1;
}

/* returns -1 if the interface is not found */
/* returns 0 if the interface is off, and 1 if it is on already */
/* if returning 0 or 1, fills in the socket and the address */
/* to do: figure out how to set bits_per_s in init_wireless */
static int abc_ip_init (const char * interface, int * sock,
                          sockaddr_t * address, sockaddr_t * bc)
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
      struct timeval start;
      gettimeofday (&start, NULL);
      int is_up = abc_ip_is_enabled ();
      printf ("abc-ip: interface is enabled: %s (%d)\n",
                is_up > 0 ? "yes" : "no", is_up);
      if (is_up == 0)
        abc_ip_set_enabled (1);

      struct timeval midtime;
      gettimeofday (&midtime, NULL);
      long long mtime = delta_us (&midtime, &start);
      /* create the socket and initialize the address */
      *sock = socket (AF_PACKET, SOCK_DGRAM, ALLNET_WIFI_PROTOCOL);
      *address = *((struct sockaddr_ll *) (ifa_loop->ifa_addr));
      if (bind (*sock, (const struct sockaddr *) address, sizeof (struct sockaddr_ll)) == -1)
        printf ("abc-ip: error binding interface %s, continuing without..\n", interface);
      if (ifa_loop->ifa_flags & IFF_BROADCAST) {
        *bc = *((struct sockaddr_ll *) (ifa_loop->ifa_broadaddr));
      } else if (ifa_loop->ifa_flags & IFF_POINTOPOINT) {
        *bc = *((struct sockaddr_ll *) (ifa_loop->ifa_dstaddr));
      } else {
        default_broadcast_address (bc);
        printf ("abc:-ip: set default broadcast address on %s\n", interface);
      }
      bc->sll_protocol = ALLNET_WIFI_PROTOCOL;  /* otherwise not set */
      bc->sll_ifindex = address->sll_ifindex;
      print_sll_addr (address, "interface address");
      print_sll_addr (bc,      "broadcast address");
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
