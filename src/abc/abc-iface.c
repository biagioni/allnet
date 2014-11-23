/* abc-iface.c: a collection of shared helper functions for abc interfaces */
#include <stdlib.h>
#include <stdio.h>
#include "abc-iface.h"
#include "lib/packet.h" /* ALLNET_WIFI_PROTOCOL */

#ifndef __APPLE__
#include <netpacket/packet.h>  /* struct sockaddr_ll */

void abc_iface_set_default_sll_broadcast_address (struct sockaddr_ll * bc)
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

void abc_iface_print_sll_addr (struct sockaddr_ll * a, char * desc)
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

