/* abc-iface.c: a collection of shared helper functions for abc interfaces */
#include <stdlib.h>
#include <stdio.h>
#include "abc-iface.h"
#include "lib/packet.h" /* ALLNET_WIFI_PROTOCOL */
#include "lib/util.h"   /* allnet_htons */
#include "lib/allnet_log.h"

/** Accept every sender */
int abc_iface_accept_sender (const struct sockaddr * sender) { return 1; }

#ifdef ALLNET_NETPACKET_SUPPORT
#include <netpacket/packet.h>  /* struct sockaddr_ll */

void abc_iface_set_default_sll_broadcast_address (struct sockaddr_ll * bc)
{
  bc->sll_family = AF_PACKET;
  bc->sll_protocol = allnet_htons (ALLNET_WIFI_PROTOCOL);
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

/* mode 0: print to screen and log ifdef DEBUG_PRINT, to log only otherwise
 * mode & 1 (i.e. 1, 3): print to log
 * mode & 2 (i.e. 2, 3): print to screen */
void abc_iface_print_sll_addr (struct sockaddr_ll * a, char * desc, int mode,
                               struct allnet_log * alog)
{
  int print_to_screen = 0;
  int print_to_log = 0;
  if ((alog != NULL) && ((mode == 0) || (mode & 1)))
    print_to_log = 1;
  if (mode & 2)
    print_to_screen = 1;
  int off = 0;
  if (desc != NULL) {
    if (print_to_screen)
      printf ("%s: ", desc);
    if (print_to_log)
      off += snprintf (alog->b + off, alog->s - off, "%s: ", desc);
  }
  if (a->sll_family != AF_PACKET) {
    if (print_to_screen)
      printf ("unknown address family %d\n", a->sll_family);
    if (print_to_log) {
      off += snprintf (alog->b + off, alog->s - off,
                       "unknown address family %d\n", a->sll_family);
      log_print (alog);
    }
    return;
  }
  if (print_to_screen)
    printf ("proto %d, ha %d pkt %d halen %d ", a->sll_protocol, a->sll_hatype,
            a->sll_pkttype, a->sll_halen);
  if (print_to_log)
    off += snprintf (alog->b + off, alog->s - off,
                     "proto %d, ha %d pkt %d halen %d ", a->sll_protocol,
                     a->sll_hatype, a->sll_pkttype, a->sll_halen);
  int i;
  char * pre = "";
  for (i = 0; i < a->sll_halen; i++) {
    if (print_to_screen)
      printf ("%s%02x", pre, a->sll_addr [i]);
    if (print_to_log)
      off += snprintf (alog->b + off, alog->s - off, "%s%02x",
                       pre, a->sll_addr [i]);
    pre = ":";
  }
  if (desc != NULL) {
    if (print_to_screen)
      printf ("\n");
    if (print_to_log)
      log_print (alog);
  }
}
#endif /* ALLNET_NETPACKET_SUPPORT */

