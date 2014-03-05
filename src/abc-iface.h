/* abc-iface.h: Bradcast abc messages onto a wireless interface */

#include <netpacket/packet.h>  /* struct sockaddr_ll */

int init_iface (char * interface, int * sock,
                struct sockaddr_ll * address, struct sockaddr_ll * bc);
unsigned long long int iface_on_off_ms;
int iface_is_on;
void iface_on (char * interface);
void iface_off (char * interface);
