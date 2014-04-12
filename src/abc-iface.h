/* abc-iface.h: Bradcast abc messages onto a wireless interface */

#include <netpacket/packet.h>  /* struct sockaddr_ll */

int init_iface (const char * interface, int * sock,
                struct sockaddr_ll * address, struct sockaddr_ll * bc);
unsigned long long int iface_on_off_ms;
extern int iface_is_on;
void iface_on (const char * interface);
void iface_off (const char * interface);
