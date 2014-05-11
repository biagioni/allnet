#ifndef ABC_IFACE_H
#define ABC_IFACE_H
/* abc-iface.h: Bradcast abc messages onto a wireless interface */

#include <netpacket/packet.h>  /* struct sockaddr_ll */

/** enum of all compile-time supported abc iface modules */
typedef enum abc_iface_type {
  ABC_IFACE_TYPE_WIFI
} abc_iface_type;

typedef struct abc_iface {
  abc_iface_type iface_type;
  int (* init_iface_cb) (const char * interface, int * sock,
              struct sockaddr_ll * address, struct sockaddr_ll * bc);
  unsigned long long int iface_on_off_ms;
  int (* iface_is_enabled_cb) ();
  int (* iface_set_enabled_cb) (int state);
} abc_iface;

#endif /* ABC_IFACE_H */
