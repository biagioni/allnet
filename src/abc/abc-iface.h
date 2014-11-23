#ifndef ABC_IFACE_H
#define ABC_IFACE_H
/* abc-iface.h: Bradcast abc messages onto a wireless interface */

#ifndef __APPLE__
#include <netpacket/packet.h>  /* struct sockaddr_ll */
typedef struct sockaddr_ll sockaddr_t;
#else /* __APPLE__ */
#include <sys/socket.h>        /* struct sockaddr */
#include <netinet/ip.h>        /* struct sockaddr_in */
typedef struct sockaddr_in sockaddr_t;
#endif /* __APPLE__ */

#define BC_ADDR(ifaceptr) ((const struct sockaddr *)&(ifaceptr)->bc_address)

/** enum of all compile-time supported abc iface modules */
typedef enum abc_iface_type {
  ABC_IFACE_TYPE_IP,
  ABC_IFACE_TYPE_WIFI
} abc_iface_type;

typedef struct abc_iface {
  /** The interface type this set of callbacks represents */
  abc_iface_type iface_type;
  int iface_is_managed;
  /** Additional parameters passed on to the iface driver */
  const char * iface_type_args;

  int iface_sockfd; /* the socket filedescriptor used with this iface */
  sockaddr_t if_address; /* the address of the interface */
  sockaddr_t bc_address; /* broacast address of the interface */
  /**
   * Callback to initialize the interface.
   * The callback must initialize all paramteres except interface
   * @param interface The interface to use (e.g. eth0 or wlan0.)
   * @param sock The interface's communication socket
   * @param address The interface socket's address
   * @param bc The interface's default broadcast address
   * @return 1 if successful, 0 on failure.
   */
  int (* init_iface_cb) (const char * interface);
  /**
   * Time in ms it takes to turn on the interface.
   * The initial value provides a guideline and should be pretty conservative.
   * The value is updated by abc after the first call to iface_set_enabled_cb
   */
  unsigned long long int iface_on_off_ms;
  /**
   * Callback that queries whether the interface is enabled.
   * @return 1 if enabled, 0 if disabled, -1 on failure.
   */
  int (* iface_is_enabled_cb) ();
  /**
   * Callback that enables/disables the interface according to state.
   * @param state 1 to enable, 0 to disable the interface.
   * @return 1 if succeeded in enabling/disabling. 0 otherwise, -1 on failure.
   */
  int (* iface_set_enabled_cb) (int state);
  /**
   * Callback to cleans up the interface and possibly restores the previous state
   * @return 1 on success, 0 on failure.
   */
  int (* iface_cleanup_cb) ();
} abc_iface;


#ifndef __APPLE__  /* not sure what replaces the sll addresses for apple */
void abc_iface_set_default_broadcast_address (struct sockaddr_ll * bc);
void abc_iface_print_sll_addr (struct sockaddr_ll * a, char * desc);
#endif /* __APPLE__ */

#endif /* ABC_IFACE_H */
