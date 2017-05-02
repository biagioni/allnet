#ifndef ABC_IFACE_H
#define ABC_IFACE_H
/* abc-iface.h: Interface used by abc for broadcasting messages on a network */

#include <sys/socket.h>        /* struct sockaddr, socklen_t */
#include <netinet/in.h>        /* struct sockaddr_in on some systems */
#include <netinet/ip.h>        /* struct sockaddr_in on other systems */

#include "lib/allnet_log.h"    /* struct allnet_log */

#ifndef __APPLE__
#ifndef __CYGWIN__
#ifndef _WIN32
#ifndef _WIN64
#ifndef __OpenBSD__
#define ALLNET_NETPACKET_SUPPORT
#endif /* __OpenBSD__ */
#endif /* _WIN64 */
#endif /* _WIN32 */
#endif /* __CYGWIN__ */
#endif /* __APPLE__ */

#ifdef ALLNET_NETPACKET_SUPPORT
#include <netpacket/packet.h>  /* struct sockaddr_ll */
#endif /* ALLNET_NETPACKET_SUPPORT */

typedef union {
  struct sockaddr sa;
#ifdef ALLNET_NETPACKET_SUPPORT
  struct sockaddr_ll ll;
#endif /* ALLNET_NETPACKET_SUPPORT */
  struct sockaddr_in in;
  struct sockaddr_in6 in6;
  struct sockaddr_storage sas;  /* this is the max size ever needed */
} sockaddr_t;

#define BC_ADDR(ifaceptr) ((const struct sockaddr *)&(ifaceptr)->bc_address)

/** Accept every sender */
int abc_iface_accept_sender (const struct sockaddr * sender);

/** enum of all compile-time supported abc iface modules */
typedef enum abc_iface_type {
  ABC_IFACE_TYPE_IP,
  ABC_IFACE_TYPE_WIFI
} abc_iface_type;

typedef struct abc_iface {
  /* useful for debugging */
  const char * iface_name;
  /** The interface type this set of callbacks represents */
  abc_iface_type iface_type;
  int iface_is_managed;
  /** Additional parameters passed on to the iface driver */
  const char * iface_type_args;

  int iface_sockfd; /* the socket filedescriptor used with this iface */
  sa_family_t if_family; /* the address family of if_address and bc_address */
  sockaddr_t if_address; /* the address of the interface */
  sockaddr_t bc_address; /* broacast address of the interface */
  socklen_t sockaddr_size; /* the size of the sockaddr_* inside sockaddr_t */
  /**
   * Callback to initialize the interface.
   * The callback must initialize all paramteres except interface
   * @param interface The interface to use (e.g. eth0 or wlan0.)
   * @param sock The interface's communication socket
   * @param address The interface socket's address
   * @param bc The interface's default broadcast address
   * @return 1 if successful, 0 on failure.
   */
  int (* init_iface_cb) (const char * interface, struct allnet_log * log);
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
  /**
   * Callback to check if a message from a given sender is to be accepted.
   * @return 1 if message should be accepted, 0 if it should be rejected.
   */
  int (* accept_sender_cb) (const struct sockaddr *);
  /** Pointer to private additional data */
  void * priv;
} abc_iface;


#ifdef ALLNET_NETPACKET_SUPPORT
extern void
  abc_iface_set_default_sll_broadcast_address (struct sockaddr_ll * bc);
/* mode 0: print to screen and log ifdef DEBUG_PRINT, to log only otherwise
 * mode & 1 (i.e. 1, 3): print to log  (unless log is NULL)
 * mode & 2 (i.e. 2, 3): print to screen */
extern void
  abc_iface_print_sll_addr (struct sockaddr_ll * a, char * desc, int mode,
                            struct allnet_log * log);
#else /* ALLNET_NETPACKET_SUPPORT */
/* not sure what replaces the sll addresses for systems that don't have them */
#endif /* ALLNET_NETPACKET_SUPPORT */

#endif /* ABC_IFACE_H */
