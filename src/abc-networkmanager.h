/* abc-networkmanager.h: abc's NetworkManager interface */

#ifndef ABC_NETWORKMANAGER_H
#define ABC_NETWORKMANAGER_H

#include <dbus-1.0/dbus/dbus.h>

#define ABC_NM_DBUS_DEST "org.freedesktop.NetworkManager"
#define ABC_NM_DBUS_OBJ "/org/freedesktop/NetworkManager"
#define ABC_NM_DBUS_IFACE "org.freedesktop.NetworkManager"
#define ALLNET_SSID_BYTE_ARRAY { 'a', 'l', 'l', 'n', 'e', 't' }

struct abc_nm_settings_priv;
typedef struct abc_nm_settings {
  DBusConnection * conn;
  const char * iface;
  const char * nm_iface_obj;
  const char * nm_conn_obj;
  struct abc_nm_settings_priv * priv;
} abc_nm_settings;

/** Init connection to NetworkManager */ 
int abc_nm_init (abc_nm_settings * self, const char * iface);
/** Connect to AllNet adhoc network */ 
int abc_nm_connect(abc_nm_settings * self);
/** Check wlan state */ 
int abc_nm_is_wireless_on (abc_nm_settings * self);
/** Enable or disable wlan depending on state */ 
int abc_nm_enable_wireless (abc_nm_settings * self, int state);

#endif /* ABC_NETWORKMANAGER_H */
