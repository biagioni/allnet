/* abc-networkmanager.h: abc-wifi's NetworkManager interface */
#ifndef ABC_NETWORKMANAGER_H
#define ABC_NETWORKMANAGER_H

#include "abc-wifi.h" /* abc_wifi_config_iface */

/** public wifi config interface ready to use */
extern abc_wifi_config_iface abc_wifi_config_nm_wlan;
int abc_wifi_config_nm_init (const char * iface, struct allnet_log * log);
int abc_wifi_config_nm_enable_wireless (int state);
int abc_wifi_config_nm_is_wireless_on ();

#endif /* ABC_NETWORKMANAGER_H */
