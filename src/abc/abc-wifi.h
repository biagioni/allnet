#ifndef ABC_WIFI_H
#define ABC_WIFI_H

#include "abc-iface.h"

/** enum of all available wifi config modules */
typedef enum abc_wifi_config {
  ABC_WIFI_CONFIG_IW,
  ABC_WIFI_CONFIG_NETWORKMANAGER
} abc_wifi_config_t;

/** public wifi config interface */
typedef struct abc_wifi_config_iface {
  abc_wifi_config_t config_type;
  int (* init_iface_cb) (const char * interface);
  int (* iface_is_enabled_cb) ();
  int (* iface_set_enabled_cb) (int state);
  int (* iface_is_connected_cb) ();
  int (* iface_connect_cb) ();
} abc_wifi_config_iface;

/** ready to use abc interface */
extern abc_iface abc_iface_wifi;

#endif /* ABC_WIFI_H */
