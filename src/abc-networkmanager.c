/* abc-networkmanager.c: abc's NetworkManager interface */

#include <dbus-1.0/dbus/dbus.h>

#include "abc-networkmanager.h"

static dbus_bool_t append_variant (DBusMessageIter * iter, int type, void * val) {
  DBusMessageIter value;
  char sig[2] = { type, '\0' };
  return (
    dbus_message_iter_open_container (iter, DBUS_TYPE_VARIANT, sig, &value)
    && dbus_message_iter_append_basic (&value, type, val)
    && dbus_message_iter_close_container (iter, &value)
  );
}

static dbus_bool_t dict_append_entry (DBusMessageIter *dict,
   const char * key, int type, void * val) {
  DBusMessageIter entry;

  if (type == DBUS_TYPE_STRING) {
    const char *str = *((const char **) val);
    if (str == NULL)
      return TRUE;
  }

  return (
    dbus_message_iter_open_container (dict, DBUS_TYPE_DICT_ENTRY, NULL, &entry)
    && dbus_message_iter_append_basic (&entry, DBUS_TYPE_STRING, &key)
    && append_variant (&entry, type, val)
    && dbus_message_iter_close_container (dict, &entry)
  );
}

static int init_dbus_connection (DBusConnection ** conn) {
  DBusError err;
  dbus_error_init (&err);
  *conn = dbus_bus_get (DBUS_BUS_SYSTEM, &err);
  if (dbus_error_is_set (&err)) {
    // TODO: allnet log
    // fprintf (stderr, "dbus: Connection Error (%s)\n", err.message);
    dbus_error_free (&err);
  }
  return (conn != NULL);
}

static DBusMessage * init_dbus_method_call (const char * dest, const char * obj, const char * iface, const char * method) {
  return dbus_message_new_method_call (dest, obj, iface, method);
}

static DBusMessage * init_nm_dbus_method_call (const char * method) {
  return init_dbus_method_call (ABC_NM_DBUS_DEST,
                                ABC_NM_DBUS_OBJ,
                                ABC_NM_DBUS_IFACE,
                                method);
}

/** Synchronously call a DBus method */
static int call_nm_dbus_method (DBusConnection * conn, DBusMessage ** msg) {
  DBusPendingCall * pending;
  // send message and get a handle for a reply
  if (!dbus_connection_send_with_reply (conn, *msg, &pending, -1)) {
    /* -1 param is default timeout */
    // fprintf (stderr, "dbus: Out of memory!\n"); // TODO: allnet log
    return 0;
  }
  if (pending == NULL) {
    // fprintf (stderr, "dbus: NULL Pending call\n"); // TODO: allnet log
    return 0;
  }
  dbus_connection_flush (conn);
  dbus_message_unref (*msg);
  dbus_pending_call_block (pending);
  *msg = dbus_pending_call_steal_reply (pending);
  dbus_pending_call_unref (pending);
  return (*msg != NULL);
}

static int get_device_path (abc_nm_settings * self) {
  /* Get device object path */
  DBusMessage * msg = init_nm_dbus_method_call ("GetDeviceByIpIface");
  if (msg == NULL)
    return 0;
  DBusMessageIter args;
  dbus_message_iter_init_append (msg, &args);
  dbus_message_iter_append_basic (&args, DBUS_TYPE_STRING, &self->iface);
  if (!call_nm_dbus_method (self->conn, &msg))
    return 0;

  if (!dbus_message_iter_init (msg, &args)
      || dbus_message_iter_get_arg_type (&args) != DBUS_TYPE_OBJECT_PATH) {
    return 0;
  }
  dbus_message_iter_get_basic (&args, &self->nm_iface_obj);
  dbus_message_unref (msg);
  return 1;
}

static int setup_connection (abc_nm_settings * self) {
  DBusMessage * msg = init_dbus_method_call (ABC_NM_DBUS_DEST,
                                              ABC_NM_DBUS_OBJ "/Settings",
                                              ABC_NM_DBUS_IFACE ".Settings",
                                              "AddConnection");
  if (msg == NULL)
    return 0;

  /* Begin of connection settings section */
  /* All connection settings must be defined here */
  const char * connection = "connection",
             * conn_keys[] = { "id",     "type",            "uuid",                                 "zone" },
             * conn_vals[] = { "AllNet", "802-11-wireless", "c25da751-1b91-4262-9f94-3dcbddfaee5e", "public" };
  //conn_vals[2] = uuid; // TODO: generate UUID

  /* Valid properties available from:
   * http://cgit.freedesktop.org/NetworkManager/NetworkManager/tree/libnm-util/nm-setting-wireless.h
   */
  const char * wlan = "802-11-wireless",
             * wlan_keys[] = { "ssid", "mode", "band", "channel" },
             * wlan_vals[] = { NULL,   "adhoc", "bg" };
  /* when chaning the ssid, make sure to adapt the number of
   * dbus_message_iter_append_basic calls below
   */
  const unsigned char ssid[] = { 'a', 'l', 'l', 'n', 'e', 't' };
  dbus_uint32_t channel = 1; /* channel 1: 2412Mhz */;

  const char * ipv4 = "ipv4";
  const char * ipv4method_key = "method";
  char * ipv4method_val =  "auto";
  /* End of connection settings section */

  DBusMessageIter args;
  dbus_message_iter_init_append (msg, &args);
  DBusMessageIter arg[6];
  if (! (
    dbus_message_iter_open_container (&args, DBUS_TYPE_ARRAY, "{sa{sv}}" , &arg[0])

    /* connection settings */
    && dbus_message_iter_open_container (&arg[0], DBUS_TYPE_DICT_ENTRY, NULL, &arg[1])
    && dbus_message_iter_append_basic (&arg[1], DBUS_TYPE_STRING, &connection)
    && dbus_message_iter_open_container (&arg[1], DBUS_TYPE_ARRAY, "{sv}", &arg[2])
    && dict_append_entry (&arg[2], conn_keys[0], DBUS_TYPE_STRING, &conn_vals[0])
    && dict_append_entry (&arg[2], conn_keys[1], DBUS_TYPE_STRING, &conn_vals[1])
    && dict_append_entry (&arg[2], conn_keys[2], DBUS_TYPE_STRING, &conn_vals[2])
    && dict_append_entry (&arg[2], conn_keys[3], DBUS_TYPE_STRING, &conn_vals[3])
    && dbus_message_iter_close_container (&arg[1], &arg[2])
    && dbus_message_iter_close_container (&arg[0], &arg[1])

    /* wireless settings */
    && dbus_message_iter_open_container (&arg[0], DBUS_TYPE_DICT_ENTRY, NULL, &arg[1])
    && dbus_message_iter_append_basic (&arg[1], DBUS_TYPE_STRING, &wlan)
    && dbus_message_iter_open_container (&arg[1], DBUS_TYPE_ARRAY, "{sv}", &arg[2])
    /* SSID dict entry as byte array */
    && dbus_message_iter_open_container (&arg[2], DBUS_TYPE_DICT_ENTRY, NULL, &arg[3])
    && dbus_message_iter_append_basic (&arg[3], DBUS_TYPE_STRING, &wlan_keys[0])
    && dbus_message_iter_open_container (&arg[3], DBUS_TYPE_VARIANT, "ay", &arg[4])
    && dbus_message_iter_open_container (&arg[4], DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE_AS_STRING, &arg[5])
    && dbus_message_iter_append_basic (&arg[5], DBUS_TYPE_BYTE, &ssid[0])
    && dbus_message_iter_append_basic (&arg[5], DBUS_TYPE_BYTE, &ssid[1])
    && dbus_message_iter_append_basic (&arg[5], DBUS_TYPE_BYTE, &ssid[2])
    && dbus_message_iter_append_basic (&arg[5], DBUS_TYPE_BYTE, &ssid[3])
    && dbus_message_iter_append_basic (&arg[5], DBUS_TYPE_BYTE, &ssid[4])
    && dbus_message_iter_append_basic (&arg[5], DBUS_TYPE_BYTE, &ssid[5])
    && dbus_message_iter_close_container (&arg[4], &arg[5])
    && dbus_message_iter_close_container (&arg[3], &arg[4])
    && dbus_message_iter_close_container (&arg[2], &arg[3])
    /* end SSID dict entry */
    && dict_append_entry (&arg[2], wlan_keys[1], DBUS_TYPE_STRING, &wlan_vals[1])
    && dict_append_entry (&arg[2], wlan_keys[2], DBUS_TYPE_STRING, &wlan_vals[2])
    && dict_append_entry (&arg[2], wlan_keys[3], DBUS_TYPE_UINT32, &channel)
    && dbus_message_iter_close_container (&arg[1], &arg[2])
    && dbus_message_iter_close_container (&arg[0], &arg[1])

    /* IPv4 config */
    && dbus_message_iter_open_container (&arg[0], DBUS_TYPE_DICT_ENTRY, NULL, &arg[1])
    && dbus_message_iter_append_basic (&arg[1], DBUS_TYPE_STRING, &ipv4)
    && dbus_message_iter_open_container (&arg[1], DBUS_TYPE_ARRAY, "{sv}", &arg[2])
    && dict_append_entry (&arg[2], ipv4method_key, DBUS_TYPE_STRING, &ipv4method_val)
    && dbus_message_iter_close_container (&arg[1], &arg[2])
    && dbus_message_iter_close_container (&arg[0], &arg[1])

    && dbus_message_iter_close_container (&args, &arg[0])
  ))
    return 0;

  if (!call_nm_dbus_method (self->conn, &msg))
    return 0;

  if (!dbus_message_iter_init (msg, &args)
      || dbus_message_iter_get_arg_type (&args) != DBUS_TYPE_OBJECT_PATH)
    return 0;
  dbus_message_iter_get_basic (&args, &self->nm_conn_obj);
  dbus_message_unref (msg);
  return 1;
}

int get_conn_obj (abc_nm_settings * self) {
  // TODO return 1 if connection is found
  return 0;
}

int  abc_nm_is_wireless_on (abc_nm_settings * self) {
  DBusMessage * msg = dbus_message_new_method_call (ABC_NM_DBUS_DEST,
                                  ABC_NM_DBUS_OBJ,
                                  "org.freedesktop.DBus.Properties",
                                  "Get");
  if (msg == NULL)
    return -1;

  DBusMessageIter args;
  dbus_message_iter_init_append (msg, &args);
  const char * nm[2] = { ABC_NM_DBUS_IFACE, "WirelessEnabled" };
  dbus_message_iter_append_basic (&args, DBUS_TYPE_STRING, &nm[0]);
  dbus_message_iter_append_basic (&args, DBUS_TYPE_STRING, &nm[1]);
  if (!call_nm_dbus_method (self->conn, &msg))
    return -1;

  dbus_bool_t wlan_enabled;
  if (!dbus_message_iter_init (msg, &args)
      || dbus_message_iter_get_arg_type (&args) != DBUS_TYPE_VARIANT)
    return -1;

  DBusMessageIter arg_var;
  dbus_message_iter_recurse (&args, &arg_var);
  dbus_message_iter_get_basic (&arg_var, &wlan_enabled);
  dbus_message_unref (msg);
  return wlan_enabled;
}

int abc_nm_init (abc_nm_settings * self, const char * iface) {
  self->conn = NULL;
  self->iface = iface;
  self->nm_iface_obj = NULL;
  self->nm_conn_obj = NULL;
  return init_dbus_connection (&self->conn);
}

int abc_nm_enable_wireless (abc_nm_settings * self, int state) {
  // TODO
  return 1;
}

int abc_nm_connect(abc_nm_settings * self) {
  if (self->conn == NULL)
    return 0;

  if (self->nm_iface_obj == NULL && !get_device_path (self)) {
    // TODO: allnet log
    return 0;
  }

  if (self->nm_conn_obj == NULL && !get_conn_obj (self)) {
    // TODO: allnet log
    return 0;
  }

  if (!abc_nm_is_wireless_on (self) && !abc_nm_enable_wireless (self, 1)) {
    // TODO: allnet log
    return 0;
  }

  // TODO: connect to nm_conn_obj
  return 1;
}
