/* abc-networkmanager.c: Configure wireless card using NetworkManager */

#include <assert.h>
#include <dbus-1.0/dbus/dbus.h>
#include <stdio.h>              /* sprintf */
#include <stdlib.h>             /* malloc */
#include <string.h>             /* strcmp, strncopy */

#include "abc-wifi.h"           /* abc_wifi_config_iface */
#include "abc-networkmanager.h"

#define ABC_NM_DBUS_DEST "org.freedesktop.NetworkManager"
#define ABC_NM_DBUS_OBJ "/org/freedesktop/NetworkManager"
#define ABC_NM_DBUS_IFACE "org.freedesktop.NetworkManager"
#define ALLNET_SSID_BYTE_ARRAY { 'a', 'l', 'l', 'n', 'e', 't' }

/* forward declarations */
static int abc_wifi_config_nm_init (const char * iface);
static int abc_wifi_config_nm_connect ();
static int abc_wifi_config_nm_is_wireless_on ();
static int abc_wifi_config_nm_enable_wireless (int state);


typedef struct abc_nm_settings {
  DBusConnection * conn;
  const char * iface;
  const char * nm_iface_obj; /* ptr to nm_iface_obj_buf */
  const char * nm_conn_obj;  /* ptr to nm_iface_conn_obj_buf */
  char nm_conn_obj_buf[50];  /* 43: /org/freedesktop/NetworkManager/Settings/13 */
  char nm_iface_obj_buf[50]; /* 41: /org/freedesktop/NetworkManager/Devices/1 */
} abc_nm_settings;

/** public wifi config interface ready to use */
abc_wifi_config_iface abc_wifi_config_nm_wlan = {
  .config_type = ABC_WIFI_CONFIG_NETWORKMANAGER,
  .init_iface_cb = abc_wifi_config_nm_init,
  .iface_is_enabled_cb = abc_wifi_config_nm_is_wireless_on,
  .iface_set_enabled_cb = abc_wifi_config_nm_enable_wireless,
  .iface_connect_cb = abc_wifi_config_nm_connect
};

static abc_nm_settings self;

static dbus_bool_t append_variant (DBusMessageIter * iter, int type, void * val)
{
  DBusMessageIter value;
  char sig[2] = { type, '\0' };
  return (
    dbus_message_iter_open_container (iter, DBUS_TYPE_VARIANT, sig, &value)
    && dbus_message_iter_append_basic (&value, type, val)
    && dbus_message_iter_close_container (iter, &value)
  );
}

static dbus_bool_t dict_append_entry (DBusMessageIter *dict,
   const char * key, int type, void * val)
{
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

static int init_dbus_connection (DBusConnection ** conn)
{
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

static DBusMessage * init_dbus_method_call (const char * dest, const char * obj, const char * iface, const char * method)
{
  return dbus_message_new_method_call (dest, obj, iface, method);
}

static DBusMessage * init_nm_dbus_method_call (const char * method)
{
  return init_dbus_method_call (ABC_NM_DBUS_DEST,
                                ABC_NM_DBUS_OBJ,
                                ABC_NM_DBUS_IFACE,
                                method);
}

/** Synchronously call a DBus method */
static int call_nm_dbus_method (DBusMessage ** msg)
{
  DBusPendingCall * pending;
  // send message and get a handle for a reply
  if (!dbus_connection_send_with_reply (self.conn, *msg, &pending, -1)) {
    /* -1 param is default timeout */
    // fprintf (stderr, "dbus: Out of memory!\n"); // TODO: allnet log
    return 0;
  }
  if (pending == NULL) {
    // fprintf (stderr, "dbus: NULL Pending call\n"); // TODO: allnet log
    return 0;
  }
  dbus_connection_flush (self.conn);
  dbus_message_unref (*msg);
  dbus_pending_call_block (pending);
  *msg = dbus_pending_call_steal_reply (pending);
  dbus_pending_call_unref (pending);
  return (*msg != NULL);
}

static int get_device_path ()
{
  /* Get device object path */
  DBusMessage * msg = init_nm_dbus_method_call ("GetDeviceByIpIface");
  if (msg == NULL)
    return 0;
  DBusMessageIter args;
  dbus_message_iter_init_append (msg, &args);
  dbus_message_iter_append_basic (&args, DBUS_TYPE_STRING, &self.iface);
  if (!call_nm_dbus_method (&msg))
    return 0;

  if (!dbus_message_iter_init (msg, &args)
      || dbus_message_iter_get_arg_type (&args) != DBUS_TYPE_OBJECT_PATH) {
    dbus_message_unref (msg);
    return 0;
  }
  dbus_message_iter_get_basic (&args, &self.nm_iface_obj);

  strncpy (self.nm_iface_obj_buf, self.nm_iface_obj, sizeof (self.nm_iface_obj_buf));
  self.nm_iface_obj = self.nm_iface_obj_buf;
  dbus_message_unref (msg);
  return 1;
}

static int setup_connection ()
{
  DBusMessage * msg = init_dbus_method_call (ABC_NM_DBUS_DEST,
                                              ABC_NM_DBUS_OBJ "/Settings",
                                              ABC_NM_DBUS_IFACE ".Settings",
                                              "AddConnection");
  if (msg == NULL)
    return 0;

  /* Begin of connection settings section */
  /* All connection settings must be defined here */
  char uuid[37]; /* e.g. "c25da751-1b91-4262-9f94-3dcbddfaee5e" */
  random_bytes (uuid, 18);
  uuid[10] &= 0xBF; /* uuid[19] is one of 8,9,A,B */
  int i = 17;
  for (i = 17; i >= 0; --i)
    sprintf (&uuid[2*i], "%x", uuid[i]);
  uuid[8] = '-';
  uuid[13] = '-';
  uuid[14] = '4';
  uuid[18] = '-';
  uuid[23] = '-';
  uuid[37] = '\0';
  const char * connection = "connection",
             * conn_keys[] = { "id",     "type",           "uuid", "zone" },
             * conn_vals[] = { "AllNet", "802-11-wireless", NULL, "public" };
  conn_vals[2] = uuid;

  /* Valid properties available from:
   * http://cgit.freedesktop.org/NetworkManager/NetworkManager/tree/libnm-util/nm-setting-wireless.h
   */
  const char * wlan = "802-11-wireless",
             * wlan_keys[] = { "ssid", "mode", "band", "channel" },
             * wlan_vals[] = { NULL,   "adhoc", "bg" };
  /* when chaning the ssid, make sure to adapt the number of
   * dbus_message_iter_append_basic calls below
   */
  const unsigned char ssid[] = ALLNET_SSID_BYTE_ARRAY;
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

  if (!call_nm_dbus_method (&msg))
    return 0;

  if (!dbus_message_iter_init (msg, &args)
      || dbus_message_iter_get_arg_type (&args) != DBUS_TYPE_OBJECT_PATH) {
    dbus_message_unref (msg);
    return 0;
  }
  dbus_message_iter_get_basic (&args, &self.nm_conn_obj);
  strncpy (self.nm_conn_obj_buf, self.nm_conn_obj, sizeof (self.nm_conn_obj_buf));
  self.nm_conn_obj = self.nm_conn_obj_buf;
  dbus_message_unref (msg);
  return 1;
}

static int activate_connection ()
{
  DBusMessage * msg = init_nm_dbus_method_call ("ActivateConnection");
  if (msg == NULL) {
    // TODO: fprintf (stderr, "dbus: NULL message\n");
    return -1;
  }
  const char * specobj = "/"; /* specific_object argument (path of AP object, or "/" for auto */
  DBusMessageIter args;
  dbus_message_iter_init_append (msg, &args);
  dbus_message_iter_append_basic (&args, DBUS_TYPE_OBJECT_PATH, &self.nm_conn_obj);
  dbus_message_iter_append_basic (&args, DBUS_TYPE_OBJECT_PATH, &self.nm_iface_obj);
  dbus_message_iter_append_basic (&args, DBUS_TYPE_OBJECT_PATH, &specobj);
  const char * actconnobj;
  if (!call_nm_dbus_method (&msg))
    return -1;

  if (!dbus_message_iter_init (msg, &args)) {
    dbus_message_unref (msg);
    return 0;
  }
  assert (dbus_message_iter_get_arg_type (&args) == DBUS_TYPE_OBJECT_PATH);
  dbus_message_iter_get_basic (&args, &actconnobj);
  // TODO: store active connection path?
  // printf ("active connection is %s\n", actconnobj);
  dbus_message_unref (msg);
  // wait for activation signal...
  return 1;
}

static int get_conn_obj ()
{
  DBusMessage * msg = init_dbus_method_call (ABC_NM_DBUS_DEST,
                              ABC_NM_DBUS_OBJ "/Settings",
                              ABC_NM_DBUS_IFACE ".Settings",
                              "ListConnections");
  if (msg == NULL)
    return 0;
  if (!call_nm_dbus_method (&msg))
    goto cleanup_fail;

  DBusMessageIter args;
  if (!dbus_message_iter_init (msg, &args)) {
    /* TODO: log fprintf (stderr, "dbus: Message has no arguments\n"); */
  } else {
    assert (dbus_message_iter_get_arg_type (&args) == DBUS_TYPE_ARRAY);
    DBusMessageIter arg_var;
    dbus_message_iter_recurse (&args, &arg_var);
    int found_con = 0;
    do {
      const char * connobj;
      assert (dbus_message_iter_get_arg_type (&arg_var) == DBUS_TYPE_OBJECT_PATH);
      dbus_message_iter_get_basic (&arg_var, &connobj);
      /* for each connection, check if it's our "allnet" connection
       * for this, the ssid must be "allnet" and mode "adhoc"
       */
      DBusMessage * cmsg = dbus_message_new_method_call (ABC_NM_DBUS_DEST,
                                                         connobj,
                                                         ABC_NM_DBUS_IFACE ".Settings.Connection",
                                                         "GetSettings");
      if (cmsg == NULL)
        goto cleanup_fail;

      if (!call_nm_dbus_method (&cmsg)) {
        dbus_message_unref (cmsg);
        goto cleanup_fail;
      }

      DBusMessageIter cargs;
      const char * keyval;
      assert (dbus_message_iter_init (cmsg, &cargs));
      assert (dbus_message_iter_get_arg_type (&cargs) == DBUS_TYPE_ARRAY);
      DBusMessageIter carg_var[6];
      dbus_message_iter_recurse (&cargs, &carg_var[0]);
      do {
        assert (dbus_message_iter_get_arg_type (&carg_var[0]) == DBUS_TYPE_DICT_ENTRY);
        dbus_message_iter_recurse (&carg_var[0], &carg_var[1]);
        assert (dbus_message_iter_get_arg_type (&carg_var[1]) == DBUS_TYPE_STRING);
        dbus_message_iter_get_basic (&carg_var[1], &keyval);
        int has_next = dbus_message_iter_next (&carg_var[1]);
        assert (has_next);
        if (strcmp (keyval, "802-11-wireless") == 0) {
          /* check mode="adhoc", ssid="allnet" */
          int is_allnet = 0;
          int is_adhoc = 0;
          assert (dbus_message_iter_get_arg_type (&carg_var[1]) == DBUS_TYPE_ARRAY);
          dbus_message_iter_recurse (&carg_var[1], &carg_var[2]);
          do {
            assert (dbus_message_iter_get_arg_type (&carg_var[2]) == DBUS_TYPE_DICT_ENTRY);
            dbus_message_iter_recurse (&carg_var[2], &carg_var[3]);
            assert (dbus_message_iter_get_arg_type (&carg_var[3]) == DBUS_TYPE_STRING);
            dbus_message_iter_get_basic (&carg_var[3], &keyval);
            has_next = dbus_message_iter_next (&carg_var[3]);
            assert (has_next);
            if (strcmp (keyval, "ssid") == 0) {
              assert (dbus_message_iter_get_arg_type (&carg_var[3]) == DBUS_TYPE_VARIANT);
              dbus_message_iter_recurse (&carg_var[3], &carg_var[4]);
              assert (dbus_message_iter_get_arg_type (&carg_var[4]) == DBUS_TYPE_ARRAY);
              dbus_message_iter_recurse (&carg_var[4], &carg_var[5]);
              char ssid[] = ALLNET_SSID_BYTE_ARRAY;
              char byte;
              int i = 0;
              int has_next;
              do {
                assert (dbus_message_iter_get_arg_type (&carg_var[5]) == DBUS_TYPE_BYTE);
                dbus_message_iter_get_basic (&carg_var[5], &byte);
              } while (byte == ssid[i] && (has_next = dbus_message_iter_next (&carg_var[5])) && ++i <= sizeof (ssid));
              if (i == sizeof (ssid) - 1 && !has_next)
                is_allnet = 1;
              /* nicer alternative, but for some reason asserts..
               * remember: ssid is a byte array, no '\0' at the end
               * char * ssid;
               * int * ssid_len;
               * dbus_message_iter_get_fixed_array (&carg_var[4], ssid, ssid_len);
               * if (*ssid_len == 6 && strncmp (ssid, "allnet", 6) == 0) {
               *   is_allnet = 1;
               * }
               */

            } else if (strcmp (keyval, "mode") == 0) {
              assert (dbus_message_iter_get_arg_type (&carg_var[3]) == DBUS_TYPE_VARIANT);
              dbus_message_iter_recurse (&carg_var[3], &carg_var[4]);
              assert (dbus_message_iter_get_arg_type (&carg_var[4]) == DBUS_TYPE_STRING);
              dbus_message_iter_get_basic (&carg_var[4], &keyval);
              if (strcmp (keyval, "adhoc") == 0)
                is_adhoc = 1;
            }
          } while (dbus_message_iter_next (&carg_var[2]));
          if (is_adhoc && is_allnet) {
            strncpy (self.nm_conn_obj_buf, connobj, sizeof (self.nm_conn_obj_buf));
            self.nm_conn_obj = self.nm_conn_obj_buf;

            dbus_message_unref (cmsg);
            dbus_message_unref (msg);
            return 1;
          }
        }
      } while (dbus_message_iter_next (&carg_var[0]));
      dbus_message_unref (cmsg);

    } while (dbus_message_iter_next (&arg_var));
  }

cleanup_fail:
  dbus_message_unref (msg);
  return 0;
}

static int  abc_wifi_config_nm_is_wireless_on ()
{
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
  if (!call_nm_dbus_method (&msg))
    return -1;

  dbus_bool_t wlan_enabled;
  if (!dbus_message_iter_init (msg, &args)
      || dbus_message_iter_get_arg_type (&args) != DBUS_TYPE_VARIANT) {
    dbus_message_unref (msg);
    return -1;
  }

  DBusMessageIter arg_var;
  dbus_message_iter_recurse (&args, &arg_var);
  dbus_message_iter_get_basic (&arg_var, &wlan_enabled);
  dbus_message_unref (msg);
  return wlan_enabled;
}

static int abc_wifi_config_nm_init (const char * iface)
{
  self.conn = NULL;
  self.iface = iface;
  self.nm_iface_obj = NULL;
  self.nm_conn_obj = NULL;
  return init_dbus_connection (&self.conn);
}

static int abc_wifi_config_nm_enable_wireless (int state)
{
  dbus_bool_t on = state;
  DBusMessage * msg = dbus_message_new_method_call (ABC_NM_DBUS_DEST,
                                  ABC_NM_DBUS_OBJ,
                                  "org.freedesktop.DBus.Properties",
                                  "Set");
  if (msg == NULL)
    return -1;

  DBusMessageIter args;
  dbus_message_iter_init_append (msg, &args);
  const char * nm[2] = { ABC_NM_DBUS_IFACE, "WirelessEnabled" };
  dbus_message_iter_append_basic (&args, DBUS_TYPE_STRING, &nm[0]);
  dbus_message_iter_append_basic (&args, DBUS_TYPE_STRING, &nm[1]);
  dbus_message_iter_append_basic (&args, DBUS_TYPE_BOOLEAN, &on);
  int ret = call_nm_dbus_method (&msg);
  dbus_message_unref (msg);
  // TODO: return 2 when wireless is on but already in use
  return ret;
}

static int abc_wifi_config_nm_connect ()
{
  if (self.conn == NULL)
    return 0;

  if (self.nm_iface_obj == NULL && !get_device_path ()) {
    // TODO: allnet log
    return 0;
  }

  if (self.nm_conn_obj == NULL && !get_conn_obj ()) {
    // TODO: allnet log
    return 0;
  }

  if (!abc_wifi_config_nm_is_wireless_on () && !abc_wifi_config_nm_enable_wireless (1)) {
    // TODO: allnet log
    return 0;
  }

  if (activate_connection () == 1)
    return 1;
  return 0;
}
