/* abc-networkmanager.c: Configure wireless card using NetworkManager */

#include <assert.h>
#include <dbus-1.0/dbus/dbus.h>
#include <stdio.h>              /* fprintf, printf, sprintf */
#include <stdlib.h>             /* malloc */
#include <string.h>             /* strcmp, strncpy */
#include <unistd.h>             /* sleep */

#include "lib/util.h"           /* random_bytes */
#include "abc-wifi.h"           /* abc_wifi_config_iface */
#include "abc-networkmanager.h"

#define ABC_NM_DBUS_DEST "org.freedesktop.NetworkManager"
#define ABC_NM_DBUS_OBJ "/org/freedesktop/NetworkManager"
#define ABC_NM_DBUS_IFACE "org.freedesktop.NetworkManager"
#define ALLNET_SSID_BYTE_ARRAY { 'a', 'l', 'l', 'n', 'e', 't' }

/* forward declarations */
static int abc_wifi_config_nm_is_connected ();
static int abc_wifi_config_nm_connect ();
static int abc_wifi_config_nm_await_connection ();
static int abc_wifi_config_nm_await_wireless ();
static int abc_wifi_config_nm_cleanup ();


typedef struct abc_nm_settings {
  DBusConnection * conn;
  const char * iface;
  const char * nm_iface_obj; /* ptr to nm_iface_obj_buf */
  const char * nm_conn_obj;  /* ptr to nm_conn_obj_buf */
  const char * nm_act_conn_obj;  /* ptr to nm_act_conn_obj_buf */
  char nm_iface_obj_buf[50]; /* len 41: /org/freedesktop/NetworkManager/Devices/1 */
  char nm_conn_obj_buf[50];  /* len 43: /org/freedesktop/NetworkManager/Settings/13 */
  char nm_act_conn_obj_buf[60]; /* len 52: /org/freedesktop/NetworkManager/Connection/Active/13 */
} abc_nm_settings;

/** public wifi config interface ready to use */
abc_wifi_config_iface abc_wifi_config_nm_wlan = {
  .config_type = ABC_WIFI_CONFIG_NETWORKMANAGER,
  .init_iface_cb = abc_wifi_config_nm_init,
  .iface_is_enabled_cb = abc_wifi_config_nm_is_wireless_on,
  .iface_set_enabled_cb = abc_wifi_config_nm_enable_wireless,
  .iface_is_connected_cb = abc_wifi_config_nm_is_connected,
  .iface_connect_cb = abc_wifi_config_nm_connect,
  .iface_cleanup_cb = abc_wifi_config_nm_cleanup
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

static void retrieve_variant (DBusMessageIter * arg, int type, void * val) {
  DBusMessageIter arg_var;
  dbus_message_iter_recurse (arg, &arg_var);
  assert (dbus_message_iter_get_arg_type (&arg_var) == type);
  dbus_message_iter_get_basic (&arg_var, val);
}

static int init_dbus_connection (DBusConnection ** conn)
{
  DBusError err;
  dbus_error_init (&err);
  *conn = dbus_bus_get (DBUS_BUS_SYSTEM, &err);
  if (dbus_error_is_set (&err)) {
    /* TODO: allnet log */
    fprintf (stderr, "dbus: Connection Error (%s)\n", err.message);
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
    return 0;
  }
  if (pending == NULL) {
    fprintf (stderr, "abc-nm: error calling dbus method (pending == NULL)\n");
    return 0;
  }
  dbus_connection_flush (self.conn);
  dbus_message_unref (*msg);
  dbus_pending_call_block (pending);
  *msg = dbus_pending_call_steal_reply (pending);
  dbus_pending_call_unref (pending);
  return (*msg != NULL);
}

/**
 * Retrieve a dbus property
 * msg must be initialized with dbus_message_iter_init (msg, &args); to read
 * the reply.
 * @return 1 on success, -1 on failure
 */
static int get_dbus_property (DBusMessage ** msg,
                                 const char * dbusobj,
                                 const char * dbusiface,
                                 const char * prop)
{
  *msg = dbus_message_new_method_call (ABC_NM_DBUS_DEST,
                                  dbusobj,
                                  "org.freedesktop.DBus.Properties",
                                  "Get");
  if (*msg == NULL)
    return -1;

  DBusMessageIter args;
  dbus_message_iter_init_append (*msg, &args);
  dbus_message_iter_append_basic (&args, DBUS_TYPE_STRING, &dbusiface);
  dbus_message_iter_append_basic (&args, DBUS_TYPE_STRING, &prop);
  if (!call_nm_dbus_method (msg))
    return -1;
  return 1;
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
  char uuid[37]; /* e.g. "c25da751-1b91-4262-9f94-3dcbddfaee5e" (36) + '\0' */
  char rand[18];
  const char hex[] = { '0', '1' ,'2', '3', '4', '5', '6', '7', '8', '9',
                       'a', 'b', 'c', 'd', 'e', 'f' };
  random_bytes (rand, sizeof (rand));
  rand[9] &= 0xFB; /* uuid[19] is one of 8,9,A,B */
  int i;
  for (i = 0; i < sizeof (rand); ++i) {
    uuid[2*i] = hex[(rand[i] >> 4) & 0xF];
    uuid[2*i + 1] = hex[rand[i] & 0xF];
  }

  uuid[8] = '-';
  uuid[13] = '-';
  uuid[14] = '4';
  uuid[18] = '-';
  uuid[23] = '-';
  uuid[36] = '\0';
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

/**
 * Synchronously await a dbus event.
 * @param rule valid rule for dbus_bus_add_match ().
 * @param msg_handler_cb Handler to invoke on matched messages. It is the
 *     handler's responsability to call dbus_message_is_signal (msg, sig_iface,
 *     sig_name). The handler must not call dbus_message_unref ().
 *     This function returns when it times out or the handler returns 0.
 * @param timeout Minimum timeout in seconds to wait for a message. 0 to wait
 *     indefinitely.
 * @return retval, if set by the callback, 0 otherwise.
 */
static int nm_dbus_await_match (const char * rule, int (*msg_handler_cb)(DBusMessage *, int * retval, void * data), int timeout, void * data)
{
  DBusError err;
  dbus_error_init (&err);

  int ret = 0;
  dbus_bus_add_match (self.conn, rule, &err);
  dbus_connection_flush (self.conn);
  if (dbus_error_is_set (&err))
    fprintf (stderr, "abc-nm: match error (%s)\n", err.message);

  else {
    int i = 0;
    while (1) {
      dbus_connection_read_write (self.conn, 0); /* non-blocking */
      DBusMessage * msg = dbus_connection_pop_message (self.conn);
      if (msg == NULL) {
        sleep (1);
        if (timeout > 0 && ++i > timeout)
          break;
        continue;
      }

      if (!msg_handler_cb (msg, &ret, data)) {
        dbus_message_unref (msg);
        break;
      }
      dbus_message_unref (msg);
    }
  }
  dbus_bus_remove_match (self.conn, rule, NULL);
  return ret;
}

static int abc_wifi_config_nm_is_connected ()
{
  if (self.nm_act_conn_obj == NULL)
    return 0;

  DBusMessage * msg;
  if (get_dbus_property (&msg, ABC_NM_DBUS_OBJ, ABC_NM_DBUS_IFACE,
              "ActiveConnections") != 1)
    return -1;

  int ret = 0;
  DBusMessageIter args;
  if (!dbus_message_iter_init (msg, &args))
    goto nm_is_connected_cleanup;

  assert (dbus_message_iter_get_arg_type (&args) == DBUS_TYPE_VARIANT);
  DBusMessageIter arg_v;
  dbus_message_iter_recurse (&args, &arg_v);
  assert (dbus_message_iter_get_arg_type (&arg_v) == DBUS_TYPE_ARRAY);
  DBusMessageIter arg_a;
  dbus_message_iter_recurse (&arg_v, &arg_a);
  do {
    const char * act_conn_obj;
    dbus_message_iter_get_basic (&arg_a, &act_conn_obj);
    if (strcmp (act_conn_obj, self.nm_act_conn_obj) == 0) {
      ret = 1;
      goto nm_is_connected_cleanup;
    }
  } while (dbus_message_iter_next (&arg_a));

nm_is_connected_cleanup:
  dbus_message_unref (msg);
  return ret;
}

static int abc_wifi_config_nm_connect ()
{
  DBusMessage * msg = init_nm_dbus_method_call ("ActivateConnection");
  if (msg == NULL)
    return -1;
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
  if (dbus_message_iter_get_arg_type (&args) != DBUS_TYPE_OBJECT_PATH) {
    if (dbus_message_iter_get_arg_type (&args) == DBUS_TYPE_STRING) {
      dbus_message_iter_get_basic (&args, &actconnobj);
      printf ("abc-nm: Error %s\n", actconnobj);
    } else
      printf ("abc-nm: Error in connect\n");
    dbus_message_unref (msg);
    return 0;
  }
  dbus_message_iter_get_basic (&args, &actconnobj);
  strncpy (self.nm_act_conn_obj_buf, actconnobj, sizeof (self.nm_act_conn_obj_buf));
  self.nm_act_conn_obj = self.nm_act_conn_obj_buf;
  dbus_message_unref (msg);
  return abc_wifi_config_nm_await_connection ();
}

static int abc_wifi_config_nm_await_connection_handler (DBusMessage * msg, int * retval, void * data)
{
  if (dbus_message_is_signal (msg, ABC_NM_DBUS_IFACE ".Connection.Active", "PropertiesChanged")) {
    DBusMessageIter args;
    if (dbus_message_iter_init (msg, &args) &&
        dbus_message_iter_get_arg_type (&args) == DBUS_TYPE_ARRAY)
    {
      DBusMessageIter arg_a[2];
      dbus_message_iter_recurse (&args, &arg_a[0]);
      do {
        assert (dbus_message_iter_get_arg_type (&arg_a[0]) == DBUS_TYPE_DICT_ENTRY);
        dbus_message_iter_recurse (&arg_a[0], &arg_a[1]);
        assert (dbus_message_iter_get_arg_type (&arg_a[1]) == DBUS_TYPE_STRING);
        const char * keyval;
        dbus_message_iter_get_basic (&arg_a[1], &keyval);
        if (strcmp (keyval, "State") == 0) {
          int has_next = dbus_message_iter_next (&arg_a[1]);
          assert (has_next);
          assert (dbus_message_iter_get_arg_type (&arg_a[1]) == DBUS_TYPE_VARIANT);
          dbus_uint32_t state;
          retrieve_variant (&arg_a[1], DBUS_TYPE_UINT32, &state);
          if (state == 2 /* NM_ACTIVE_CONNECTION_STATE_ACTIVATED */)
            *retval = 1;
          else if (state == 4 /* NM_ACTIVE_CONNECTION_STATE_DEACTIVATED */)
            self.nm_act_conn_obj = NULL;
          return 0;
        }
      } while (dbus_message_iter_next (&arg_a[0]));
    }
  }
  return 1;
}

/** Wait for activation signal... */
static int abc_wifi_config_nm_await_connection ()
{
  const char * fmt = "type='signal',interface='" ABC_NM_DBUS_IFACE
                     ".Connection.Active',path='%s'";
  char * rule = (char *)malloc ((strlen (fmt) -2 + strlen (self.nm_act_conn_obj) + 1) * sizeof (char));
  sprintf (rule, fmt, self.nm_act_conn_obj);
  int ret = nm_dbus_await_match (rule, abc_wifi_config_nm_await_connection_handler, 25, NULL);
  free (rule);
  return ret;
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
  if (dbus_message_iter_init (msg, &args)) {
    assert (dbus_message_iter_get_arg_type (&args) == DBUS_TYPE_ARRAY);
    DBusMessageIter arg_var;
    dbus_message_iter_recurse (&args, &arg_var);
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

/** Checks if a non-allnet connection is occupying our interface */
static int abc_wifi_config_nm_is_device_busy ()
{
  /* check if the allnet connection is active.
   * Step 1/3: Get active connections */
  DBusMessage * msg;
  if (get_dbus_property (&msg, ABC_NM_DBUS_OBJ, ABC_NM_DBUS_IFACE,
              "ActiveConnections") != 1)
    return -1;

  int ret = -1;
  DBusMessageIter args;
  if (!dbus_message_iter_init (msg, &args))
    goto device_is_busy_cleanup;
  assert (dbus_message_iter_get_arg_type (&args) == DBUS_TYPE_VARIANT);
  DBusMessageIter arg_v;
  dbus_message_iter_recurse (&args, &arg_v);
  assert (dbus_message_iter_get_arg_type (&arg_v) == DBUS_TYPE_ARRAY);
  DBusMessageIter arg_a;
  dbus_message_iter_recurse (&arg_v, &arg_a);
  do {
    const char * act_conn_obj;
    dbus_message_iter_get_basic (&arg_a, &act_conn_obj);

    /* Step 2/3: Check if it's _not_ the allnet connection */
    DBusMessage * amsg = dbus_message_new_method_call (ABC_NM_DBUS_DEST,
                                    act_conn_obj,
                                    "org.freedesktop.DBus.Properties",
                                    "GetAll");
    if (amsg == NULL)
      goto device_is_busy_cleanup;

    const char * dbusiface = ABC_NM_DBUS_IFACE ".Connection.Active";
    DBusMessageIter aargs;
    dbus_message_iter_init_append (amsg, &aargs);
    dbus_message_iter_append_basic (&aargs, DBUS_TYPE_STRING, &dbusiface);
    if (!call_nm_dbus_method (&amsg))
      goto device_is_busy_cleanup;

    if (!dbus_message_iter_init (amsg, &aargs)
        || dbus_message_iter_get_arg_type (&aargs) != DBUS_TYPE_ARRAY) {
      dbus_message_unref (amsg);
      goto device_is_busy_cleanup;
    }
    int our_conn;
    int our_dev = 0;
    do { /* loop over all properties */
      DBusMessageIter aarg_v[3];
      dbus_message_iter_recurse (&aargs, &aarg_v[0]);
      assert (dbus_message_iter_get_arg_type (&aarg_v[0]) == DBUS_TYPE_DICT_ENTRY);
      dbus_message_iter_recurse (&aarg_v[0], &aarg_v[1]);
      /* property key */
      assert (dbus_message_iter_get_arg_type (&aarg_v[1]) == DBUS_TYPE_STRING);
      const char * key;
      dbus_message_iter_get_basic (&aarg_v[1], &key);
      int has_next = dbus_message_iter_next (&aarg_v[1]);
      assert (has_next);
      /* property value */
      assert (dbus_message_iter_get_arg_type (&aarg_v[1]) == DBUS_TYPE_VARIANT);
      dbus_message_iter_recurse (&aarg_v[1], &aarg_v[2]);

      if (strcmp (key, "Connection") == 0) {
        assert (dbus_message_iter_get_arg_type (&aarg_v[2]) == DBUS_TYPE_OBJECT_PATH);
        const char * conn_obj;
        dbus_message_iter_get_basic (&aarg_v[2], &conn_obj);
        /* Step 3/3: It's not the allnet connection, is it on our device? */
        our_conn = (strcmp (conn_obj, self.nm_conn_obj) == 0);

      } else if (strcmp (key, "Devices") == 0) {
        assert (dbus_message_iter_get_arg_type (&aarg_v[2]) == DBUS_TYPE_ARRAY);
        dbus_message_iter_recurse (&aarg_v[2], &aarg_v[3]);
        do {
          assert (dbus_message_iter_get_arg_type (&aarg_v[3]) == DBUS_TYPE_OBJECT_PATH);
          const char * dev_obj;
          dbus_message_iter_get_basic (&aarg_v[3], &dev_obj);
          if (strcmp (dev_obj, self.nm_iface_obj) == 0) {
            our_dev = 1; /* It is on our device */
            break;
          }
        } while (dbus_message_iter_next (&aarg_v[3]));
      }
      if (!our_conn && our_dev) {
        ret = 1; /* There's a foreign connection on our device -> we're busy */
        dbus_message_unref (amsg);
        goto device_is_busy_cleanup;
      }
    } while (dbus_message_iter_next (&aargs));
    dbus_message_unref (amsg);
  } while (dbus_message_iter_next (&arg_a)); /* active connections */

  ret = 0;
device_is_busy_cleanup:
  dbus_message_unref (msg);
  return ret;
}

int abc_wifi_config_nm_is_wireless_on ()
{
  DBusMessage * msg;
  if (get_dbus_property (&msg, ABC_NM_DBUS_OBJ, ABC_NM_DBUS_IFACE,
              "WirelessEnabled") != 1)
    return -1;
  DBusMessageIter args;
  if (!dbus_message_iter_init (msg, &args)
      || dbus_message_iter_get_arg_type (&args) != DBUS_TYPE_VARIANT) {
    dbus_message_unref (msg);
    return -1;
  }

  dbus_bool_t wlan_enabled;
  retrieve_variant (&args, DBUS_TYPE_BOOLEAN, &wlan_enabled);
  dbus_message_unref (msg);

  if (wlan_enabled && abc_wifi_config_nm_is_device_busy () == 1)
    return 2;
  return wlan_enabled;
}

int abc_wifi_config_nm_init (const char * iface)
{
  self.conn = NULL;
  self.iface = iface;
  self.nm_iface_obj = NULL;
  self.nm_conn_obj = NULL;
  self.nm_act_conn_obj = NULL;

  if (!init_dbus_connection (&self.conn))
    return 0;

  if (!get_device_path ()) {
    fprintf (stderr, "abc-nm: error: failed to resolve interface dbus object\n"); /* TODO: allnet log */
    return 0;
  }

  if (!get_conn_obj ()) {
    printf ("abc-nm: No NetworkManager connection AllNet found, creating new one\n");
    if (!setup_connection ())
      return 0;
  }
  return 1;
}

static int abc_wifi_config_nm_await_wireless_handler (DBusMessage * msg, int * retval, void * data)
{
  if (dbus_message_is_signal (msg, ABC_NM_DBUS_IFACE ".Device.Wireless", "PropertiesChanged")) {
    DBusMessageIter args;
    if (dbus_message_iter_init (msg, &args) &&
        dbus_message_iter_get_arg_type (&args) == DBUS_TYPE_ARRAY)
    {
      DBusMessageIter arg_a[2];
      dbus_message_iter_recurse (&args, &arg_a[0]);
      do {
        assert (dbus_message_iter_get_arg_type (&arg_a[0]) == DBUS_TYPE_DICT_ENTRY);
        dbus_message_iter_recurse (&arg_a[0], &arg_a[1]);
        assert (dbus_message_iter_get_arg_type (&arg_a[1]) == DBUS_TYPE_STRING);
        const char * keyval;
        dbus_message_iter_get_basic (&arg_a[1], &keyval);
        if (strcmp (keyval, "State") == 0) {
          int has_next = dbus_message_iter_next (&arg_a[1]);
          assert (has_next);
          assert (dbus_message_iter_get_arg_type (&arg_a[1]) == DBUS_TYPE_VARIANT);
          dbus_uint32_t state;
          retrieve_variant (&arg_a[1], DBUS_TYPE_UINT32, &state);
          /* All states between those are active states */
          if (state > 20 || /* NM_DEVICE_STATE_UNAVAILABLE */
              state <= 100) /* NM_DEVICE_STATE_ACTIVATED */
            *retval = 1;
          return 0;
        }
      } while (dbus_message_iter_next (&arg_a[0]));
    }
  }
  return 1;
}

static int abc_wifi_config_nm_await_wireless (int state)
{
  const char * fmt = "type='signal',interface='" ABC_NM_DBUS_IFACE
                     ".Device.Wireless',path='%s'";
  char * rule = (char *)malloc ((strlen (fmt) -2 + strlen (self.nm_iface_obj) + 1) * sizeof (char));
  sprintf (rule, fmt, self.nm_iface_obj);
  int ret = nm_dbus_await_match (rule, abc_wifi_config_nm_await_wireless_handler, 5, NULL);
  free (rule);
  return ret == state;
}

int abc_wifi_config_nm_enable_wireless (int state)
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
  append_variant (&args, DBUS_TYPE_BOOLEAN, &on);
  int ret = call_nm_dbus_method (&msg);
  dbus_message_unref (msg);
  if (!state)
    self.nm_act_conn_obj = NULL;
  return ret && abc_wifi_config_nm_await_wireless (state);
}

static int abc_wifi_config_nm_cleanup ()
{
  return 1;
}
