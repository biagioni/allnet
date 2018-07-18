/* abc-iw.c: Configure wireless card using iw-tools */

#include <stdio.h>     /* perror, printf, snprintf */
#include <stdlib.h>    /* exit */
#include <string.h>    /* strlen */
#include <unistd.h>    /* fork, dup2, execvp */
#include <sys/socket.h> /* struct sockaddr */
#include <net/if.h>    /* IFNAMSIZ */
#include <sys/types.h> /* pid_t */
#include <sys/wait.h>  /* waitpid */

#include "abc-wifi.h" /* abc_wifi_config_iface */
#include "abc-iw.h"
#ifdef USE_NETWORK_MANAGER
#include "abc-networkmanager.h"

static int nm_init = 0;
#endif

/* forward declarations */
static int abc_wifi_config_iw_init (const char * iface, struct allnet_log * l);
static int abc_wifi_config_iw_is_connected ();
static int abc_wifi_config_iw_connect ();
static int abc_wifi_config_iw_is_wireless_on ();
static int abc_wifi_config_iw_set_enabled (int state);
static int abc_wifi_config_iw_cleanup ();

typedef struct abc_wifi_config_iw_settings {
  const char * iface;
  int is_connected;
  int is_enabled;
} abc_wifi_config_iw_settings;

/** public iw-based wifi config interface, ready to use */
abc_wifi_config_iface abc_wifi_config_iw = {
  .config_type = ABC_WIFI_CONFIG_IW,
  .init_iface_cb = abc_wifi_config_iw_init,
  .iface_is_enabled_cb = abc_wifi_config_iw_is_wireless_on,
  .iface_set_enabled_cb = abc_wifi_config_iw_set_enabled,
  .iface_is_connected_cb = abc_wifi_config_iw_is_connected,
  .iface_connect_cb = abc_wifi_config_iw_connect,
  .iface_cleanup_cb = abc_wifi_config_iw_cleanup
};

static abc_wifi_config_iw_settings self;

static struct allnet_log * alog = NULL;

/**
 * similar to system(3), but more control over what gets printed
 * Destructive on input
 */
static int my_system (char * command)
{
  pid_t pid = fork ();
  if (pid < 0) {
    perror ("fork");
    snprintf (alog->b, alog->s, "error forking command '%s'\n", command);
    log_print (alog);
    printf ("error forking command '%s'\n", command);
    return -1;
  }
  if (pid == 0) {   /* child */
    int num_args = 1;
    char * argv [100];
    char * p = command;
    int found_blank = 0;
    argv [0] = command;
    while ((*p != '\0') &&
           (num_args <= (int) (sizeof (argv) / sizeof (char *)))) {
      if (found_blank) {
        if (*p != ' ') {
          argv [num_args] = p;
          num_args++;
          found_blank = 0;
        }
      } else if (*p == ' ') {
        found_blank = 1;
        *p = '\0';
      }
      p++;
    }
    if (num_args >= (int) (sizeof (argv) / sizeof (char *))) {
      snprintf (alog->b, alog->s, "error: reading beyond argv %d\n", num_args);
      log_print (alog);
      argv [sizeof (argv) / sizeof (char *) - 1] = NULL;
    } else {
      argv [num_args] = NULL;
    }
/*
    printf ("executing ");
    char ** debug_p = argv;
    while (*debug_p != NULL) {
      printf ("%s ", *debug_p);
      debug_p++;
    }
    printf ("\n");
*/
#ifdef DEBUG_PRINT
    dup2 (1, 2);   /* make stderr be a copy of stdout */
#else /* DEBUG_PRINT */
    close (0);  /* close stdin */
    close (1);  /* close stdout */
    close (2);  /* close stderr */
#endif /* DEBUG_PRINT */
    execvp (argv [0], argv);
    perror ("execvp");
    exit (1);
  }
  /* parent */
  int status;
  do {
    waitpid (pid, &status, 0);
  } while (! WIFEXITED (status));
/*
  printf ("child process (%s) exited, status is %d\n",
          command, WEXITSTATUS (status));
*/
  return (WEXITSTATUS (status));
}

/**
 * Execute an iw command
 * @param basic_command Command with %s where interface is to be replaced
 * @param interface wireless interface (e.g. wlan0)
 * @param wireless_status alternate expected return status. If matched this
 *           function returns 2.
 * @param fail_wireless Error message when wireless_status is encountered or NULL.
 * @param fail_other Error message for unexpected errors or NULL.
 * @return 1 if successful (command returned 0), 2 if command status matches
 *           wireless_status, 0 otherwise */
static int if_command (const char * basic_command, const char * interface,
                       int wireless_status, const char * fail_wireless,
                       const char * fail_other)
{
  static int printed_success = 0;
  char command [1000];
  int ilen = 0;
  if (interface != NULL)
    ilen = (int)strlen (interface);
  if (strlen (basic_command) + ilen + 1 >= sizeof (command)) {
    snprintf (alog->b, alog->s, "abc-iw: command %d+interface %d + 1 >= %d\n",
              (int) (strlen (basic_command)), ilen, (int) (sizeof (command)));
    log_print (alog);
    snprintf (alog->b, alog->s, basic_command, interface);
    log_print (alog);
    return 0;
  }
  if (interface != NULL)
    snprintf (command, sizeof (command), basic_command, interface);
  else
    snprintf (command, sizeof (command), "%s", basic_command);
  int sys_result = my_system (command);
  int max_print_success = 0;
#ifdef DEBUG_PRINT
  max_print_success = 4;
#endif /* DEBUG_PRINT */
  if ((sys_result == 0) && (printed_success++ < max_print_success))
    printf ("abc-iw: result of calling '%s' was %d\n", command, sys_result);
  if (sys_result != 0) {
    if (sys_result != -1) {
      snprintf (alog->b, alog->s,
                "abc-iw: program exit status for %s was %d\n",
                command, sys_result);
      log_print (alog);
#ifdef DEBUG_PRINT
      printf ("abc-iw: program exit status for %s was %d, ws %d\n", command,
              sys_result, wireless_status);
#endif /* DEBUG_PRINT */
    }
    if (sys_result != wireless_status) {
      if (fail_other != NULL)
        snprintf (alog->b, alog->s,
                  "abc-iw: call to '%s' failed, %s\n", command, fail_other);
      else
        snprintf (alog->b, alog->s,
                  "abc-iw: call to '%s' failed\n", command);
      log_print (alog);
      if (fail_other == NULL)
        printf ("abc-iw: result of calling '%s' was %d\n", command, sys_result);
      else if (strlen (fail_other) > 0)
        printf ("%s\n", fail_other);
    } else {
      if (fail_wireless == NULL) {
        printf ("abc-iw: result of calling '%s' was %d\n", command, sys_result);
      } else if (strlen (fail_wireless) > 0) {
        snprintf (alog->b, alog->s,
                  "abc-iw: call to '%s' failed, %s\n", command, fail_wireless);
        log_print (alog);
        printf ("%s: %s\n", interface, fail_wireless);
      }
      return 2;
    }
    return 0;
  }
  return 1;
}

static int abc_wifi_config_iw_init (const char * iface,
                                    struct allnet_log * use_log)
{
  alog = use_log;
#ifdef USE_NETWORK_MANAGER
  if (abc_wifi_config_nm_init (iface, use_log)) {
    nm_init = abc_wifi_config_nm_is_wireless_on ();
    if (nm_init) {
      snprintf (alog->b, alog->s,
                "abc-iw: disabling NetworkManager on iface `%s'\n", iface);
      log_print (alog);
      printf ("abc-iw: disabling NetworkManager on iface `%s'\n", iface);
      if (abc_wifi_config_nm_enable_wireless (0)) {
        snprintf (alog->b, alog->s,
                  "abc-iw: NetworkManager disabled on iface `%s'\n", iface);
        log_print (alog);
      }
    }
    /* disabling an iface in NM sets soft RFKILL which needs to be cleared for
     * ifconfig to work. */
    /* TODO: this should look up the device index and only unblock that
     * in case the iface is not wifi or multiple wifi ifaces are present. */
    /* TODO: this should be done either here or below, not both */
    char command [] = "rfkill unblock wifi";
#ifdef DEBUG_PRINT
    int ret = my_system (command);
    printf ("abc-iw: DEBUG: result of rfkill unblock: %d\n", ret);
#else /* DEBUG_PRINT */
    my_system (command);
#endif /* DEBUG_PRINT */
  }
#endif
  self.iface = iface;
  self.is_connected = 0;
  self.is_enabled = 0;
  return 1;
}

static int abc_wifi_config_iw_is_connected ()
{
  return self.is_connected;
}

/** Join allnet adhoc network */
/* 2015/03/16: commands appear to be:
   rfkill unblock wifi
   iw dev $if set type ibss
   ifconfig $if up
   iw dev $if ibss join allnet 2412 fixed-freq 60:a4:4c:e8:bc:9c
   see also https://wireless.wiki.kernel.org/en/users/documentation/iw/vif
 */
static int abc_wifi_config_iw_connect ()
{
  if (self.is_connected)
    return 1;
#ifdef DEBUG_PRINT
  snprintf (alog->b, alog->s, "abc: opening interface %s\n", self.iface);
  log_print (alog);
#endif /* DEBUG_PRINT */
  char * mess = NULL;
  if (geteuid () != 0)
    mess = "probably need to be root";
  if (! if_command ("rfkill unblock wifi", NULL, 1, "", mess))
    printf ("rfkill failed\n");
  int iwret = if_command ("iw dev %s set type ibss", self.iface, 240, "", mess);
  if (iwret == 2) { /* this happens if iface is up and in managed mode */
    /* so bring it down first, then repeat */
    if (! if_command ("ifconfig %s down", self.iface, 0, NULL,
                      "unable to turn off interface"))
      return 0;
    if (! if_command ("iw dev %s set type ibss", self.iface, 0, NULL, mess))
      return 0;
  }
  if (! if_command ("ifconfig %s up", self.iface, 255,
                    "interface already up", mess))
    return 0;
/* it is better to leave first, in case it is set incorrectly -- otherwise
 * sometimes the next command fails but we are not on allnet */
  char * leave_cmd = "iw dev %s ibss leave";
  if (! if_command (leave_cmd, self.iface, 67, "", mess)) {
    /* whether it succeeds or not, we are OK */
  }
/* giving a specific BSSID (60:a4:4c:e8:bc:9c) on one trial sped up the
 * time to turn on the interface from over 5s to less than 1/2s, because
 * the driver no longer scans to see if somebody else is already offering
 * this ssid on a different bssid.  This also keeps different allnets
 * for trying to use different bssids, which prevents communication.
 * This BSSID is the MAC address of an existing Ethernet card,
 * so should not be in use by anyone else in the world. */
  char * cmd = "iw dev %s ibss join allnet 2412 fixed-freq 60:a4:4c:e8:bc:9c";
  if (! if_command (cmd, self.iface, 142, "interface already on allnet", mess))
    return 0;
/* if (! if_command ("iw dev %s ibss join allnet 2412 fixed-freq", self.iface,
      142, "interface already on allnet", mess))
    return 0; */
  self.is_connected = 1;

  /* unset power save mode (if available) -- at most once */
  static int set_power_save = 1;
  if (set_power_save) {   /* do this at most once */
    if_command ("iw dev %s set power_save off", self.iface, 161,
                "" /* power saving not supported, no error message */ , NULL);
    set_power_save = 0;
  }

  return 1;
#if 0   /* previous code, didn't seem to work as well */
/* need to execute the commands:
      sudo iw dev $if set type ibss
      sudo iw dev $if ibss join allnet 2412
 */
  const char * mess = NULL;
  if (geteuid () != 0)
    mess = "probably need to be root";
  int r = if_command ("iw dev %s set type ibss", self.iface, 240,
                      "wireless interface not available for ad-hoc mode",
                      mess);
  if (r != 1)
    return 0;
/* giving a specific BSSID (60:a4:4c:e8:bc:9c) speeds up the time to turn on
 * the interface from over 5s to less than 1/2s, because the driver no longer
 * scans to see if somebody else is already offering this ssid on a different
 * bssdid.  The BSSID is the MAC address of an existing Ethernet card,
 * so should not be in use by anyone else in the world. */
  if (! if_command
          ("iw dev %s ibss join allnet 2412 fixed-freq 60:a4:4c:e8:bc:9c",
           self.iface, 142, "allnet ad-hoc mode already set",
           "unknown problem"))
    return 0;
  /* use `iw dev WLAN0 link` since we're already using iw above.
   * An alternative way would be to use NL80211 directly
   * as does "iw event" (see source "case NL80211_CMD_JOIN_IBSS") */
  char * cmdfmt = "iw dev %s link";
  char cmd [12 + IFNAMSIZ]; /* IFNAMSIZ includes \0 */
  char command_result [16];
  long sleep = 25;  /* in ms */
  long slept = 0;   /* in ms */
  do {
/* 50ms: empirically established time to connect to an _existing_ adhoc net */
    usleep (sleep * 1000L);
    slept += sleep;
    if (sleep < 800)
      sleep *= 2;
    snprintf (cmd, sizeof (cmd), cmdfmt, self.iface);
    FILE * in = popen (cmd, "r");
    if ((in == NULL) ||
        (fgets (command_result, sizeof (command_result) - 1, in) == NULL) ||
        (pclose (in) == -1)) {
      perror ("abc-iw");
      return 0;
    }
    command_result [sizeof (command_result) - 1] = '\0';
#ifdef DEBUG_PRINT
    printf ("result of %s is '%s'\n", cmd, command_result);
#endif /* DEBUG_PRINT */
  } while ((strncmp (command_result, "Not connected.", 14) == 0) &&
           (slept < 14000L));
  if (slept >= 14000L) {
    snprintf (alog->b, alog->s,
              "abc-iw: timeout hit, cell still not associated\n");
    log_print (alog);
    return 0;
  }
  self.is_connected = 1;
  return 1;
#endif /* 0    previous code, didn't seem to work as well */
}

/** Returns wlan state (1: enabled or 0: disabled, -1: unknown) */
static int abc_wifi_config_iw_is_wireless_on ()
{
  /* TODO: check if already connected to something else (busy) and return 2. */
  return self.is_enabled;
}

/** Enable or disable wlan depending on state (1 or 0) */
static int abc_wifi_config_iw_set_enabled (int state)
{
  if (self.is_enabled == state)
    return 1;

  /* call (sudo) ifconfig $if {up|down} */
  if (state) {
    if (if_command ("ifconfig %s up", self.iface, 0, NULL, NULL)) {
      self.is_enabled = 1;
      return 1;
    }
  } else {
    if (self.is_connected) {
#if 0  /* or, we should connect to the ibss in the other direction */
      if_command ("iw dev %s ibss leave", self.iface,
                  /* 161, "interface is not in ibss mode" */
                  189, "ad-hoc network already disconnected",
                  "unknown problem");
#endif /* 0 */
      self.is_connected = 0;
    }

    if (if_command ("ifconfig %s down", self.iface, 0, NULL, NULL)) {
      self.is_enabled = 0;
      return 1;
    }
  }
  self.is_enabled = -1;
  return -1;
}

static int abc_wifi_config_iw_cleanup ()
{
#ifdef USE_NETWORK_MANAGER
  if (nm_init)
    abc_wifi_config_nm_enable_wireless (1);
#endif
  return 1;
}
