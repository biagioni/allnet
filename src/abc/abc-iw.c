/* abc-iw.c: Configure wireless card using iw-tools */

#include <stdio.h>     /* perror, printf, snprintf */
#include <stdlib.h>    /* exit */
#include <string.h>    /* strlen */
#include <unistd.h>    /* fork, dup2, execvp */
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
static int abc_wifi_config_iw_init (const char * iface);
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

/**
 * similar to system(3), but more control over what gets printed
 * Destructive on input
 */
static int my_system (char * command)
{
  pid_t pid = fork ();
  if (pid < 0) {
    perror ("fork");
    printf ("error forking for command '%s'\n", command);
    return -1;
  }
  if (pid == 0) {   /* child */
    int num_args = 1;
    char * argv [100];
    char * p = command;
    int found_blank = 0;
    argv [0] = command;
    while (*p != '\0' && num_args <= sizeof (argv) / sizeof (char *)) {
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
    if (num_args >= sizeof (argv) / sizeof (char *)) {
      printf ("error: reading beyond array %d\n", num_args);
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
    dup2 (1, 2);   /* make stderr be a copy of stdout */
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
  int size = strlen (basic_command) + strlen (interface) + 1;
  char * command = malloc (size);
  if (command == NULL) {
    fprintf (stderr, "abc-iw: unable to allocate %d bytes for command:\n", size);
    fprintf (stderr, basic_command, interface);
    return 0;
  }
  snprintf (command, size, basic_command, interface);
  int sys_result = my_system (command);
  int max_print_success = 0;
#ifdef DEBUG_PRINT
  max_print_success = 4;
#endif /* DEBUG_PRINT */
  if ((sys_result != 0) || (printed_success++ < max_print_success))
    printf ("abc: result of calling '%s' was %d\n", command, sys_result);
  if (sys_result != 0) {
    if (sys_result != -1)
      printf ("abc: program exit status for %s was %d\n",
              command, sys_result);
    if (sys_result != wireless_status) {
      if (fail_other != NULL)
        fprintf (stderr, "abc-iw: call to '%s' failed, %s\n", command, fail_other);
      else
        fprintf (stderr, "abc-iw: call to '%s' failed\n", command);
    } else {
      fprintf (stderr, "abc-iw: call to '%s' failed, %s\n", command, fail_wireless);
      free (command);
      return 2;
    }
    free (command);
    return 0;
  }
  free (command);
  return 1;
}

static int abc_wifi_config_iw_init (const char * iface)
{
#ifdef USE_NETWORK_MANAGER
  if (abc_wifi_config_nm_init (iface)) {
    nm_init = abc_wifi_config_nm_is_wireless_on ();
    if (nm_init) {
      printf ("abc-iw: disabling NetworkManager on iface `%s'\n", iface);
      if (abc_wifi_config_nm_enable_wireless (0)) {
        printf ("abc-iw: NetworkManager disabled on iface `%s'\n", iface);
      }
    }
    /* disabling an iface in NM sets soft RFKILL which needs to be cleared for
     * ifconfig to work. */
    /* TODO: this should look up the device index and only unblock that in case
     * that the iface is not wifi or multiple wifi ifaces are present. */
    int ret = system ("rfkill unblock wifi");
    printf ("abc-iw: DEBUG: result of rfkill unblock: %d\n", ret);
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
static int abc_wifi_config_iw_connect ()
{
  if (self.is_connected)
    return 1;
#ifdef DEBUG_PRINT
  printf ("abc: opening interface %s\n", self.iface);
#endif /* DEBUG_PRINT */
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
  if (r != 1 || !if_command ("iw dev %s ibss join allnet 2412 fixed-freq", self.iface,
                      142, "allnet ad-hoc mode already set", "unknown problem"))
    return 0;
  /* use `iw dev WLAN0 link` since we're already using iw above.
   * An alternative way would be to use NL80211 directly
   * as does "iw event" (see source "case NL80211_CMD_JOIN_IBSS") */
  char * cmdfmt = "iw dev %s link";
  char cmd[12 + IFNAMSIZ]; /* IFNAMSIZ includes \0 */
  char tmp[16];
  long sleep = 25;
  long slept = 0;
  do {
    /* 50ms: empirically established time to connect to an _existing_ adhoc net */
    usleep (sleep * 1000L);
    slept += sleep;
    if (slept < 7000L)
      sleep *= 2;
    if (sleep == 100)
      sleep = 1000L;
    snprintf (cmd, sizeof (cmd), cmdfmt, self.iface);
    FILE * in = popen (cmd, "r");
    if ((in == NULL) ||
        (fgets (tmp, sizeof (tmp), in) == NULL) ||
        (pclose (in) == -1))
      goto connerr;
  } while (tmp[0] == 'N' /* strncmp (tmp, "Not connected.", 14) == 0 */ && slept < 14000L);
  if (slept >= 14000L)
    printf ("abc-iw: timeout hit, cell still not associated\n");

  self.is_connected = 1;
  return 1;

connerr:
  perror ("abc-iw");
  return 0;
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
      /* set power save mode (if available) */
      if_command ("iw dev %s set power_save on", self.iface, 0, NULL, NULL);
      return 1;
    }
  } else {
    if (self.is_connected) {
      if_command ("iw dev %s ibss leave", self.iface,
                          /* 161, "interface is not in ibss mode" */
                          189, "ad-hoc network already disconnected", "unknown problem");
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
