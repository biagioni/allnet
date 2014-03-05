/* abc-wifi.c: Bradcast abc messages onto a wireless interface
 *
 * to do: If the interface is on and connected to a wireless LAN, I never
 * enter send mode.  Instead, I use energy saving mode to receive once
 * every basic cycle, and transmit once every 200 cycles.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ifaddrs.h>
#include <net/if.h>            /* ifa_flags */
#include <netpacket/packet.h>  /* struct sockaddr_ll */

#include "packet.h"

iface_is_on = 0;

/* similar to system(3), but more control over what gets printed */
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
    while (*p != '\0') {
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
    argv [num_args] = NULL;
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

/* return 1 if successful, 0 otherwise */
/* return 2 if failed, but returned status matches wireless_status */
static int if_command (char * basic_command, char * interface,
                       int wireless_status, char * fail_wireless,
                       char * fail_other)
{
  static int printed_success = 0;
  int size = strlen (basic_command) + strlen (interface) + 1;
  char * command = malloc (size);
  if (command == NULL) {
    printf ("abc: unable to allocate %d bytes for command:\n", size);
    printf (basic_command, interface);
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
        printf ("abc: call to '%s' failed, %s\n", command, fail_other);
      else
        printf ("abc: call to '%s' failed\n", command);
    } else {
      printf ("abc: call to '%s' failed, %s\n", command, fail_wireless);
      return 2;
    }
    return 0;
  }
  return 1;
}

/* returns 1 if successful, 2 if already up, 0 for failure */
static int wireless_up (char * interface)
{
#ifdef DEBUG_PRINT
  printf ("abc: opening interface %s\n", interface);
#endif /* DEBUG_PRINT */
/* need to execute the commands:
      sudo iw dev $if set type ibss
      sudo ifconfig $if up
      sudo iw dev $if ibss join allnet 2412
 */
  char * mess = "probably a wired or configured interface";
  if (geteuid () != 0)
    mess = "probably need to be root";
  int r = if_command ("iw dev %s set type ibss", interface, 240,
                      "wireless interface not available for ad-hoc mode",
                      mess);
  if (r == 0)
    return 0;
  if (r == 2) /* already up, no need to bring up the interface */
    return 2;
  /* continue with the other commands, which should succeed */
  if (! if_command ("ifconfig %s up", interface, 0, NULL, NULL))
    return 0;
  r = if_command ("iw dev %s ibss join allnet 2412", interface,
                  142, "allnet ad-hoc mode already set", "unknown problem");
  /* if (r == 0)
    return 0; */
  if (r == 0)
    return 2;
  return 1;
}

/* returns 1 if successful, 0 for failure */
static int wireless_down (char * interface)
{
#ifdef DEBUG_PRINT
  printf ("taking down interface %s\n", interface);
#endif /* DEBUG_PRINT */
/* doesn't seem to be necessary or helpful
  if (! if_command ("iw dev %s set type managed", interface, NULL))
    return 0;
*/
  if (! if_command ("ifconfig %s down", interface, 0, NULL, NULL))
    return 0;
  return 1;
}

static void default_broadcast_address (struct sockaddr_ll * bc)
{
  bc->sll_family = AF_PACKET;
  bc->sll_protocol = ALLNET_WIFI_PROTOCOL;
  bc->sll_hatype = 1;   /* used? */
  bc->sll_pkttype = 0;  /* not used */
  bc->sll_halen = 6;
  bc->sll_addr [0] = 0xff;
  bc->sll_addr [1] = 0xff;
  bc->sll_addr [2] = 0xff;
  bc->sll_addr [3] = 0xff;
  bc->sll_addr [4] = 0xff;
  bc->sll_addr [5] = 0xff;
  printf ("set default broadcast address\n");
}

static void print_sll_addr (struct sockaddr_ll * a, char * desc)
{
  if (desc != NULL)
    printf ("%s: ", desc);
  if (a->sll_family != AF_PACKET) {
    printf ("unknown address family %d\n", a->sll_family);
    return;
  }
  printf ("proto %d, ha %d pkt %d halen %d ", a->sll_protocol, a->sll_hatype,
          a->sll_pkttype, a->sll_halen);
  int i;
  for (i = 0; i < a->sll_halen; i++) {
    if (i > 0) printf (":");
    printf ("%02x", a->sll_addr [0]);
  }
  if (desc != NULL)
    printf ("\n");
}

unsigned long long int iface_on_off_ms = 150;  /* default */

/* returns -1 if the interface is not found */
/* returns 0 if the interface is off, and 1 if it is on already */
/* if returning 0 or 1, fills in the socket and the address */
/* to do: figure out how to set bits_per_s in init_wireless */
int init_iface (char * interface, int * sock,
                struct sockaddr_ll * address, struct sockaddr_ll * bc)
{
  struct ifaddrs * ifa;
  if (getifaddrs (&ifa) != 0) {
    perror ("getifaddrs");
    exit (1);
  }
  struct ifaddrs * ifa_loop = ifa;
  while (ifa_loop != NULL) {
    if ((ifa_loop->ifa_addr->sa_family == AF_PACKET) &&
        (strcmp (ifa_loop->ifa_name, interface) == 0)) {
      struct timeval start;
      gettimeofday (&start, NULL);
      int is_up = wireless_up (interface);
      int in_use = (is_up == 2);
      if (is_up) {
        struct timeval midtime;
        gettimeofday (&midtime, NULL);
        long long mtime = delta_us (&midtime, &start);
        if (! in_use) {
          wireless_down (interface);
          struct timeval finish;
          gettimeofday (&finish, NULL);
          long long time = delta_us (&finish, &start);
          printf ("abc: %s is wireless, %lld.%03lld ms to turn on+off\n",
                  interface, time / 1000LL, time % 1000LL);
          printf ("  (%lld.%03lld ms to turn on)\n",
                  mtime / 1000LL, mtime % 1000LL);
          iface_on_off_ms = time;
        }
        /* create the socket and initialize the address */
        *sock = socket (AF_PACKET, SOCK_DGRAM, ALLNET_WIFI_PROTOCOL);
        *address = *((struct sockaddr_ll *) (ifa_loop->ifa_addr));
        if (ifa_loop->ifa_flags & IFF_BROADCAST)
          *bc = *((struct sockaddr_ll *) (ifa_loop->ifa_broadaddr));
        else if (ifa_loop->ifa_flags & IFF_POINTOPOINT)
          *bc = *((struct sockaddr_ll *) (ifa_loop->ifa_dstaddr));
        else
          default_broadcast_address (bc);
        bc->sll_protocol = ALLNET_WIFI_PROTOCOL;  /* otherwise not set */
        print_sll_addr (address, "interface address");
        print_sll_addr (bc,      "broadcast address");
        freeifaddrs (ifa);
        iface_is_on = in_use;
        return in_use;
      }
    }
    ifa_loop = ifa_loop->ifa_next;
  }
  freeifaddrs (ifa);
  iface_is_on = -1;
  return -1;  /* interface not found */
}

void iface_on (char * interface)
{
  if (! iface_is_on) {
    wireless_up (interface);
    iface_is_on = 1;
  }
}

void iface_off (char * interface)
{
  if (iface_is_on) {
    wireless_down (interface);
    iface_is_on = 0;
  }
}
