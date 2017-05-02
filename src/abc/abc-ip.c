/* abc-ip.c: Broadcast abc messages onto a generic ip interface */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>           /* close */
#include <ifaddrs.h>
#include <sys/socket.h>       /* struct sockaddr */
#include <net/if.h>           /* ifa_flags */
#include <netinet/in.h>       /* struct sockaddr_in */
#include <sys/time.h>         /* gettimeofday */

#include "lib/util.h"         /* delta_us */

#include "abc-iface.h"        /* sockaddr_t */

#include "abc-ip.h"

/* forward declarations */
static int abc_ip_init (const char * interface, struct allnet_log * log);
static int abc_ip_is_enabled ();
static int abc_ip_set_enabled (int state);
static int abc_ip_cleanup ();
static int abc_ip_accept_sender (const struct sockaddr *);

struct abc_iface_ip_priv {
} abc_iface_ip_priv;

abc_iface abc_iface_ip = {
  .iface_name = NULL,
  .iface_type = ABC_IFACE_TYPE_IP,
  .iface_is_managed = 0,
  .iface_type_args = NULL,
  .iface_sockfd = -1,
  .if_family = AF_INET,
  .if_address = {},
  .bc_address = {},
  .sockaddr_size = sizeof (struct sockaddr_in),
  .init_iface_cb = abc_ip_init,
  .iface_on_off_ms = 0, /* always on iface */
  .iface_is_enabled_cb = abc_ip_is_enabled,
  .iface_set_enabled_cb = abc_ip_set_enabled,
  .iface_cleanup_cb = abc_ip_cleanup,
  .accept_sender_cb = abc_ip_accept_sender,
  .priv = NULL
};

/* 2016/04/10 -- not in use yet, but good to have */
static struct allnet_log * alog = NULL;

static int abc_ip_is_enabled ()
{
  return 1;
}

static int abc_ip_set_enabled (int state)
{
  return 0;
}

/**
 * Init abc ip interface and UDP socket
 * @param interface Interface string of iface to init
 * @return 1 on success, 0 otherwise
 */
static int abc_ip_init (const char * interface, struct allnet_log * use_log)
{
  alog = use_log;
  abc_iface_ip.priv = &abc_iface_ip_priv;
  struct ifaddrs * ifa;
  if (getifaddrs (&ifa) != 0) {
    perror ("abc-ip: getifaddrs");
    return 0;
  }
  int ret = 0;
  struct ifaddrs * ifa_loop = ifa;
  while (ifa_loop != NULL) {
    if ((ifa_loop->ifa_addr != NULL) &&
        (ifa_loop->ifa_addr->sa_family == AF_INET) &&
        (strcmp (ifa_loop->ifa_name, interface) == 0)) {
      if (!(ifa_loop->ifa_flags & IFF_UP)) {
        fprintf (stderr, "abc-ip: interface %s is down\n", ifa_loop->ifa_name);
        goto abc_ip_init_cleanup;
      }
      abc_iface_ip.if_address.in = *((struct sockaddr_in *)ifa_loop->ifa_addr);
#ifdef TRACKING_TIME
      struct timeval start;
      gettimeofday (&start, NULL);
#endif /* TRACKING_TIME */
      if (abc_ip_is_enabled () == 0)
        abc_ip_set_enabled (1);
#ifdef TRACKING_TIME
      struct timeval midtime;
      gettimeofday (&midtime, NULL);
      long long mtime = delta_us (&midtime, &start);
#endif /* TRACKING_TIME */
      /* create the socket and initialize the address */
      abc_iface_ip.iface_sockfd = socket (AF_INET, SOCK_DGRAM, IPPROTO_UDP);
      if (abc_iface_ip.iface_sockfd == -1) {
        perror ("abc-ip: error creating socket");
        goto abc_ip_init_cleanup;
      }
      int flag = 1;
      if (setsockopt (abc_iface_ip.iface_sockfd, SOL_SOCKET, SO_BROADCAST,
                      &flag, sizeof (flag)) != 0)
        printf ("abc-ip: error setting broadcast flag\n");
#ifdef SO_BINDTODEVICE
      /* we bind to the device to only send to and receive from that device.
       * SO_BINDTODEVICE is reserved for the superuser (for no obvious reason),
       * so it will fail otherwise.  However, the only consequence is that
       * we might receive from multiple interfaces and send to multiple
       * interfaces, which is not a problem!!!
       * some systems do not define SO_BINDTODEVICE, hence the ifdef */
      if (setsockopt (abc_iface_ip.iface_sockfd, SOL_SOCKET, SO_BINDTODEVICE,
                      interface, strlen (interface)) != 0) {
        if (geteuid () == 0)
          printf ("abc-ip: error binding to device\n");
      }
#endif /* SO_BINDTODEVICE */
#ifdef SO_NOSIGPIPE
      int option = 1;
      if (setsockopt (abc_iface_ip.iface_sockfd, SOL_SOCKET, SO_NOSIGPIPE, &option, sizeof (int)) != 0)
        perror ("abc-ip setsockopt nosigpipe");
#endif /* SO_NOSIGPIPE */
      struct sockaddr_in sa;
      sa.sin_family = AF_INET;
      sa.sin_addr.s_addr = htonl (INADDR_ANY);
      sa.sin_port = htons (ALLNET_ABC_IP_PORT);
      memset (&sa.sin_zero, 0, sizeof (sa.sin_zero));
      if (bind (abc_iface_ip.iface_sockfd,
                (struct sockaddr *)&sa, sizeof (sa)) == -1) {
#ifndef __CYGWIN__
#ifndef _WIN32
#ifndef _WIN64
        static int printed = 0;
        if (! printed) {
          perror ("abc-ip bind interface");
          printf ("abc-ip: error binding interface %s\n", interface);
          printed = 1;
        }
#endif /* _WIN64 */
#endif /* _WIN32 */
#endif /* __CYGWIN__ */
#ifdef DEBUG_PRINT
        perror ("abc-ip: error binding interface");
        printf ("error binding interface %s\n", interface);
#endif /* DEBUG_PRINT */
        close (abc_iface_ip.iface_sockfd);
        abc_iface_ip.iface_sockfd = -1;
        goto abc_ip_init_cleanup;
      }
      if (ifa_loop->ifa_flags & IFF_BROADCAST) {
        abc_iface_ip.bc_address.sa = *(ifa_loop->ifa_broadaddr);
      } else {
        abc_iface_ip.bc_address.in.sin_addr.s_addr = htonl (INADDR_BROADCAST);
        printf ("abc-ip: set default broadcast address on %s\n", interface);
      }
      abc_iface_ip.bc_address.in.sin_family = AF_INET;
      abc_iface_ip.bc_address.in.sin_port = htons (ALLNET_ABC_IP_PORT);
      memset (&abc_iface_ip.bc_address.in.sin_zero, 0,
              sizeof (abc_iface_ip.bc_address.in.sin_zero));
      ret = 1;
      goto abc_ip_init_cleanup;
    }
    ifa_loop = ifa_loop->ifa_next;
  }
abc_ip_init_cleanup:
  freeifaddrs (ifa);
  return ret;
}

static int abc_ip_cleanup () {
  if (abc_iface_ip.iface_sockfd != -1) {
    if (close (abc_iface_ip.iface_sockfd) != 0) {
      perror ("abc-ip: error closing socket");
      return 0;
    }
    abc_iface_ip.iface_sockfd = -1;
  }
  return 1;
}

/**
 * Accept a sender if it's not coming from our own address
 * @param sender struct sockaddr_in * of the sender
 * @return 0 if we are the sender, 1 otherwise
 */
static int abc_ip_accept_sender (const struct sockaddr * sender)
{
  const struct sockaddr_in * sai = (const struct sockaddr_in *)sender;
  struct sockaddr_in * own = (struct sockaddr_in *)&abc_iface_ip.if_address;
  return (own->sin_addr.s_addr != sai->sin_addr.s_addr);
}
