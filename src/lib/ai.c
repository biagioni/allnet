/* ai.c: utility functions for struct addr_info and struct internet_addr */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>  /* exit if IPv6 address size is not 16 */
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#ifndef ANDROID
#include <ifaddrs.h>
#include <net/if.h>  /* IFF_LOOPBACK, etc */
#else /* ANDROID */
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/if.h>
#include <arpa/inet.h>
#endif /* ANDROID */
#include <sys/ioctl.h>

#include "packet.h"
#include "ai.h"
#include "util.h"

/* buffer parameter must have at least size 42 */
/* returns the number of buffer characters used */
static int ip6_to_string (const unsigned char * ip, char * buffer)
{
  unsigned short s [8];
  int i;
  for (i = 0; i < 8; i ++)
    s [i] = (ip [2 * i] * 256) + (ip [2 * i + 1]);
  return snprintf (buffer, 42, "%x:%x:%x:%x:%x:%x:%x:%x",
                   s [0], s [1], s [2], s [3], s [4], s [5], s [6], s [7]);
}

void print_addr_info (struct addr_info * ai)
{
  printf ("(%d) ", ai->nbits);
  if (ai->nbits > 0)
    print_buffer ((char *) (ai->destination), (ai->nbits + 7) / 8, NULL,
                  ADDRESS_SIZE, 0);
  printf (", v %d, port %d, addr ", ai->ip.ip_version, ntohs (ai->ip.port));
  unsigned char * ap = (unsigned char *) &(ai->ip.ip);
  char ip6_buf [50];
  ip6_to_string (ap, ip6_buf);
  if (ai->ip.ip_version == 4)
    printf ("%u.%u.%u.%u\n", ap [12], ap [13], ap [14], ap [15]);
  else
    printf ("%s\n", ip6_buf);
}

/* includes a newline at the end of the address info */
int addr_info_to_string (struct addr_info * ai, char * buf, size_t bsize)
{
  int offset = 0;
  offset += snprintf (buf, bsize, "(%d) ", ai->nbits);
  offset += buffer_to_string ((char *) (ai->destination), (ai->nbits + 7) / 8,
                              NULL, ADDRESS_SIZE, 0,
                              buf + offset, bsize - offset);
  offset += snprintf (buf + offset, bsize - offset,
                      ", v %d, port %d, addr ", ai->ip.ip_version,
                      ntohs (ai->ip.port));
  unsigned char * ap = (unsigned char *) &(ai->ip.ip);
  if (ai->ip.ip_version == 4)
    offset += snprintf (buf + offset, bsize - offset,
                        "%u.%u.%u.%u", ap [12], ap [13], ap [14], ap [15]);
  else if ((bsize - offset) >= 42)
    offset += ip6_to_string (ap, buf + offset);
  offset += snprintf (buf + offset, bsize - offset, "\n");
  return offset;
}

/* prints a newline at the end of the address info */
void print_ia (struct internet_addr * ia)
{
  printf ("v %d, port %d, addr ", ia->ip_version, ntohs (ia->port));
  unsigned char * p = (unsigned char *) (&(ia->ip));
  if (ia->ip_version == 4)
    printf ("%u.%u.%u.%u\n", p [12], p [13], p [14], p [15]);
  else
    print_buffer ((char *)p, 16, NULL, 16, 1);
}

/* includes a newline at the end of the address info */
int ia_to_string (const struct internet_addr * ia, char * buf, size_t bsize)
{
  int offset = 0;
  offset += snprintf (buf + offset, bsize - offset,
                      "v %d, port %d, addr ", ia->ip_version, ntohs (ia->port));
  if (ia->ip_version == 4) {
    unsigned char * p = ((unsigned char *) &(ia->ip)) + 12;
    offset += snprintf (buf + offset, bsize - offset, "%u.%u.%u.%u\n",
                        p [0], p [1], p [2], p [3]);
  } else {
    offset += buffer_to_string ((char *) &(ia->ip), 16, NULL, 16, 1,
                                buf + offset, bsize - offset);
  }
  return offset;
}

/* sap must point to at least sizeof (struct sockaddr_in6) bytes */
/* returns 1 for success, 0 for failure */
/* if salen is not NULL, it is given the appropriate length (0 for failure) */
int ia_to_sockaddr (struct internet_addr * ia,
                    struct sockaddr * sap, socklen_t * salen)
{
  struct sockaddr_in  * sin  = (struct sockaddr_in  *) sap;
  struct sockaddr_in6 * sin6 = (struct sockaddr_in6 *) sap;
  if (salen != NULL)
    *salen = 0;  /* for addresses other than IPv4 and IPv6 */

  if (ia->ip_version == 6) {
    memset (sin6, 0, sizeof (struct sockaddr_in6));
    sin6->sin6_family = AF_INET6;
    memcpy (&(sin6->sin6_addr), &(ia->ip), 16);
    sin6->sin6_port = ia->port;
    if (salen != NULL)
      *salen = sizeof (struct sockaddr_in6);
  } else if (ia->ip_version == 4) {
    memset (sin, 0, sizeof (struct sockaddr_in));
    sin->sin_family = AF_INET;
    memcpy (&(sin->sin_addr), ((char *) (&(ia->ip))) + 12, 4);
    sin->sin_port = ia->port;
    if (salen != NULL)
      *salen = sizeof (struct sockaddr_in);
  } else {   /* not found */
    printf ("coding error: addr_info has version %d\n", ia->ip_version);
    return 0;
  }
  return 1;
}

/* addr must point to 4 bytes if af is AF_INET, 16 bytes for AF_INET6 */
/* if nbits > 0, dest should point to at least (nbits + 7) / 8 bytes */
/* port must be in big-endian order (i.e. after applying htons) */
/* returns 1 for success, 0 for failure */
int init_addr (int af, unsigned char * addr, int port,
               struct internet_addr * ia)
{
  unsigned char * iap = ia->ip.s6_addr;
  memset (iap, 0, sizeof (struct internet_addr));
  int size = sizeof (ia->ip.s6_addr);
  if (size != 16) {   /* sanity check -- is something very wrong? */
    printf ("error: IPv6 address %d, not 16 bytes long!\n", size);
    exit (1);
  }
  if (af == AF_INET) {
    ia->ip_version = 4;
    iap [10] = 0xff;
    iap [11] = 0xff;
    memcpy (iap + 12, addr, 4);
  } else if (af == AF_INET6) {
    ia->ip_version = 6;
    memcpy (iap, addr, size);
  } else {
    printf ("error: unknown address family %d\n", af);
    return 0;
  }
  ia->port = port;
  return 1;
}

int sockaddr_to_ia (struct sockaddr * sap, socklen_t addr_size,
                    struct internet_addr * ia)
{
  struct sockaddr_in  * sin  = (struct sockaddr_in  *) sap;
  struct sockaddr_in6 * sin6 = (struct sockaddr_in6 *) sap;
  if ((sap->sa_family == AF_INET) &&
      (addr_size >= (int) (sizeof (struct sockaddr_in)))) {
    init_addr (AF_INET, (unsigned char *) &(sin->sin_addr), sin->sin_port, ia);
    return 1;
  } else if ((sap->sa_family == AF_INET6) &&
             (addr_size >= (int) (sizeof (struct sockaddr_in6)))) {
    init_addr (AF_INET6, (unsigned char *) &(sin6->sin6_addr),
               sin6->sin6_port, ia);
    return 1;
  } else {
    printf ("error: unable to create address info with family %d, size %d\n",
            sap->sa_family, addr_size);
    return 0;
  }
}

/* sap must point to at least sizeof (struct sockaddr_in6) bytes */
/* returns 1 for success, 0 for failure */
/* if salen is not NULL, it is given the appropriate length (0 for failure) */
int ai_to_sockaddr (struct addr_info * ai,
                    struct sockaddr * sap, socklen_t * salen)
{
  return ia_to_sockaddr (&(ai->ip), sap, salen);
}

/* addr must point to 4 bytes if af is AF_INET, 16 bytes for AF_INET6 */
/* if nbits > 0, dest should point to at least (nbits + 7) / 8 bytes */
/* port must be in big-endian order (i.e. after applying htons) */
/* returns 1 for success, 0 for failure */
int init_ai (int af, unsigned char * addr, int port, int nbits,
             unsigned char * dest, struct addr_info * ai)
{
  memset ((char *) ai, 0, sizeof (struct addr_info));
  ai->nbits = nbits;
  if (! (init_addr (af, addr, port, &(ai->ip))))
    return 0;

  memset (ai->destination, 0, ADDRESS_SIZE);
  int nbytes = (nbits + 7) / 8;
  if (nbytes > ADDRESS_SIZE) {
    printf ("warning: in init_ai, nbits %d, nbytes %d, limiting to %d\n",
            nbits, nbytes, ADDRESS_SIZE);
    nbytes = ADDRESS_SIZE;
    nbits = ADDRESS_SIZE * 8;
  }
  ai->nbits = nbits;
  if (nbits > 0)
    memcpy (ai->destination, dest, nbytes);
  return 1;
}

int sockaddr_to_ai (struct sockaddr * sap, socklen_t addr_size,
                    struct addr_info * ai)
{
  /* init_ai with 0 bits and NULL address simply sets address to all 0s */
  memset ((char *) ai, 0, sizeof (struct addr_info));
  return sockaddr_to_ia (sap, addr_size, &(ai->ip));
}

/* returns 1 if the two addresses are the same, 0 otherwise */
int same_ai (struct addr_info * a, struct addr_info * b)
{
  if ((a == NULL) && (b == NULL))
    return 1;
  if ((a == NULL) || (b == NULL))
    return 0;
  if (a->ip.ip_version == b->ip.ip_version) {
    if (memcmp (a->ip.ip.s6_addr, b->ip.ip.s6_addr, 16) == 0)
      return 1;
    if (a->ip.ip_version == 6)
      return 0;
    return (memcmp (a->ip.ip.s6_addr + 12, b->ip.ip.s6_addr + 12, 4) == 0);
  }
  unsigned char ipv4_in_ipv6 [] =
    { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff }; 
  if ((a->ip.ip_version == 6) &&
      (memcmp (a->ip.ip.s6_addr, ipv4_in_ipv6, 12) == 0))
    return (memcmp (a->ip.ip.s6_addr + 12, b->ip.ip.s6_addr + 12, 4) == 0);
  if ((b->ip.ip_version == 6) &&
      (memcmp (b->ip.ip.s6_addr, ipv4_in_ipv6, 12) == 0))
    return (memcmp (a->ip.ip.s6_addr + 12, b->ip.ip.s6_addr + 12, 4) == 0);
  return 0;  /* different versions, no ipv4 in ipv6 match */
}

/* returns 1 if the two addresses and ports are the same, 0 otherwise */
int same_aip (struct addr_info * a, struct addr_info * b)
{
  if (same_ai (a, b)) {
    if ((a != NULL) && (b != NULL) && (a->ip.port != b->ip.port))
      return 0;
    return 1;
  } else {
    return 0;
  }
}

/* if this is an IPv4-encoded-as-IPv6 address, make it an IPv4 address again */
void standardize_ip (struct sockaddr * ap, socklen_t asize)
{
  struct sockaddr_in  * ap4  = (struct sockaddr_in  *) ap;
  struct sockaddr_in6 * ap6  = (struct sockaddr_in6 *) ap;
  /* sometimes an incoming IPv4 connection is recorded as an IPv6 connection.
   * we want to record it as an IPv4 connection */
  char ipv4_in_ipv6_prefix [] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};
  if ((ap->sa_family == AF_INET6) &&
      (asize >= sizeof (struct sockaddr_in6)) &&
      (memcmp (ap6->sin6_addr.s6_addr, ipv4_in_ipv6_prefix, 12) == 0)) {
#ifdef DEBUG_PRINT
    printf ("converting IPv6 address: ");
    print_sockaddr (ap, asize, 1);
#endif /* DEBUG_PRINT */
    int port = ap6->sin6_port;
    uint32_t ip4; 
    memcpy ((char *) (&ip4), ap6->sin6_addr.s6_addr + 12, 4);
    ap4->sin_family = AF_INET;
    ap4->sin_port = port;
    ap4->sin_addr.s_addr = ip4;
#ifdef DEBUG_PRINT
    printf ("converted to IPv4 address: ");
    print_sockaddr (ap, asize, 1);
#endif /* DEBUG_PRINT */
  }
#ifdef DEBUG_PRINT
  else
    printf ("standardize_ip not converted, af %d\n", ap->sa_family);
#endif /* DEBUG_PRINT */
}

/* is this address a local IP? */
int is_loopback_ip (struct sockaddr * ap, socklen_t asize)
{
  struct sockaddr_in  * ap4 = (struct sockaddr_in  *) ap;
  struct sockaddr_in6 * ap6 = (struct sockaddr_in6 *) ap;
  if ((asize >= sizeof (struct sockaddr_in)) && (ap->sa_family == AF_INET)) {
    return ap4->sin_addr.s_addr == htonl (INADDR_LOOPBACK);
  } else if ((asize >= sizeof (struct sockaddr_in6)) &&
             (ap->sa_family == AF_INET6)) {
    return (0 == memcmp (&(ap6->sin6_addr), &(in6addr_loopback),
                         sizeof (ap6->sin6_addr)));
  } else  /* unknown address type */
    return 0;
}

#ifndef ANDROID
/* quadratic time if called for each interface, but usually
 * we don't have many interfaces */
static int is_in_ap_list (char * name, struct ifaddrs * list)
{
  while (list != NULL) {
    if (strcmp (name, list->ifa_name) == 0)
      return 1;
    list = list->ifa_next;
  }
  return 0;
}

int getifaddrs_interface_addrs (struct interface_addr ** interfaces)
{
  struct ifaddrs * ap;
  if (getifaddrs (&ap) != 0) {
    perror ("getifaddrs");
    return 0;
  }
  int num_interfaces = 0;
  if (interfaces == NULL) { /* code is much simpler for null interfaces */
    struct ifaddrs * next = ap;
    while (next != NULL) {
      if (! is_in_ap_list (next->ifa_name, next->ifa_next))
        num_interfaces++;
      next = next->ifa_next;
    }
    freeifaddrs (ap);
    return num_interfaces;
  }
  int num_ifaddrs = 0;
  size_t str_length = 0;  /* compute the size needed for strings */
  struct ifaddrs * next = ap;
  while (next != NULL) {
    if ((next->ifa_addr != NULL) &&
        ((next->ifa_addr->sa_family == AF_INET) ||
         (next->ifa_addr->sa_family == AF_INET6))) {
      num_ifaddrs++;
    }
    if (! is_in_ap_list (next->ifa_name, next->ifa_next)) {
      num_interfaces++;
      str_length += strlen (next->ifa_name) + 1;
    }
    next = next->ifa_next;
  }
  size_t size = num_interfaces * sizeof (struct interface_addr) +
                str_length + num_ifaddrs * sizeof (struct sockaddr_storage);
  char * result = malloc_or_fail (size, "interface_addrs");
#ifdef DEBUG_PRINT
  printf ("result %p size %zd (to %p)\n", result, size, result + size - 1);
  printf ("%d interfaces (size %zd), %d addrs (size %zd)\n",
          num_interfaces, sizeof (struct interface_addr),
          num_ifaddrs, sizeof (struct sockaddr_storage));
#endif /* DEBUG_PRINT */
  /* partition the allocated space into three sections, each holding different
   * kinds of data: the array of interface_addr, the strings, and the
   * sockaddr_storage locations */
  *interfaces = (struct interface_addr *) result;
  char * strings = result + (num_interfaces * sizeof (struct interface_addr));
  struct sockaddr_storage * addrs =
    (struct sockaddr_storage *) (strings + str_length);
#ifdef DEBUG_PRINT
  printf ("partitioned into: %p, %p, %p\n", *interfaces, strings, addrs);
#endif /* DEBUG_PRINT */
  next = ap;
  int assigned_interfaces = 0;
  while (next != NULL) {
    int j;
    int found = 0;
    for (j = 0; j < assigned_interfaces; j++) {
      if (strcmp (next->ifa_name, ((*interfaces) [j].interface_name)) == 0)
        found = 1;
    }
    if (found) {
      next = next->ifa_next;
      continue;   /* already assigned, move on to the next */
    }
    /* check to see whether this interface has IP addresses */
    struct ifaddrs * loop = next;
    int has_addresses = 0;
    while (loop != NULL) {
      if ((loop->ifa_name != NULL) &&
          (strcmp (next->ifa_name, loop->ifa_name) == 0) &&
          (loop->ifa_addr != NULL) &&
          ((loop->ifa_addr->sa_family == AF_INET) ||
           (loop->ifa_addr->sa_family == AF_INET6))) {
        has_addresses = 1;
        break;   /* found a valid address, no need to look further */
      }
      loop = loop->ifa_next;
    }
    if (! has_addresses) {
#if 0   /* interfaces with no addresses can still be used in /wifi mode */
      next = next->ifa_next;
      continue;   /* no addresses, move on to the next */
#endif /* 0 */
    }
    if (assigned_interfaces >= num_interfaces) {  /* error */
      printf ("error in %d getifaddrs interfaces\n", num_interfaces);
      int i;
      for (i = 0; i < num_interfaces; i++) {
        printf ("interface %s: loop %d, bc %d, up %d, %d addrs\n",
                (*interfaces) [i].interface_name,
                (*interfaces) [i].is_loopback,
                (*interfaces) [i].is_broadcast,
                (*interfaces) [i].is_up,
                (*interfaces) [i].num_addresses);
        int ib;
        for (ib = 0; ib < (*interfaces) [i].num_addresses; ib++)
          print_buffer (((char *) ((*interfaces) [i].addresses + ib)),
                        sizeof (struct sockaddr_storage), "  address",
                        10000, 1);
      }
    /* if there is an error, should crash now, allowing use of the debugger */
    }
    struct interface_addr * current = (*interfaces) + assigned_interfaces;
    assigned_interfaces++;
    /* copy the name */
    current->interface_name = strings;  /* point to available buffer space */
    strcpy (current->interface_name, next->ifa_name);
    strings += strlen (current->interface_name) + 1;
    /* set the variables */
    current->is_loopback = ((next->ifa_flags & IFF_LOOPBACK) != 0);
    current->is_broadcast = ((next->ifa_flags & IFF_BROADCAST) != 0);
    current->is_up = ((next->ifa_flags & IFF_UP) != 0);
    /* set the addresses */
    int addr_count = 0;
    loop = next;
    current->addresses = addrs;
    while (loop != NULL) {
      if (strcmp (current->interface_name, loop->ifa_name) == 0) {
        if (loop->ifa_addr != NULL) {
          if ((loop->ifa_addr->sa_family == AF_INET) ||
              (loop->ifa_addr->sa_family == AF_INET6)) {
            memset (addrs, 0, sizeof (struct sockaddr_storage));
            if (loop->ifa_addr->sa_family == AF_INET)
              memcpy (addrs, loop->ifa_addr, sizeof (struct sockaddr_in));
            else
              memcpy (addrs, loop->ifa_addr, sizeof (struct sockaddr_in6));
            addrs++;
            addr_count++;
          }
        }
      }
      loop = loop->ifa_next;
    }
    current->num_addresses = addr_count;
    next = next->ifa_next;
  }
  freeifaddrs (ap);
  if (num_interfaces != assigned_interfaces) {
    printf ("%d/%d getifaddrs interfaces\n",
            num_interfaces, assigned_interfaces);
    int i;
    for (i = 0; i < num_interfaces; i++) {
      printf ("interface %s: loop %d, bc %d, up %d, %d addrs\n",
              (*interfaces) [i].interface_name,
              (*interfaces) [i].is_loopback,
              (*interfaces) [i].is_broadcast,
              (*interfaces) [i].is_up,
              (*interfaces) [i].num_addresses);
      int j;
      for (j = 0; j < (*interfaces) [i].num_addresses; j++)
        print_buffer (((char *) ((*interfaces) [i].addresses + j)),
                      sizeof (struct sockaddr_storage), "  address", 10000, 1);
    }
  }
#ifdef DEBUG_PRINT
  print_buffer (result, size, "result", size, 1);
#endif /* DEBUG_PRINT */
  if (num_interfaces != assigned_interfaces) {
    printf ("error: num_interfaces %d, assigned_interfaces %d\n",
            num_interfaces, assigned_interfaces);
    exit (1);
  }
  return num_interfaces;
}

#endif /* ANDROID */

#ifdef LOG_PACKETS  /* if log_packets is defined, check this too */
#define CHECK_INTERFACE_ADDRS
#endif /* LOG_PACKETS */

#if defined(ANDROID) || defined(CHECK_INTERFACE_ADDRS)

/* similar to grep -c */
static int number_matching_lines (const char * pattern, const char * file)
{
  if (file == NULL)
    return 0;
  int result = 0;
  size_t plen = strlen (pattern);
  while (*file != '\0') {
    if (strncmp (pattern, file, plen) == 0) {
      result++;
      /* advance to end of line or end of file */
      while ((*file != '\0') && (*file != '\n'))
        file++;
    }
    if (*file != '\0')
      file++;
  }
  return result;
}

static void get_v6_addr (const char * interface, const char * ipv6_file,
                         int index, struct sockaddr_storage * addr)
{
  if (ipv6_file == NULL) {
    printf ("get_v6_addr: illegal null file\n");
    return;
  }
  while (strlen (ipv6_file) > 0) {
    char * eol = strchr (ipv6_file, '\n');
    /* the last bytes before eol should be the interface name */
    if (((eol - ipv6_file) > strlen (interface)) &&
        (strncmp (eol - strlen (interface), interface,
                  strlen (interface)) == 0)) {  /* matches interface */ 
      if (index == 0) {
        struct sockaddr_in6 * sinp = (struct sockaddr_in6 *) addr;
        sinp->sin6_family = AF_INET6;
        int extra = 0;
        sscanf (ipv6_file, "%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx %*x %*x %2x",
                sinp->sin6_addr.s6_addr + 0,
                sinp->sin6_addr.s6_addr + 1,
                sinp->sin6_addr.s6_addr + 2,
                sinp->sin6_addr.s6_addr + 3,
                sinp->sin6_addr.s6_addr + 4,
                sinp->sin6_addr.s6_addr + 5,
                sinp->sin6_addr.s6_addr + 6,
                sinp->sin6_addr.s6_addr + 7,
                sinp->sin6_addr.s6_addr + 8,
                sinp->sin6_addr.s6_addr + 9,
                sinp->sin6_addr.s6_addr + 10,
                sinp->sin6_addr.s6_addr + 11,
                sinp->sin6_addr.s6_addr + 12,
                sinp->sin6_addr.s6_addr + 13,
                sinp->sin6_addr.s6_addr + 14,
                sinp->sin6_addr.s6_addr + 15, &extra);
        if (extra == 0x20)  /* not sure this is always accurate */
          sinp->sin6_scope_id = 2;
        return;
      } else {
        index--;
      }
    }
    ipv6_file = eol + 1;
  }
}

/* result is statically allocated */
static int read_special_file (const char * name, char ** contents)
{
  *contents = NULL;
  static char buffer [20000];
  int fd = open (name, O_RDONLY);
  if (fd < 0) {
    perror ("read_special_file open");
    return 0;
  }
  ssize_t length = read (fd, buffer, sizeof (buffer));
  if (length < 0) {
    perror ("read_special_file open");
    close (fd);
    return 0;
  }
  close (fd);
  *contents = buffer;
  return (int)length;
}

int ioctl_interface_addrs (struct interface_addr ** interfaces)
{
  char * ipv6_file = NULL;
  read_special_file ("/proc/net/if_inet6", &ipv6_file);
  int socket_fd = socket (AF_INET, SOCK_DGRAM, 0);
  struct ifreq ifr;
  int interface_index;
  int interface_count = 0;
  int ifaddrs_count = 0;
  size_t str_length = 0;
  int last_valid_interface = 0;
  for (interface_index = 0; interface_index < 100; interface_index++) {
    ifr.ifr_ifindex = interface_index;
    int success = (ioctl (socket_fd, SIOCGIFNAME, &ifr) >= 0);
    if ((success) && (strlen (ifr.ifr_name) > 0)) {
      last_valid_interface = interface_index;
      str_length += strlen (ifr.ifr_name) + 1;
      /* how many addresses does it have? */
      int num_v4_addrs = 0;
      if (ioctl (socket_fd, SIOCGIFADDR, &ifr) >= 0)
        num_v4_addrs = 1;
      int num_v6_addrs = number_matching_lines (ifr.ifr_name, ipv6_file);
      if ((num_v4_addrs > 0) || (num_v6_addrs > 0)) {
        ifaddrs_count += num_v6_addrs + num_v4_addrs;
      }
      interface_count++;  /* count it, even if it has no addresses */
    }
    memset (&ifr, 0, sizeof (ifr));  /* next */
    ifr.ifr_ifindex = interface_index;
  }
#ifdef DEBUG_PRINT
  printf ("final interface count is %d, last %d, %d addresses\n",
          interface_count, last_valid_interface, ifaddrs_count);
#endif /* DEBUG_PRINT */
  size_t size = interface_count * sizeof (struct interface_addr) +
                str_length + ifaddrs_count * sizeof (struct sockaddr_storage);
  char * result = malloc_or_fail (size, "interface_addrs");
#ifdef DEBUG_PRINT
  printf ("result %p size %zd (to %p)\n", result, size, result + size - 1);
  printf ("%d interfaces (size %zd), %d addrs (size %zd)\n",
          interface_count, sizeof (struct interface_addr),
          ifaddrs_count, sizeof (struct sockaddr_storage));
#endif /* DEBUG_PRINT */
  /* partition the allocated space into three sections, each holding different
   * kinds of data: the array of interface_addr, the strings, and the
   * sockaddr_storage locations */
  *interfaces = (struct interface_addr *) result;
  char * strings = result + (interface_count * sizeof (struct interface_addr));
  struct sockaddr_storage * addrs =
    (struct sockaddr_storage *) (strings + str_length);
#ifdef DEBUG_PRINT
  printf ("partitioned into: %p, %p, %p\n", *interfaces, strings, addrs);
#endif /* DEBUG_PRINT */
  int i = 0;
  for (interface_index = 0; interface_index <= last_valid_interface;
       interface_index++) {
    ifr.ifr_ifindex = interface_index;
    if (ioctl (socket_fd, SIOCGIFNAME, &ifr) >= 0) {
      int num_v6_addrs = number_matching_lines (ifr.ifr_name, ipv6_file);
      int num_v4_addrs = 0;
      if (ioctl (socket_fd, SIOCGIFADDR, &ifr) >= 0)  /* has IPv4 address */
        num_v4_addrs = 1;
      if ((num_v4_addrs == 0) && (num_v6_addrs == 0)) {
        continue; /* do not return this interface */
      }
      struct interface_addr * current = (*interfaces) + i;
      i++;   /* next interface will be in the next location in the result */
      /* copy the name */
      current->interface_name = strings;
      strcpy (current->interface_name, ifr.ifr_name);
      strings += strlen (current->interface_name) + 1;
      /* set the variables */
      struct ifreq flags_ifr = ifr;  /* get the name */
      if (ioctl (socket_fd, SIOCGIFFLAGS, &flags_ifr) < 0) {
        perror ("ioctl flags");
        close (socket_fd);
        return 0;
      }
      current->is_loopback = ((flags_ifr.ifr_flags & IFF_LOOPBACK) != 0);
      current->is_broadcast = ((flags_ifr.ifr_flags & IFF_BROADCAST) != 0);
      current->is_up = ((flags_ifr.ifr_flags & IFF_UP) != 0);
      /* set the addresses */
      int addr_count = num_v4_addrs + num_v6_addrs;
      memset (addrs, 0, addr_count * sizeof (struct sockaddr_storage));
      current->addresses = addrs;
      if (num_v4_addrs > 0) {
        if (ifr.ifr_addr.sa_family == AF_INET)
          memcpy (addrs, &(ifr.ifr_addr), sizeof (struct sockaddr_in));
        else if (ifr.ifr_addr.sa_family == AF_INET6)
          memcpy (addrs, &(ifr.ifr_addr), sizeof (struct sockaddr_in6));
        addrs++;
      }
      int j;
      for (j = 0; j < num_v6_addrs; j++) {
        get_v6_addr (ifr.ifr_name, ipv6_file, j, addrs);
        addrs++;
      }
      current->num_addresses = addr_count;
    }
  }
  close (socket_fd);
#ifdef DEBUG_PRINT
  printf ("%d ioctl interfaces\n", interface_count);
  for (i = 0; i < interface_count; i++) {
    printf ("interface %s: loop %d, bc %d, up %d, %d addrs\n",
            (*interfaces) [i].interface_name,
            (*interfaces) [i].is_loopback,
            (*interfaces) [i].is_broadcast,
            (*interfaces) [i].is_up,
            (*interfaces) [i].num_addresses);
    int j;
    for (j = 0; j < (*interfaces) [i].num_addresses; j++)
      print_buffer (((char *) ((*interfaces) [i].addresses + j)),
                    sizeof (struct sockaddr_storage), "  address", 10000, 1);
  }
  print_buffer (result, size, "result", size, 1);
#endif /* DEBUG_PRINT */
  return interface_count;
}
#endif /* defined(ANDROID) || defined(CHECK_INTERFACE_ADDRS) */

#ifdef CHECK_INTERFACE_ADDRS
static int same_interfaces (struct interface_addr * a1,
                            struct interface_addr * a2)
{
  if (strcmp (a1->interface_name, a2->interface_name) != 0) {
    printf ("same_interfaces: %s != %s\n", a1->interface_name,
            a2->interface_name);
    return 0;
  }
  if (a1->is_loopback != a2->is_loopback) {
    printf ("same_interfaces: loopback flags are %d != %d for interface %s\n",
            a1->is_loopback, a2->is_loopback, a1->interface_name);
    return 0;
  }
  if (a1->is_broadcast != a2->is_broadcast) {
    printf ("same_interfaces: broadcast flags are %d != %d for interface %s\n",
            a1->is_broadcast, a2->is_broadcast, a1->interface_name);
    return 0;
  }
  if (a1->is_up != a2->is_up) {
    printf ("same_interfaces: up flags are %d != %d for interface %s\n",
            a1->is_up, a2->is_up, a1->interface_name);
    return 0;
  }
  if (a1->num_addresses != a2->num_addresses) {
    printf ("same_interfaces: num_addresses are %d != %d for interface %s\n",
            a1->num_addresses, a2->num_addresses, a1->interface_name);
    return 0;
  }
  int i;
  for (i = 0; i < a1->num_addresses; i++) {
    if (memcmp ((char *) (a1->addresses + i), (char *) (a2->addresses + i),
                sizeof (struct sockaddr_storage)) != 0) {
      printf ("same_interfaces: addresses [%d] do not match for interface %s\n",
              i, a1->interface_name);
      print_buffer ((char *) (a1->addresses + i),
                    sizeof (struct sockaddr_storage), "a1", 2000, 1);
      print_buffer ((char *) (a2->addresses + i),
                    sizeof (struct sockaddr_storage), "a2", 2000, 1);
      return 0;
    }
  }
  return 1;
}
#endif /* CHECK_INTERFACE_ADDRS */

/* getifaddrs is not completely portable, so this is implemented in
 * any way the local system supports.
 * returns the number n of interface addresses.
 * if interfaces is not NULL, *interfaces is assigned to point to malloc'd
 * storage with n addresses, may be free'd (as a block -- interface_name
 * and addresses point to within *interfaces) */
int interface_addrs (struct interface_addr ** interfaces)
{
#ifndef ANDROID  /* check that this works */
  int result = getifaddrs_interface_addrs (interfaces);
#ifdef CHECK_INTERFACE_ADDRS
  struct interface_addr * other_interfaces = NULL;
  int other = ioctl_interface_addrs (&other_interfaces);
  if (result != other) {
    printf ("ioctl_interface_addrs %d, getifaddrs_interface_addrs %d\n",
             result, other);
    exit (1);   /* it's an error */
  }
  if ((interfaces != NULL) && (other_interfaces != NULL) &&
      (! same_interfaces (*interfaces, other_interfaces))) {
    exit (1);   /* it's an error */
  }
#endif /* CHECK_INTERFACE_ADDRS */
#else /* ANDROID */
  int result = ioctl_interface_addrs (interfaces);
#endif /* ANDROID */
  return result;
}
