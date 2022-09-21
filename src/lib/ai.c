/* ai.c: utility functions for struct addr_info and struct internet_addr */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>  /* exit if IPv6 address size is not 16 */
#include <unistd.h>
#include <inttypes.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <sys/types.h>
#ifndef ANDROID
#include <ifaddrs.h>
#include <net/if.h>  /* IFF_LOOPBACK, etc */
#else /* ANDROID */
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/if.h>
#endif /* ANDROID */
#include <arpa/inet.h>
#include <sys/ioctl.h>

#include "packet.h"
#include "ai.h"
#include "util.h"

/* buffer parameter must have at least size 42 */
/* returns the number of buffer characters used */
static int ip6_to_string (const unsigned char * ip, char * buffer)
{
  const char * p = (const char *) ip;
  return snprintf (buffer, 42, "%x:%x:%x:%x:%x:%x:%x:%x",
                   readb16 (p), readb16 (p + 2), readb16 (p + 4),
                   readb16 (p + 6), readb16 (p + 8), readb16 (p + 10),
                   readb16 (p + 12), readb16 (p + 14));
}

void print_addr_info (struct allnet_addr_info * ai)
{
  printf ("(%d) ", ai->nbits);
  if (ai->nbits > 0)
    print_buffer ((char *) (ai->destination), (ai->nbits + 7) / 8, NULL,
                  ALLNET_ADDRESS_SIZE, 0);
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
int addr_info_to_string (struct allnet_addr_info * ai, char * buf, size_t bsize)
{
  int offset = 0;
  offset += snprintf (buf, bsize, "(%d) ", ai->nbits);
  offset += buffer_to_string ((char *) (ai->destination), (ai->nbits + 7) / 8,
                              NULL, ALLNET_ADDRESS_SIZE,
                              0, buf + offset, bsize - offset);
  offset += snprintf (buf + offset, bsize - offset,
                      ", dist %d, v %d, port %d, addr ", ai->hops,
                      ai->ip.ip_version, ntohs (ai->ip.port));
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
void print_ia (struct allnet_internet_addr * ia)
{
  printf ("v %d, port %d, addr ", ia->ip_version, ntohs (ia->port));
  unsigned char * p = (unsigned char *) (&(ia->ip));
  char * q = (char *) p;
  if (ia->ip_version == 4)
    printf ("%u.%u.%u.%u\n", p [12], p [13], p [14], p [15]);
  else
    printf ("%x:%x:%x:%x:%x:%x:%x:%x\n",
            readb16 (q), readb16 (q + 2), readb16 (q + 4),
            readb16 (q + 6), readb16 (q + 8), readb16 (q + 10),
            readb16 (q + 12), readb16 (q + 14));
}

/* includes a newline at the end of the address info */
int ia_to_string (const struct allnet_internet_addr * ia,
                  char * buf, size_t bsize)
{
  int offset = 0;
  offset += snprintf (buf + offset, bsize - offset,
                      "v %d, port %d, addr ", ia->ip_version, ntohs (ia->port));
  if (ia->ip_version == 4) {
    unsigned char * p = ((unsigned char *) &(ia->ip)) + 12;
    offset += snprintf (buf + offset, bsize - offset, "%u.%u.%u.%u\n",
                        p [0], p [1], p [2], p [3]);
  } else {
    char * p = (char *) &(ia->ip);
    offset += snprintf (buf + offset, bsize - offset,
                        "%x:%x:%x:%x:%x:%x:%x:%x\n",
                        readb16 (p), readb16 (p + 2), readb16 (p + 4),
                        readb16 (p + 6), readb16 (p + 8), readb16 (p + 10),
                        readb16 (p + 12), readb16 (p + 14));
  }
  return offset;
}

/* returns 1 for success, 0 for failure */
/* if salen is not NULL, it is given the appropriate length (0 for failure) */
int ia_to_sockaddr (const struct allnet_internet_addr * ia,
                    struct sockaddr_storage * sap, socklen_t * salen)
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
    printf ("coding error: allnet_internet_addr has version %d\n",
            ia->ip_version);
    print_buffer (ia, sizeof (struct allnet_internet_addr), NULL, 1000, 1);
    return 0;
  }
  return 1;
}

/* returns 1 for success, 0 for failure */
/* takes sas as input, and returns the result (if any) in sas and alen
 * ai_embed_v4_in_v6 is needed since apple OSX and perhaps other systems
 * don't support sending to IPv4 addresses on IPv6 sockets */
int ai_embed_v4_in_v6 (struct sockaddr_storage * sas, socklen_t * alen)
{
  struct sockaddr * sa = (struct sockaddr *) sas;
  if (sa->sa_family != AF_INET)
    return 0;   /* nothing to do */
  struct sockaddr_in * source = (struct sockaddr_in *) sas;
  struct sockaddr_storage temp;
  memset (&temp, 0, sizeof (temp));
  struct sockaddr_in6 * sin6 = (struct sockaddr_in6 *) (&temp);
  sin6->sin6_family = AF_INET6;
  sin6->sin6_port = source->sin_port;
  /* ipv4-in-v6 address has 10 bytes of 0, 2 bytes of ff, then the ipv4 */
  char * p = (char *) (&(sin6->sin6_addr));
  p [10] = p [11] = 0xff;
  memcpy (p + 12, &source->sin_addr, 4);
  memcpy (sas, &temp, sizeof (*sas));
  *alen = sizeof (struct sockaddr_in6);
  return 1;
}

/* addr must point to 4 bytes if af is AF_INET, 16 bytes for AF_INET6 */
/* if nbits > 0, dest should point to at least (nbits + 7) / 8 bytes */
/* port must be in big-endian order (i.e. after applying htons) */
/* returns 1 for success, 0 for failure */
int init_addr (int af, const unsigned char * addr, int port,
               struct allnet_internet_addr * ia)
{
  unsigned char * iap = ia->ip.s6_addr;
  memset (iap, 0, sizeof (struct allnet_internet_addr));
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

/* returns 1 for success, 0 for failure */
/* addr_size is only used for error checking, may be greater than the size
 * of sockaddr_in/6, and is ignored if it is 0 */
int sockaddr_to_ia (const struct sockaddr * sap, socklen_t addr_size,
                    struct allnet_internet_addr * ia)
{
  struct sockaddr_in  * sin  = (struct sockaddr_in  *) sap;
  struct sockaddr_in6 * sin6 = (struct sockaddr_in6 *) sap;
  if ((sap->sa_family == AF_INET) &&
      ((addr_size == 0) || (addr_size >= sizeof (struct sockaddr_in)))) {
    init_addr (AF_INET, (unsigned char *) &(sin->sin_addr), sin->sin_port, ia);
    return 1;
  }
  if ((sap->sa_family == AF_INET6) &&
      ((addr_size == 0) || (addr_size >= sizeof (struct sockaddr_in6)))) {
    if ((readb64 ((char *) sin6->sin6_addr.s6_addr) != 0) || /* regular ipv6 */
        (readb16 ((char *) sin6->sin6_addr.s6_addr + 8) != 0) ||
        (readb16 ((char *) sin6->sin6_addr.s6_addr + 10) != 0xffff))
      init_addr (AF_INET6, sin6->sin6_addr.s6_addr, sin6->sin6_port, ia);
    else               /* ipv4-in-ipv6 address starting with ::ffff */
      init_addr (AF_INET,  sin6->sin6_addr.s6_addr + 12, sin->sin_port, ia);
    return 1;
  }
  printf ("error: unable to create address info with family %d, size %d\n",
          sap->sa_family, addr_size);
  return 0;
}

/* sap must point to at least sizeof (struct sockaddr_in6) bytes */
/* returns 1 for success, 0 for failure */
/* if salen is not NULL, it is given the appropriate length (0 for failure) */
int ai_to_sockaddr (const struct allnet_addr_info * ai,
                    struct sockaddr_storage * sap, socklen_t * salen)
{
  return ia_to_sockaddr (&(ai->ip), sap, salen);
}

/* addr must point to 4 bytes if af is AF_INET, 16 bytes for AF_INET6 */
/* if nbits > 0, dest should point to at least (nbits + 7) / 8 bytes */
/* port must be in big-endian order (i.e. after applying htons) */
/* returns 1 for success, 0 for failure */
int init_ai (int af, const unsigned char * addr, int port, int nbits,
             const unsigned char * dest, struct allnet_addr_info * ai)
{
  memset ((char *) ai, 0, sizeof (struct allnet_addr_info));
  ai->nbits = nbits;
  if (! (init_addr (af, addr, port, &(ai->ip))))
    return 0;

  memset (ai->destination, 0, ALLNET_ADDRESS_SIZE);
  int nbytes = (nbits + 7) / 8;
  if (nbytes > ALLNET_ADDRESS_SIZE) {
    printf ("warning: in init_ai, nbits %d, nbytes %d, limiting to %d\n",
            nbits, nbytes, ALLNET_ADDRESS_SIZE);
    nbytes = ALLNET_ADDRESS_SIZE;
    nbits = ALLNET_ADDRESS_BITS;
  }
  ai->nbits = nbits;
  if (nbits > 0)
    memcpy (ai->destination, dest, nbytes);
  return 1;
}

int sockaddr_to_ai (const struct sockaddr * sap, socklen_t addr_size,
                    struct allnet_addr_info * ai)
{
  /* init_ai with 0 bits and NULL address simply sets address to all 0s */
  memset ((char *) ai, 0, sizeof (struct allnet_addr_info));
  return sockaddr_to_ia (sap, addr_size, &(ai->ip));
}

/* returns 1 if the two addresses are the same, 0 otherwise */
int same_ai (const struct allnet_addr_info * a,
             const struct allnet_addr_info * b)
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
int same_aip (const struct allnet_addr_info * a,
              const struct allnet_addr_info * b)
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
int is_loopback_ip (const struct sockaddr * ap, socklen_t asize)
{
  struct sockaddr_in  * ap4 = (struct sockaddr_in  *) ap;
  struct sockaddr_in6 * ap6 = (struct sockaddr_in6 *) ap;
  if ((asize >= sizeof (struct sockaddr_in)) && (ap->sa_family == AF_INET)) {
    return (127 == *((char *) (&ap4->sin_addr.s_addr)));
  } else if ((asize >= sizeof (struct sockaddr_in6)) &&
             (ap->sa_family == AF_INET6)) {
    char * p = (char *) (&(ap6->sin6_addr));
    return ((0 == memcmp (p, &(in6addr_loopback), sizeof (ap6->sin6_addr))) ||
            ((memget (p, 0, 10)) &&
             (memget (p + 10, 0xff, 2)) &&
             (readb32 (p + 12) == INADDR_LOOPBACK)));
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

static int getifaddrs_interface_addrs (struct interface_addr ** interfaces)
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
  char * result = malloc_or_fail (size, "getifaddrs_interface_addrs");
#ifdef DEBUG_PRINT
  printf ("result %p size %zd (to %p)\n", result, size, result + size - 1);
  printf ("%d interfaces (size %zd), %d addrs (size %zd)\n",
          num_interfaces, sizeof (struct interface_addr),
          num_ifaddrs, sizeof (struct sockaddr_storage));
#endif /* DEBUG_PRINT */
#ifdef PRINT_INTERFACES
static int interfaces_printed = 0;
#endif /* PRINT_INTERFACES */
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
      if ((next->ifa_name != NULL) &&
          (strcmp (next->ifa_name, ((*interfaces) [j].interface_name)) == 0))
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
/* interfaces with no addresses can still be used in /wifi mode */
#ifdef DISCARD_INTERFACES_WITHOUT_ADDRESSES
      next = next->ifa_next;
      continue;   /* no addresses, move on to the next */
#endif /* DISCARD_INTERFACES_WITHOUT_ADDRESSES */
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
    strncpy (current->interface_name, next->ifa_name, str_length);
    str_length -= strlen (current->interface_name) + 1;
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
      if ((loop->ifa_name != NULL) &&
          (strcmp (current->interface_name, loop->ifa_name) == 0)) {
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
#ifdef PRINT_INTERFACES
if (! interfaces_printed) {
printf ("getifaddrs %s has address: ", current->interface_name);
struct sockaddr * sap = loop->ifa_addr;
int len = ((sap->sa_family == AF_INET) ? sizeof (struct sockaddr_in) :
           ((sap->sa_family == AF_INET6) ? sizeof (struct sockaddr_in6) : 20));
print_buffer (sap, len, NULL, len, 1);
}
#endif /* PRINT_INTERFACES */
        }
      }
      loop = loop->ifa_next;
    }
    current->num_addresses = addr_count;
    next = next->ifa_next;
  }
  freeifaddrs (ap);
#ifdef PRINT_INTERFACES
interfaces_printed = 1;  /* only print once */
#endif /* PRINT_INTERFACES */
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

static int ioctl_interface_addrs (struct interface_addr ** interfaces)
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
  char * result = malloc_or_fail (size, "ioctl_interface_addrs");
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
#ifdef PRINT_INTERFACES
static int interfaces_printed = 0;
#endif /* PRINT_INTERFACES */
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
#ifdef PRINT_INTERFACES
if (! interfaces_printed) {
printf ("ioctl %s has address: ", current->interface_name);
struct sockaddr * sap = &(ifr.ifr_addr);
int len = ((sap->sa_family == AF_INET) ? sizeof (struct sockaddr_in) :
           ((sap->sa_family == AF_INET6) ? sizeof (struct sockaddr_in6) : 20));
print_buffer (sap, len, NULL, len, 1);
}
#endif /* PRINT_INTERFACES */
      }
      int j;
      for (j = 0; j < num_v6_addrs; j++) {
        get_v6_addr (ifr.ifr_name, ipv6_file, j, addrs);
        addrs++;
      }
      current->num_addresses = addr_count;
    }
  }
#ifdef PRINT_INTERFACES
interfaces_printed = 1;  /* only print once */
#endif /* PRINT_INTERFACES */
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
  if (other_interfaces != NULL)
    free (other_interfaces);
#endif /* CHECK_INTERFACE_ADDRS */
#else /* ANDROID */
  int result = ioctl_interface_addrs (interfaces);
#endif /* ANDROID */
  return result;
}

/* same as interface_addrs, but return the valid broadcast addresses */
int interface_broadcast_addrs (struct sockaddr_storage ** addrs)
{
/* we use a fixed-size array because it is simpler if we don't have to
 * count first, then allocate.  128 should be more than enough */
#define MAX_BC_ADDRS	128
  struct sockaddr_storage intermediate [MAX_BC_ADDRS];  /* copy of result */
  memset (intermediate, 0, sizeof (intermediate));
  int socket_fd = socket (AF_INET, SOCK_DGRAM, 0);
  struct ifreq ifr;
  int interface_index;
  int result_count = 0;
  for (interface_index = 0; interface_index < MAX_BC_ADDRS; interface_index++) {
#if defined(__APPLE__)||defined(_WIN32)||defined(_WIN64)||defined(__CYGWIN__)
    int success = (if_indextoname (interface_index, ifr.ifr_name) != NULL);
#else
    ifr.ifr_ifindex = interface_index;
    int success = (ioctl (socket_fd, SIOCGIFNAME, &ifr) >= 0);
#endif /* __APPLE__ */
    if ((success) && (strlen (ifr.ifr_name) > 0)) {
      success = (ioctl (socket_fd, SIOCGIFFLAGS, &ifr) >= 0);
      if (success && (ifr.ifr_flags & IFF_BROADCAST)) {
        if (ioctl (socket_fd, SIOCGIFBRDADDR, &ifr) >= 0) {
          /* SIOCGIFBRDADDR only returns AF_INET/ipv4 addresses */
          struct sockaddr * sap = (struct sockaddr *) &(ifr.ifr_broadaddr);
          int previous;
          int already_found = 0;
          for (previous = 0; previous < interface_index; previous++) {
            if (memcmp (intermediate + previous, intermediate + interface_index,
                        sizeof (struct sockaddr)) == 0)
              already_found = 1;
          }
          if ((already_found) || (sap->sa_family != AF_INET))
            continue;  /* do not add */
          uint32_t ip = htonl (((struct sockaddr_in *) sap)->sin_addr.s_addr);
          if ((ip != 0) && ((ip >> 24) != 0x7f)) {
            memcpy (intermediate + result_count, &(ifr.ifr_broadaddr),
                    sizeof (struct sockaddr));  /* only ipv4, sizeof sockaddr */
            result_count++;
          }
        }
      }
    }
  }
  close (socket_fd);
  if ((result_count > 0) && (addrs != NULL))
    *addrs = memcpy_malloc (intermediate,
                            sizeof (struct sockaddr_storage) * result_count,
                            "interface_broadcast_addrs");
  return result_count;
}

/* test whether this address is syntactically valid address (e.g.
 * not all zeros, not a local or loopback address), returning
 * 1 if valid, -1 if it is an ipv4-in-ipv6 address, and 0 otherwise */
int is_valid_address (const struct allnet_internet_addr * ip)
{
  if (ip->ip_version == 4) {
    if ((readb32 ((char *) (ip->ip.s6_addr + 12)) == 0) ||   /* 0.0.0.0 */
        (readb16 ((char *) (ip->ip.s6_addr + 10)) != 0xffff) ||
        (readb16 ((char *) (ip->ip.s6_addr +  8)) != 0) ||
        (readb64 ((char *) (ip->ip.s6_addr     )) != 0) ||
        (* ((ip->ip.s6_addr + 12)) == 127) || /* 127.x.y.z */
        (* ((ip->ip.s6_addr + 12)) == 10 ) || /* 10.x.y.z */
        ((ip->ip.s6_addr [12] == 172) &&
         ((ip->ip.s6_addr [13] & 0xf0) == 16)) || /* 172.16/12 */
        ((ip->ip.s6_addr [12] == 192) &&
         (ip->ip.s6_addr [13] == 168)) ||  /* 192.168/16 */
        ((ip->ip.s6_addr [12] == 169) &&
         (ip->ip.s6_addr [13] == 254)))    /* link local 169.254/16 */
      return 0;
    return 1;
  } else if (ip->ip_version == 6) {
    if ((readb64 ((char *) ip->ip.s6_addr) == 0) &&
        (readb64 ((char *) ip->ip.s6_addr + 8) == 0))  /* all-zeros address */
      return 0;
    int first_byte = (*((char *) ip->ip.s6_addr)) & 0xff;
    if ((first_byte == 0xff) ||           /* multicast */
        (first_byte == 0xfe) ||           /* link local */
        (first_byte == 0xfc) || (first_byte == 0xfd))  /* unique local addr */
      return 0;
    if ((readb64 ((char *) (ip->ip.s6_addr    )) == 0) &&
        (readb16 ((char *) (ip->ip.s6_addr + 8)) == 0) &&
        (readb16 ((char *) (ip->ip.s6_addr + 10)) == 0xffff)) { /* v4 in v6 */
      struct allnet_internet_addr v4_addr = *ip;
      v4_addr.ip_version = 4;
      return - (is_valid_address (&v4_addr));
    }
    return 1;
  } else {
    printf ("is_valid_address: unknown ip version %d\n", ip->ip_version);
    print_buffer (ip, sizeof (struct allnet_internet_addr), NULL, 200, 1);
    return 0;
  }
  return 1;
}

/* as well as the obvious comparisons, returns true also for
 * an IPv4-embedded-in-IPv6 that matches a plain IPv4 address */
int same_sockaddr (const struct sockaddr_storage * a, socklen_t alen,
                   const struct sockaddr_storage * b, socklen_t blen)
{
  if ((a == NULL) || (b == NULL) || (alen == 0) || (blen == 0))
    return 0;        /* invalid sockaddrs do not match */
  if (alen == blen) {
    if (alen == sizeof (struct sockaddr_in)) {
      struct sockaddr_in * sinp_a = (struct sockaddr_in *) a;
      struct sockaddr_in * sinp_b = (struct sockaddr_in *) b;
      return ((sinp_a->sin_family == AF_INET) &&
              (sinp_b->sin_family == AF_INET) &&
              (sinp_a->sin_port == sinp_b->sin_port) &&
              (sinp_a->sin_addr.s_addr == sinp_b->sin_addr.s_addr));
    }
    if (alen == sizeof (struct sockaddr_in6)) {
      struct sockaddr_in6 * sinp_a = (struct sockaddr_in6 *) a;
      struct sockaddr_in6 * sinp_b = (struct sockaddr_in6 *) b;
      return ((sinp_a->sin6_family == AF_INET6) &&
              (sinp_b->sin6_family == AF_INET6) &&
              (sinp_a->sin6_port == sinp_b->sin6_port) &&
              (memcmp (&(sinp_a->sin6_addr.s6_addr),
                       &(sinp_b->sin6_addr.s6_addr),
                       sizeof (sinp_a->sin6_addr.s6_addr)) == 0));
    }
    /* may not work on systems where sockaddrs have a length field */
    return (memcmp (a, b, alen) == 0);
  }
  if ((alen == sizeof (struct sockaddr_in)) &&
      (blen == sizeof (struct sockaddr_in6))) {  /* see if b is an ipv4 */
    const struct sockaddr_in6 * b6 = (const struct sockaddr_in6 *) b;
    if ((readb64 (((char *) &(b6->sin6_addr))     ) == 0) &&
        (readb16 (((char *) &(b6->sin6_addr)) +  8) == 0) &&
        (readb16 (((char *) &(b6->sin6_addr)) + 10) == 0xffff)) {
      const struct sockaddr_in * a4 = (const struct sockaddr_in *) a;
      return ((a4->sin_family == AF_INET) && (b6->sin6_family == AF_INET6) &&
              (a4->sin_port == b6->sin6_port) &&
              (0 ==
               memcmp (&a4->sin_addr, (((char *) &(b6->sin6_addr)) + 12), 4)));
    }
  } else if ((alen == sizeof (struct sockaddr_in6)) &&
             (blen == sizeof (struct sockaddr_in))) { /* see if a is an ipv4 */
    const struct sockaddr_in6 * a6 = (const struct sockaddr_in6 *) a;
    if ((readb64 (((char *) &(a6->sin6_addr))     ) == 0) &&
        (readb16 (((char *) &(a6->sin6_addr)) +  8) == 0) &&
        (readb16 (((char *) &(a6->sin6_addr)) + 10) == 0xffff)) {
      const struct sockaddr_in * b4 = (const struct sockaddr_in *) b;
      return ((b4->sin_family == AF_INET) && (a6->sin6_family == AF_INET6) &&
              (b4->sin_port == a6->sin6_port) &&
              (0 ==
               memcmp (&b4->sin_addr, (((char *) &(a6->sin6_addr)) + 12), 4)));
    }
  }
  return 0;
}

/* copy a name such as a.bc.d to DNS format, i.e. \1a\2bc\1d\0
 * return the number of characters for the DNS format */ 
static int copy_dns_name (char * to, const char * name,
                          const char * prev_queries)
{
  size_t nlen = strlen (name);
  size_t label_len = 0;
  size_t current_len = 0;
  const char * current_label = name;
  size_t i;
  for (i = 0; i < nlen; i++) {
    if (name [i] == '.') {
      if (label_len > 0) {
        *to = label_len;          /* copy the current label */
        memcpy (to + 1, current_label, label_len);
        to += (label_len + 1);
        current_label += label_len + 1;
        current_len += label_len + 1;
        label_len = 0;
      } else {  /* zero-length label (..), skip */
        printf ("DNS error: skipping zero-length label %s\n", current_label);
        current_label += 1;
      }
    } else {
      label_len++;
    }
  }
  /* reached end of name */
  *to = label_len;          /* copy the current label */
  memcpy (to + 1, current_label, label_len);
  to [label_len + 1] = 0;   /* add the root label for DNS */
  return (int) (current_len + label_len + 2);
}

/* returns the number of servers filled in, or 0 for errors */
static int get_dns_servers (struct sockaddr_storage * servers, int nservers)
{
  if (nservers < 1)
    return 0;
  char * data = NULL;
  static int report_first_error = 1;
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
  report_first_error = 0;
#endif
  int size = read_file_malloc ("/etc/resolv.conf", &data, report_first_error);
  int num_found = 0;
  if ((size > 0) && (data != NULL)) {
    char * p = data;
    while (p != NULL) {
#define NAMESERVER_STR  "nameserver "
      p = strstr (p, NAMESERVER_STR);
      char * ip = ((p == NULL) ? NULL : (p + strlen (NAMESERVER_STR)));
#undef NAMESERVER_STR
      if ((p != NULL) && (ip != NULL) && (strlen (ip) > 0)) {
        p = index (ip, '\n');
        if (p != NULL) {
          *p = '\0';   /* terminate the ip string */
          p++;         /* point to the start of the new line, if any */
        }
        struct in_addr binary_ip;
        struct in6_addr binary_ip6;
        if (inet_pton (AF_INET, ip, &binary_ip)) {
          struct sockaddr_in * sinp =
            (struct sockaddr_in *) (servers + num_found);
          memset (sinp, 0, sizeof (struct sockaddr_in));
          sinp->sin_family = AF_INET;
          sinp->sin_addr.s_addr = binary_ip.s_addr;
          sinp->sin_port = htons (53);
          num_found++;
        } else if (inet_pton (AF_INET6, ip, &binary_ip6)) {
          struct sockaddr_in6 * sin6p =
            (struct sockaddr_in6 *) (servers + num_found);
          memset (sin6p, 0, sizeof (struct sockaddr_in6));
          sin6p->sin6_family = AF_INET6;
          memcpy (&(sin6p->sin6_addr), &binary_ip6, sizeof (binary_ip6));
          sin6p->sin6_port = htons (53);
          num_found++;
        }
      }
    }
    free (data);
  }
#ifdef DEBUG_PRINT
  printf ("found %d servers\n", num_found);
#endif /* DEBUG_PRINT */
  if (num_found <= 0) {   /* some error, use 4.2.21 and 2620:fe::fe */
    if (report_first_error)
      printf ("/etc/resolv.conf is empty or missing, using defaults\n");
    report_first_error = 0;
    struct sockaddr_in * sinp = (struct sockaddr_in *) servers;
    memset (sinp, 0, sizeof (struct sockaddr_in));
    sinp->sin_family = AF_INET;
    inet_pton (AF_INET, "4.2.2.1", &(sinp->sin_addr));
    sinp->sin_port = htons (53);
    num_found = 1;
    if (nservers > 1) {
      struct sockaddr_in6 * sin6p = (struct sockaddr_in6 *) (servers + 1);
      memset (sin6p, 0, sizeof (struct sockaddr_in6));
      sin6p->sin6_family = AF_INET6;
      inet_pton (AF_INET6, "2620:fe::fe", &(sin6p->sin6_addr));
      sin6p->sin6_port = htons (53);
      num_found = 2;
    }
  }
  return num_found;
}

#define DNS_HEADER_SIZE		12
#define DNS_IPV4_TYPE		1
#define DNS_IPV6_TYPE		28

static void print_dns_name_diff (const char * response, const char * orig,
                                 size_t max, size_t index, const char * desc)
{
  printf ("same_dns_name %s: difference at index %zd of ", desc, index);
  print_buffer (response, max, "response", max, 0);
  print_buffer (orig, max, ", original", max, 1);
}

static int same_dns_name (const char * response, const char * orig, size_t max)
{
  int label_length = response [0];
  if (orig [0] != label_length) {
    print_dns_name_diff (response, orig, max, 0, "first label length");
    return 0;
  }
  size_t ic = 1;    /* index of current character */
  while ((ic < max) && (label_length != 0)) {
    int cr = response [ic] & 0xff;
    int co = orig [ic] & 0xff;
    if (tolower (cr) != tolower (co)) {
      print_dns_name_diff (response, orig, max, 0, "label");
      return 0;
    }
    ic++;
    label_length--;
    if (label_length == 0) {   /* look for the next label, which may be 0 */
      label_length = response [ic];
      if (orig [ic] != label_length) {
        print_dns_name_diff (response, orig, max, 0, "label length");
        return 0;
      }
      ic++;
    }
  }
  return 1;
}

/* return the number of valid answers found */
static int
  dns_callback (const char * response, ssize_t received,
                const struct sockaddr_storage * from, socklen_t flen,
                int min_dns_id, int num_dns_ids,
                const struct sockaddr_storage * servers, int nservers,
                void (* callback) (const char * name, int id, int valid,
                                   const struct sockaddr * addr),
                const char ** names, const int * callback_ids, int count)
{
#ifdef DEBUG_PRINT
  print_buffer (response, received, "received response", received, 1);
#endif /* DEBUG_PRINT */
  int found_sender = 0;   /* received from one of the servers I sent to? */
  const struct sockaddr * debug_sender = NULL;
  int debug_alen = sizeof (struct sockaddr_in);
  int i;
  for (i = 0; i < nservers; i++) {
    socklen_t alen = sizeof (struct sockaddr_in);
    if (servers [i].ss_family == AF_INET6)
      alen = sizeof (struct sockaddr_in6);
    debug_alen = alen;
    if (same_sockaddr (from, flen, servers + i, alen)) {
      found_sender = 1;
      debug_sender = (const struct sockaddr *) (servers + i);
      break;
    }
  }
  if (! found_sender) {
    printf ("dns received from unknown sender\n");
    return 0;
  }
  /* sanity checks */
  if (received <= DNS_HEADER_SIZE) {
    printf ("dns received only %zd bytes\n", received);
    unsigned int r = (unsigned int) received;
    print_buffer (response, r, NULL, r, 1);
    return 0;
  }
  int received_id = readb16 (response);
  if ((received_id < min_dns_id) || (received_id >= min_dns_id + num_dns_ids)) {
    printf ("dns received unknown id %x, not in %x..%x\n", received_id,
            min_dns_id, min_dns_id + num_dns_ids + 1);
    return 0;
  }
  /* 0x8000 means response, not truncated, no error */
  int correct_answer = ((readb16 (response + 2) & 0xFA0F) == 0x8000);
  /* 0x8003 means response, not truncated, no such name */
  int no_such_name   = ((readb16 (response + 2) & 0xFA0F) == 0x8003);
  if ((! correct_answer) && (! no_such_name)) {
#ifdef DEBUG_PRINT
    printf ("dns received bad code %x\n", readb16 (response + 2));
#endif /* DEBUG_PRINT */
    return 0;
  }
  int num_answers = readb16 (response + 6);
  if ((readb16 (response + 4) != 1) || (correct_answer && (num_answers < 1))) {
#ifdef DEBUG_PRINT
    printf ("dns received %d questions, %d answers\n",
            readb16 (response + 4), num_answers);
#endif /* DEBUG_PRINT */
    return 0;
  }
  /* save the name */
  char original_name [512];
  int name_ptr = 0;
  int response_pos = DNS_HEADER_SIZE;
  int end_of_name = response_pos;
  int indirect_found = 0;
  while (response_pos < received) {
    int label_len = response [response_pos];
    if (label_len == 0) {  /* done */
      original_name [name_ptr] = '\0';
      response_pos++;
      if (! indirect_found)
        end_of_name++;
      break;
    }
    if ((label_len <= 63) && (response_pos + label_len < received)) {
      if (name_ptr + label_len + 1 >= sizeof (original_name)) {
        printf ("domain name too long!  %d + %d + 1 >= %zd\n",
                name_ptr, label_len, sizeof (original_name));
        printf ("  from ");
        print_sockaddr ((struct sockaddr *)debug_sender, debug_alen);
        printf ("\n");
        return 0;
      }
      /* name follows, copy it */
      memcpy (original_name + name_ptr, response + response_pos + 1, label_len);
      original_name [name_ptr + label_len] = '.';
      name_ptr += label_len + 1;
      response_pos += label_len + 1;
      if (! indirect_found)  /* still on the initial sequence of labels */
        end_of_name += label_len + 1;
    } else {                /* indirection */
      /* response_pos moves to the label, end_of_name will no longer change */
      indirect_found = 1;
      response_pos = label_len & 0x3f;
    }
  }
#ifdef DEBUG_PRINT
  printf ("original name is '%s'\n", original_name);
#endif /* DEBUG_PRINT */
  /* check to see that this is a name we requested */
  int name_index = -1;
  for (i = 0; i < count; i++) {
    size_t name_len = strlen (original_name);
    if ((strcmp (names [i], original_name) == 0) ||
        /* original_name is terminated by '.', names [i] may not be */
        ((name_len > 0) && (name_len == strlen (names [i]) + 1) &&
         (strncmp (names [i], original_name, name_len - 1) == 0))) {
      name_index = i;
    }
  }
  if (name_index < 0) {
    printf ("dns response for %s, not found in name list\n", original_name);
    return 0;
  }
  if (no_such_name) {   /* server tells us name does not have an IP address */
    struct sockaddr_storage sas;
    memset (&sas, 0, sizeof (sas));
    struct sockaddr * sap = (struct sockaddr *) &sas;
    if (end_of_name + 4 <= received) {
      int type = readb16 (response + end_of_name);
      if (type == DNS_IPV4_TYPE)         /* ipv4 */
        sas.ss_family = AF_INET;
      else if (type == DNS_IPV6_TYPE)   /* ipv6 */
        sas.ss_family = AF_INET6;
    }  /* else ss_family is 0 */
#ifdef DEBUG_PRINT
    printf ("no such name: calling DNS callback for [%d] %s/%d\n",
            name_index, names [name_index], callback_ids [name_index]);
    print_buffer (response, (int)received, "received response", 512, 1);
#endif /* DEBUG_PRINT */
    callback (names [name_index], callback_ids [name_index], 0, sap);
    return 0;
  }
  if (end_of_name + 4 > received) {
    printf ("dns response size %zd, end of query name %d\n",
            received, end_of_name);
    print_buffer (response, (int)received, "received response", 512, 1);
    return 0;
  }
  size_t answer_start = end_of_name + 4;  /* after type/class of query */
  size_t answer_fixed = answer_start + 2;  /* in the common case c00c */
  int num_found = 0;
  /* check each of the answers, and call callback for each valid answer */
  while ((answer_start + 10 <= received) && (num_found < num_answers)) {
    if (readb16 (response + answer_start) != 0xc00c) {  /* unusual */
      int query_size = end_of_name - DNS_HEADER_SIZE;
      if (same_dns_name (response + answer_start, response + DNS_HEADER_SIZE,
                         query_size)) {
        /* server repeated query in answer */
        answer_fixed = answer_start + query_size;
      } else {
        printf ("dns answer at offset %zd is %04x not 0xc00c\n", answer_start,
                readb16 (response + answer_start));
        printf ("memcmp (%p, %p, %d) == %d\n",
                response + answer_start, response + DNS_HEADER_SIZE,
                query_size,
                memcmp (response + answer_start, response + DNS_HEADER_SIZE,
                        query_size));
        print_buffer (response + answer_start, query_size + 4,
                      "comparing", 100, 0);
        print_buffer (response + DNS_HEADER_SIZE, query_size + 4,
                      " to", 100, 1);
        print_buffer (response, (int)received, "complete response",
                      (int)received, 1);
        printf ("from: ");
        print_sockaddr ((struct sockaddr *)debug_sender, debug_alen);
        printf ("\n");
        return num_found;
      }
    }
    int type = readb16 (response + answer_fixed);
    struct sockaddr_storage sas;
    memset (&sas, 0, sizeof (sas));
    struct sockaddr * sap = (struct sockaddr *) &sas;
    struct sockaddr_in * sinp = (struct sockaddr_in *) &sas;
    struct sockaddr_in6 * sin6p = (struct sockaddr_in6 *) &sas;
    if ((type == DNS_IPV6_TYPE) && (answer_fixed + 20 <= received)) { /* ipv6 */
      sin6p->sin6_family = AF_INET6;
      memcpy (&(sin6p->sin6_addr), response + answer_fixed + 10, 16);
      sin6p->sin6_port = htons (ALLNET_PORT);
#ifdef DEBUG_PRINT
      printf ("success: calling DNS callback for [%d] %s/%d, IPv6, ",
              name_index, names [name_index], callback_ids [name_index]);
      print_sockaddr (sap, sizeof (struct sockaddr_in6)); printf ("\n");
#endif /* DEBUG_PRINT */
      callback (names [name_index], callback_ids [name_index], 1, sap);
      num_found++;
    } else if (type == DNS_IPV4_TYPE) {   /* ipv4 */
      sinp->sin_family = AF_INET;
      memcpy (&(sinp->sin_addr), response + answer_fixed + 10, 4);
      sinp->sin_port = htons (ALLNET_PORT);
      answer_start = answer_fixed + 8;
#ifdef DEBUG_PRINT
      printf ("success: calling DNS callback for [%d] %s/%d, IPv4, ",
              name_index, names [name_index], callback_ids [name_index]);
      print_sockaddr (sap, sizeof (struct sockaddr_in)); printf ("\n");
#endif /* DEBUG_PRINT */
      callback (names [name_index], callback_ids [name_index], 1, sap);
    } else {
      printf ("dns invalid type %d, answer_start %zd\n", type, answer_start);
      print_buffer (response, (int)received, "response", (int)received, 1);
      break;
    }
    answer_start += readb16 (response + answer_fixed + 8) + 12;
    num_found++;
  }
  return num_found;
}

/* returns true if this is an IP address, e.g. "1.2.3.4", which does not
 * need to call DNS, and therefore immediately calls the callback. */
static int callback_for_ips (const char * name, int callback_id,
                             void (* callback) (const char * name, int id,
                                                int valid,
                                                const struct sockaddr * addr))
{
  char sockaddr_if_given [sizeof (struct in6_addr)];
  if (inet_pton (AF_INET, name, sockaddr_if_given) == 1) {
    struct sockaddr_in sin;
    memset (&sin, 0, sizeof (sin));
    sin.sin_family = AF_INET;
    memcpy (&(sin.sin_addr), sockaddr_if_given, sizeof (sin.sin_addr));
    sin.sin_port = htons (ALLNET_PORT);
    callback (name, callback_id, 1, (struct sockaddr *) (&sin));
    return 1;
  }
  if (inet_pton (AF_INET6, name, sockaddr_if_given) == 1) {
    struct sockaddr_in6 sin;
    memset (&sin, 0, sizeof (sin));
    sin.sin6_family = AF_INET6;
    memcpy (&(sin.sin6_addr), sockaddr_if_given, sizeof (sin.sin6_addr));
    sin.sin6_port = htons (ALLNET_PORT);
    callback (name, callback_id, 1, (struct sockaddr *) (&sin));
    return 1;
  }
  return 0;
}

/* using getaddrinfo makes it hard or impossible to do static linking,
 * whereas static linking is useful for distributing the software as
 * self-contained binaries.
 * Also, getaddrinfo only queries one name at a time, when it would be much
 * easier to request all translations at once.
 * Finally, the response should be returned in real time.
 * allnet_dns sends a query for each of the names to each server
 *    in /etc/hosts.  When it gets a valid response, it calls the 
 *    callback with the original name, the corresponding id, and the address.
 *    valid is zero if there is no address for the name (RCODE=3)
 *    allnet_dns itself returns after it gets all its responses, or when
 *    it times out, usually after 10-20s.
 *    allnet_dns returns the number of addresses found, or 0 for errors
 */
int allnet_dns (const char ** names, const int * callback_ids, int count,
                void (* callback) (const char * name, int id, int valid,
                                   const struct sockaddr * addr))
{
  if (count <= 0)
    return 0;
  /* find all the servers that this host is using */
#define MAX_DNS_SERVERS		100
  struct sockaddr_storage servers [MAX_DNS_SERVERS];
  int nservers = get_dns_servers (servers, MAX_DNS_SERVERS);
  if (nservers <= 0)
    return 0;
  /* open the two sockets we use */
  int s4 = socket (AF_INET, SOCK_DGRAM, 0);
  if (s4 < 0) {
    perror ("allnet_dns v4 socket");
    return 0;
  }
  int s6 = socket (AF_INET6, SOCK_DGRAM, 0);
  if (s6 < 0) {   /* don't die, just use the v4 socket */
    perror ("allnet_dns v4 socket");
  }
#ifdef DEBUG_PRINT
  printf ("s4 %d, s6 %d\n", s4, s6);
#endif /* DEBUG_PRINT */
  /* build the query packet */
  char query_packet [512];  /* RFC 1035, section 2.3.4, max UDP packet size */
  int npackets = 0;
  /* for each server for each name send up to 2 different query IDs (v4+v6) */
  int max_actual_servers = ((nservers > 2) ? 2 : nservers);
  int min_dns_id = (int)random_int (1, 65534 - max_actual_servers * count * 2);
  int num_dns_ids = 0;
  int in;
  for (in = 0; in < count; in++) {
    if (callback_for_ips (names [in], callback_ids [in], callback))
      continue;   /* resolved, go on to the next entry */
    int iaf;   /* ipv4 and ipv6 */
    for (iaf = 0; iaf < 2; iaf++) {
      memset (query_packet, 0, sizeof (query_packet));
      writeb16 (query_packet + 2, 0x0100);   /* query, recursion desired */
      writeb16 (query_packet + 4, 1);        /* one question, 0 answers etc */
      size_t offset = DNS_HEADER_SIZE;
      /* +2 for the root label and the length of the first label */
      size_t nlen = strlen (names [in]) + 2;
      size_t qlen = nlen + 4;   /* 4 bytes for query type and class */
#ifdef DEBUG_PRINT
      if (offset + qlen >= sizeof (query_packet))
      printf ("error: %zd + %zd >= %zd\n", offset, qlen, sizeof (query_packet));
#endif /* DEBUG_PRINT */
      /* we send exactly one query per packet */
      char * query = query_packet + offset;
      int clen = copy_dns_name (query, names [in],
                                query_packet + DNS_HEADER_SIZE);
if (nlen != clen) printf ("error: nlen %zd, clen %d for %s\n", nlen, clen, names [in]);
      writeb16 (query + nlen, (iaf == 0) ? DNS_IPV4_TYPE : DNS_IPV6_TYPE);
      writeb16 (query + nlen + 2, 1);   /* query class 1, Internet */
      offset += qlen;
      /* send the query packet to at most two randomly chosen servers */
      int server_offset = ((nservers <= 2) ? 0 :
                           (int)(random_int (0, nservers - 2)));
      int is = 0;
      for (is = 0; (is < nservers) && (is < 2); is++) {
        writeb16 (query_packet, min_dns_id + num_dns_ids);
        struct sockaddr_storage * this_server = servers + (is + server_offset);
        int s = s4;
        socklen_t alen = sizeof (struct sockaddr_in);
        if (this_server->ss_family == AF_INET6) {
          s = s6;
          alen = sizeof (struct sockaddr_in6);
        }
        if (s >= 0) {
          ssize_t send_res = sendto (s, query_packet, offset, 0,
                                     (struct sockaddr *) (this_server), alen);
          if (send_res != offset) {
            int e = errno;
            if (unusual_sendto_error (e)) {
              perror ("allnet_dns sendto");
              printf ("allnet_dns sendto %zd returned %zd, errno %d\n",
                      offset, send_res, e);
            }
          } else {
            npackets++;
            num_dns_ids++;
#ifdef DEBUG_PRINT
            print_buffer (query_packet, offset, "sent", offset, 0);
            print_buffer (this_server, alen, " to", alen, 1);
#endif /* DEBUG_PRINT */
            sleep_time_random_us (20 * 1000);  /* about 10ms between packets */
          }
        }
      }
    }
  }
  /* wait up to about 4-5 seconds for all the replies */
  int num_received = 0;
  unsigned long long int start = allnet_time ();
  unsigned long long int sleep_time = 1000; /* 1000us = 1ms */
  char response_packet [512];
  while (start + 4 > allnet_time ()) {
    struct sockaddr_storage sas;
    socklen_t slen = sizeof (sas);
    struct sockaddr * sap = (struct sockaddr *) (&sas);
    ssize_t received = recvfrom (s4, response_packet, sizeof (response_packet),
                                 MSG_DONTWAIT, sap, &slen);
    if ((received <= 0) && (s6 >= 0)) {
      slen = sizeof (sas);
      received = recvfrom (s6, response_packet, sizeof (response_packet),
                           MSG_DONTWAIT, sap, &slen);
    }
#ifdef DEBUG_PRINT
    printf ("received %zd, num_received %d\n", received, num_received);
#endif /* DEBUG_PRINT */
    if (received > 0)
      num_received += dns_callback (response_packet, received,
                                    &sas, slen, min_dns_id, num_dns_ids,
                                    servers, nservers, callback,
                                    names, callback_ids, count);
    sleep_time_random_us (sleep_time);
    sleep_time += sleep_time;   /* double the sleep time */
  }
  if (s4 >= 0) close (s4);
  if (s6 >= 0) close (s6);
#ifdef DEBUG_PRINT
  printf ("allnet_dns done, returning %d\n", num_received);
#endif /* DEBUG_PRINT */
#undef MAX_DNS_SERVERS
  return num_received;
}

