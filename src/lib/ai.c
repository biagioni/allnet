/* ai.c: utility functions for struct addr_info and struct internet_addr */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>  /* exit if IPv6 address size is not 16 */

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
    printf ("%d.%d.%d.%d\n", ap [12], ap [13], ap [14], ap [15]);
  else
    printf ("%s\n", ip6_buf);
}

/* includes a newline at the end of the address info */
int addr_info_to_string (struct addr_info * ai, char * buf, int bsize)
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
                        "%d.%d.%d.%d", ap [12], ap [13], ap [14], ap [15]);
  else if ((bsize - offset) >= 42)
    offset += ip6_to_string (ap, buf + offset);
  offset += snprintf (buf + offset, bsize - offset, "\n");
  return offset;
}

/* prints a newline at the end of the address info */
void print_ia (struct internet_addr * ia)
{
  printf ("v %d, port %d, addr ", ia->ip_version, ntohs (ia->port));
  if (ia->ip_version == 4)
    print_buffer (((char *) &(ia->ip)) + 12, 4, NULL, 4, 1);
  else
    print_buffer ((char *) &(ia->ip), 16, NULL, 16, 1);
}

/* includes a newline at the end of the address info */
int ia_to_string (const struct internet_addr * ia, char * buf, int bsize)
{
  int offset = 0;
  offset += snprintf (buf + offset, bsize - offset,
                      "v %d, port %d, addr ", ia->ip_version, ntohs (ia->port));
  if (ia->ip_version == 4)
    offset += buffer_to_string (((char *) &(ia->ip)) + 12, 4, NULL, 4, 1,
                                buf + offset, bsize - offset);
  else
    offset += buffer_to_string ((char *) &(ia->ip), 16, NULL, 16, 1,
                                buf + offset, bsize - offset);
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

int sockaddr_to_ia (struct sockaddr * sap, int addr_size,
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

int sockaddr_to_ai (struct sockaddr * sap, int addr_size,
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
