/* ai.c: utility functions for struct addr_info and struct internet_addr */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>  /* exit if IPv6 address size is not 16 */

#include "packet.h"
#include "ai.h"

void print_addr_info (struct addr_info * ai)
{
  printf (" %p (%d) ", ai, ai->nbits);
  print_buffer (ai->destination, (ai->nbits + 7) / 8, NULL, 4, 0);
  printf (", v %d, port %d, addr ", ai->ip.ip_version, ntohs (ai->ip.port));
  if (ai->ip.ip_version == 4)
    print_buffer (((char *) &(ai->ip.ip)) + 12, 4, NULL, 4, 1);
  else
    print_buffer ((char *) &(ai->ip.ip), 16, NULL, 16, 1);
}

/* includes a newline at the end of the address info */
int addr_info_to_string (struct addr_info * ai, char * buf, int bsize)
{
  int offset = 0;
  offset += snprintf (buf, bsize, " %p (%d) ", ai, ai->nbits);
  offset += buffer_to_string (ai->destination, (ai->nbits + 7) / 8, NULL,
                              ADDRESS_SIZE, 0, buf + offset, bsize - offset);
  offset += snprintf (buf + offset, bsize - offset,
                      ", v %d, port %d, addr ", ai->ip.ip_version,
                      ntohs (ai->ip.port));
  if (ai->ip.ip_version == 4)
    offset += buffer_to_string (((char *) &(ai->ip.ip)) + 12, 4, NULL, 4, 1,
                                buf + offset, bsize - offset);
  else
    offset += buffer_to_string ((char *) &(ai->ip.ip), 16, NULL, 16, 1,
                                buf + offset, bsize - offset);
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
int ia_to_sockaddr (struct internet_addr * ia, struct sockaddr * sap)
{
  struct sockaddr_in  * sin  = (struct sockaddr_in  *) sap;
  struct sockaddr_in6 * sin6 = (struct sockaddr_in6 *) sap;

  if (ia->ip_version == 6) {
    sin6->sin6_family = AF_INET6;
    memcpy (&(sin6->sin6_addr), &(ia->ip), 16);
    sin6->sin6_port = ia->port;
  } else if (ia->ip_version == 4) {
    sin->sin_family = AF_INET;
    memcpy (&(sin->sin_addr), ((char *) (&(ia->ip))) + 12, 4);
    sin->sin_port = ia->port;
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
int init_addr (int af, char * addr, int port, struct internet_addr * ia)
{
  char * iap = ia->ip.s6_addr;
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
      (addr_size >= sizeof (struct sockaddr_in))) {
    init_addr (AF_INET, (char *) &(sin->sin_addr), sin->sin_port, ia);
    return 1;
  } else if ((sap->sa_family == AF_INET6) &&
             (addr_size >= sizeof (struct sockaddr_in6))) {
    init_addr (AF_INET6, (char *) &(sin6->sin6_addr), sin6->sin6_port, ia);
    return 1;
  } else {
    printf ("unable to create address info with family %d, size %d\n",
            sap->sa_family, addr_size);
    return 0;
  }
}

/* sap must point to at least sizeof (struct sockaddr_in6) bytes */
/* returns 1 for success, 0 for failure */
int ai_to_sockaddr (struct addr_info * ai, struct sockaddr * sap)
{
  return ia_to_sockaddr (&(ai->ip), sap);

#if 0
  struct sockaddr_in  * sin  = (struct sockaddr_in  *) sap;
  struct sockaddr_in6 * sin6 = (struct sockaddr_in6 *) sap;

  if (ai->ip.ip_version == 6) {
    sin6->sin6_family = AF_INET6;
    memcpy (&(sin6->sin6_addr), &(ai->ip.ip), 16);
    sin6->sin6_port = ai->ip.port;
  } else if (ai->ip.ip_version == 4) {
    sin->sin_family = AF_INET;
    memcpy (&(sin->sin_addr), ((char *) (&(ai->ip.ip))) + 12, 4);
    sin->sin_port = ai->ip.port;
  } else {   /* not found */
    printf ("coding error: addr_info has version %d\n", ai->ip.ip_version);
    return 0;
  }
  return 1;
#endif /* 0 */
}

/* addr must point to 4 bytes if af is AF_INET, 16 bytes for AF_INET6 */
/* if nbits > 0, dest should point to at least (nbits + 7) / 8 bytes */
/* port must be in big-endian order (i.e. after applying htons) */
/* returns 1 for success, 0 for failure */
int init_ai (int af, char * addr, int port, int nbits, char * dest,
             struct addr_info * ai)
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
#if 0
  struct sockaddr_in  * sin  = (struct sockaddr_in  *) sap;
  struct sockaddr_in6 * sin6 = (struct sockaddr_in6 *) sap;
  if ((sap->sa_family == AF_INET) &&
      (addr_size >= sizeof (struct sockaddr_in))) {
    init_ai (AF_INET, (char *) &(sin->sin_addr), sin->sin_port, 0, NULL, ai);
    return 1;
  } else if ((sap->sa_family == AF_INET6) &&
           (addr_size >= sizeof (struct sockaddr_in6))) {
    init_ai (AF_INET6, (char *) &(sin6->sin6_addr), sin6->sin6_port, 0, NULL,
             ai);
    return 1;
  } else {
    printf ("unable to create address info with family %d, size %d\n",
            sap->sa_family, addr_size);
    return 0;
  }
#endif /* 0 */
}


