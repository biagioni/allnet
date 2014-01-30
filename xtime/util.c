/* util.c: a place for useful functions used by different programs */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netpacket/packet.h>
#include <arpa/inet.h>

#include "util.h"

/* print up to max of the count characters in the buffer.
 * desc is printed first unless it is null
 * a newline is printed after if print_eol
 */
void print_buffer (const char * buffer, int count, char * desc,
                   int max, int print_eol)
{
  int i;
  if (desc != NULL)
    printf ("%s (%d bytes):", desc, count);
  else
    printf ("%d bytes:", count);
  if (buffer == NULL)
    printf ("(null)");
  else {
    for (i = 0; i < count && i < max; i++)
      printf (" %02x", buffer [i] & 0xff);
    if (i < count)
      printf (" ...");
  }
  if (print_eol)
    printf ("\n");
}

/* same as print_buffer, but prints to the given string */
void buffer_to_string (const char * buffer, int count, char * desc,
                       int max, int print_eol, char * to, int tsize)
{
  int i;
  int offset;
  if (desc != NULL)
    offset = snprintf (to, tsize, "%s (%d bytes):", desc, count);
  else
    offset = snprintf (to, tsize, "%d bytes:", count);
  if (buffer == NULL)
    offset += snprintf (to + offset, tsize - offset, "(null)");
  else {
    for (i = 0; i < count && i < max; i++)
      offset += snprintf (to + offset, tsize - offset,
                          " %02x", buffer [i] & 0xff);
    if (i < count)
      offset += snprintf (to + offset, tsize - offset, " ...");
  }
  if (print_eol)
    offset += snprintf (to + offset, tsize - offset, "\n");
}

int print_sockaddr_str (struct sockaddr * sap, int addr_size, int tcp,
                         char * s, int len)
{
  char * proto = "";
  if (tcp == 1)
    proto = "/tcp";
  else if (tcp == 0)
    proto = "/udp";
  if (sap == NULL)
    return snprintf (s, len, "(null %s)", proto);
  struct sockaddr_in  * sin  = (struct sockaddr_in  *) sap;
  struct sockaddr_in6 * sin6 = (struct sockaddr_in6 *) sap;
  struct sockaddr_un  * sun  = (struct sockaddr_un  *) sap;
  struct sockaddr_ll  * sll  = (struct sockaddr_ll  *) sap;
  /* char str [INET_ADDRSTRLEN]; */
  int num_initial_zeros = 0;  /* for printing ipv6 addrs */
  int n = 0;   /* offset for printing */
  int i;
  switch (sap->sa_family) {
  case AF_INET:
    n += snprintf (s + n, len - n, "ip4%s %s %d/%x",
                   proto, inet_ntoa (sin->sin_addr),
                   ntohs (sin->sin_port), ntohs (sin->sin_port));
    if ((addr_size != 0) && (addr_size != sizeof (struct sockaddr_in)))
      n += snprintf (s + n, len - n, " (size %d rather than %zd)",
                     addr_size, sizeof (struct sockaddr_in));
    break;
  case AF_INET6:
    /* inet_ntop (AF_INET6, sap, str, sizeof (str)); */
    n += snprintf (s + n, len - n, "ip6%s ", proto);
    for (i = 0; i + 1 < sizeof (sin6->sin6_addr); i++)
      if ((sin6->sin6_addr.s6_addr [i] & 0xff) == 0)
        num_initial_zeros++;
      else
        break;
    if (num_initial_zeros > 0)
      n += snprintf (s + n, len - n, "::");
    for (i = num_initial_zeros; i + 1 < sizeof (sin6->sin6_addr); i++)
      n += snprintf (s + n, len - n, "%x:", sin6->sin6_addr.s6_addr [i] & 0xff);
    /* last one is not followed by : */
    n += snprintf (s + n, len - n, "%x %d/%x",
                   sin6->sin6_addr.s6_addr [i] & 0xff,
                   ntohs (sin6->sin6_port), ntohs (sin6->sin6_port));
    if ((addr_size != 0) && (addr_size != sizeof (struct sockaddr_in6)))
      n += snprintf (s + n, len - n, " (size %d rather than %zd)",
                     addr_size, sizeof (struct sockaddr_in6));
    break;
  case AF_UNIX:
    n += snprintf (s + n, len - n, "unix%s %s", proto, sun->sun_path);
    if ((addr_size != 0) && (addr_size != sizeof (struct sockaddr_un)))
      n += snprintf (s + n, len - n, " (size %d rather than %zd)",
                     addr_size, sizeof (struct sockaddr_un));
    break;
  case AF_PACKET:
    n += snprintf (s + n, len - n,
                   "packet protocol%s 0x%x if %d ha %d pkt %d address (%d)",
                   proto, sll->sll_protocol, sll->sll_ifindex, sll->sll_hatype,
                   sll->sll_pkttype, sll->sll_halen);
    for (i = 0; i < sll->sll_halen; i++)
      n += snprintf (s + n, len - n, " %02x", sll->sll_addr [i] & 0xff);
    if ((addr_size != 0) && (addr_size != sizeof (struct sockaddr_ll)))
      n += snprintf (s + n, len - n, " (size %d rather than %zd)",
                     addr_size, sizeof (struct sockaddr_ll));
    break;
  default:
    n += snprintf (s + n, len - n, "unknown address family %d%s",
                   sap->sa_family, proto);
    break;
  }
  return n;
}

/* tcp should be 1 for TCP, 0 for UDP, -1 for neither */
void print_sockaddr (struct sockaddr * sap, int addr_size, int tcp)
{
  char buffer [1000];
  print_sockaddr_str (sap, addr_size, tcp, buffer, sizeof (buffer));
  printf ("%s", buffer);
}

#if 0
/* tcp should be 1 for TCP, 0 for UDP, -1 for neither */
void print_sockaddr (struct sockaddr * sap, int addr_size, int tcp)
{
  char * proto = "";
  if (tcp == 1)
    proto = "/tcp";
  else if (tcp == 0)
    proto = "/udp";
  if (sap == NULL) {
    printf ("(null %s)", proto);
    return;
  }
  struct sockaddr_in  * sin  = (struct sockaddr_in  *) sap;
  struct sockaddr_in6 * sin6 = (struct sockaddr_in6 *) sap;
  struct sockaddr_un  * sun  = (struct sockaddr_un  *) sap;
  struct sockaddr_ll  * sll  = (struct sockaddr_ll  *) sap;
  /* char str [INET_ADDRSTRLEN]; */
  int num_initial_zeros = 0;  /* for printing ipv6 addrs */
  int i;
  switch (sap->sa_family) {
  case AF_INET:
    printf ("ip4%s %s %d/%x", proto, inet_ntoa (sin->sin_addr),
            ntohs (sin->sin_port), ntohs (sin->sin_port));
    if ((addr_size != 0) && (addr_size != sizeof (struct sockaddr_in)))
      printf (" (size %d rather than %zd)",
              addr_size, sizeof (struct sockaddr_in));
    break;
  case AF_INET6:
    /* inet_ntop (AF_INET6, sap, str, sizeof (str)); */
    printf ("ip6%s ", proto);
    for (i = 0; i + 1 < sizeof (sin6->sin6_addr); i++)
      if ((sin6->sin6_addr.s6_addr [i] & 0xff) == 0)
        num_initial_zeros++;
      else
        break;
    if (num_initial_zeros > 0)
      printf ("::");
    for (i = num_initial_zeros; i + 1 < sizeof (sin6->sin6_addr); i++)
      printf ("%x:", sin6->sin6_addr.s6_addr [i] & 0xff);
    /* last one is not followed by : */
    printf ("%x %d/%x", sin6->sin6_addr.s6_addr [i] & 0xff,
            ntohs (sin6->sin6_port), ntohs (sin6->sin6_port));
    if ((addr_size != 0) && (addr_size != sizeof (struct sockaddr_in6)))
      printf (" (size %d rather than %zd)",
              addr_size, sizeof (struct sockaddr_in6));
    break;
  case AF_UNIX:
    printf ("unix%s %s", proto, sun->sun_path);
    if ((addr_size != 0) && (addr_size != sizeof (struct sockaddr_un)))
      printf (" (size %d rather than %zd)",
              addr_size, sizeof (struct sockaddr_un));
    break;
  case AF_PACKET:
    printf ("packet protocol%s 0x%x if %d ha %d pkt %d address (%d)",
            proto, sll->sll_protocol, sll->sll_ifindex, sll->sll_hatype,
            sll->sll_pkttype, sll->sll_halen);
    for (i = 0; i < sll->sll_halen; i++)
      printf (" %02x", sll->sll_addr [i] & 0xff);
    if ((addr_size != 0) && (addr_size != sizeof (struct sockaddr_ll)))
      printf (" (size %d rather than %zd)",
              addr_size, sizeof (struct sockaddr_ll));
    break;
  default:
    printf ("unknown address family %d%s", sap->sa_family, proto);
    break;
  }
}
#endif /* 0 */

/* print a message with the current time */
void print_timestamp (char * message)
{
  struct timeval now;
  gettimeofday (&now, NULL);
  printf ("%s at %ld.%06ld\n", message, now.tv_sec, now.tv_usec);
}

/* return nbits+1 if the first nbits of x match the first nbits of y, else 0 */
/* where nbits is the lesser of xbits and ybits */
int matches (unsigned char * x, int xbits, unsigned char * y, int ybits)
{
  int nbits = xbits;
  if (nbits > ybits)
    nbits = ybits;
  int bytes = nbits / 8;  /* rounded-down number of bytes */
/*
  printf ("matching %d bits, %d bytes, of ", nbits, bytes);
  print_buffer (x, bytes + 1, NULL, 6, 0);
  printf (", ");
  print_buffer (y, bytes + 1, NULL, 6, 1);
*/
  int i;
  for (i = 0; i < bytes; i++)
    if (x [i] != y [i])
      return 0;
/* if ((nbits % 8) == 0) printf ("matches!!!\n"); */
  if ((nbits % 8) == 0)   /* identical */
    return nbits + 1;
  int shift = 8 - nbits % 8;
  if ((((x [bytes]) & 0xff) >> shift) == (((y [bytes]) & 0xff) >> shift)) {
    /* printf ("bits match!!!\n"); */
    return nbits + 1;
  }
  return 0;
}

/* useful time functions */
unsigned long long delta_us (struct timeval * t1, struct timeval * t2)
{
  if ((t1->tv_sec < t2->tv_sec) ||
      ((t1->tv_sec == t2->tv_sec) &&
       (t1->tv_usec < t2->tv_usec)))  /* t1 before t2, return 0 */
    return 0LL;
  unsigned long long result = t1->tv_usec - t2->tv_usec;
  result += (t1->tv_sec - t2->tv_sec) * US_PER_S;
  return result;
}

void add_us (struct timeval * t, unsigned long long us)
{
  t->tv_usec += us % US_PER_S;         /* add microseconds to tv_usec */
  t->tv_sec += t->tv_usec / US_PER_S;  /* any carry goes into tv_sec */
  t->tv_usec = t->tv_usec % US_PER_S;  /* tv_usec should be < 1,000,000 */
  t->tv_sec += us / US_PER_S;          /* whole seconds added to tv_sec */
}

/* set result to a random time between start + min and start + max */
void set_time_random (struct timeval * start, unsigned long long min,
                      unsigned long long max, struct timeval * result)
{
  unsigned long long delta = max - min;
  unsigned long long r = random ();
  unsigned long long us = min + r % delta;
  *result = *start;
  add_us (result, us);
}

/* if malloc is not successful, exit after printing */
void * malloc_or_fail (int bytes, char * desc)
{
  void * result = malloc (bytes);
  if (result == NULL) {
    printf ("unable to allocate %d bytes for %s\n", bytes, desc);
    * ((int *) result) = 3;   /* cause a segmentation fault */
  }
  return result;
}

/* copy a string to new storage, using malloc_or_fail to get the memory */
char * strcpy_malloc (char * string, char * desc)
{
  int size = strlen (string) + 1;
  char * result = malloc_or_fail (size, desc);
  snprintf (result, size, "%s", string);
  return result;
}

char * strcat_malloc (char * s1, char * s2, char * desc)
{
  int size = strlen (s1) + strlen (s2) + 1;
  char * result = malloc_or_fail (size, desc);
  snprintf (result, size, "%s%s", s1, s2);
  return result;
}

char * strcat3_malloc (char * s1, char * s2, char * s3, char * desc)
{
  int size = strlen (s1) + strlen (s2) + strlen (s3) + 1;
  char * result = malloc_or_fail (size, desc);
  snprintf (result, size, "%s%s%s", s1, s2, s3);
  return result;
}

/* copy memory to new storage, using malloc_or_fail to get the memory */
void * memcpy_malloc (void * bytes, int bsize, char * desc)
{
  char * result = malloc_or_fail (bsize, desc);
  memcpy (result, bytes, bsize);
  return result;
}

/* low-grade randomness, in case the other calls don't work */
static void computed_random_bytes (char * buffer, int bsize)
{
  int i;
  for (i = 0; i < bsize; i++)
    buffer [i] = random () % 256;
}

/* returns 1 if succeeds, 0 otherwise */
static int dev_urandom_bytes (char * buffer, int bsize)
{
  int fd = open ("/dev/urandom", O_RDONLY);
  if (fd < 0) {
    perror ("open /dev/urandom");
    return 0;
  }
  int r = read (fd, buffer, bsize);
  if (r < bsize) {
    perror ("read /dev/urandom");
    return 0;
  }
  close (fd);
  return 1;
}

/* fill this array with random bytes */
void random_bytes (char * buffer, int bsize)
{
  if (! dev_urandom_bytes (buffer, bsize))
    computed_random_bytes (buffer, bsize);
}

/* place the values 0..n-1 at random within the given array */
void random_permute_array (int n, int * array)
{
  int i;
  for (i = 0; i < n; i++)
    array [i] = i;
  if (n <= 1)  /* done */
    return;
  /* now assign to each element a random selection of the other elements */
  for (i = 0; i < n; i++) {
    int r = random () % n;
    int swap = array [i];   /* this code works even if r == i */
    array [i] = array [r];
    array [r] = swap;
  }
/* printf ("permutation of %d is", n);
  for (i = 0; i < n; i++)
    printf (" %d", array [i]);
  printf ("\n"); */
}

/* malloc and return an n-element int array containing the values 0..n-1
 * in some random permuted order */
int * random_permute (int n)
{
  int * result = malloc_or_fail (n * sizeof (int), "random_permute");
  random_permute_array (n, result);
  return result;
}

