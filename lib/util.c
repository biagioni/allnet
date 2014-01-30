/* util.c: a place for useful functions used by different programs */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netpacket/packet.h>
#include <arpa/inet.h>

#include "../packet.h"
#include "../mgmt.h"
#include "log.h"
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

void print_packet (const char * buffer, int count, char * desc, int print_eol)
{
  if (! is_valid_message (buffer, count)) {
    printf ("invalid message");
    return;
  }
  printf ("valid message (pls implement print_packet)\n");
}

/* same as print_buffer, but prints to the given string */
void packet_to_string (const char * buffer, int count, char * desc,
                       int print_eol, char * to, int tsize)
{
  if (! is_valid_message (buffer, count)) {
    snprintf (to, tsize, "invalid message");
    return;
  }
  snprintf (to, tsize, "valid message (pls implement packet_to_string)\n");
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
/* if t1 < t2, returns 0, otherwise returns t1 - t2 */
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

/* returns 1 if now is before the given time, and 0 otherwise */
int is_before (struct timeval * t)
{
  struct timeval now;
  gettimeofday (&now, NULL);
  if (now.tv_sec < t->tv_sec)
    return 1;
  if (now.tv_sec > t->tv_sec)
    return 0;
  /* now.tv_sec == t->tv_sec */
  if (now.tv_usec < t->tv_usec)
    return 1;
  return 0;
}

void add_us (struct timeval * t, unsigned long long us)
{
  t->tv_usec += us % US_PER_S;         /* add microseconds to tv_usec */
  t->tv_sec += t->tv_usec / US_PER_S;  /* any carry goes into tv_sec */
  t->tv_usec = t->tv_usec % US_PER_S;  /* tv_usec should be < 1,000,000 */
  t->tv_sec += us / US_PER_S;          /* whole seconds added to tv_sec */
}

/* computes the next time that is a multiple of granularity.  If immediate_ok,
 * returns 0 if the current time is already a multiple of granularity */
time_t compute_next (time_t from, time_t granularity, int immediate_ok)
{
  time_t delta = from % granularity;
  if ((immediate_ok) && (delta == 0))
    /* already at the beginning of the interval */
    return from;
/*
  printf ("compute_next returning %ld = %ld + (%ld - %ld)\n",
          from + (granularity - delta), from, granularity, delta);
*/
  return from + (granularity - delta);
}

/* set result to a random time between start + min and start + max */
void set_time_random (struct timeval * start, unsigned long long min,
                      unsigned long long max, struct timeval * result)
{
  unsigned long long int delta = 0;
  if (max > min)
    delta = max - min;
  unsigned long long int r = random ();
  unsigned long long int us = min + r % delta;
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

/* returns the file size, and if content_p is not NULL, allocates an
 * array to hold the file contents and assigns it to content_p.
 * in case of problems, returns 0
 */
int read_file_malloc (char * file_name, char ** content_p, int print_errors)
{
  struct stat st;
  if (stat (file_name, &st) < 0) {
    if (print_errors) {
      perror ("stat");
      printf ("read_file_malloc: unable to stat %s\n", file_name);
    }
    return 0;
  }
  if (st.st_size == 0)
    return 0;
  if (content_p == NULL) {   /* just make sure could read the file */
    if (access (file_name, R_OK) == 0)
      return st.st_size;
    else
      return 0;
  }
  char * result = malloc (st.st_size);
  if (result == NULL) {
    if (print_errors)
      printf ("unable to allocate %zd bytes for contents of file %s\n",
              st.st_size, file_name);
    return 0;
  }
  int fd = open (file_name, O_RDONLY);
  if (fd < 0) {
    if (print_errors) {
      perror ("open");
      printf ("unable to open file %s for reading\n", file_name);
    }
    free (result);
    return 0;
  }
  int n = read (fd, result, st.st_size);
  if (n != st.st_size) {
    if (print_errors) {
      perror ("read");
      printf ("unable to read %zd bytes from %s, got %d\n",
              st.st_size, file_name, n);
    }
    free (result);
    close (fd);
    return 0;
  }
  close (fd);
  *content_p = result;
  return st.st_size;
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

/* read a big-endian n-bit number into an unsigned int */
/* if the pointer is NULL, returns 0 */
unsigned int readb16 (char * p)
{
  unsigned int result = 0;
  if (p == NULL)
    return result;
  result = (((unsigned int) ((p [0]) & 0xff)) <<  8) |
           (((unsigned int) ((p [1]) & 0xff))      );
  return result;
}

unsigned long int readb32 (char * p)
{
  unsigned long int result = 0;
  if (p == NULL)
    return result;
  result = (((unsigned long int) ((p [0]) & 0xff)) << 24) |
           (((unsigned long int) ((p [1]) & 0xff)) << 16) |
           (((unsigned long int) ((p [2]) & 0xff)) <<  8) |
           (((unsigned long int) ((p [3]) & 0xff))      );
  return result;
}

unsigned long long int readb48 (char * p)
{
  unsigned long long int result = 0;
  if (p == NULL)
    return result;
  result = (((unsigned long long int) ((p [0]) & 0xff)) << 40) |
           (((unsigned long long int) ((p [1]) & 0xff)) << 32) |
           (((unsigned long long int) ((p [2]) & 0xff)) << 24) |
           (((unsigned long long int) ((p [3]) & 0xff)) << 16) |
           (((unsigned long long int) ((p [4]) & 0xff)) <<  8) |
           (((unsigned long long int) ((p [5]) & 0xff))      );
  return result;
}

unsigned long long int readb64 (char * p)
{
  unsigned long long int result = 0;
  if (p == NULL)
    return result;
  result = (((unsigned long long int) ((p [0]) & 0xff)) << 56) |
           (((unsigned long long int) ((p [1]) & 0xff)) << 48) |
           (((unsigned long long int) ((p [2]) & 0xff)) << 40) |
           (((unsigned long long int) ((p [3]) & 0xff)) << 32) |
           (((unsigned long long int) ((p [4]) & 0xff)) << 24) |
           (((unsigned long long int) ((p [5]) & 0xff)) << 16) |
           (((unsigned long long int) ((p [6]) & 0xff)) <<  8) |
           (((unsigned long long int) ((p [7]) & 0xff))      );
  return result;
}

/* write an n-bit number in big-endian order into an array.  If the pointer
 * is NULL, does nothing */
void writeb16 (char * p, unsigned int value)
{
  if (p == NULL)
    return;
  p [0] = (value >>  8) & 0xff; p [1] =  value        & 0xff;
}

void writeb32 (char * p, unsigned long int value)
{
  if (p == NULL)
    return;
  p [0] = (value >> 24) & 0xff; p [1] = (value >> 16) & 0xff;
  p [2] = (value >>  8) & 0xff; p [3] =  value        & 0xff;
}

void writeb48 (char * p, unsigned long long int value)
{
  if (p == NULL)
    return;
  p [0] = (value >> 40) & 0xff; p [1] = (value >> 32) & 0xff;
  p [2] = (value >> 24) & 0xff; p [3] = (value >> 16) & 0xff;
  p [4] = (value >>  8) & 0xff; p [5] =  value        & 0xff;
}

void writeb64 (char * p, unsigned long long int value)
{
  if (p == NULL)
    return;
  p [0] = (value >> 56) & 0xff; p [1] = (value >> 48) & 0xff;
  p [2] = (value >> 40) & 0xff; p [3] = (value >> 32) & 0xff;
  p [4] = (value >> 24) & 0xff; p [5] = (value >> 16) & 0xff;
  p [6] = (value >>  8) & 0xff; p [7] =  value        & 0xff;
}

/* returns 1 if the message is valid, 0 otherwise */
int is_valid_message (const char * packet, int size)
{
  if (size < ALLNET_HEADER_SIZE) {
    snprintf (log_buf, LOG_SIZE, 
              "received a packet with %d bytes, %zd required\n",
              size, ALLNET_HEADER_SIZE);
    log_print ();
    return 0;
  }
/* received a message with a header */
  struct allnet_header * ah = (struct allnet_header *) packet;
/* make sure version, address bit counts and hops are sane */
  if ((ah->version != ALLNET_VERSION) ||
      (ah->src_nbits > ADDRESS_BITS) || (ah->dst_nbits > ADDRESS_BITS) ||
      (ah->hops > ah->max_hops)) {
    snprintf (log_buf, LOG_SIZE, 
              "received %d addr sizes %d, %d (max %d), hops %d, %d\n",
              ah->version, ah->src_nbits, ah->dst_nbits, ADDRESS_BITS,
              ah->hops, ah->max_hops);
    log_print ();
    return 0;
  }
/* check the validity of the packet, as defined in packet.h */
  if (((ah->message_type == ALLNET_TYPE_ACK) ||
       (ah->message_type == ALLNET_TYPE_DATA_REQ)) && (ah->transport != 0)) {
    snprintf (log_buf, LOG_SIZE, 
              "received message type %d, transport 0x%x != 0\n",
              ah->message_type, ah->transport);
    log_print ();
    return 0;
  }
  int payload_size = size - ALLNET_AFTER_HEADER (ah->transport, size);
  if ((ah->message_type == ALLNET_TYPE_ACK) &&
      ((payload_size % MESSAGE_ID_SIZE) != 0)) {
    snprintf (log_buf, LOG_SIZE, 
              "received ack message, but size %d(%d) mod %d == %d != 0\n",
              payload_size, size, MESSAGE_ID_SIZE,
              payload_size % MESSAGE_ID_SIZE);
    log_print ();
    return 0;
  }
  if ((ah->transport & ALLNET_TRANSPORT_ACK_REQ != 0) &&
      (payload_size < MESSAGE_ID_SIZE)) {
    snprintf (log_buf, LOG_SIZE, "message has size %d (%d), min %d\n",
              payload_size, size, MESSAGE_ID_SIZE);
    log_print ();
    return 0;
  }
  if ((ah->transport & ALLNET_TRANSPORT_ACK_REQ == 0) &&
      (ah->transport & ALLNET_TRANSPORT_LARGE != 0)) {
    snprintf (log_buf, LOG_SIZE, "large message missing ack bit\n");
    log_print ();
    return 0;
  }
  if ((ah->transport & ALLNET_TRANSPORT_EXPIRATION != 0)) {
    time_t now = time (NULL);
    char * ep = ALLNET_EXPIRATION (ah, ah->transport, size);
    if ((now <= Y2K_SECONDS_IN_UNIX) || (ep == NULL) ||
        (readb64 (ep) < (now - Y2K_SECONDS_IN_UNIX))) {
      snprintf (log_buf, LOG_SIZE, "expired packet, %lld < %ld (ep %p)\n",
                readb64 (ep), now - Y2K_SECONDS_IN_UNIX, ep);
      log_print ();
      return 0;
    }
  }
  if ((ah->transport & ALLNET_TRANSPORT_TRACE != 0)) {
    struct allnet_trace_entry * th =
      (struct allnet_trace_entry *) (ALLNET_TRACE (ah, ah->transport, size));
    if ((th == NULL) ||  /* at least the last entry should be valid */
        (! ALLNET_VALID_TRACE (th, ALLNET_NUM_TRACES - 1))) {
      snprintf (log_buf, LOG_SIZE, "bad trace header %p %x %d\n",
                ah, ah->transport, size);
      log_print ();
      return 0;
    }
  }
  return 1;
}

/* if we see a TRACE_PATH message that we have generated, remember the
 * address we put into the header */
/* not sure how much error checking we should do -- we only look at
 * locally-generated packets */
static void remember_own_address (struct allnet_header * hp, int size,
                                  int locally_generated, char * addr,
                                  int * nbits)
{
  if ((hp->hops != 0) || (! locally_generated))
   /* not locally generated, ignore */
    return;
  if (hp->message_type != ALLNET_TYPE_MGMT)
    return;
  int mgmt_offset = ALLNET_AFTER_HEADER (hp->transport, size);
  if (mgmt_offset + sizeof (struct allnet_header_mgmt) +
      sizeof (struct allnet_mgmt_trace_path) < size)
    return;
  struct allnet_header_mgmt * mhp = 
    (struct allnet_header_mgmt *) (((char *) hp) + mgmt_offset);
  if (mhp->mgmt_type != ALLNET_MGMT_TRACE_PATH)
    return;
  struct allnet_mgmt_trace_path * mtp =
    (struct allnet_mgmt_trace_path * )
      (((char *) hp) + mgmt_offset + sizeof (struct allnet_header_mgmt));
  if ((mtp->trace_type != ALLNET_MGMT_TRACE_ID) &&
      (mtp->trace_type != ALLNET_MGMT_TRACE_ACK))
    return;   /* unknown trace type */
  int index = ALLNET_NUM_TRACES - 1;
  struct allnet_trace_entry * atep = (mtp->trace) + index;
  *nbits = atep->nbits;
  memcpy (addr, atep->address, ADDRESS_SIZE);
}

/* if the packet is being traced, add our local info */
/* the packet is assumed to be valid */
void add_trace_info (char * packet, int size, int is_local)
{
  static unsigned int saved_nbits = 0;
  static unsigned char saved_trace_addr [ADDRESS_SIZE];
  if (saved_nbits == 0)
    bzero (saved_trace_addr, ADDRESS_SIZE);
    
  struct allnet_header * ah = (struct allnet_header *) packet;
  remember_own_address (ah, size, is_local, saved_trace_addr, &saved_nbits);

  if (ah->transport & ALLNET_TRANSPORT_TRACE == 0)
    return;   /* nothing to do */
  struct allnet_trace_entry * th =
    (struct allnet_trace_entry *) (ALLNET_TRACE (ah, ah->transport, size));
  int trace_end_offset = ALLNET_AFTER_TRACE (ah->transport, size);
  if ((th == NULL) || (! ALLNET_VALID_TRACE (th, ALLNET_NUM_TRACES - 1)) ||
      (trace_end_offset == 0)) {
    snprintf (log_buf, LOG_SIZE, "bad trace header\n");
    log_print ();
    return;   /* no space in packet, so do not trace */
  }
  struct timeval now;
  gettimeofday (&now, NULL);  /* time to add to the header */

  /* shift the existing trace entries to make room for the new one */
  int trace_start_offset = ((char *) th) - packet;
  memmove (th, th + sizeof (struct allnet_trace_entry),
           sizeof (struct allnet_trace_entry) * (ALLNET_NUM_TRACES - 1));

  struct allnet_trace_entry * atep = th + (ALLNET_NUM_TRACES - 1);

  /* initialize the new entry */
  atep->precision = 11;         /* about 0.5ms -- one extra bit to capture
                                 * the rounding from dividing by a number that
                                 * is not a power of 2 (10^6) */
  unsigned long long int fraction = now.tv_usec * ((1LL << 63) / 1000000);
  writeb64 (atep->seconds,
            (unsigned long long int) (now.tv_sec - Y2K_SECONDS_IN_UNIX));
  writeb64 (atep->seconds_fraction, fraction);
  /* clear the last 48 bits */
  bzero (atep->seconds_fraction + 2, ALLNET_TIME_SIZE - 2);
  /* clear 5 bits: 0xe0 keeps 3 bits, giving 11 bits total */
  atep->seconds_fraction [1] = (atep->seconds_fraction [1]) & 0xe0;
  atep->nbits = saved_nbits;
  memcpy (atep->address, saved_trace_addr, ADDRESS_SIZE);
}

