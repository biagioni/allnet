/* request.c: send data or a data request, see what comes back */
/* command line to send a data request:
   allnet-data-test token since d1,d2,d3/db s1,s2,s3/sb m1,m2,m3/mb, where
     token is an int to be used as the token (0 for a random token)
     since is an int (-1 to print the current time and exit)
     [dsm][1..] are destination or source addresses or message IDs, in hex
     [dsm]b are the number of bits specified in the address or ID
     if [dsm]b is 0, no preceding addresses are needed, /0 is fine
     the number of hops may optionally be specified at the end

   alternate command line to send random data:
   allnet-data-test src dst contents [hops], where
     src and dst are addresses in format hex/bits or /0
     contents is a hex string of the form 01.23.45.67.89.ab.cd
     the number of hops may optionally be specified at the end

both may also use -c dir and -p port for debugging, to use dir
as the config directory or port as the local port to connect to.
 */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <pthread.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "lib/packet.h"
#include "lib/util.h"
#include "lib/app_util.h"
#include "lib/priority.h"
#include "lib/configfiles.h"

/* fills in the bitset and *nbitsp, and returns the size,
 *   returns 0 in case of errors or /0 */
static int parse_bits (const char * arg, char * bitset, int bsize,
                       unsigned char * nbitsp)
{
  memset (bitset, 0, bsize);
  *nbitsp = 0;
  const char * slash = index (arg, '/');
  if (slash == NULL) {
    printf ("unable to find / in %s\n", arg);
    return 0;
  }
  char * end;
  long int nbits = strtol (slash + 1, &end, 10);
  if (end == slash + 1) {
    printf ("unable to find number of bits after / in %s\n", arg);
    return 0;
  }
  if (nbits <= 0) {
    printf ("number of bits is %ld in %s, ignoring\n", nbits, arg);
    return 0;
  }
  if (nbits > 16) {
    printf ("error, number of bits is %ld in %s\n", nbits, arg);
    return 0;
  }
  *nbitsp = nbits;
  int power_two = 1 << nbits;
  printf ("%ld bits\n", nbits);
  int used = ((nbits <= 3) ? 1 : (1 << (nbits - 3)));
  if (used > bsize) {
    printf ("error: %ld bits require %d > %d bytes in the bitset\n",
            nbits, used, bsize);
    return 0;
  }
  const char * p = arg;
  int multiplier = 1 << (16 - nbits);
  do {
    long int value = strtol (p, &end, 16);
    if ((value < 0) || (end == p)) {
      printf ("error reading hex at %s (original %s)\n", p, arg);
      return 0;
    }
    if (value >= power_two) {
      printf ("error: %ld greater than 2^%ld = %d (%s/%s)\n",
              value, nbits, power_two, p, arg);
      return 0;
    }
int debug = value;
    value *= multiplier;
printf ("value %d -> %ld (x %d), %ld bits\n", debug, value, multiplier, nbits);
printf ("bitset [%d] = %02x -> ", allnet_bitmap_byte_index (nbits, value),
        bitset [allnet_bitmap_byte_index (nbits, value)] & 0xff);
    bitset [allnet_bitmap_byte_index (nbits, value)] |= (allnet_bitmap_byte_mask (nbits, value));
printf ("%02x\n", bitset [allnet_bitmap_byte_index (nbits, value)] & 0xff);
printf ("mask %d\n", allnet_bitmap_byte_mask (nbits, value) & 0xff);
    p = end + 1;
  } while (*end == ',');
  return used;
}

static void print_received_packets ()
{
  struct received_message {
    int refcount;
    int msize;
    char message [ALLNET_MTU];
  };
  static struct received_message messages [1000]; 
  memset (messages, 0, sizeof (messages));
  static int num_received = 0;
  unsigned long long int finish = allnet_time_ms () + 5000;
  unsigned long long int now;
  int i;
  while ((now = allnet_time_ms ()) < finish) {
    char * received = NULL;
    unsigned int priority = 0;
    int r = local_receive ((int) (finish - now), &received, &priority);
    if ((r <= 0) || (received == NULL)) {
      printf ("\nread returned %d to timeout %lld, rcvd %d\n", r, finish - now,
              num_received);
      break;
    }
    int duplicate = 0;
    for (i = 0; i < num_received; i++) {
      if ((r == messages [i].msize) &&
          (memcmp (received, messages [i].message, r) == 0)) {
        messages [i].refcount = messages [i].refcount + 1;
        duplicate = 1;
      }
    }
    if (! duplicate) {
      messages [num_received].refcount = 1;
      messages [num_received].msize = r;
      memcpy (messages [num_received].message, received, r);
      num_received++;
    }
    free (received);
  }
  for (i = 0; i < num_received; i++) {
    struct allnet_header * check_hp =
      (struct allnet_header *) (messages [i].message);
    if ((check_hp->message_type == ALLNET_TYPE_DATA) &&
        ((check_hp->transport & ALLNET_TRANSPORT_ACK_REQ) != 0)) {
      printf ("rcvd mid %4db %2dc", messages [i].msize, messages [i].refcount);
      print_buffer (ALLNET_MESSAGE_ID (check_hp, check_hp->transport,
                                       messages [i].msize), 16, NULL, 16, 1);
    } else {
      printf ("%4db %2dc %x/%x, ", messages [i].msize, messages [i].refcount,
              check_hp->message_type, check_hp->transport);
      print_buffer (check_hp, messages [i].msize, NULL, 10, 1);
    }
  }
}

static void request (char ** argv, int sock, int hops)
{
#if 0
  struct received_message {
    int refcount;
    int msize;
    char message [ALLNET_MTU];
  };
  static struct received_message messages [1000]; 
  memset (messages, 0, sizeof (messages));
  static int num_received = 0;
#endif /* 0 */
  printf ("args are: %s %s %s %s %s\n", argv [1], argv [2],
          argv [3], argv [4], argv [5]);
  char * end;
  long long int token = strtoll (argv [1], &end, 10);
  long long int since = strtoll (argv [2], &end, 10);
  printf ("token %lld, since %lld\n", token, since);
  if (since < 0) {
    printf ("allnet time now is %lld\n", allnet_time ());
    return;
  }
  char packet [ALLNET_MTU];
  memset (packet, 0, sizeof (packet));
  struct allnet_header * hp =
    init_packet (packet, sizeof (packet), ALLNET_TYPE_DATA_REQ, hops, 0,
                 NULL, 0, NULL, 0, NULL, NULL);
  hp->transport |= ALLNET_TRANSPORT_DO_NOT_CACHE;
  struct allnet_data_request * reqp =
    (struct allnet_data_request *)
      ALLNET_DATA_START (hp, hp->transport, sizeof (packet));
  writeb64u (reqp->token, token);
  writeb64u (reqp->since, since);
  char * bitmap = (char *) reqp->dst_bitmap;  /* at beginning of bitmaps */
  int dsize = parse_bits (argv [3], bitmap, 1024, &(reqp->dst_bits_power_two));
  bitmap += dsize;
  int ssize = parse_bits (argv [4], bitmap, 1024, &(reqp->src_bits_power_two));
  bitmap += ssize;
  int msize = parse_bits (argv [5], bitmap, 1024, &(reqp->mid_bits_power_two));
  bitmap += msize;
  size_t total_size = bitmap - packet;
print_buffer (packet, total_size, "sending request", total_size, 1);
  if (! local_send (packet, total_size, ALLNET_PRIORITY_ONE_HALF)) {
    printf ("unable to send %zd bytes\n", total_size);
    return;
  }
  print_received_packets ();
#if 0
  unsigned long long int finish = allnet_time_ms () + 5000;
  unsigned long long int now;
  int i;
  while ((now = allnet_time_ms ()) < finish) {
    char * received = NULL;
    unsigned int priority = 0;
    int r = local_receive ((int) (finish - now), &received, &priority);
    if ((r <= 0) || (received == NULL)) {
      printf ("\nread returned %d to timeout %lld, rcvd %d\n", r, finish - now,
              num_received);
      break;
    }
    int duplicate = 0;
    for (i = 0; i < num_received; i++) {
      if ((r == messages [i].msize) &&
          (memcmp (received, messages [i].message, r) == 0)) {
        messages [i].refcount = messages [i].refcount + 1;
        duplicate = 1;
      }
    }
    if (! duplicate) {
      messages [num_received].refcount = 1;
      messages [num_received].msize = r;
      memcpy (messages [num_received].message, received, r);
      num_received++;
    }
    free (received);
  }
  for (i = 0; i < num_received; i++) {
    struct allnet_header * check_hp =
      (struct allnet_header *) (messages [i].message);
    if ((check_hp->message_type == ALLNET_TYPE_DATA) &&
        ((check_hp->transport & ALLNET_TRANSPORT_ACK_REQ) != 0)) {
      printf ("rcvd mid %4db %2dc", messages [i].msize, messages [i].refcount);
      print_buffer (ALLNET_MESSAGE_ID (check_hp, check_hp->transport,
                                       messages [i].msize), 16, NULL, 16, 1);
    } else {
      printf ("%4db %2dc %x/%x, ", messages [i].msize, messages [i].refcount,
              check_hp->message_type, check_hp->transport);
      print_buffer (check_hp, messages [i].msize, NULL, 10, 1);
    }
  }
#endif /* 0 */
}

static int convert_hex (const char * hex, char * buffer, int max)
{
  int count = 0;
  while (count < max) {
    int byte;
    int n = sscanf (hex, "%2x", &byte);
    if (n == 1) {   /* success */
      buffer [count++] = byte;
      hex += 2;
      if (*hex == '.')
        hex++;
    } else {
      return count;
    }
  }
  return count;
}

static int convert_addr (char * addr, char * buffer)
{
  memset (buffer, 0, ALLNET_ADDRESS_SIZE);
  char * slash = index (addr, '/');
  if (slash == NULL)
    return 0;
  int nbits = atoi (slash + 1);
  *slash = '\0';
  if ((nbits <= 0) || (nbits > ALLNET_ADDRESS_BITS))
    return 0;
  int nbytes = convert_hex (addr, buffer, ALLNET_ADDRESS_SIZE);
  if (nbytes * 8 < nbits)
    return 0;
  return nbits;
}

static void send_data (char ** argv, int sock, int hops)
{
  char packet [ALLNET_MTU];
  memset (packet, 0, sizeof (packet));
  char src [ALLNET_ADDRESS_SIZE];
  char dst [ALLNET_ADDRESS_SIZE];
  int src_bits = convert_addr (argv [1], src);
  int dst_bits = convert_addr (argv [2], dst);
  struct allnet_header * hp =
    init_packet (packet, sizeof (packet), ALLNET_TYPE_DATA, hops, 0,
                 (const unsigned char *) src, src_bits,
                 (const unsigned char *) dst, dst_bits, NULL, NULL);
  hp->transport = ALLNET_TRANSPORT_EXPIRATION;
  char * exp_ptr = ALLNET_EXPIRATION (hp, hp->transport, sizeof (packet));
  unsigned long long int exp = allnet_time () + 3600;
  writeb64 (exp_ptr, exp);
  int hsize = ALLNET_SIZE_HEADER (hp);
  char * payload = packet + hsize;
  int bytes = convert_hex (argv [3], payload, sizeof (packet) - hsize);
  size_t total_size = hsize + bytes;
print_buffer (packet, total_size, "sending request", total_size, 1);
  if (! local_send (packet, total_size, ALLNET_PRIORITY_ONE_HALF)) {
    printf ("unable to send %zd bytes\n", total_size);
    return;
  }
  print_received_packets ();
}

int main (int argc, char ** argv)
{
  if ((argc > 3) && (strcmp (argv [1], "-c") == 0)) {
    set_home_directory (argv [2]);
    argc -= 2;
    argv += 2;
  }
  int optional_port = 0;
  if ((argc > 3) && (strcmp (argv [1], "-p") == 0)) {
    optional_port = atoi (argv [2]);
    argc -= 2;
    argv += 2;
  }
  if ((argc == 4) || (argc == 5)) {         /* sending data */
    int sock = connect_to_local (argv [0], argv [0], NULL, 1, 1, optional_port);
    int hops = 10;
    if (argc == 5)
      hops = atoi (argv [4]);
printf ("%d (%s) hops\n", hops, argv [6]);
    send_data (argv, sock, hops);
  } else if ((argc == 6) || (argc == 7)) {  /* data request */
    int sock = connect_to_local (argv [0], argv [0], NULL, 1, 1, 0);
    int hops = 10;
    if (argc == 7)
      hops = atoi (argv [6]);
printf ("%d (%s) hops\n", hops, argv [6]);
    request (argv, sock, hops);
    return 0;
  } else {
    printf ("usage: %s "
            "token since d1,d2,d3/db s1,s2,s3/sb m1,m2,m3/mb [hops]\n",
            argv [0]);
    printf ("   (%d arguments given, 5 expected)\n", argc - 1);
    printf ("token is an int to be used as the token (0 for a random token)\n");
    printf ("since is an int (-1 to print the current time and exit)\n");
    printf ("[dsm][1..] are destination or source addresses or message IDs, "
            "in hex\n");
    printf ("[dsm]b are the number of bits specified in the address or ID\n");
    printf ("if [dsm]b is 0, no preceding addresses are needed, /0 is fine\n");
    printf ("  for example, %s 96 609633046 0,2,6,f/4 /0 /0\n", argv [0]);
    printf ("optionally, a final argument may give the number of hops\n");
    return 1;
  }
}
