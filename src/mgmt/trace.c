/* trace.c: standalone application to generate and handle AllNet traces */
/* can be called as daemon (traced) or client (any other name)
 * both the daemon and the client may take as argument:
   - one or more addresses (in hex, with or without separating :,. )
   - optionally, followed by / and the number of bits of the address, in 0..64
   the argument and bits default to 0/0 if not specified
 * for the daemon, the specified address is my address, used to fill in
   the response.
 * the daemon will optionally take a '-m' option, to specify tracing
   only when we match the address.
 * for the client, the specified address is the address to trace
 * the client also takes:
           -f repeats forever, or -r n repeats n times
           -m only reports responses from matching addresses
           -i does not report intermediate nodes (a bit like ping)
           -i implies -m
           -v for verbose
           -t sec, time to sleep after send (default 5 seconds)
           -h hops gives the maximum number of hops (default 10)
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/time.h> /* struct timeval, gettimeofday */
#include <signal.h>
#include <stdint.h>
#include <inttypes.h>
#include <limits.h>
#include <fcntl.h>

#include "lib/packet.h"
#include "lib/mgmt.h"
#include "lib/util.h"
#include "lib/app_util.h"
#include "lib/configfiles.h"
#include "lib/priority.h"
#include "lib/allnet_log.h"
#include "lib/dcache.h"
#include "lib/trace_util.h"

static struct allnet_log * alog = NULL;

static int get_nybble (const char * string, int * offset)
{
  const char * p = string + *offset;
  while ((*p == ':') || (*p == ',') || (*p == '.'))
    p++;
  *offset = (int)((p + 1) - string);
  if ((*p >= '0') && (*p <= '9'))
    return *p - '0';
  if ((*p >= 'a') && (*p <= 'f'))
    return 10 + *p - 'a';
  if ((*p >= 'A') && (*p <= 'F'))
    return 10 + *p - 'A';
  *offset = (int)(p - string);   /* point to the offending character */
  return -1;
}

static int get_byte (const char * string, int * offset, unsigned char * result)
{
  int first = get_nybble (string, offset);
  if (first == -1)
    return 0;
  *result = (first << 4);
  int second = get_nybble (string, offset);
  if (second == -1)
      return 4;
  *result = (first << 4) | second;
  /* printf ("get_byte returned %x\n", (*result) & 0xff); */
  return 8;
}

static int get_address (const char * address, unsigned char * result, int rsize)
{
  int offset = 0;
  int index = 0;
  int bits = 0;
  while (index < rsize) {
    int new_bits = get_byte (address, &offset, result + index);
    if (new_bits <= 0)
      break;
    bits += new_bits;
    if (new_bits < 8)
      break;
    index++;
  }
  if (address [offset] == '/') { /* number of bits follows */
    char * end;
    long given_bits = strtol (address + offset + 1, &end, 10);
    if ((end != address + offset + 1) && (given_bits <= bits))
      bits = (int)given_bits;
  }
  return bits;
}

static void trace_usage (char * pname)
{
  printf ("usage: %s [-f|-r n] [-m] [-i] [-v] [-t sec] %s\n",
          pname, "[<address_in_hex>[/<number_of_bits>]]*");
  printf ("       -f repeats forever, or -r n repeats n times\n");
  printf ("       -m only reports responses from matching addresses\n");
  printf ("       -i does not report intermediate nodes (a bit like ping)\n");
  printf ("       -i implies -m\n");
  printf ("       -v for verbose\n");
  printf ("       -t sec, time to sleep after send (default 5 seconds)\n");
  printf ("       -h hops gives the maximum number of hops (default 10)\n");
}

static int atoi_in_range (char * value, int min, int max, int dflt, char * name)
{
  char * finish;
  long int result = strtol (value, &finish, 10);
  if ((finish == value) || /* no conversion */
      (result < min) || ((max != 0) && (result > max))) {
    printf ("%s should be ", name);
    if (max != 0)
      printf ("between %d and %d ", min, max);
    else
      printf ("at least %d ", min);
    printf ("(using default %d %s)\n", dflt, name);
    return dflt;
  }
  return (int)result;
}

int trace_main (int argc, char ** argv)
{
  /* even if using gnu getopt, behave in a standard manner */
  setenv ("POSIXLY_CORRECT", "", 0);
  int no_intermediates = 0;
  int repeat = 1;
  int match_only = 0;
  int verbose = 0;
  int opt;
  int sleep = 5;
  int nhops = 10;
  char * opt_string = "mivfr:t:h:";
  while ((opt = getopt (argc, argv, opt_string)) != -1) {
    switch (opt) {
    case 'm': match_only = 1; break;
    case 'i': no_intermediates = 1; match_only = 1; break;
    case 'v': verbose = 1; break;
    case 'f': repeat = 0; break;
    case 'r': repeat = atoi_in_range (optarg, 1, 0, repeat, "repeats"); break;
    case 't': sleep = atoi_in_range (optarg, 1, 0, sleep, "seconds"); break;
    case 'h': nhops = atoi_in_range (optarg, 1, 255, nhops, "hops"); break;
    default:
      trace_usage (argv [0]);
      exit (1);
    }
  }
  log_to_output (verbose);

#if 0
  /* up to two non-option arguments */
  if (argc > optind + 2) {
    printf ("%s: argc %d, optind %d, %d non-options, at most 2 allowed\n",
            argv [0], argc, optind, argc - (optind + 1));
    trace_usage (argv [0]);
    return 1;
  }
#else /* 1 */
  /* allow up to MAX_ADDRS addresses */
#define MAX_ADDRS	255
  if (argc > optind + MAX_ADDRS) {
    printf ("%s: argc %d, optind %d, %d non-options, at most %d allowed\n",
            argv [0], argc, optind, argc - (optind + 1), MAX_ADDRS);
    trace_usage (argv [0]);
    return 1;
  }
#endif /* 0 */

  unsigned char addresses [ADDRESS_SIZE * MAX_ADDRS];
  memset (addresses, 0, sizeof (addresses));/* set any unused part to zeros */
  int abits [MAX_ADDRS];
  memset (abits, 0, sizeof (abits));        /* set any unused part to zero */
  int num_addrs;
  for (num_addrs = 0; num_addrs < (argc - optind); num_addrs++) {
    /* use the address(es) specified on the command line */
    int b = get_address (argv [optind + num_addrs],
                         addresses + (num_addrs * ADDRESS_SIZE), ADDRESS_SIZE);
    if (b <= 0) {
      printf ("argc %d/%d/%s, invalid number of bits, should be > 0\n",
              argc, optind, argv [optind]);
      trace_usage (argv [0]);
      return 1;
    }
    abits [num_addrs] = b;
#ifdef DEBUG_PRINT
    printf ("using address [%d] = %02x/%d\n", num_addrs,
            addresses [(num_addrs * ADDRESS_SIZE)],
            abits [num_addrs]);
#endif /* DEBUG_PRINT */
  }
  alog = init_log ("trace");
  int sock = connect_to_local (argv [0], argv [0], NULL, 0, 1);
  if (sock < 0)
    return 1;

  struct sigaction siga;
  siga.sa_handler = &trace_print_summary;
  sigemptyset (&(siga.sa_mask));
  siga.sa_flags = 0;
  if (sigaction (SIGINT, &siga, NULL) != 0)
    perror ("sigaction");  /* not fatal */
  if (argc > optind + 1) {   /* number of hops from the command line */
    int n = atoi (argv [optind + 1]);
    if (n > 0)
      nhops = n;
  }
  do_trace_loop (sock, num_addrs, addresses, abits,
                 repeat, sleep, nhops, match_only,
                 no_intermediates, 1, 0, STDOUT_FILENO, 0, NULL, alog);
  return 0;
}

#ifdef ALLNET_USE_FORK  /* not on iOS, define main */
int main (int argc, char ** argv)
{
  return trace_main (argc, argv);
}
#endif /* ALLNET_USE_FORK */
