/* trace.c: standalone application to generate and handle AllNet traces */
/* can be called as daemon (traced) or client (any other name)
 * both the daemon and the client may take as argument:
   - an address (in hex, with or without separating :,. )
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
#include "lib/pipemsg.h"
#include "lib/priority.h"
#include "lib/log.h"
#include "lib/dcache.h"

#ifdef __IPHONE_OS_VERSION_MIN_REQUIRED /* on iOS, have a trace_main function */
#ifndef TRACE_MAIN_FUNCTION
#define TRACE_MAIN_FUNCTION
#endif /* TRACE_MAIN_FUNCTION */
#endif /* __IPHONE_OS_VERSION_MIN_REQUIRED */

#ifdef TRACE_MAIN_FUNCTION

static int print_details = 1;

static int get_nybble (const char * string, int * offset)
{
  const char * p = string + *offset;
  while ((*p == ':') || (*p == ',') || (*p == '.'))
    p++;
  *offset = (p + 1) - string;
  if ((*p >= '0') && (*p <= '9'))
    return *p - '0';
  if ((*p >= 'a') && (*p <= 'f'))
    return 10 + *p - 'a';
  if ((*p >= 'A') && (*p <= 'F'))
    return 10 + *p - 'A';
  *offset = p - string;   /* point to the offending character */
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
    int given_bits = strtol (address + offset + 1, &end, 10);
    if ((end != address + offset + 1) && (given_bits <= bits))
      bits = given_bits;
  }
  return bits;
}
#endif /* TRACE_MAIN_FUNCTION */

static void init_trace_entry (struct allnet_mgmt_trace_entry * new_entry,
                              int hops, struct timeval * now,
                              unsigned char * my_address, int abits)
{
  bzero (new_entry, sizeof (struct allnet_mgmt_trace_entry));
  /* assume accuracy is 1ms, or 3 decimal digits */
  new_entry->precision = 64 + 3;
  writeb64u (new_entry->seconds, now->tv_sec - ALLNET_Y2K_SECONDS_IN_UNIX);
  writeb64u (new_entry->seconds_fraction, now->tv_usec / 1000);
  if (now->tv_sec <= ALLNET_Y2K_SECONDS_IN_UNIX) { /* clock is wrong */
    writeb64u (new_entry->seconds, 0);
    writeb64u (new_entry->seconds_fraction, 0);
    new_entry->precision = 0;
  }
  new_entry->hops_seen = hops;
  new_entry->nbits = abits;
  memcpy (new_entry->address, my_address, (abits + 7) / 8);
}

static int add_my_entry (char * in, int insize, struct allnet_header * inhp,
                         struct allnet_mgmt_header * inmp,
                         struct allnet_mgmt_trace_req * intrp,
                         struct timeval * now,
                         unsigned char * my_address, int abits,
                         char * * result)
{
  *result = NULL;
  if (intrp->num_entries >= 255)
    return 0;

  int n = intrp->num_entries + 1;
  int t = inhp->transport;
  int k = readb16u (intrp->pubkey_size);
  int needed = ALLNET_TRACE_REQ_SIZE (t, n, k);
  *result = calloc (needed, 1);
  if (*result == NULL) {
    printf ("add_my_entry unable to allocate %d bytes for %d\n", needed, n);
    return 0;
  }
/*
  packet_to_string (in, insize, "add_my_entry original packet", 1,
                    log_buf, LOG_SIZE);
  log_print ();
*/

  /* can copy the header verbatim, and all of the trace request
   * except the pubkey */
  int copy_size = ALLNET_TRACE_REQ_SIZE (t, intrp->num_entries, 0);
  memcpy (*result, in, copy_size);
  
  struct allnet_mgmt_trace_req * trp =
    (struct allnet_mgmt_trace_req *)
      ((*result) + ALLNET_MGMT_HEADER_SIZE (t));
  trp->num_entries = n;
  struct allnet_mgmt_trace_entry * new_entry = trp->trace + (n - 1);
  init_trace_entry (new_entry, inhp->hops, now, my_address, abits);
  if (k > 0) {
    char * inkey = ((char *) (intrp->trace)) +
                   (sizeof (struct allnet_mgmt_trace_entry) * (n - 1));
    char * key = ((char *) (trp->trace)) +
                 (sizeof (struct allnet_mgmt_trace_entry) * n);
    memcpy (key, inkey, k);
  }
#ifdef LOG_PACKETS
  packet_to_string (*result, needed, "add_my_entry packet copy", 1,
                    log_buf, LOG_SIZE);
  log_print ();
#endif /* LOG_PACKETS */
  return needed;
}

/* returns the size of the message to send, or 0 in case of failure */
/* no encryption yet */
static int make_trace_reply (struct allnet_header * inhp, int insize,
                             struct timeval * now,
                             unsigned char * my_address, int abits,
                             struct allnet_mgmt_trace_req * intrp,
                             int intermediate, int num_entries,
                             char ** result)
{
  *result = NULL;
/*
  snprintf (log_buf, LOG_SIZE, "making trace reply with %d entries, int %d\n",
            num_entries, intermediate);
  log_print ();
 */
  int insize_needed =
    ALLNET_TRACE_REQ_SIZE (inhp->transport, intrp->num_entries, 0);
  if (insize < insize_needed) {
    printf ("error: trace req needs %d, has %d\n", insize_needed, insize);
    return 0;
  }
  if (num_entries < 1) {
    printf ("error: trace reply num_entries %d < 1 \n", num_entries);
    return 0;
  }
  int size_needed = ALLNET_TRACE_REPLY_SIZE (0, num_entries);
  int total;
  struct allnet_header * hp =
    create_packet (size_needed - ALLNET_SIZE (0), ALLNET_TYPE_MGMT,
                   inhp->hops + 4, ALLNET_SIGTYPE_NONE, my_address, abits,
                   inhp->source, inhp->src_nbits, NULL, NULL, &total);
  if ((hp == NULL) || (total != size_needed)) {
    printf ("hp is %p, total is %d, size_needed %d\n", hp, total, size_needed);
    return 0;
  }
  if (inhp->hops == 0) /* local, no need to send reply outwards */
    hp->max_hops = 0;
  *result = (char *) hp;

  struct allnet_mgmt_header * mp =
    (struct allnet_mgmt_header *) (ALLNET_DATA_START(hp, hp->transport, total));
  mp->mgmt_type = ALLNET_MGMT_TRACE_REPLY;

  struct allnet_mgmt_trace_reply * trp =
    (struct allnet_mgmt_trace_reply *)
      (((char *) mp) + (sizeof (struct allnet_mgmt_header)));

  trp->encrypted = 0;
  trp->intermediate_reply = intermediate;
  trp->num_entries = num_entries;
  memcpy (trp->trace_id, intrp->trace_id, MESSAGE_ID_SIZE);
  int i;
  /* if num_entries is 1, this loop never executes */
  /* if num_entries is 2, this loop executes once to copy
   * intrp->trace [intrp->num_entries - 1] to trp->trace [0] */
  for (i = 0; i + 1 < num_entries; i++)
    trp->trace [i] = intrp->trace [i + intrp->num_entries - (num_entries - 1)];
  struct allnet_mgmt_trace_entry * new_entry = trp->trace + (num_entries - 1);
  init_trace_entry (new_entry, inhp->hops, now, my_address, abits);

  int ksize = readb16u (intrp->pubkey_size);
  if (ksize > 0) {
    printf ("to do: encryption of trace replies\n");
    char * key = ((char *) (intrp->trace)) +
                 (sizeof (struct allnet_mgmt_trace_entry) * intrp->num_entries);
    print_buffer (key, ksize, "key", 15, 1);
  }
#ifdef LOG_PACKETS
  packet_to_string (*result, total, "my reply: ", 1, log_buf, LOG_SIZE);
  log_print ();
#endif /* LOG_PACKETS */
  return size_needed;
}

/* see if adht has an address, if so, use that */
static void get_my_addr (unsigned char * my_addr, int my_addr_size)
{
  /* init to a random value, in case there is no address in the file */
  random_bytes ((char *) my_addr, my_addr_size);
  int fd = open_read_config ("adht", "my_id", 1);
  int count = 0;
  while (fd < 0) {  /* wait for adht to create the file */
    sleep (1);
    fd = open_read_config ("adht", "my_id", 1);
    if (count++ > 10) {
      printf ("error: traced still waiting for adht peer file creation\n");
      snprintf (log_buf, LOG_SIZE,
                "error: traced still waiting for adht peer file creation\n");
      log_print ();
      if (count > 20)
        exit (1);
    }
  }
#define EXPECTED_FIRST_LINE	33  /* first line should always be 33 bytes */
  char line [EXPECTED_FIRST_LINE];
  int n = read (fd, line, EXPECTED_FIRST_LINE);
  close (fd);
  if (n != EXPECTED_FIRST_LINE)
    return;
  line [EXPECTED_FIRST_LINE - 1] = '\0';  /* terminate by overwriting \n */
#undef EXPECTED_FIRST_LINE
  int i;
  char * start = line + 9;
  for (i = 0; i < ADDRESS_SIZE; i++) {
    char * end;
    my_addr [i] = strtol (start, &end, 16);
    if (start == end) {   /* nothing read */
      random_bytes ((char *) my_addr, my_addr_size);
      return;
    }
    start = end;
  }
}

#ifdef DEBUG_PRINT_ID
static void debug_prt_trace_id (void * state, void * n)
{
  print_buffer (n, MESSAGE_ID_SIZE, NULL, MESSAGE_ID_SIZE, 1);
  int offset = * ((int *) state);
  if (offset > 20)
    offset += snprintf (log_buf + offset, LOG_SIZE - offset, ", ");
  offset += buffer_to_string (n, MESSAGE_ID_SIZE, NULL, MESSAGE_ID_SIZE, 0,
                              log_buf + offset, LOG_SIZE - offset);
  * ((int *) state) = offset;
}
#endif /* DEBUG_PRINT_ID */

static int same_trace_id (void * n1, void * n2)
{
  int result = (memcmp (n1, n2, MESSAGE_ID_SIZE) == 0);
#ifdef DEBUG_PRINT_ID
  int off = snprintf (log_buf, LOG_SIZE, "same_trace_id (");
  off += buffer_to_string (n1, MESSAGE_ID_SIZE, NULL, MESSAGE_ID_SIZE, 0,
                           log_buf + off, LOG_SIZE - off);
  off += snprintf (log_buf + off, LOG_SIZE - off, ", ");
  off += buffer_to_string (n2, MESSAGE_ID_SIZE, NULL, MESSAGE_ID_SIZE, 0,
                           log_buf + off, LOG_SIZE - off);
  off += snprintf (log_buf + off, LOG_SIZE - off, ") => %d\n", result);
  log_print ();
#endif /* DEBUG_PRINT_ID */
  return result;
}

static void acknowledge_bcast (int sock, char * message, int msize)
{
  /* ignore any packet other than unencrypted packets requesting an ack */
  struct allnet_header * hp = (struct allnet_header *) message;
  if ((hp->message_type != ALLNET_TYPE_CLEAR) ||
      ((hp->transport & ALLNET_TRANSPORT_ACK_REQ) == 0))  /* ignore */
    return;
  int hsize = ALLNET_SIZE (hp->transport);
  if (msize < hsize + MESSAGE_ID_SIZE)
    return;
  int asize;
  unsigned char * received = (unsigned char *) (message + hsize);
  struct allnet_header * ack = create_ack (hp, received, NULL, 0, &asize);
  if ((asize == 0) || (ack == NULL))
    return;
  if (! send_pipe_message_free (sock, (char *) ack, asize,
                                ALLNET_PRIORITY_DEFAULT_LOW))
    snprintf (log_buf, LOG_SIZE, "unable to send broadcast ack\n");
  else
    snprintf (log_buf, LOG_SIZE, "sent broadcast ack\n");
  log_print ();
}

/* check for a recent trace with same ID.  If found, or the cache is full,
 * return 1, to say the trace should not be forwarded or replied to.
 * if the cache fills in less than a second, traces are ignored for
 * a second, to avoid forwarding too many traces.  The cache is then
 * made available for recording new traces -- we still look at all the
 * old traces that haven't yet been overwritten.
 * trace_id must have MESSAGE_ID_SIZE bytes
 */
static int is_in_trace_cache (const unsigned char * trace_id /* MESSAGE_ID_SIZE */ )
{
  static time_t last_received = 0;
  static time_t first_received = 0;
  static int next = 0;
#define TRACE_CACHE_SIZE	10
  static char cache [TRACE_CACHE_SIZE] [MESSAGE_ID_SIZE];
  time_t now = time (NULL);
  if (next >= TRACE_CACHE_SIZE) {
    if ((first_received == last_received) && (now <= last_received))
      return 1;    /* cache is full, ignore trace messages */
    next = 0;    /* enough time has passed, reset cache */
  }
  /* look through all of the cache, even if next < TRACE_CACHE_SIZE,
   * to match older traces that might still be in the cache */
  int i;
  for (i = 0; i < TRACE_CACHE_SIZE; i++) {
    if (memcmp (cache [i], trace_id, MESSAGE_ID_SIZE) == 0)
      return 1;   /* already seen, ignore */
  }
  /* trace not found, add the trace_id to the cache */
  if (next == 0)
    first_received = now;
  memcpy (cache [next], trace_id, MESSAGE_ID_SIZE);
  next++;
  last_received = now;
  return 0;  /* respond */
#undef TRACE_CACHE_SIZE
}

static void respond_to_trace (int sock, char * message, int msize,
                              int priority,
                              unsigned char * my_address, int abits,
                              int match_only, int forward_only,
                              void * cache)
{
  /* ignore any packet other than valid trace requests with at least 1 entry */
  struct allnet_header * hp = (struct allnet_header *) message;
  if ((hp->message_type != ALLNET_TYPE_MGMT) ||
      (msize < ALLNET_TRACE_REQ_SIZE (hp->transport, 1, 0)))
    return;
/* snprintf (log_buf, LOG_SIZE, "survived msize %d/%zd\n", msize,
            ALLNET_TRACE_REQ_SIZE (hp->transport, 1, 0));
  log_print (); */
  struct allnet_mgmt_header * mp =
    (struct allnet_mgmt_header *) (message + ALLNET_SIZE (hp->transport));
  if (mp->mgmt_type != ALLNET_MGMT_TRACE_REQ)
    return;
  struct allnet_mgmt_trace_req * trp =
    (struct allnet_mgmt_trace_req *)
      (message + ALLNET_MGMT_HEADER_SIZE (hp->transport));
#ifdef LOG_PACKETS
  int off = snprintf (log_buf, LOG_SIZE,
                      "respond_to_trace got %d byte trace request, %d %d: ",
                      msize, match_only, forward_only);
  packet_to_string (message, msize, NULL, 1, log_buf + off, LOG_SIZE - off);
  log_print ();
#endif /* LOG_PACKETS */
  int num_entries = (trp->num_entries & 0xff);
  int k = readb16u (trp->pubkey_size);
/* snprintf (log_buf, LOG_SIZE, "packet has %d entries %d key, size %d/%zd\n",
             num_entries, k, msize,
             ALLNET_TRACE_REQ_SIZE (hp->transport, num_entries, k));
  log_print (); */
  if ((num_entries < 1) ||
      (msize < ALLNET_TRACE_REQ_SIZE (hp->transport, num_entries, k)))
    return;

  if (is_in_trace_cache (trp->trace_id))
    return;

  /* found a valid trace request */
  if (cache_get_match (cache, same_trace_id, trp->trace_id) != NULL) {
#ifdef LOG_PACKETS
    buffer_to_string ((char *) (trp->trace_id), MESSAGE_ID_SIZE,
                      "duplicate trace_id", 5, 1, log_buf, LOG_SIZE);
    log_print ();
#endif /* LOG_PACKETS */
    return;     /* duplicate */
  }
  /* else new trace, save it in the cache so we only forward it once */
  cache_add (cache, memcpy_malloc (trp->trace_id, MESSAGE_ID_SIZE, "trace id"));
#ifdef DEBUG_PRINT_ID
  int debug_off = snprintf (log_buf, LOG_SIZE, "cache contains: ");
  printf ("cache contains: ");
  cache_map (cache, debug_prt_trace_id, &debug_off);
  debug_off += snprintf (log_buf + debug_off, LOG_SIZE - debug_off, "\n");
  log_print ();
#endif /* DEBUG_PRINT_ID */

  struct timeval timestamp;
  gettimeofday (&timestamp, NULL);

  /* do two things: forward the trace, and possibly respond to the trace. */

  int mbits = abits;
  if (mbits > hp->dst_nbits)
    mbits = hp->dst_nbits;   /* min of abits, and hp->dst_nbits */
  int nmatch = matches (my_address, abits, hp->destination, hp->dst_nbits);
#ifdef DEBUG_PRINT
  printf ("matches (");
  print_buffer (my_address, abits, NULL, (abits + 7) / 8, 0);
  printf (", ");
  print_buffer (hp->destination, hp->dst_nbits, NULL,
                (hp->dst_nbits + 7) / 8, 0);
  printf (") => %d (%d needed)\n", nmatch, mbits);
#endif /* DEBUG_PRINT */
  /* when forwarding, use a low priority > epsilon, to tell ad it is from us */
  int fwd_priority = ALLNET_PRIORITY_TRACE_FWD;
  if ((forward_only) || ((match_only) && (nmatch < mbits))) {
    /* forward without adding my entry */
    if (! send_pipe_message (sock, message, msize, fwd_priority))
      printf ("unable to forward trace response\n");
    snprintf (log_buf, LOG_SIZE, "forwarded %d bytes\n", msize);
    log_print ();
    return;  /* we are done, no need to reply */
  } /* else: add my entry before forwarding */
  char * new_msg;
  int n = add_my_entry (message, msize, hp, mp, trp, &timestamp,
                        my_address, abits, &new_msg);
#ifdef LOG_PACKETS
  if (n > 0) {
    int off = snprintf (log_buf, LOG_SIZE,
                        "forwarding trace req %d <- %d ", n, msize);
    packet_to_string (new_msg, n, NULL, 1, log_buf + off, LOG_SIZE - off);
    log_print ();
  }
#endif /* LOG_PACKETS */

  char * response = NULL;
  int rsize = 0;
  if (trp->intermediate_replies) {   /* generate a reply */

    if (nmatch >= mbits)  /* exact match, send final response */
      rsize = make_trace_reply (hp, msize, &timestamp, my_address, abits,
                                trp, 0, trp->num_entries + 1, &response);
    else if (hp->hops > 0) /* not my local sender, send back 2 trace entries */
      rsize = make_trace_reply (hp, msize, &timestamp, my_address, abits,
                                trp, 1, 2, &response);
    else   /* my local sender, send a 1-entry response */
      rsize = make_trace_reply (hp, msize, &timestamp, my_address, abits,
                                trp, 1, 1, &response);
  }

/* send request, reply, or both */
  char * messages [2];
  int mlens [2];
  int priorities [2];
  messages [0] = new_msg;
  mlens [0] = n;
  priorities [0] = fwd_priority;
  messages [1] = response;
  mlens [1] = rsize;
/* trace responses go with the lowest possible priority */
  priorities [1] = ALLNET_PRIORITY_TRACE;

  int count = 0;  /* how many to send? */
  int first = 1;  /* send the request first, or only the reply? */
  if (n > 0) {
    count = 1;
    first = 0;
  }
  if (rsize > 0)
    count += 1;

  if (! send_pipe_multiple_free (sock, count, messages + first,
                                 mlens + first, priorities + first))
    snprintf (log_buf, LOG_SIZE, "unable to send trace request+reply\n");
  else
    snprintf (log_buf, LOG_SIZE, "sent trace request+reply of sizes %d+%d\n",
              n, rsize);
#ifdef LOG_PACKETS
  log_print ();
#endif /* LOG_PACKETS */
}

static void main_loop (int sock, pd p, unsigned char * my_address, int nbits,
                       int match_only, int forward_only)
{
  void * cache = cache_init (100, free);
  while (1) {
    char * message;
    int pipe, pri;
    int timeout = PIPE_MESSAGE_WAIT_FOREVER;
    int found = receive_pipe_message_any (p, timeout, &message, &pipe, &pri);
    if (found < 0) {
      snprintf (log_buf, LOG_SIZE, "traced pipe closed, exiting\n");
      log_print ();
      /* printf ("traced pipe closed, exiting\n"); */
      exit (1);
    }
#ifdef DEBUG_PRINT
    print_packet (message, found, "received", 1);
#endif /* DEBUG_PRINT */
    if (is_valid_message (message, found)) {
      acknowledge_bcast (sock, message, found);
      respond_to_trace (sock, message, found, pri + 1, my_address, nbits,
                        match_only, forward_only, cache);
    }
    free (message);
  }
}

#ifdef TRACE_MAIN_FUNCTION
static void send_trace (int sock, unsigned char * address, int abits,
                        char * trace_id,
                        unsigned char * my_address, int my_abits, int max_hops)
{
  int total_size = ALLNET_TRACE_REQ_SIZE (0, 1, 0);
  int data_size = total_size - ALLNET_SIZE (0);
  int allocated = 0;
  struct allnet_header * hp =
    create_packet (data_size, ALLNET_TYPE_MGMT, max_hops, ALLNET_SIGTYPE_NONE,
                   my_address, my_abits, address, abits, NULL, NULL,
                   &allocated);
  if (allocated != total_size) {
    printf ("error in send_trace: %d %d %d\n", allocated,
            total_size, data_size);
    if (hp != NULL)
      free (hp);
    return;
  }

  char * buffer = (char *) hp;
  struct allnet_mgmt_header * mp =
    (struct allnet_mgmt_header *) (buffer + ALLNET_SIZE (hp->transport));
  struct allnet_mgmt_trace_req * trp =
    (struct allnet_mgmt_trace_req *)
      (buffer + ALLNET_MGMT_HEADER_SIZE (hp->transport));

  mp->mgmt_type = ALLNET_MGMT_TRACE_REQ;

  trp->intermediate_replies = 1;
  trp->num_entries = 1;
  writeb16u (trp->pubkey_size, 0);
  /* pubkey_size is 0, so no public key */
  memcpy (trp->trace_id, trace_id, MESSAGE_ID_SIZE);
  struct timeval time;
  gettimeofday (&time, NULL);
  init_trace_entry (trp->trace, 0, &time, my_address, my_abits);

/*  print_packet (buffer, total_size, "sending trace", 1);
  snprintf (log_buf, LOG_SIZE, "sending trace of size %d\n", total_size);
  log_print (); */
  /* sending with priority epsilon indicates to ad that we only want to
   * send to the trace server, which then forwards to everyone else */
  if (! send_pipe_message_free (sock, buffer, total_size,
                                ALLNET_PRIORITY_TRACE))
    snprintf (log_buf, LOG_SIZE,
              "unable to send trace message of %d bytes\n", total_size);
  else
    snprintf (log_buf, LOG_SIZE, "sent %d-byte trace message\n", total_size);
  log_print ();
}

static unsigned long long int power10 (int n)
{
  if (n < 1)
    return 1;
  return 10 * power10 (n - 1);
}

struct arrival {
  struct timeval time;
  struct allnet_mgmt_trace_entry value;
};

#define MAX_ARRIVALS	256
static int num_arrivals = 0;
static struct arrival arrivals [MAX_ARRIVALS];

/* looks for this entry in the arrivals array */
/* returns -1 if not found, otherwise the index */
static int find_arrival (struct allnet_mgmt_trace_entry * entry)
{
  int ebits = entry->nbits;
  int ehops = entry->hops_seen & 0xff;
/* printf ("\nfinding  %d/%d: ", ebits, ehops);
print_bitstring (entry->address, 0, ebits, 1); */
  int i;
  for (i = 0; i < num_arrivals; i++) {
    int abits = arrivals [i].value.nbits;
    int ahops = arrivals [i].value.hops_seen & 0xff;
/*
printf ("comparing %d/%d (%d): ", abits, arrivals [i].value.hops_seen,
        matches (entry->address, ebits, arrivals [i].value.address, abits));
print_bitstring (arrivals [i].value.address, 0, abits, 1);
*/
    if ((abits == ebits) && (ehops == ahops) &&
        (matches (entry->address, ebits, arrivals [i].value.address, abits)
         >= ebits))
      return i;
  }
  return -1;
}

static int sent_count = 0;
static int received_count = 0;
static int64_t min_rtt = -1;  /* in units of microseconds */
static int64_t max_rtt = -1;
static int64_t sum_rtt = 0;  /* sum_rtt / received_count is the mean rtt */

/* print summaries.  Also, signal handler in case we are stopped */
static void print_summary_file (int signal, FILE * out)
{
  if (sent_count > 0) {
    char * ps = "packets";
    if (sent_count == 1)
      ps = "packet";
    if (received_count > 0) {
      int64_t mean_rtt = sum_rtt / ((int64_t) received_count);
      fprintf (out, "sent %d %s, received %d, ",
               sent_count, ps, received_count);
      fprintf (out, "rtt min/mean/max is %" PRId64 ".%03d/", min_rtt / 1000,
               (int) (min_rtt % 1000));
      fprintf (out, "%" PRId64 ".%03d/", mean_rtt / 1000,
               (int) (mean_rtt % 1000));
      fprintf (out, "%" PRId64 ".%03d\n", max_rtt / 1000,
               (int) (max_rtt % 1000));
    } else {  /* received_count is 0 */
      fprintf (out, "sent %d %s, received 0\n", sent_count, ps);
    }
  } /* else nothing sent, print nothing */
  if ((signal == SIGHUP) || (signal == SIGINT) || (signal == SIGKILL)) {
    /* printf ("exiting on signal %d\n", signal); */
    exit (1);
  }
}

static void print_summary (int signal)
{
  print_summary_file (signal, stdout);
}


static void record_rtt (unsigned long long us)
{
  if ((min_rtt < 0) || (us < min_rtt))
    min_rtt = us;
  if ((max_rtt < 0) || (max_rtt < us))
    max_rtt = us;
  sum_rtt += us;
  received_count++;
}

static void print_times (struct allnet_mgmt_trace_entry * entry,
                         struct timeval * start, struct timeval * now,
                         int save_to_intermediate, FILE * out)
{
  if ((start != NULL) && (now != NULL)) {
    unsigned long long int fraction = readb64u (entry->seconds_fraction);
    if (entry->precision <= 64)
      fraction = fraction / (((unsigned long long int) (-1LL)) / 1000000LL);
    else if (entry->precision <= 70)  /* decimal in low-order bits */
      fraction = fraction * (power10 (70 - entry->precision));
    else
      fraction = fraction / (power10 (entry->precision - 70));
    if (fraction >= 1000000LL) {  /* should be converted to microseconds */
      printf ("error: fraction (%u) %lld gives %lld >= 1000000 microseconds\n",
              entry->precision, readb64u (entry->seconds_fraction),
              fraction);
      fraction = 0LL;
    }
    struct timeval timestamp;
    timestamp.tv_sec = (time_t) (readb64u (entry->seconds));
    timestamp.tv_usec = (suseconds_t)fraction;
    unsigned long long int delta = delta_us (&timestamp, start);
  /* printf ("%ld.%06ld - %ld.%06ld = %lld\n",
          timestamp.tv_sec, timestamp.tv_usec,
          start->tv_sec, start->tv_usec, delta); */
    if (print_details) {
      if (delta > 0)
        fprintf (out, " %6lld.%03lldms timestamp, ", delta / 1000LL,
                 delta % 1000LL);
      else
        fprintf (out, "                         ");
    }
  
    delta = delta_us (now, start);
    int index = find_arrival (entry);
    if (index >= 0) {
      delta = delta_us (&(arrivals [index].time), start);
    } else if ((save_to_intermediate) && (num_arrivals + 1 < MAX_ARRIVALS)) {
      arrivals [num_arrivals].value = *entry;
      arrivals [num_arrivals].time = *now;
      num_arrivals++;
    }
    fprintf (out, " %6lld.%03lldms rtt,", delta / 1000LL, delta % 1000LL);
  }
}

static void print_entry (struct allnet_mgmt_trace_entry * entry,
                         struct timeval * start, struct timeval * now,
                         int print_eol, FILE * out)
{
  int index = (entry->hops_seen) & 0xff;
  fprintf (out, "%3d ", index);

  if (entry->nbits > 0)
    fprintf (out, "%02x", entry->address [0] % 0xff);
  int i;
  for (i = 1; ((i < ADDRESS_SIZE) && (i < (entry->nbits + 7) / 8)); i++)
    fprintf (out, ".%02x", entry->address [i] % 0xff);
  fprintf (out, "/%d", entry->nbits);

  if (print_eol)
    fprintf (out, "\n");
}

static void print_trace_result (struct allnet_mgmt_trace_reply * trp,
                                struct timeval start, struct timeval finish,
                                int seq, int match_only, int no_intermediates,
                                FILE * out)
{
  unsigned long long us = delta_us (&finish, &start);
  /* put the unix times into allnet format */
  start.tv_sec -= ALLNET_Y2K_SECONDS_IN_UNIX;
  finish.tv_sec -= ALLNET_Y2K_SECONDS_IN_UNIX;
  if (trp->encrypted) {
    fprintf (out, "to do: implement decrypting encrypted trace result\n");
    return;
  }
  if (trp->intermediate_reply == 0) {      /* final reply */
    record_rtt (us);
    int first = 1;
    if (no_intermediates)
      first = trp->num_entries - 1;
    if (trp->num_entries > 1) {
      if ((! no_intermediates) && (! match_only))
        fprintf (out, "trace to matching destination:\n");
      int i;
      for (i = first; i < trp->num_entries; i++) {
        if (print_details) {
          if (i + 1 == trp->num_entries)
            fprintf (out, "%4d: ", seq + 1);
          else
            fprintf (out, "      ");
          fprintf (out, "         ");
        }
        print_times (trp->trace + i, &start, &finish, 1, out);
        print_entry (trp->trace + i, &start, &finish, 1, out);
      }
    }
  } else if ((no_intermediates) || (match_only)) {  /* skip intermediates */
                                                    /* and not exact match */
  } else if (trp->num_entries == 2) {
    /* generally two trace entries for intermediate replies */
    fprintf (out, "forward: ");
    print_times (trp->trace + 1, &start, &finish, 1, out);
    print_entry (trp->trace + 0, NULL, NULL, 0, out);
    fprintf (out, "  to");
    print_entry (trp->trace + 1, &start, &finish, 1, out);
  } else if (trp->num_entries == 1) {
    /* generally only one trace entry, so always print the first */
    fprintf (out, "local:   ");
    print_times (trp->trace, &start, &finish, 1, out);
    print_entry (trp->trace, &start, &finish, 1, out);
  } else {
    fprintf (out, "intermediate response with %d entries\n", trp->num_entries);
  }
  fflush (out);
}

static void handle_packet (char * message, int msize, char * seeking,
                           struct timeval start, int seq,
                           int match_only, int no_intermediates, FILE * out)
{
/* print_packet (message, msize, "handle_packet got", 1); */
  if (! is_valid_message (message, msize))
    return;
  struct allnet_header * hp = (struct allnet_header *) message;

  int min_size = ALLNET_TRACE_REPLY_SIZE (0, 1);
  if (msize < min_size)
    return;
  if (hp->message_type != ALLNET_TYPE_MGMT)
    return;
  min_size = ALLNET_TRACE_REPLY_SIZE (hp->transport, 1);
  if (msize < min_size)
    return;

  struct allnet_mgmt_header * mp =
    (struct allnet_mgmt_header *) (message + ALLNET_SIZE (hp->transport));
  if (mp->mgmt_type != ALLNET_MGMT_TRACE_REPLY)
    return;

  struct allnet_mgmt_trace_reply * trp =
    (struct allnet_mgmt_trace_reply *)
      (message + ALLNET_MGMT_HEADER_SIZE (hp->transport));
  unsigned char * trace_id = trp->trace_id;
  if (memcmp (trace_id, seeking, MESSAGE_ID_SIZE) != 0) {
#ifdef DEBUG_PRINT
    printf ("received trace_id does not match expected trace_id\n");
    print_buffer (seeking , MESSAGE_ID_SIZE, "expected trace_id", 100, 1);
    print_buffer ((char *) trace_id, MESSAGE_ID_SIZE,
                  "received trace_id", 100, 1);
#endif /* DEBUG_PRINT */
    return;
  }
  struct timeval now;
  gettimeofday (&now, NULL);
/*
  printf ("%ld.%06ld: ", now.tv_sec - ALLNET_Y2K_SECONDS_IN_UNIX, now.tv_usec);
  print_packet (message, msize, "trace reply packet received", 1);
*/
  snprintf (log_buf, LOG_SIZE, "matching trace response of size %d\n", msize);
  log_print ();
  print_trace_result (trp, start, now, seq, match_only, no_intermediates, out);
}

static void wait_for_responses (int sock, pd p, char * trace_id, int sec,
                                int seq, int match_only, int no_intermediates,
                                FILE * out)
{
  num_arrivals = 0;   /* not received anything yet */
  unsigned long long int max_ms = sec * 1000;
  unsigned long long int time_spent = 0;
  unsigned long long int start = allnet_time_ms ();
  struct timeval tv_start;
  gettimeofday (&tv_start, NULL);
  while (time_spent < max_ms) {
    int pipe;
    int pri;
    char * message;
    unsigned long long int computed_ms = max_ms - time_spent;
    int ms = (computed_ms > INT_MAX) ? INT_MAX : ((int) computed_ms);
    int found = receive_pipe_message_any (p, ms, &message, &pipe, &pri);
    if (found < 0) {
#ifdef DEBUG_PRINT
      printf ("trace pipe closed, exiting\n");  
#endif /* DEBUG_PRINT */
      exit (1);
    }
    handle_packet (message, found, trace_id, tv_start, seq,
                   match_only, no_intermediates, out);
    if (found > 0)
      free (message);
    time_spent = allnet_time_ms () - start;
  }
#ifdef DEBUG_PRINT
  printf ("timeout\n");
#endif /* DEBUG_PRINT */
}

static void usage (char * pname, int daemon)
{
  if (daemon) {
    printf ("usage: %s [-m] [-v] [<my_address_in_hex>[/<number_of_bits>]]\n",
            pname);
    printf ("       -m specifies tracing only when we match the address\n"); 
    printf ("       -v for verbose\n");
  } else {
    printf ("usage: %s [-v] [-f|-r n] [-m] [-i] %s\n",
            "[<my_address_in_hex>[/<number_of_bits> [hops]]]\n", pname);
    printf ("       -f repeats forever, or -r n repeats n times\n");
    printf ("       -m only reports responses from matching addresses\n");
    printf ("       -i does not report intermediate nodes (a bit like ping)\n");
    printf ("       -i implies -m\n");
    printf ("       -v for verbose\n");
    printf ("       -t sec, time to sleep after send (default 5 seconds)\n");
    printf ("       -h hops gives the maximum number of hops (default 10)\n");
  }
}

#if 0   /* replaced by getopt */
static int get_repeat_option (int * argcp, char ** argv)
{
  int orig_argc = *argcp;
  int i;
  for (i = 1; i < orig_argc; i++) {
    if (strcmp (argv [i], "-r") == 0) {  /* found a match */
      int skip = 1;
      int result = 0;                    /* repeat forever */
      if (i + 1 < orig_argc) {
        char * e;
        int count = strtol (argv [i + 1], &e, 10);
        if (e != argv [i + 1]) {  /* found something */
          result = count;
          skip = 2;
        }
      }
      int j;
      for (j = i; j + skip < orig_argc; j++)
        argv [j] = argv [j + skip];
      *argcp = orig_argc - skip;
      return result;
    }
  }
  return 1;   /* only repeat once */
}
#endif /* 0 */

#endif /* TRACE_MAIN_FUNCTION */

void traced_main (char * pname)
{
  pd p = init_pipe_descriptor ();
  int sock = connect_to_local (pname, pname, p);
  if (sock < 0)
    return;

  unsigned char address [ADDRESS_SIZE];
  bzero (address, sizeof (address));  /* set any unused part to all zeros */
  int abits = 16;
  get_my_addr (address, sizeof (address));

#ifdef DEBUG_PRINT
  printf ("trace daemon (m %d) for %d bits: ", match_only, abits);
  print_bitstring (address, 0, abits, 1);
#endif /* DEBUG_PRINT */
  main_loop (sock, p, address, abits, 0, 0);
  printf ("trace error: main loop returned\n");
  return;
}

#ifdef TRACE_MAIN_FUNCTION
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
  return result;
}

static void do_trace_loop (int sock, pd p, unsigned char * address, int abits,
                           int repeat, int sleep, int nhops, int match_only,
                           int no_intermediates, int wide, FILE * out)
{
  print_details = wide;
#ifdef DEBUG_PRINT
  printf ("tracing %d bits to %d hops: ", abits, nhops);
  print_bitstring (address, 0, abits, 1);
#endif /* DEBUG_PRINT */
  char trace_id [MESSAGE_ID_SIZE];
  unsigned char my_addr [ADDRESS_SIZE];
  int count;
  for (count = 0; (repeat == 0) || (count < repeat); count++) {
/* printf ("%d/%d\n", count, repeat); */
    random_bytes (trace_id, sizeof (trace_id));
    random_bytes ((char *) my_addr, sizeof (my_addr));
    send_trace (sock, address, abits, trace_id, my_addr, 5, nhops);
    sent_count++;
    wait_for_responses (sock, p, trace_id, sleep, count,
                        match_only, no_intermediates, out);
  }
  print_summary_file (0, out);
  print_details = 1;
}

/* parts of this duplicate some of the code in traced_main, but
 * supporting the address on the command line seems like a useful feature */
int trace_main (int argc, char ** argv)
{
  int is_daemon = 0;
  if (strstr (argv [0], "traced") != NULL)  /* called as daemon */
    is_daemon = 1;

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
  if (is_daemon)
    opt_string = "mv";
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
      usage (argv [0], is_daemon);
      exit (1);
    }
  }
  log_to_output (verbose);

  /* daemon may have one non-option argument, user program up to two */
  if ((argc > optind + 1) && ((is_daemon) || (argc > optind + 2))) {
    printf ("argc %d, optind %d, at most %d allowed for %s\n", argc, optind,
            ((is_daemon) ? 1 : 2), argv [0]);
    usage (argv [0], is_daemon);
    return 1;
  }

  unsigned char address [ADDRESS_SIZE];
  bzero (address, sizeof (address));  /* set any unused part to all zeros */
  int abits = 0;
  if (is_daemon) {
    get_my_addr (address, sizeof (address));
    abits = 16;
  }
  if (argc > optind) {   /* use the address specified on the command line */
    bzero (address, sizeof (address));  /* set unused part to all zeros */
    abits = get_address (argv [optind], address, sizeof (address));
    if (abits <= 0) {
      printf ("argc %d/%d/%s, invalid number of bits, should be > 0\n",
              argc, optind, argv [optind]);
      usage (argv [0], is_daemon);
      return 1;
    }
  }

  pd p = init_pipe_descriptor ();
  int sock = connect_to_local (argv [0], argv [0], p);
  if (sock < 0)
    return 1;
/* print_buffer (address, abits, "argument address", 8, 1); */

  if (is_daemon) {     /* called as daemon */
#ifdef DEBUG_PRINT
    printf ("trace daemon (m %d) for %d bits: ", match_only, abits);
    print_bitstring (address, 0, abits, 1);
#endif /* DEBUG_PRINT */
    main_loop (sock, p, address, abits, match_only, 0);
    printf ("trace error: main loop returned\n");
    return 1;
  } else {                                    /* called as client */
    struct sigaction siga;
    siga.sa_handler = &print_summary;
    sigemptyset (&(siga.sa_mask));
    siga.sa_flags = 0;
    if (sigaction (SIGINT, &siga, NULL) != 0)
      perror ("sigaction");  /* not fatal */
    if (argc > optind + 1) {   /* number of hops from the command line */
      int n = atoi (argv [optind + 1]);
      if (n > 0)
        nhops = n;
    }
    do_trace_loop (sock, p, address, abits, repeat, sleep, nhops, match_only,
                   no_intermediates, 1, stdout);
#if 0
#ifdef DEBUG_PRINT
    printf ("tracing %d bits to %d hops: ", abits, nhops);
    print_bitstring (address, 0, abits, 1);
#endif /* DEBUG_PRINT */
    char trace_id [MESSAGE_ID_SIZE];
    unsigned char my_addr [ADDRESS_SIZE];
    int count;
    for (count = 0; (repeat == 0) || (count < repeat); count++) {
/* printf ("%d/%d\n", count, repeat); */
      random_bytes (trace_id, sizeof (trace_id));
      random_bytes ((char *) my_addr, sizeof (my_addr));
      send_trace (sock, address, abits, trace_id, my_addr, 5, nhops);
      sent_count++;
      wait_for_responses (sock, p, trace_id, sleep, count,
                          match_only, no_intermediates, stdout);
    }
    print_summary (0);
#endif /* 0 */
  }
  return 0;
}

/* returns a (malloc'd) string representation of the trace result */
char * trace_string (const char * tmp_dir, int sleep, const char * dest,
                     int nhops, int no_intermediates, int match_only, int wide)
{
  unsigned char address [ADDRESS_SIZE];
  bzero (address, sizeof (address));  /* set any unused part to all zeros */
  int abits = 0;
  if ((dest != NULL) && (strlen (dest) > 0)) {
    abits = get_address (dest, address, sizeof (address));
    if (abits <= 0)
      return strcat_malloc ("illegal destination ", dest, "trace_string");
  }

  pd p = init_pipe_descriptor ();
  int sock = connect_to_local ("trace_string", "trace_string", p);
  if (sock < 0)
    return strcpy_malloc ("unable to connect to allnet", "trace_string");

#define TEMP_FILE	"tmp-file"
  char * fname = strcat3_malloc (tmp_dir, "/", TEMP_FILE, "trace_string");
  FILE * file = fopen (fname, "w");
  if (file == NULL)
    return strcat_malloc ("unable to open file ", fname, "trace_string");

  do_trace_loop (sock, p, address, abits, 1, sleep, nhops, match_only,
                 no_intermediates, wide, file);
#if 0
#ifdef DEBUG_PRINT
  printf ("tracing %d bits to %d hops: ", abits, nhops);
  print_bitstring (address, 0, abits, 1);
#endif /* DEBUG_PRINT */
  char trace_id [MESSAGE_ID_SIZE];
  unsigned char my_addr [ADDRESS_SIZE];
  random_bytes (trace_id, sizeof (trace_id));
  random_bytes ((char *) my_addr, sizeof (my_addr));
  send_trace (sock, address, abits, trace_id, my_addr, 5, nhops);
  sent_count++;
  wait_for_responses (sock, p, trace_id, sleep, 0,
                      match_only, no_intermediates, file);
  print_summary_file (0, file);
#endif /* 0 */
  fclose (file);
  char * result;
  size_t success = read_file_malloc (fname, &result, 0);
  if (success <= 0)
    result = strcat_malloc ("unable to read file ", fname, "trace_string");
  unlink (fname);
  free (fname);
  return result;
}

void trace_pipe (int pipe, int sleep, const char * dest,
                 int nhops, int no_intermediates, int match_only, int wide)
{
  FILE * pipe_file = fdopen (pipe, "w");
  if (pipe_file == NULL) {
    char * err = "unable to open pipe file ";
    write (pipe, err, strlen (err));
    return;
  }
  unsigned char address [ADDRESS_SIZE];
  bzero (address, sizeof (address));  /* set any unused part to all zeros */
  int abits = 0;
  if ((dest != NULL) && (strlen (dest) > 0)) {
    abits = get_address (dest, address, sizeof (address));
    if (abits <= 0)
      printf ("illegal destination %s\n", dest);
  }

  pd p = init_pipe_descriptor ();
  int sock = connect_to_local ("trace_pipe", "trace_pipe", p);
  if (sock < 0) {
    printf ("unable to connect to allnet\n");
    return;
  }

  do_trace_loop (sock, p, address, abits, 1, sleep, nhops, match_only,
                 no_intermediates, wide, pipe_file);
  fclose (pipe_file);
}

#ifndef __IPHONE_OS_VERSION_MIN_REQUIRED  /* not on iOS, define main */
int main (int argc, char ** argv)
{
  return trace_main (argc, argv);
}
#endif /* __IPHONE_OS_VERSION_MIN_REQUIRED */

#endif /* TRACE_MAIN_FUNCTION */
