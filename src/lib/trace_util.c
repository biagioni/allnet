/* trace_util.c: software to generate and handle AllNet traces */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <stdint.h>
#include <inttypes.h>
#include <limits.h>
#include <fcntl.h>

#include "packet.h"
#include "mgmt.h"
#include "configfiles.h"
#include "util.h"
#include "pipemsg.h"
#include "priority.h"
#include "dcache.h"
#include "app_util.h"
#include "allnet_log.h"
#include "allnet_queue.h"
#include "trace_util.h"
#include "sha.h"
#include "routing.h"

static int print_details = 1;

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

/* if queue is not null, writes to the queue.  Otherwise writes to the fd */
static int write_string_to (const char * string, int null_term, int fd,
                            struct allnet_queue * queue)
{
  size_t len = strlen (string);
/* printf ("writing string '%s' of length %zd\n", string, len); */
  if (len == 0)
    return 0;
  int result = 0;
  if (null_term)
    len++;
  if (queue != NULL) {
    if (allnet_enqueue (queue, (const unsigned char *)string, (int)len, 1))
      result = (int)len;
  } else {
    result = (int) write (fd, string, len);
  }
  return result;
}

#define CHECK_FOR_DUPLICATES

#ifdef CHECK_FOR_DUPLICATES
/* returns 1 if the packet was seen within the last NUM_REMEMBERED packets.
 * Otherwise, returns 0 and remembers this packet */
int packet_received_before (char * message, int msize,
                            char * remembered_hashes, int nh, int * position)
{
  if (*position < 0) {
    memset (remembered_hashes, 0, nh * MESSAGE_ID_SIZE);
    *position = 0;
  }
  if (msize <= 4)
    return 1;  /* should be caught before calling packet_received_before */
  char hash [MESSAGE_ID_SIZE];
  /* when hashing, skip the hop counts */
  sha512_bytes (message + 4, msize - 4, hash, MESSAGE_ID_SIZE);
  int i;
  for (i = 0; i < nh; i++) {
    if (memcmp (remembered_hashes + (i * MESSAGE_ID_SIZE),
                hash, MESSAGE_ID_SIZE) == 0)
      return 1;  /* found */
  }
  /* not found, add */
  if ((*position < 0) || (*position >= nh))
    *position = 0;
  memcpy (remembered_hashes + ((*position) * MESSAGE_ID_SIZE), hash,
          MESSAGE_ID_SIZE);
  *position = *position + 1;
  return 0;   /* not found */
#undef NUM_REMEMBERED_HASHES
}
#endif /* CHECK_FOR_DUPLICATES */

/* check for a recent trace with same ID.
#ifdef LIMIT_RATE_OF_TRACES
 * if we already handled n traces this s-second period (n = 20, s = 5), or
#endif
 * if this trace was received before, return 1 to say the trace should not
 * be forwarded or replied to.
 * trace_id must have MESSAGE_ID_SIZE bytes
 */
static int is_in_trace_cache (const unsigned char * trace_id)
{
#define TRACE_CACHE_SIZE        (4 * 1024)   /* 4K traces, 64KByte */

#ifdef LIMIT_RATE_OF_TRACES  /* not sure this code works */
#define TRACE_INTERVAL_SECONDS  5            /* 5-second intervals */
#define TRACE_INTERVAL_MAX      20           /* up to 20 traces every 5s */
  static unsigned int sent_this_interval = 0;
  static time_t last_received = 0;
  time_t now = time (NULL) / TRACE_INTERVAL_SECONDS;
  if (now == last_received) {
    if (sent_this_interval >= TRACE_INTERVAL_MAX)
      return 1;    /* already worked hard during this interval */
  } else {         /* new interval, reset the count and the interval */
    sent_this_interval = 0;
  }
#endif /* LIMIT_RATE_OF_TRACES */
  static char cache [TRACE_CACHE_SIZE] [MESSAGE_ID_SIZE];
  /* look through all of the cache to find any matching traces */
  int i;
  for (i = 0; i < TRACE_CACHE_SIZE; i++) {
    if (memcmp (cache [i], trace_id, MESSAGE_ID_SIZE) == 0)
      return 1;   /* already seen, ignore */
  }
  /* trace not found, add the trace_id to the cache at the next position */
  static int next = 0;       /* next place to save messages */
  memcpy (cache [next], trace_id, MESSAGE_ID_SIZE);
  next = (next + 1) % TRACE_CACHE_SIZE;
#undef TRACE_CACHE_SIZE

#ifdef LIMIT_RATE_OF_TRACES
  sent_this_interval++;   /* increment the number sent in this interval */
  last_received = now;
#undef TRACE_INTERVAL_SECONDS
#undef TRACE_INTERVAL_MAX
#endif /* LIMIT_RATE_OF_TRACES */
  return 0;  /* respond */
}

static void init_trace_entry (struct allnet_mgmt_trace_entry * new_entry,
                              int hops, unsigned char * my_address, int abits,
                              int local)
{
  memset (new_entry, 0, sizeof (struct allnet_mgmt_trace_entry));
  /* assume accuracy is 1ms, or 3 decimal digits */
  long long int now = allnet_time_us ();
  /* assume accuracy is 1ms, or 3 decimal digits,
   * unless the hop count is 0, in which case accuracy is 1us or 6 digits */
  new_entry->precision = 64 + 3 + (local ? 3 : 0);
  writeb64u (new_entry->seconds, now / (1000 * (local ? 1 : 1000)));
  writeb64u (new_entry->seconds_fraction, (now % 1000000) / (local ? 1 : 1000));
  new_entry->hops_seen = hops;
  new_entry->nbits = abits;
  memcpy (new_entry->address, my_address, (abits + 7) / 8);
}

/* see if adht has an address, if so, use that */
void get_my_addr (unsigned char * my_addr, int my_addr_size,
                  struct allnet_log * alog)
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
      snprintf (alog->b, alog->s,
                "error: traced still waiting for adht peer file creation\n");
      log_print (alog);
      if (count > 20)
        return;
    }
  }
#define EXPECTED_FIRST_LINE	33  /* first line should always be 33 bytes */
  char line [EXPECTED_FIRST_LINE];
  ssize_t n = read (fd, line, EXPECTED_FIRST_LINE);
  close (fd);
  if (n != EXPECTED_FIRST_LINE)
    return;   /* random ID on each new invocation */
  line [EXPECTED_FIRST_LINE - 1] = '\0';  /* terminate by overwriting \n */
#undef EXPECTED_FIRST_LINE
  int i;
  char * start = line + 9;
  for (i = 0; i < ADDRESS_SIZE; i++) {
    char * end;
    my_addr [i] = strtol (start, &end, 16);
    if (start == end) {   /* not read, go back to a random ID */
      random_bytes ((char *) my_addr, my_addr_size);
      return;
    }
    start = end;
  }
}

static unsigned int add_my_entry (char * in, unsigned int insize,
                                  struct allnet_header * inhp,
                                  struct allnet_mgmt_header * inmp,
                                  struct allnet_mgmt_trace_req * intrp,
                                  unsigned char * my_address,
                                  unsigned int abits,
                                  char * * result)
{
  *result = NULL;
  if (intrp->num_entries >= 255)
    return 0;
  int n = intrp->num_entries + 1;
  int t = inhp->transport;
  int k = readb16u (intrp->pubkey_size);
  unsigned int needed = ALLNET_TRACE_REQ_SIZE (t, n, k);
  *result = calloc (needed, 1);
  if (*result == NULL) {
    printf ("add_my_entry unable to allocate %d bytes for %d\n", needed, n);
    return 0;
  }
  /* can copy the header verbatim, and all of the trace request
   * except the pubkey */
  int copy_size = ALLNET_TRACE_REQ_SIZE (t, intrp->num_entries, 0);
  memcpy (*result, in, copy_size);

  struct allnet_mgmt_trace_req * trp =
    (struct allnet_mgmt_trace_req *)
      ((*result) + ALLNET_MGMT_HEADER_SIZE (t));
  trp->num_entries = n;
  struct allnet_mgmt_trace_entry * new_entry = trp->trace + (n - 1);
  init_trace_entry (new_entry, inhp->hops, my_address, abits, inhp->hops == 1);
  if (k > 0) {
    char * inkey = ((char *) (intrp->trace)) +
                   (sizeof (struct allnet_mgmt_trace_entry) * (n - 1));
    char * key = ((char *) (trp->trace)) +
                 (sizeof (struct allnet_mgmt_trace_entry) * n);
    memcpy (key, inkey, k);
  }
  return needed;
}

static int make_trace_reply (struct allnet_header * inhp, int insize,
                             struct allnet_mgmt_trace_req * intrp,
                             int intermediate, unsigned int num_entries,
                             unsigned char * my_address, unsigned int abits,
                             char ** result)
{
  *result = NULL;
  unsigned int insize_needed =
    ALLNET_TRACE_REQ_SIZE (inhp->transport, intrp->num_entries, 0);
  if (insize < insize_needed) {
    printf ("error: trace req needs %d, has %d\n", insize_needed, insize);
    return 0;
  }
  if (num_entries < 1) {
    printf ("error: trace reply num_entries %d < 1 \n", num_entries);
    return 0;
  }

  unsigned int size_needed = ALLNET_TRACE_REPLY_SIZE (0, num_entries);
  unsigned int total = 0;
  struct allnet_header * hp =
    create_packet (size_needed - ALLNET_SIZE (0), ALLNET_TYPE_MGMT,
                   inhp->hops + 4, ALLNET_SIGTYPE_NONE, my_address, abits,
                   inhp->source, inhp->src_nbits, NULL, NULL, &total);
  if ((hp == NULL) || (total != size_needed)) {
    printf ("hp is %p, total is %u, size_needed %d\n", hp, total, size_needed);
    return 0;
  }
  *result = (char *) hp;

  struct allnet_mgmt_header * mp =
    (struct allnet_mgmt_header *)(ALLNET_DATA_START(hp, hp->transport, total));
  mp->mgmt_type = ALLNET_MGMT_TRACE_REPLY;

  struct allnet_mgmt_trace_reply * trp =
    (struct allnet_mgmt_trace_reply *)
      (((char *) mp) + (sizeof (struct allnet_mgmt_header)));

  trp->encrypted = 0;
  trp->intermediate_reply = intermediate;
  trp->num_entries = num_entries;
  memcpy (trp->trace_id, intrp->trace_id, MESSAGE_ID_SIZE);
  unsigned int i;
  /* if num_entries is 1, this loop never executes */
  /* if num_entries is 2, this loop executes once to copy
   * intrp->trace [intrp->num_entries - 1] to trp->trace [0] */
  for (i = 0; i + 1 < num_entries; i++)
    trp->trace [i] = intrp->trace [i + intrp->num_entries - (num_entries - 1)];
  struct allnet_mgmt_trace_entry * new_entry = trp->trace + (num_entries - 1);
  init_trace_entry (new_entry, inhp->hops, my_address, abits, 0);

  int ksize = readb16u (intrp->pubkey_size);
  if (ksize > 0) {
    printf ("to do: encryption of trace replies\n");
    char * key = ((char *) (intrp->trace)) +
                 (sizeof (struct allnet_mgmt_trace_entry) * intrp->num_entries);
    print_buffer (key, ksize, "traced key", 15, 1);
  }
  return size_needed;
}

/* assuming that message is a valid trace request, fills in "req" and "reqsize"
 * with the trace request to forward, and reply to send back
 * req is NULL and req_size is 0 if the request should not be forwarded
 * req is NULL and req_size is > 0 if the original request should be forwarded
 * reply is NULL and *reply_size is 0 if there is no reply */
void trace_forward (char * message, int msize,
                    unsigned char * my_address, unsigned int abits,
                    char ** req, int * req_size, /* out: forward */ 
                    char ** reply, int * reply_size) /* out: reply */
{
  *req = NULL;
  *req_size = 0;
  *reply = NULL;
  *reply_size = 0;
  /* ignore any packet other than valid trace requests with at least 1 entry */
  struct allnet_header * hp = (struct allnet_header *) message;
  if ((msize < ALLNET_HEADER_SIZE) ||              /* sanity check */
      (hp->message_type != ALLNET_TYPE_MGMT) ||
      (msize < ALLNET_TRACE_REQ_SIZE (hp->transport, 1, 0)))
    return;
  struct allnet_mgmt_header * mp =
    (struct allnet_mgmt_header *) (message + ALLNET_SIZE (hp->transport));
  if (mp->mgmt_type != ALLNET_MGMT_TRACE_REQ)
    return;
  struct allnet_mgmt_trace_req * trp =
    (struct allnet_mgmt_trace_req *)
      (message + ALLNET_MGMT_HEADER_SIZE (hp->transport));
  int num_entries = (trp->num_entries & 0xff);
  int k = readb16u (trp->pubkey_size);
  if ((num_entries < 1) ||
      (msize < ALLNET_TRACE_REQ_SIZE (hp->transport, num_entries, k)))
    return;
  if (is_in_trace_cache (trp->trace_id))
    return;
  unsigned int mbits = abits;
  if (mbits > hp->dst_nbits)
    mbits = hp->dst_nbits;   /* min of abits, and hp->dst_nbits */
  unsigned int nmatch = matches (my_address, abits,
                                 hp->destination, hp->dst_nbits);
  if ((nmatch >= mbits) || (trp->intermediate_replies)) {   /* reply */
    if (nmatch >= mbits)  /* exact match, send final response */
      *reply_size = make_trace_reply (hp, msize, trp, 0, trp->num_entries + 1,
                                      my_address, abits, reply);
    else if (hp->hops > 0) /* not my local sender, send back 2 trace entries */
      *reply_size = make_trace_reply (hp, msize, trp, 1, 2,
                                      my_address, abits, reply);
    else   /* my local sender, send a 1-entry response */
      *reply_size = make_trace_reply (hp, msize, trp, 1, 1,
                                      my_address, abits, reply);
  }
  if (trp->intermediate_replies) {   /* add my entry before forwarding */
    *req_size = add_my_entry (message, msize, hp, mp, trp,
                              my_address, abits, req);
  } else {                           /* forward unmodified */
    *req = NULL;
    *req_size = msize;
  }
}

static void send_trace (int sock, const unsigned char * address, int abits,
                        char * trace_id, unsigned char * my_address,
                        int my_abits, int max_hops, int record_intermediates,
                        struct allnet_log * alog)
{
  unsigned int total_size = ALLNET_TRACE_REQ_SIZE (0, 1, 0);
  unsigned int data_size = minz (total_size, ALLNET_SIZE (0));
  unsigned int allocated = 0;
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

  trp->intermediate_replies = record_intermediates;
  trp->num_entries = 1;
  writeb16u (trp->pubkey_size, 0);
  /* pubkey_size is 0, so no public key */
  memcpy (trp->trace_id, trace_id, MESSAGE_ID_SIZE);
  init_trace_entry (trp->trace, 0, my_address, my_abits, 1);

  snprintf (alog->b, alog->s, "sending trace of size %d\n", total_size);
  log_print (alog);
  if (! local_send (buffer, total_size, ALLNET_PRIORITY_TRACE))
    snprintf (alog->b, alog->s,
              "unable to send trace message of %d bytes\n", total_size);
  else
    snprintf (alog->b, alog->s, "sent %d-byte trace message\n", total_size);
  log_print (alog);
}

/* in case of overflow, returns ULLONG_MAX */
static unsigned long long int power10 (int n)
{
  if (n < 0)
    return 1;
  static unsigned long long int results [] =
    { 1ULL, 10ULL, 100ULL,
      1000ULL, 10000ULL, 100000ULL,
      1000000ULL, 10000000ULL, 100000000ULL,
      1000000000ULL, 10000000000ULL, 100000000000ULL,
      1000000000000ULL, 10000000000000ULL, 100000000000000ULL,
      1000000000000000ULL, 10000000000000000ULL, 100000000000000000ULL,
      1000000000000000000ULL, 10000000000000000000ULL };
  static int max_index = sizeof (results) / sizeof (unsigned long long int) - 1;
  if (n > max_index)
    return ULLONG_MAX;
  return results [n];
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
static void print_summary_file (int signal, int null_term, int fd_out,
                                struct allnet_queue * queue)
{
  if (sent_count > 0) {
    char * ps = "packets";
    if (sent_count == 1)
      ps = "packet";
    char buf [1000];
    int off = 0;
    if (received_count > 0) {
      int64_t mean_rtt = sum_rtt / ((int64_t) received_count);
      off += snprintf (buf + off, sizeof (buf) - off,
                       "sent %d %s, received %d, ",
                       sent_count, ps, received_count);
      off += snprintf (buf + off, sizeof (buf) - off,
                       "rtt min/mean/max is %" PRId64 ".%06d/",
                       min_rtt / 1000000, (int) (min_rtt % 1000000));
      off += snprintf (buf + off, sizeof (buf) - off,
                       "%" PRId64 ".%06d/", mean_rtt / 1000000,
                       (int) (mean_rtt % 1000000));
      off += snprintf (buf + off, sizeof (buf) - off,
                       "%" PRId64 ".%06ds\n", max_rtt / 1000000,
                       (int) (max_rtt % 1000000));
    } else {  /* received_count is 0 */
      off += snprintf (buf + off, sizeof (buf) - off,
                       "sent %d %s, received 0\n", sent_count, ps);
    }
    write_string_to (buf, null_term, fd_out, queue);
  } /* else nothing sent, print nothing */
  if ((signal == SIGHUP) || (signal == SIGINT) || (signal == SIGKILL)) {
    /* printf ("exiting on signal %d\n", signal); */
    exit (1);
  }
}

/* print to stdout the summary line for a trace */
void trace_print_summary (int signal)
{
  print_summary_file (signal, 0, STDOUT_FILENO, NULL);
}


static void record_rtt (unsigned long long uus)
{
  int64_t us = uus;
  if ((min_rtt < 0) || (us < min_rtt))
    min_rtt = us;
  if ((max_rtt < 0) || (max_rtt < us))
    max_rtt = us;
  sum_rtt += us;
  received_count++;
}

static int print_times (struct allnet_mgmt_trace_entry * entry,
                        struct timeval * start, struct timeval * now,
                        int save_to_intermediate, int print_rtt,
                        char * buf, int bsize)
{
  int off = 0;
  if ((start != NULL) && (now != NULL)) {
    unsigned long long int fraction = readb64u (entry->seconds_fraction);
    if (entry->precision <= 64)  /* binary precision */
      fraction = fraction / (((unsigned long long int) (-1LL)) / 1000000LL);
    else if (entry->precision <= 70)  /* decimal in low-order bits */
      fraction = fraction * (power10 (70 - entry->precision));
    else                              /* more than 6 digits of precision */
      fraction = fraction / (power10 (entry->precision - 70));
    if (fraction >= 1000000LL) {  /* should be converted to microseconds */
      printf ("error: fraction (%u) %lld gives %lld >= 1000000 microseconds\n",
              entry->precision, readb64u (entry->seconds_fraction),
              fraction);
      fraction = 0LL;
    }
  
    unsigned long long int delta = delta_us (now, start);
    int index = find_arrival (entry);
    if (index >= 0) {
      delta = delta_us (&(arrivals [index].time), start);
    } else if ((save_to_intermediate) && (num_arrivals + 1 < MAX_ARRIVALS)) {
      arrivals [num_arrivals].value = *entry;
      arrivals [num_arrivals].time = *now;
      num_arrivals++;
    }
    if (print_rtt) {
      off += snprintf (buf + off, bsize - off,
                       " %3lld.%06llds rtt", delta / 1000000LL,
                       delta % 1000000LL);
    } else {
      off += snprintf (buf + off, bsize - off, "                ");
    }
    struct timeval timestamp;
    timestamp.tv_sec = (time_t) (readb64u (entry->seconds));
    timestamp.tv_usec = (suseconds_t)fraction;
    unsigned long long int delta_ts = delta_us (&timestamp, start);
  /* printf ("%ld.%06ld - %ld.%06ld = %lld\n",
          timestamp.tv_sec, timestamp.tv_usec,
          start->tv_sec, start->tv_usec, delta_ts); */
    if (print_details) {
      unsigned long long int now_delta = delta_us (now, start);
      if ((delta_ts > 0) && (now_delta > 0) && (delta_ts < now_delta))
        off += snprintf (buf + off, bsize - off,
                         " %3lld.%06llds timestamp", delta_ts / 1000000LL,
                         delta_ts % 1000000LL);
    }
    off += snprintf (buf + off, bsize - off, "\n");
  }
  return off;
}

static int print_entry (struct allnet_mgmt_trace_entry * entry,
                        struct timeval * start, struct timeval * now,
                        int print_eol, int print_hop, int indent_hop,
                        char * buf, int bsize)
{
  int off = 0;
  if (entry->nbits > 0)
    off += snprintf (buf + off, bsize - off,
                     "%02x", entry->address [0] % 0xff);
  int i;
  for (i = 1; ((i < ADDRESS_SIZE) && (i < (entry->nbits + 7) / 8)); i++)
    off += snprintf (buf + off, bsize - off,
                     ".%02x", entry->address [i] % 0xff);
  off += snprintf (buf + off, bsize - off, "/%d  ", entry->nbits);

  if (print_hop) {
    int index = (entry->hops_seen) & 0xff;
    if (indent_hop)
      off += snprintf (buf + off, minz (bsize, off), "              ");
    off += snprintf (buf + off, minz (bsize, off), "%3d hop  ", index);
  }

  if (print_eol)
    off += snprintf (buf + off, bsize - off, "\n");
  return off;
}

static void print_trace_result (struct allnet_mgmt_trace_reply * trp,
                                struct timeval start, struct timeval finish,
                                int seq, int match_only, int no_intermediates,
                                int null_term,
                                int fd_out, struct allnet_queue * queue)
{
  unsigned long long us = delta_us (&finish, &start);
  /* put the unix times into allnet format */
  start.tv_sec -= ALLNET_Y2K_SECONDS_IN_UNIX;
  finish.tv_sec -= ALLNET_Y2K_SECONDS_IN_UNIX;
  if (trp->encrypted) {
    write_string_to ("to do: implement decrypting encrypted trace result\n",
                     null_term, fd_out, queue);
    return;
  }
  char buf [10000] = "";
  int off = 0;
  if (trp->intermediate_reply == 0) {      /* final reply */
    record_rtt (us);
    int first = 1;
    if (no_intermediates)
      first = trp->num_entries - 1;
    if (trp->num_entries > 1) {
      int indent = 0;
      if ((! no_intermediates) && (! match_only)) {
        off += snprintf (buf + off, sizeof (buf) - off,
                         "trace to matching destination:\n");
        indent = 1;
      }
      int i;
      for (i = first; i < trp->num_entries; i++) {
        int initial_off = off;
        if (print_details) {
          if (i + 1 == trp->num_entries)
            off += snprintf (buf + off, sizeof (buf) - off, "%4d: ", seq + 1);
          else
            off += snprintf (buf + off, sizeof (buf) - off, "      ");
          off += snprintf (buf + off, sizeof (buf) - off, "   ");
        }
        int indented_off = off;
        off += print_entry (trp->trace + i, &start, &finish, 0, 1, indent,
                            buf + off, sizeof (buf) - off);
        int print_rtt = ((! match_only) || (i + 1 == trp->num_entries));
        off += print_times (trp->trace + i, &start, &finish, 1, print_rtt,
                            buf + off, sizeof (buf) - off);
        if (indented_off == off) {
          off = initial_off;
          buf [off] = '\0';
        }
      }
    }
  } else if ((no_intermediates) || (match_only)) {  /* skip intermediates */
                                                    /* and not exact match */
  } else if (trp->num_entries == 2) {
    /* generally two trace entries for intermediate replies */
    off += snprintf (buf + off, sizeof (buf) - off, "forward: ");
    off += print_entry (trp->trace + 0, NULL, NULL, 0, 0, 0,
                        buf + off, sizeof (buf) - off);
    off += snprintf (buf + off, sizeof (buf) - off, "to  ");
    off += print_entry (trp->trace + 1, &start, &finish, 0, 1, 0,
                        buf + off, sizeof (buf) - off);
    off += print_times (trp->trace + 1, &start, &finish, 1, 1,
                        buf + off, sizeof (buf) - off);
  } else if (trp->num_entries == 1) {
    /* only one trace entry, so always print the first */
    off += snprintf (buf + off, sizeof (buf) - off, "local:   ");
    off += print_entry (trp->trace, &start, &finish, 0, 1, 1,
                        buf + off, sizeof (buf) - off);
    off += print_times (trp->trace, &start, &finish, 1, 1,
                        buf + off, sizeof (buf) - off);
  } else {
    off += snprintf (buf + off, sizeof (buf) - off,
                     "intermediate response with %d entries\n",
                     trp->num_entries);
  }
  write_string_to (buf, null_term, fd_out, queue);
}

static void handle_packet (char * message, int msize, char * seeking,
                           struct timeval start, int seq,
                           int match_only, int no_intermediates,
                           int null_term, int fd_out,
                           struct allnet_queue * queue,
                           char * rememberedh, int nh, int * positionh,
                           struct allnet_log * alog)
{
/* print_packet (message, msize, "handle_packet got", 1); */
  char * reason = NULL;
  if (! is_valid_message (message, msize, &reason)) {
    snprintf (alog->b, alog->s, "trace_util invalid packet: %s\n",
              reason);
    return;
  }
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
  if (memcmp (trace_id, seeking, MESSAGE_ID_SIZE - 1) != 0) {
#ifdef DEBUG_PRINT
    printf ("received trace_id does not match expected trace_id\n");
    print_buffer (seeking, MESSAGE_ID_SIZE, "expected trace_id", 100, 1);
    print_buffer ((char *) trace_id, MESSAGE_ID_SIZE,
                  "received trace_id", 100, 1);
#endif /* DEBUG_PRINT */
    return;
  }
#ifdef CHECK_FOR_DUPLICATES
  if (packet_received_before (message, msize, rememberedh, nh, positionh)) {
#ifdef DEBUG_PRINT
    print_packet (message, msize, "received duplicate trace packet", 1);
#endif /* DEBUG_PRINT */
    return;
  }  /* if not received before, it is now cached for future packets */
#endif /* CHECK_FOR_DUPLICATES */
  struct timeval now;
  gettimeofday (&now, NULL);
/*
  printf ("%ld.%06ld: ", now.tv_sec - ALLNET_Y2K_SECONDS_IN_UNIX, now.tv_usec);
  print_packet (message, msize, "trace reply packet received", 1);
*/
  snprintf (alog->b, alog->s, "matching trace response of size %d\n", msize);
  log_print (alog);
  print_trace_result (trp, start, now, seq, match_only,
                      no_intermediates, null_term, fd_out, queue);
}

static void wait_for_responses (int sock, char * trace_id, int sec,
                                int seq, int match_only, int no_intermediates,
                                int null_term,
                                int fd_out, struct allnet_queue * queue,
                                char * rememberedh, int nh, int * positionh,
                                struct timeval tv_start,
                                struct allnet_log * alog)
{
  num_arrivals = 0;   /* not received anything yet */
  unsigned long long int max_ms = ((sec <= 0) ? 1 : sec) * 1000;
  unsigned long long int time_spent = 0;
  unsigned long long int start = allnet_time_ms ();
  while ((sec < 0) || (time_spent < max_ms)) {
    unsigned int pri;
    char * message;
    unsigned long long int computed_ms = max_ms - time_spent;
    if (computed_ms > INT_MAX) computed_ms = INT_MAX;
    int ms = (int) computed_ms;
    int found = local_receive (ms, &message, &pri);
#if 0
    int pipe;
    int found = receive_pipe_message_any (p, ms, &message, &pipe, &pri);
    if (found < 0) {
#ifdef DEBUG_PRINT
      printf ("trace pipe closed, exiting\n");  
#endif /* DEBUG_PRINT */
      exit (1);
    }
#endif /* 0 */
    if (found > 0) {
      handle_packet (message, found, trace_id, tv_start, seq, match_only,
                     no_intermediates, null_term, fd_out, queue,
                     rememberedh, nh, positionh, alog);
      free (message);
    }
    local_send_keepalive ();
    time_spent = allnet_time_ms () - start;
  }
#ifdef DEBUG_PRINT
  printf ("timeout\n");
#endif /* DEBUG_PRINT */
}

void do_trace_loop (int sock,
                    int naddrs, unsigned char * addresses, int * abits,
                    int repeat, int sleep, int nhops, int match_only,
                    int no_intermediates, int wide, int null_term,
                    int fd_out, int reset_counts,
                    struct allnet_queue * queue, struct allnet_log * alog)
{
  if (reset_counts) {
    sent_count = 0;
    received_count = 0;
    min_rtt = -1;
    max_rtt = -1;
    sum_rtt = 0;
  }
#define NUM_REMEMBERED_HASHES	1000
  char remembered_hashes [NUM_REMEMBERED_HASHES * MESSAGE_ID_SIZE];
  int remembered_position = 0;
  
  print_details = wide;
#ifdef DEBUG_PRINT
  printf ("tracing %d bits to %d hops: ", abits, nhops);
  print_bitstring (address, 0, abits, 1);
#endif /* DEBUG_PRINT */
  char trace_id [MESSAGE_ID_SIZE];
  unsigned char my_addr [ADDRESS_SIZE];
  unsigned char extra_addr [ADDRESS_SIZE];
  routing_my_address (my_addr);
  int addr_high_5bits = my_addr [0] & 0xf8;   /* my 5 high bits */
  memset (my_addr, 0, sizeof (my_addr));
  memset (extra_addr, 0, sizeof (my_addr));
  int count;
  for (count = 0; (repeat == 0) || (count < repeat); count++) {
/* printf ("%d/%d\n", count, repeat); */
    random_bytes (trace_id, sizeof (trace_id));
    my_addr [0] = addr_high_5bits;
    struct timeval tv_start;
    gettimeofday (&tv_start, NULL);
    if (naddrs == 0) {
      send_trace (sock, extra_addr, 0, trace_id, my_addr, 5, nhops,
                  ! no_intermediates, alog);
      sent_count++;
    } else {
      int dest;
      for (dest = 0; dest < naddrs; dest++) {
        trace_id [MESSAGE_ID_SIZE - 1] = dest;
        send_trace (sock, addresses + (dest * ADDRESS_SIZE), abits [dest],
                    trace_id, my_addr, 5, nhops, ! no_intermediates, alog);
        sent_count++;
      }
    }
    wait_for_responses (sock, trace_id, sleep, count,
                        match_only, no_intermediates, null_term,
                        fd_out, queue, remembered_hashes,
                        NUM_REMEMBERED_HASHES, &remembered_position,
                        tv_start, alog);
  }
  print_summary_file (0, null_term, fd_out, queue);
  print_details = 1;
}

/* returns a (malloc'd) string representation of the trace result */
char * trace_string (const char * tmp_dir, int sleep, const char * dest,
                     int nhops, int no_intermediates, int match_only, int wide)
{
  unsigned char address [ADDRESS_SIZE];
  memset (address, 0, sizeof (address));  /* set any unused part to all zeros */
  int abits = 0;
  if ((dest != NULL) && (strlen (dest) > 0)) {
    abits = get_address (dest, address, sizeof (address));
    if (abits <= 0)
      return strcat_malloc ("illegal destination ", dest, "trace_string");
  }

  struct allnet_log * alog = init_log ("trace_string");
  int sock = connect_to_local ("trace_string", "trace_string", NULL, 1);
  if (sock < 0)
    return strcpy_malloc ("unable to connect to allnet", "trace_string");

#define TEMP_FILE	"tmp-file"
  char * fname = strcat3_malloc (tmp_dir, "/", TEMP_FILE, "trace_string");
  int fd = open (fname, O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR);
  if (fd < 0)
    return strcat_malloc ("unable to open file ", fname, "trace_string");

  int abits_array [1];
  abits_array [0] = abits;
  do_trace_loop (sock, 1, address, abits_array, 1, sleep, nhops, match_only,
                 no_intermediates, wide, 0, fd, 0, NULL, alog);
  close (fd);
  char * result;
  size_t success = read_file_malloc (fname, &result, 0);
  if (success <= 0)
    result = strcat_malloc ("unable to read file ", fname, "trace_string");
  unlink (fname);
  free (fname);
  return result;
}

void trace_pipe (int pipe, struct allnet_queue * queue,
                 int sleep, const char * dest, int nhops, int no_intermediates,
                 int match_only, int wide)
{
  unsigned char address [ADDRESS_SIZE];
  memset (address, 0, sizeof (address));  /* set any unused part to all zeros */
  int abits = 0;
  if ((dest != NULL) && (strlen (dest) > 0)) {
    abits = get_address (dest, address, sizeof (address));
    if (abits <= 0)
      printf ("illegal destination %s\n", dest);
  }

  struct allnet_log * alog = init_log ("trace_string");
  int sock = connect_to_local ("trace_pipe", "trace_pipe", NULL, 1);
  if (sock < 0) {
    printf ("unable to connect to allnet\n");
    return;
  }

  int abits_array [1];
  abits_array [0] = abits;
  do_trace_loop (sock, 1, address, abits_array, 1, sleep, nhops, match_only,
                 no_intermediates, wide, 1, pipe, 0, queue, alog);
}

/* just start a trace, returning 1 for success, 0 failure
 * trace_id must have MESSAGE_ID_SIZE or be NULL */
int start_trace (int sock, const unsigned char * addr, unsigned int abits,
                 unsigned int nhops, int record_intermediates,
                 char * trace_id)
{
  random_bytes (trace_id, MESSAGE_ID_SIZE);
  unsigned char my_addr [ADDRESS_SIZE];
  random_bytes ((char *) my_addr, sizeof (my_addr));
  struct allnet_log * alog = init_log ("start_trace");
  send_trace (sock, addr, abits, trace_id, my_addr, 5, nhops,
              record_intermediates, alog);
  return 1;
}


static int trace_seen_before (unsigned char * addr, int abits, int trace_count)
{
  if (abits > 64)
    return 1;    /* don't print this one */
  if (trace_count == 0)  /* never started a trace */
    return 1;    /* don't print this one */
#define MAX_SEEN        4096
  static unsigned char seen_addrs [MAX_SEEN] [ADDRESS_SIZE];
  static int seen_bits [MAX_SEEN];
  static int seen_count = 0;  /* how many entries are used in seen_adrs/bits */
  static int trace_count_seen = 0;  /* value of trace_count on the last call */
  if (trace_count_seen != trace_count) {  /* new trace, re-initialize */
    memset (seen_addrs, 0, sizeof (seen_addrs));
    memset (seen_bits, 0, sizeof (seen_bits));
    trace_count_seen = trace_count;
    memcpy (seen_addrs [0], addr, ADDRESS_SIZE);  /* record this trace */
    seen_bits [0] = abits;
    seen_count = 1;
    return 0;                                     /* never seen before */
  }
  int i;
  for (i = 0; i < seen_count; i++) {
    if ((abits == seen_bits [i]) &&
        (matches (addr, abits, seen_addrs [i], seen_bits [i]) >= abits)) {
      return 1;  /* seen before */
    }
  }  /* not found, add it (if there is room) */
     /* if we run out of room, we will print duplicates */
  if (seen_count < MAX_SEEN) {
    memcpy (seen_addrs [seen_count], addr, ADDRESS_SIZE);
    seen_bits [seen_count] = abits;
    seen_count++;
  }
#undef MAX_SEEN
  return 0;
}

/* returns a pointer to a static buffer */
static char * print_addr (unsigned char * addr, int abits)
{
  if (abits > 64)
    return "";
  static char result [100];  /* 27 should be enough */
  if (abits == 0) {          /* special case */
    snprintf (result, sizeof (result), "00/0");
    return result;
  }
  char * ptr = result;
  size_t remaining = sizeof (result);
  int bits_left = abits;
  while ((bits_left > 0) && (remaining > 0)) {
    int value = (*addr) & 0xff;
    if (bits_left < 8) {
      value = value >> (8 - bits_left);  /* clear low-order bits */
      value = value << (8 - bits_left);  /* and restore the number */
    }
    size_t off = snprintf (ptr, remaining, "%02x%s", value,
                           ((bits_left > 8) ? "." : ""));
    bits_left = bits_left - 8;
    addr++;
    ptr += off;
    if (remaining >= off)
      remaining -= off;
    else
      remaining = 0;
  }
  snprintf (ptr, remaining, "/%d", abits);
  return result;
}

/* convert to a string (of size slen) the result of a trace,
 * eliminating duplicates of past received traces */
void trace_to_string (char * string, size_t slen,
                      struct allnet_mgmt_trace_reply * trace,
                      int trace_count, unsigned long long int trace_start_time)
{
  snprintf (string, slen, "%s", "");   /* empty string */
  if (trace->num_entries <= 0)
    return;
  if (trace->intermediate_reply == 0) {   /* final reply */
    unsigned int index = trace->num_entries - 1;
    struct allnet_mgmt_trace_entry * entry = trace->trace + index;
    unsigned long long int now = allnet_time_ms ();
    unsigned long long int delta = now - trace_start_time;
    unsigned long long int sec = delta / 1000;
    unsigned long long int msec = delta % 1000;
    if (! trace_seen_before (entry->address, entry->nbits, trace_count))
      snprintf (string, slen, "%3d: %s  %d hops %3lld.%03llds rtt\n",
                trace_count, print_addr (entry->address, entry->nbits),
                entry->hops_seen, sec, msec);
  }
}

