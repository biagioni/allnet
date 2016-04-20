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
#include "trace_util.h"

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

static int write_string_to_fd (char * string, int fd)
{
  return (int) write (fd, string, strlen (string));
}

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

static void send_trace (int sock, unsigned char * address, int abits,
                        char * trace_id, unsigned char * my_address,
                        int my_abits, int max_hops,
                        struct allnet_log * alog)
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
  snprintf (alog->b, alog->s, "sending trace of size %d\n", total_size);
  log_print (alog); */
  /* sending with priority epsilon indicates to ad that we only want to
   * send to the trace server, which then forwards to everyone else */
  if (! send_pipe_message_free (sock, buffer, total_size,
                                ALLNET_PRIORITY_TRACE, alog))
    snprintf (alog->b, alog->s,
              "unable to send trace message of %d bytes\n", total_size);
  else
    snprintf (alog->b, alog->s, "sent %d-byte trace message\n", total_size);
  log_print (alog);
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
static void print_summary_file (int signal, int fd_out)
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
                       "rtt min/mean/max is %" PRId64 ".%03d/", min_rtt / 1000,
                       (int) (min_rtt % 1000));
      off += snprintf (buf + off, sizeof (buf) - off,
                       "%" PRId64 ".%03d/", mean_rtt / 1000,
                       (int) (mean_rtt % 1000));
      off += snprintf (buf + off, sizeof (buf) - off,
                       "%" PRId64 ".%03d\n", max_rtt / 1000,
                       (int) (max_rtt % 1000));
    } else {  /* received_count is 0 */
      off += snprintf (buf + off, sizeof (buf) - off, "sent %d %s, received 0\n", sent_count, ps);
    }
    write_string_to_fd (buf, fd_out);
  } /* else nothing sent, print nothing */
  if ((signal == SIGHUP) || (signal == SIGINT) || (signal == SIGKILL)) {
    /* printf ("exiting on signal %d\n", signal); */
    exit (1);
  }
}

/* print to stdout the summary line for a trace */
void trace_print_summary (int signal)
{
  print_summary_file (signal, STDOUT_FILENO);
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
                         int save_to_intermediate, int fd_out)
{
  char buf [1000] = "";
  int off = 0;
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
        off += snprintf (buf + off, sizeof (buf) - off,
                         " %3lld.%06llds timestamp, ", delta / 1000000LL,
                         delta % 1000000LL);
      else
        off += snprintf (buf + off, sizeof (buf) - off,
                         "                        ");
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
    off += snprintf (buf + off, sizeof (buf) - off,
                     " %3lld.%06llds rtt,", delta / 1000000LL,
                     delta % 1000000LL);
  }
  write_string_to_fd (buf, fd_out);
}

static void print_entry (struct allnet_mgmt_trace_entry * entry,
                         struct timeval * start, struct timeval * now,
                         int print_eol, int fd_out)
{
  char buf [1000];
  int off = 0;

  int index = (entry->hops_seen) & 0xff;
  off = snprintf (buf, sizeof (buf), "%3d ", index);

  if (entry->nbits > 0)
    off += snprintf (buf + off, sizeof (buf) - off,
                     "%02x", entry->address [0] % 0xff);
  int i;
  for (i = 1; ((i < ADDRESS_SIZE) && (i < (entry->nbits + 7) / 8)); i++)
    off += snprintf (buf + off, sizeof (buf) - off,
                     ".%02x", entry->address [i] % 0xff);
  off += snprintf (buf + off, sizeof (buf) - off, "/%d", entry->nbits);

  if (print_eol)
    off += snprintf (buf + off, sizeof (buf) - off, "\n");
  write_string_to_fd (buf, fd_out);
}

static void print_trace_result (struct allnet_mgmt_trace_reply * trp,
                                struct timeval start, struct timeval finish,
                                int seq, int match_only, int no_intermediates,
                                int fd_out)
{
  unsigned long long us = delta_us (&finish, &start);
  /* put the unix times into allnet format */
  start.tv_sec -= ALLNET_Y2K_SECONDS_IN_UNIX;
  finish.tv_sec -= ALLNET_Y2K_SECONDS_IN_UNIX;
  if (trp->encrypted) {
    write_string_to_fd ("to do: implement decrypting encrypted trace result\n",
                        fd_out);
    return;
  }
  if (trp->intermediate_reply == 0) {      /* final reply */
    record_rtt (us);
    int first = 1;
    if (no_intermediates)
      first = trp->num_entries - 1;
    if (trp->num_entries > 1) {
      if ((! no_intermediates) && (! match_only))
        write_string_to_fd ("trace to matching destination:\n", fd_out);
      int i;
      for (i = first; i < trp->num_entries; i++) {
        if (print_details) {
          char buf [1000];
          int off = 0;
          if (i + 1 == trp->num_entries)
            off += snprintf (buf, sizeof (buf), "%4d: ", seq + 1);
          else
            off += snprintf (buf, sizeof (buf), "      ");
          snprintf (buf + off, sizeof (buf) - off, "         ");
          write_string_to_fd (buf, fd_out);
        }
        print_times (trp->trace + i, &start, &finish, 1, fd_out);
        print_entry (trp->trace + i, &start, &finish, 1, fd_out);
      }
    }
  } else if ((no_intermediates) || (match_only)) {  /* skip intermediates */
                                                    /* and not exact match */
  } else if (trp->num_entries == 2) {
    /* generally two trace entries for intermediate replies */
    write_string_to_fd ("forward: ", fd_out);
    print_times (trp->trace + 1, &start, &finish, 1, fd_out);
    print_entry (trp->trace + 0, NULL, NULL, 0, fd_out);
    write_string_to_fd ("  to", fd_out);
    print_entry (trp->trace + 1, &start, &finish, 1, fd_out);
  } else if (trp->num_entries == 1) {
    /* generally only one trace entry, so always print the first */
    write_string_to_fd ("local:   ", fd_out);
    print_times (trp->trace, &start, &finish, 1, fd_out);
    print_entry (trp->trace, &start, &finish, 1, fd_out);
  } else {
    char buf [1000];
    snprintf (buf, sizeof (buf),
              "intermediate response with %d entries\n", trp->num_entries);
    write_string_to_fd (buf, fd_out);
  }
}

static void handle_packet (char * message, int msize, char * seeking,
                           struct timeval start, int seq,
                           int match_only, int no_intermediates, int fd_out,
                           struct allnet_log * alog)
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
  snprintf (alog->b, alog->s, "matching trace response of size %d\n", msize);
  log_print (alog);
  print_trace_result (trp, start, now, seq, match_only,
                      no_intermediates, fd_out);
}

static void wait_for_responses (int sock, pd p, char * trace_id, int sec,
                                int seq, int match_only, int no_intermediates,
                                int fd_out, struct allnet_log * alog)
{
  num_arrivals = 0;   /* not received anything yet */
  unsigned long long int max_ms = ((sec <= 0) ? 1 : sec) * 1000;
  unsigned long long int time_spent = 0;
  unsigned long long int start = allnet_time_ms ();
  struct timeval tv_start;
  gettimeofday (&tv_start, NULL);
  while ((sec < 0) || (time_spent < max_ms)) {
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
                   match_only, no_intermediates, fd_out, alog);
    if (found > 0)
      free (message);
    time_spent = allnet_time_ms () - start;
  }
#ifdef DEBUG_PRINT
  printf ("timeout\n");
#endif /* DEBUG_PRINT */
}

void do_trace_loop (int sock, pd p, unsigned char * address, int abits,
                    int repeat, int sleep, int nhops, int match_only,
                    int no_intermediates, int wide, int fd_out,
                    struct allnet_log * alog)
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
    send_trace (sock, address, abits, trace_id, my_addr, 5, nhops, alog);
    sent_count++;
    wait_for_responses (sock, p, trace_id, sleep, count,
                        match_only, no_intermediates, fd_out, alog);
  }
  print_summary_file (0, fd_out);
  print_details = 1;
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

  struct allnet_log * alog = init_log ("trace_string");
  pd p = init_pipe_descriptor (alog);
  int sock = connect_to_local ("trace_string", "trace_string", p);
  if (sock < 0)
    return strcpy_malloc ("unable to connect to allnet", "trace_string");

#define TEMP_FILE	"tmp-file"
  char * fname = strcat3_malloc (tmp_dir, "/", TEMP_FILE, "trace_string");
  int fd = open (fname, O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR);
  if (fd < 0)
    return strcat_malloc ("unable to open file ", fname, "trace_string");

  do_trace_loop (sock, p, address, abits, 1, sleep, nhops, match_only,
                 no_intermediates, wide, fd, alog);
  close (fd);
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
  unsigned char address [ADDRESS_SIZE];
  bzero (address, sizeof (address));  /* set any unused part to all zeros */
  int abits = 0;
  if ((dest != NULL) && (strlen (dest) > 0)) {
    abits = get_address (dest, address, sizeof (address));
    if (abits <= 0)
      printf ("illegal destination %s\n", dest);
  }

  struct allnet_log * alog = init_log ("trace_string");
  pd p = init_pipe_descriptor (alog);
  int sock = connect_to_local ("trace_pipe", "trace_pipe", p);
  if (sock < 0) {
    printf ("unable to connect to allnet\n");
    return;
  }

  do_trace_loop (sock, p, address, abits, 1, sleep, nhops, match_only,
                 no_intermediates, wide, pipe, alog);
}

