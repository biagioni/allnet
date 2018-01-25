/* traced.c: standalone application to handle AllNet traces 
 *           and also acknowledge broadcast packets that need an ack */
/* the daemon may take as argument:
   - an address (in hex, with or without separating :,. )
   - optionally, followed by / and the number of bits of the address, in 0..64
   the argument and bits default to 0/0 if not specified
 * this specified address is my address, used to fill in the response.
 * optionally a '-m' option, to specify tracing only when we match the address.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include "lib/packet.h"
#include "lib/mgmt.h"
#include "lib/util.h"
#include "lib/dcache.h"
#include "lib/pipemsg.h"
#include "lib/priority.h"
#include "lib/configfiles.h"
#include "lib/app_util.h"
#include "lib/allnet_log.h"
#include "lib/trace_util.h"

static struct allnet_log * alog = NULL;

static int do_respond_to_trace ()
{
  time_t mod = config_file_mod_time ("adht", "do_not_respond_to_trace");
  if (mod != 0)  /* file exists */
    return 0;
  return 1;
}

static void init_trace_entry (struct allnet_mgmt_trace_entry * new_entry,
                              int hops, struct timeval * now,
                              unsigned char * my_address, int abits, int local)
{
  memset (new_entry, 0, sizeof (struct allnet_mgmt_trace_entry));
  /* assume accuracy is 1ms, or 3 decimal digits,
   * unless the hop count is 0, in which case accuracy is 1us or 6 digits */
  new_entry->precision = 64 + 3 + (local ? 3 : 0);
  writeb64u (new_entry->seconds, now->tv_sec - ALLNET_Y2K_SECONDS_IN_UNIX);
  writeb64u (new_entry->seconds_fraction,
             now->tv_usec / (local ? 1 : 1000));
  if (now->tv_sec <= ALLNET_Y2K_SECONDS_IN_UNIX) { /* clock is wrong */
    writeb64u (new_entry->seconds, 0);
    writeb64u (new_entry->seconds_fraction, 0);
    new_entry->precision = 0;
  }
  new_entry->hops_seen = hops;
  new_entry->nbits = abits;
  memcpy (new_entry->address, my_address, (abits + 7) / 8);
}

static unsigned int add_my_entry (char * in, unsigned int insize,
                                  struct allnet_header * inhp,
                                  struct allnet_mgmt_header * inmp,
                                  struct allnet_mgmt_trace_req * intrp,
                                  struct timeval * now,
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
/*
  packet_to_string (in, insize, "add_my_entry original packet", 1,
                    alog->b, alog->s);
  log_print (alog);
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
  init_trace_entry (new_entry, inhp->hops, now, my_address, abits,
                    inhp->hops == 0);
  if (k > 0) {
    char * inkey = ((char *) (intrp->trace)) +
                   (sizeof (struct allnet_mgmt_trace_entry) * (n - 1));
    char * key = ((char *) (trp->trace)) +
                 (sizeof (struct allnet_mgmt_trace_entry) * n);
    memcpy (key, inkey, k);
  }
#ifdef LOG_PACKETS
  packet_to_string (*result, needed, "add_my_entry packet copy", 1,
                    alog->b, alog->s);
  log_print (alog);
#endif /* LOG_PACKETS */
  return needed;
}

/* returns the size of the message to send, or 0 in case of failure */
/* no encryption yet */
static int make_trace_reply (struct allnet_header * inhp, unsigned int insize,
                             struct timeval * now,
                             unsigned char * my_address, unsigned int abits,
                             struct allnet_mgmt_trace_req * intrp,
                             int intermediate, unsigned int num_entries,
                             char ** result)
{
  *result = NULL;
/*
  snprintf (alog->b, alog->s, "making trace reply with %d entries, int %d\n",
            num_entries, intermediate);
  log_print (alog);
 */
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
  if (inhp->hops == 0) /* local, no need to send reply outwards */
    hp->max_hops = 0;
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
  init_trace_entry (new_entry, inhp->hops, now, my_address, abits,
                    inhp->hops == 0);

  int ksize = readb16u (intrp->pubkey_size);
  if (ksize > 0) {
    printf ("to do: encryption of trace replies\n");
    char * key = ((char *) (intrp->trace)) +
                 (sizeof (struct allnet_mgmt_trace_entry) * intrp->num_entries);
    print_buffer (key, ksize, "traced key", 15, 1);
  }
#ifdef LOG_PACKETS
  packet_to_string (*result, total, "my reply: ", 1, alog->b, alog->s);
  log_print (alog);
#endif /* LOG_PACKETS */
  return size_needed;
}

#ifdef DEBUG_PRINT_ID
static void debug_prt_trace_id (void * state, void * n)
{
  print_buffer (n, MESSAGE_ID_SIZE, NULL, MESSAGE_ID_SIZE, 1);
  int offset = * ((int *) state);
  if (offset > 20)
    offset += snprintf (alog->b + offset, alog->s - offset, ", ");
  offset += buffer_to_string (n, MESSAGE_ID_SIZE, NULL, MESSAGE_ID_SIZE, 0,
                              alog->b + offset, alog->s - offset);
  * ((int *) state) = offset;
}
#endif /* DEBUG_PRINT_ID */

static void acknowledge_bcast (int sock, char * message, unsigned int msize)
{
  /* ignore any packet other than unencrypted packets requesting an ack */
  struct allnet_header * hp = (struct allnet_header *) message;
  if ((hp->message_type != ALLNET_TYPE_CLEAR) ||
      ((hp->transport & ALLNET_TRANSPORT_ACK_REQ) == 0))  /* ignore */
    return;
  unsigned int hsize = ALLNET_SIZE (hp->transport);
  if (msize < hsize + MESSAGE_ID_SIZE)
    return;
  unsigned int asize;
  unsigned char * received = (unsigned char *) (message + hsize);
  struct allnet_header * ack = create_ack (hp, received, NULL, 0, &asize);
  if ((asize == 0) || (ack == NULL))
    return;
  if (! send_pipe_message_free (sock, (char *) ack, asize,
                                ALLNET_PRIORITY_DEFAULT_LOW, alog))
    snprintf (alog->b, alog->s, "unable to send broadcast ack\n");
  else
    snprintf (alog->b, alog->s, "sent broadcast ack\n");
  log_print (alog);
}

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
#define TRACE_CACHE_SIZE	(4 * 1024)   /* 4K traces, 64KByte */

#ifdef LIMIT_RATE_OF_TRACES  /* not sure this code works */
#define TRACE_INTERVAL_SECONDS	5	     /* 5-second intervals */
#define TRACE_INTERVAL_MAX	20	     /* up to 20 traces every 5s */
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

static void respond_to_trace (int sock, char * message, unsigned int msize,
                              int priority,
                              unsigned char * my_address, unsigned int abits,
                              int match_only, int forward_only)
{
  /* ignore any packet other than valid trace requests with at least 1 entry */
  struct allnet_header * hp = (struct allnet_header *) message;
  if ((msize < ALLNET_HEADER_SIZE) ||              /* sanity check */
      (hp->message_type != ALLNET_TYPE_MGMT) ||
      (msize < ALLNET_TRACE_REQ_SIZE (hp->transport, 1, 0)))
    return;
/* snprintf (alog->b, alog->s, "survived msize %d/%zd\n", msize,
            ALLNET_TRACE_REQ_SIZE (hp->transport, 1, 0));
  log_print (alog); */
  struct allnet_mgmt_header * mp =
    (struct allnet_mgmt_header *) (message + ALLNET_SIZE (hp->transport));
  if (mp->mgmt_type != ALLNET_MGMT_TRACE_REQ)
    return;
  struct allnet_mgmt_trace_req * trp =
    (struct allnet_mgmt_trace_req *)
      (message + ALLNET_MGMT_HEADER_SIZE (hp->transport));
#ifdef LOG_PACKETS
  int off = snprintf (alog->b, alog->s,
                      "respond_to_trace got %d byte trace request, %d %d: ",
                      msize, match_only, forward_only);
  packet_to_string (message, msize, NULL, 1, alog->b + off, alog->s - off);
  log_print (alog);
#endif /* LOG_PACKETS */
  int num_entries = (trp->num_entries & 0xff);
  int k = readb16u (trp->pubkey_size);
/* snprintf (alog->b, alog->s, "packet has %d entries %d key, size %d/%zd\n",
             num_entries, k, msize,
             ALLNET_TRACE_REQ_SIZE (hp->transport, num_entries, k));
  log_print (alog); */
  if ((num_entries < 1) ||
      (msize < ALLNET_TRACE_REQ_SIZE (hp->transport, num_entries, k)))
    return;

  if (is_in_trace_cache (trp->trace_id))
    return;

  struct timeval timestamp;
  gettimeofday (&timestamp, NULL);
  /* do two things: forward the trace, and possibly respond to the trace. */

  unsigned int mbits = abits;
  if (mbits > hp->dst_nbits)
    mbits = hp->dst_nbits;   /* min of abits, and hp->dst_nbits */
  unsigned int nmatch = matches (my_address, abits,
                                 hp->destination, hp->dst_nbits);
#ifdef DEBUG_PRINT
  printf ("matches (");
  print_buffer ((char *)my_address, abits, NULL, (abits + 7) / 8, 0);
  printf (", ");
  print_buffer ((char *)hp->destination, hp->dst_nbits, NULL,
                (hp->dst_nbits + 7) / 8, 0);
  printf (") => %d (%d needed)\n", nmatch, mbits);
#endif /* DEBUG_PRINT */
  /* when forwarding, use a low priority > epsilon, to tell ad it is from us */
  unsigned int fwd_priority = ALLNET_PRIORITY_TRACE_FWD;
  if ((! do_respond_to_trace ()) || (forward_only) ||
      ((match_only) && (nmatch < mbits))) {
    /* forward without adding my entry */
    if (! send_pipe_message (sock, message, msize, fwd_priority, alog))
      printf ("unable to forward trace response\n");
    snprintf (alog->b, alog->s, "forwarded %d bytes\n", msize);
    log_print (alog);
    return;  /* we are done, no need to reply */
  } /* else: add my entry before forwarding */
  char * new_msg;
  int n = add_my_entry (message, msize, hp, mp, trp, &timestamp,
                        my_address, abits, &new_msg);
#ifdef LOG_PACKETS
  if (n > 0) {
    int off = snprintf (alog->b, alog->s,
                        "forwarding trace req %d <- %d ", n, msize);
    packet_to_string (new_msg, n, NULL, 1, alog->b + off, alog->s - off);
    log_print (alog);
  }
#endif /* LOG_PACKETS */

  char * response = NULL;
  int rsize = 0;
  if ((trp->intermediate_replies) || (nmatch >= mbits)) { /* generate a reply */
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
  unsigned int mlens [2];
  unsigned int priorities [2];
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
#ifdef LOG_PACKETS
  off = snprintf (alog->b, alog->s, "respond_to_trace sending %d messages\n",
                  count);
  packet_to_string (messages [first], mlens [first], "first message", 1,
                    alog->b + off, alog->s - off); 
  off = strlen (alog->b);
  if (count > 1)
    packet_to_string (messages [first + 1], mlens [first + 1], "second message",
                      1, alog->b + off, alog->s - off); 
  log_print (alog);
#endif /* LOG_PACKETS */
  if (! send_pipe_multiple_free (sock, count, messages + first,
                                 mlens + first, priorities + first, alog))
    snprintf (alog->b, alog->s, "unable to send trace request+reply\n");
  else
    snprintf (alog->b, alog->s, "sent trace request+reply of sizes %d+%d\n",
              n, rsize);
#ifdef LOG_PACKETS
  log_print (alog);
#endif /* LOG_PACKETS */
}

static void main_loop (int wsock, pd p,
                       unsigned char * my_address, unsigned int nbits,
                       int match_only, int forward_only)
{
  while (1) {
    char * message;
    int pipe;
    unsigned int pri;
    int timeout = PIPE_MESSAGE_WAIT_FOREVER;
    int found = receive_pipe_message_any (p, timeout, &message, &pipe, &pri);
    if (found < 0) {
      snprintf (alog->b, alog->s, "traced pipe closed, exiting\n");
      log_print (alog);
      /* printf ("traced pipe closed, exiting\n"); */
      exit (1);
    }
#ifdef DEBUG_PRINT
    print_packet (message, found, "traced received", 1);
#endif /* DEBUG_PRINT */
    if ((found > 0) && (is_valid_message (message, found, NULL))) {
      acknowledge_bcast (wsock, message, (unsigned int) found);
      respond_to_trace (wsock, message, (unsigned int) found,
                        pri + 1, my_address, nbits, match_only, forward_only);
    }
    free (message);
  }
}

/* called in iOS, which does not start separate processes */
void traced_thread (char * pname, int rpipe, int wpipe)
{
  if (alog == NULL)
    alog = init_log ("traced_thread");
printf ("traced_thread (%s), sockets %d %d\n", pname, rpipe, wpipe);
  unsigned char address [ADDRESS_SIZE];
  memset (address, 0, sizeof (address));  /* set any unused part to all zeros */
  unsigned int abits = 16;
  get_my_addr (address, sizeof (address), alog);
  if (alog == NULL)
    alog = init_log ("traced_thread");
  pd p = init_pipe_descriptor (alog);
    printf ("traced_thread adding pipe %d, wpipe %d\n", rpipe, wpipe);
  add_pipe (p, rpipe, "traced_thread");
  printf ("trace thread for %d bits: ", abits);
  print_bitstring (address, 0, abits, 1);
  main_loop (wpipe, p, address, abits, 0, 0);
  printf ("trace error: main thread returned\n");
}

/* called in systems that support fork */
void traced_main (char * pname)
{
  unsigned char address [ADDRESS_SIZE];
  memset (address, 0, sizeof (address));  /* set any unused part to all zeros */
  unsigned int abits = 16;
  get_my_addr (address, sizeof (address), alog);

  if (alog == NULL)
    alog = init_log ("traced_main");
  pd p = init_pipe_descriptor (alog);
  int sock = connect_to_local (pname, pname, NULL, p);
  if (sock < 0)
    return;

#ifdef DEBUG_PRINT
  printf ("trace daemon for %d bits: ", abits);
  print_bitstring (address, 0, abits, 1);
#endif /* DEBUG_PRINT */
  main_loop (sock, p, address, abits, 0, 0);
  printf ("trace error: main loop returned\n");
}

