/* ad.c: main allnet daemon to forward allnet messages */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "lib/packet.h"
#include "lib/mgmt.h"
#include "social.h"
#include "track.h"
#include "record.h"
#include "lib/pipemsg.h"
#include "lib/priority.h"
#include "lib/log.h"
#include "lib/util.h"

#define PROCESS_PACKET_DROP	1
#define PROCESS_PACKET_LOCAL	2  /* only forward to alocal */
#define PROCESS_PACKET_OUT	3  /* only forward to aip and the abc's */
#define PROCESS_PACKET_ALL	4  /* forward to alocal, aip, and the abc's */

/* compute a forwarding priority for non-local packets */
static int packet_priority (char * packet, struct allnet_header * hp, int size,
                            struct social_info * soc)
{
  int sig_size = 0;
  if (hp->sig_algo != ALLNET_SIGTYPE_NONE)
    sig_size = ((packet [size - 2] & 0xff) << 8) + (packet [size - 1] & 0xff);
  int valid = 0;
  int social_distance = UNKNOWN_SOCIAL_TIER;
  int rate_fraction = largest_rate ();
  int hsize = ALLNET_SIZE (hp->transport);
snprintf (log_buf, LOG_SIZE, "packet_priority (%d, %d + %d + 2 = %d <? %d)\n",
hp->sig_algo, hsize, sig_size, (hsize + sig_size + 2), size); log_print ();
  if ((sig_size > 0) && (hsize + sig_size + 2 < size)) {
    char * verify = packet + hsize; 
    int vsize = size - (hsize + sig_size + 2);
    char * sig = packet + hsize + vsize;
    social_distance =
       social_connection (soc, verify, vsize, hp->source, hp->src_nbits,
                          hp->sig_algo, sig, sig_size, &valid);
  }
  if (valid)
    rate_fraction = track_rate (hp->source, hp->src_nbits, size);
  else
    social_distance = UNKNOWN_SOCIAL_TIER;
  int cacheable = ((hp->transport & ALLNET_TRANSPORT_DO_NOT_CACHE) == 0);
  return compute_priority (size, hp->src_nbits, hp->dst_nbits,
                           hp->hops, hp->max_hops, social_distance,
                           rate_fraction, cacheable);
}

static int process_mgmt (char * message, int msize, int is_local,
                         int * priority, struct social_info * soc)
{
  /* if sent from local, use the priority they gave us */
  /* else set priority to the lowest possible.  Generally the right thing */
  /* to do unless we know better (and doesn't affect local delivery). */
  if (! is_local)
    *priority = ALLNET_PRIORITY_DEFAULT_LOW;

  struct allnet_header * hp = (struct allnet_header *) message;
  int hs = ALLNET_AFTER_HEADER (hp->transport, msize);
  if (msize < hs + sizeof (struct allnet_mgmt_header))
    return PROCESS_PACKET_DROP;
  struct allnet_mgmt_header * ahm = 
    (struct allnet_mgmt_header *) (message + hs);
  switch (ahm->mgmt_type) {
  case ALLNET_MGMT_BEACON:
  case ALLNET_MGMT_BEACON_REPLY:
  case ALLNET_MGMT_BEACON_GRANT:
    return PROCESS_PACKET_DROP;   /* do not forward beacons */
  case ALLNET_MGMT_PEER_REQUEST:
  case ALLNET_MGMT_PEERS:
  case ALLNET_MGMT_DHT:
  case ALLNET_MGMT_ID_REQUEST:
    if (is_local) {               /* from DHT daemon (idrq: acache or client) */
      return PROCESS_PACKET_OUT;  /* forward to the internet */
    } else {
      return PROCESS_PACKET_LOCAL;/* only forward to the DHT */
    }
  case ALLNET_MGMT_TRACE_REQ:
    if ((is_local) && (*priority == ALLNET_PRIORITY_TRACE_FWD)) {
      /* from trace daemon, send out */
      return PROCESS_PACKET_OUT;  /* forward as a normal data packet */
    } else if (is_local) {
      return PROCESS_PACKET_DROP; /* from trace app, ignore */
    } else {                      /* from outside */
      return PROCESS_PACKET_LOCAL;/* only forward to the trace server/app */
    }
  case ALLNET_MGMT_TRACE_REPLY:
    if (! is_local) {
      *priority = ALLNET_PRIORITY_TRACE;  /* give it very low priority */
      return PROCESS_PACKET_ALL;          /* forward locally and out */
    } else {
      return PROCESS_PACKET_OUT;          /* local packet, forward out */
    }
  default:
    snprintf (log_buf, LOG_SIZE, "unknown management message type %d\n",
              ahm->mgmt_type);
    log_print ();
    *priority = ALLNET_PRIORITY_EPSILON;
    return PROCESS_PACKET_ALL;   /* forward unknown management packets */
  }
}

/* return 0 to drop the packet (do nothing), 1 to process as a request packet,
 * 2 to forward only to local destinations, and 3 to forward everywhere */
/* if returning 3, fills in priority */
static int process_packet (char * packet, int size, int is_local,
                           struct social_info * soc, int * priority)
{
  if (! is_valid_message (packet, size))
    return PROCESS_PACKET_DROP;

/* skip the hop count in the hash, since it changes at each hop */
#define HEADER_SKIP	3
  /* have we received this packet in the last minute?  if so, drop it */
  int time = record_packet_time (packet + HEADER_SKIP, size - HEADER_SKIP, 0);
#undef HEADER_SKIP
  if ((time > 0) && (time < 60)) {
    snprintf (log_buf, LOG_SIZE, 
              "packet received in the last %d seconds, dropping\n", time);
    log_print ();
    return PROCESS_PACKET_DROP;     /* duplicate, ignore */
  }

  /* should be valid */
  struct allnet_header * ah = (struct allnet_header *) packet;

  /* compute a forwarding priority for non-local packets */
  if (! is_local) {
    *priority = packet_priority (packet, ah, size, soc);
    /* before forwarding, increment the number of hops seen */
    if (ah->hops < 255)   /* do not increment 255 to 0 */
      ah->hops++;
  }
  snprintf (log_buf, LOG_SIZE, "forwarding packet with %d hops\n", ah->hops);
  log_print ();

  if (ah->message_type == ALLNET_TYPE_MGMT) {     /* AllNet management */
    int r = process_mgmt (packet, size, is_local, priority, soc);
    return r;
  }

  /* forward out any local packet, unless the hop count has been reached */
  /* this allows packets with hops == max_hops to be forwarded locally */
  if (is_local) {
    if (ah->hops < ah->max_hops)
      return PROCESS_PACKET_OUT;
    else
      return PROCESS_PACKET_DROP;  /* already forwarded by alocal */
  }

  if (ah->hops >= ah->max_hops)   /* reached hop count */
  /* no matter what it is, only forward locally, i.e. to alocal */
    return PROCESS_PACKET_LOCAL;

  /* send each of the packets, with its priority, to each of the pipes */
  return PROCESS_PACKET_ALL;
}

static void send_all (char * packet, int psize, int priority,
                      int * write_pipes, int nwrite, char * desc)
{
  int n = snprintf (log_buf, LOG_SIZE,
                    "send_all (%s) sending %d bytes priority %d to %d pipes: ",
                    desc, psize, priority, nwrite);
  int i;
  for (i = 0; i < nwrite; i++)
    n += snprintf (log_buf + n, LOG_SIZE - n, "%d%s", write_pipes [i],
                   (((i + 1) < nwrite) ? ", " : "\n"));
  log_print ();
  for (i = 0; i < nwrite; i++) {
    if (! send_pipe_message (write_pipes [i], packet, psize, priority)) {
      snprintf (log_buf, LOG_SIZE, "write_pipes [%d] = %d is no longer valid\n",
                i, write_pipes [i]);
      log_print ();
    }
  }
}

/* runs forever, and only returns in case of error. */
/* the first read_pipe and the first write_pipe are from/to alocal.
 * the second read_pipe and write_pipe are from/to aip
 * there may or may not be more pipes, but they should generally be the
 * same number, even though the code only explicitly refers to the first
 * three and doesn't require the same number of read and write pipes
 */
static void main_loop (int npipes, int * read_pipes, int * write_pipes,
                       int update_seconds, int max_social_bytes, int max_checks)
{
  int i;
  for (i = 0; i < npipes; i++)
    add_pipe (read_pipes [i]);
/* snprintf (log_buf, LOG_SIZE, "ad calling init_social\n"); log_print (); */
  struct social_info * soc = init_social (max_social_bytes, max_checks);
/* snprintf (log_buf, LOG_SIZE, "ad calling update_social\n"); log_print (); */
  time_t next_update = update_social (soc, update_seconds);
/* snprintf (log_buf, LOG_SIZE, "ad finished update_social\n"); log_print ();*/

  while (1) {
    /* read messages from each of the pipes */
    char * packet = NULL;
    int from_pipe;
 /* incoming priorities ignored unless from local */
    int priority = ALLNET_PRIORITY_EPSILON;
    int psize = receive_pipe_message_any (PIPE_MESSAGE_WAIT_FOREVER,
                                          &packet, &from_pipe, &priority);
snprintf (log_buf, LOG_SIZE, "ad received %d, fd %d\n", psize, from_pipe);
log_print ();
    if (psize <= 0) { /* for now exit */
      snprintf (log_buf, LOG_SIZE,
                "error: received %d from receive_pipe_message_any, pipe %d\n%s",
                psize, from_pipe, "  exiting\n");
      log_print ();
      exit (1);
    }
    /* packets generated by alocal are local */
    int is_local = (from_pipe == read_pipes [0]);
    int p = process_packet (packet, psize, is_local, soc, &priority);
    switch (p) {
    case PROCESS_PACKET_ALL:
      log_packet ("sending to all", packet, psize);
      send_all (packet, psize, priority, write_pipes, npipes, "all");
      break;
    case PROCESS_PACKET_OUT:
      log_packet ("sending out", packet, psize);
/* alocal should be the first pipe, so just skip it */
      send_all (packet, psize, priority, write_pipes + 1, npipes - 1, "out");
      break;
    /* all the rest are not forwarded, so priority does not matter */
    case PROCESS_PACKET_LOCAL:   /* send only to alocal */ 
      log_packet ("sending to alocal", packet, psize);
/* alocal should be the first pipe, so only write to that */
      send_all (packet, psize, 0, write_pipes, 1, "local");
      break;
    case PROCESS_PACKET_DROP:    /* do not forward */
      log_packet ("dropping packet", packet, psize);
      /* do nothing */
      break;
    }
    free (packet);  /* was allocated by receive_pipe_message_any */

    /* about once every next_update seconds, re-read social connections */
    if (time (NULL) >= next_update)
      next_update = update_social (soc, update_seconds);
  }
}

/* arguments are: the number of read/write pipes, then an array of pairs of
 * file descriptors (ints) for each pipe, from/to alocal, aip.
 * any additional pipes will again be pairs from/to each abc.
 */
void ad_main (int npipes, int * rpipes, int * wpipes)
{
  init_log ("ad");
  if (npipes < 2) {
    printf ("%d pipes, at least 2 needed\n", npipes);
    return;
  }
  snprintf (log_buf, LOG_SIZE, "AllNet (ad) version %d\n", ALLNET_VERSION);
  log_print ();
  int i;
  for (i = 0; i < npipes; i++) {
    snprintf (log_buf, LOG_SIZE,
              "read_pipes [%d] = %d, write_pipes [%d] = %d\n",
              i, rpipes [i], i, wpipes [i]);
    log_print ();
  }
  main_loop (npipes, rpipes, wpipes, 30, 30000, 5);
  snprintf (log_buf, LOG_SIZE, "ad error: main loop returned, exiting\n");
  log_print ();
}

#ifndef NO_MAIN_FUNCTION
/* global debugging variable -- if 1, expect more debugging output */
/* set in main */
int allnet_global_debugging = 0;

/* arguments are: the number of pipes, then pairs of read and write file
 * file descriptors (ints) for each pipe, from/to alocal, aip.
 * any additional pipes will again be pairs from/to each abc.
 */
int main (int argc, char ** argv)
{
  int verbose = get_option ('v', &argc, argv);
  if (verbose)
    allnet_global_debugging = verbose;

  init_log ("ad");
  if (argc < 2) {
    printf ("need to have at least the number of read and write pipes\n");
    print_usage (argc, argv, 0, 1);
    return -1;
  }
  int npipes = atoi (argv [1]);
  if (npipes < 2) {
    printf ("%d pipes, at least 2 needed\n", npipes);
    print_usage (argc, argv, 0, 1);
    return -1;
  }
  if (argc != 2 * npipes + 2) {
    printf ("%d arguments, expected 2 + %d for %d pipes\n",
            argc, 2 * npipes, npipes);
    print_usage (argc, argv, 0, 1);
    return -1;
  }
  if (argc < 5) {
    printf ("need to have at least 2 each read and write pipes\n");
    print_usage (argc, argv, 0, 1);
    return -1;
  }
  snprintf (log_buf, LOG_SIZE, "AllNet (ad) version %d\n", ALLNET_VERSION);
  log_print ();
  int * all_pipes  = malloc (sizeof (int) * npipes * 2);
  if (all_pipes == NULL) {
    printf ("allocation error in ad main\n");
    print_usage (argc, argv, 0, 1);
    return -1;
  }

  int i;
  for (i = 0; i < npipes; i++) {
    all_pipes [i         ] = atoi (argv [2 + 2 * i    ]);
    all_pipes [npipes + i] = atoi (argv [2 + 2 * i + 1]);
  }
  for (i = 0; i < 2 * npipes; i++) {
    snprintf (log_buf, LOG_SIZE, "all_pipes [%d] = %d\n", i, all_pipes [i]);
    log_print ();
  }
  ad_main (npipes, all_pipes, all_pipes + npipes);
  return 1;
}
#endif /* NO_MAIN_FUNCTION */

