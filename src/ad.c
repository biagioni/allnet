/* ad.c: main allnet daemon to forward allnet messages */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "lib/packet.h"
#include "lib/mgmt.h"
#include "social.h"
#include "track.h"
#include "lib/pipemsg.h"
#include "lib/priority.h"
#include "lib/log.h"
#include "lib/util.h"

#define PROCESS_PACKET_DROP	1
#define PROCESS_PACKET_LOCAL	2
#define PROCESS_PACKET_ALL	3

/* compute a forwarding priority for non-local packets */
static int packet_priority (char * packet, struct allnet_header * hp, int size,
                            struct social_info * soc)
{
  int sig_size = 0;
  if (hp->sig_algo != ALLNET_SIGTYPE_NONE)
    sig_size = (packet [size - 2] & 0xff) << 8 + (packet [size - 1] & 0xff);
  int valid = 0;
  int social_distance = UNKNOWN_SOCIAL_TIER;
  int rate_fraction = largest_rate ();
  if ((sig_size > 0) && (ALLNET_SIZE (hp->transport) + sig_size + 2 > size)) {
    char * sig = packet + (size - 2 - sig_size);
    char * verify = packet + ALLNET_HEADER_SIZE; 
    int vsize = size - (ALLNET_HEADER_SIZE + sig_size + 2);
    social_distance =
       social_connection (soc, verify, vsize, hp->source, hp->src_nbits,
                          hp->sig_algo, sig, sig_size, &valid);
  }
  if (valid)
    rate_fraction = track_rate (hp->source, hp->src_nbits, size);
  else
    social_distance = UNKNOWN_SOCIAL_TIER;
  return compute_priority (size, hp->src_nbits, hp->dst_nbits,
                           hp->hops, hp->max_hops, social_distance,
                           rate_fraction);
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
    if (is_local) {               /* from local application or DHT daemon */
      return PROCESS_PACKET_ALL;  /* forward to the DHT */
    } else {
      return PROCESS_PACKET_LOCAL;/* only forward to the DHT or other local */
    }
  case ALLNET_MGMT_TRACE_REQ:
    if ((is_local) && (*priority == ALLNET_PRIORITY_TRACE_FWD)) {
      return PROCESS_PACKET_ALL;  /* forward as a normal data packet */
    } else {                      /* from trace app or from outside */
      return PROCESS_PACKET_LOCAL;/* only forward to the trace server/app */
    }
  case ALLNET_MGMT_TRACE_REPLY:
    if (! is_local)
      *priority = ALLNET_PRIORITY_TRACE;
    return PROCESS_PACKET_ALL;    /* forward to all with very low priority */
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
  static time_t trace_received = 0;

/* skip the hop count in the hash, since it changes at each hop */
#define HEADER_SKIP	3
  /* have we received this packet in the last minute?  if so, drop it */
  int time = record_packet_time (packet + HEADER_SKIP, size - HEADER_SKIP, 0);
#undef HEADER_SKIP
  if ((time > 0) && (time < 60)) {
    if (is_local)
      return PROCESS_PACKET_LOCAL;  /* should be OK to forward locally */
    snprintf (log_buf, LOG_SIZE, 
              "packet received in the last %d seconds, dropping\n", time);
    log_print ();
    return PROCESS_PACKET_DROP;     /* duplicate, ignore */
  }

  /* should be valid */
  struct allnet_header * ah = (struct allnet_header *) packet;

  /* before forwarding, increment the number of hops seen */
  if ((! is_local) && (ah->hops < 255))   /* do not increment 255 to 0 */
    ah->hops++;
  snprintf (log_buf, LOG_SIZE, "forwarding packet with %d hops\n", ah->hops);
  log_print ();

  if (ah->message_type == ALLNET_TYPE_MGMT) {     /* AllNet management */
    int r = process_mgmt (packet, size, is_local, priority, soc);
    return r;
  }

  if (is_local)
    return PROCESS_PACKET_ALL;

  if (ah->hops >= ah->max_hops)   /* reached hop count */
  /* no matter what it is, only forward locally, i.e. to alocal */
    return PROCESS_PACKET_LOCAL;

  /* compute a forwarding priority for non-local packets */
  *priority = packet_priority (packet, ah, size, soc);

  /* send each of the packets, with its priority, to each of the pipes */
  return PROCESS_PACKET_ALL;
}

static void send_all (char * packet, int psize, int priority,
                      int * write_pipes, int nwrite, char * desc)
{
  int n = snprintf (log_buf, LOG_SIZE,
                    "send_all (%s) sending %d bytes to %d pipes: ",
                    desc, psize, nwrite);
  int i;
  for (i = 0; i < nwrite; i++)
    n += snprintf (log_buf + n, LOG_SIZE - n, "%d, ", write_pipes [i]);
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
static void main_loop (int * read_pipes, int nread,
                       int * write_pipes, int nwrite,
                       int update_seconds, int max_social_bytes, int max_checks)
{
  int i;
  for (i = 0; i < nread; i++)
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
      send_all (packet, psize, priority, write_pipes, nwrite, "all");
      break;
    /* all the rest are not forwarded, so priority does not matter */
    case PROCESS_PACKET_LOCAL:   /* send only to alocal */ 
      log_packet ("sending to alocal", packet, psize);
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

/* arguments are: the number of pipes, then pairs of read and write file
 * file descriptors (ints) for each pipe, from/to alocal, aip.
 * any additional pipes will again be pairs from/to each abc.
 */
int main (int argc, char ** argv)
{
  init_log ("ad");
  if (argc < 2) {
    printf ("need to have at least the number of read and write pipes\n");
    return -1;
  }
  int npipes = atoi (argv [1]);
  if (npipes < 2) {
    printf ("%d pipes, at least 2 needed\n", npipes);
    return -1;
  }
  if (argc != 2 * npipes + 2) {
    printf ("%d arguments, expected 2 + %d for %d pipes\n",
            argc, 2 * npipes, npipes);
    return -1;
  }
  if (argc < 5) {
    printf ("need to have at least 2 each read and write pipes\n");
    return -1;
  }
  snprintf (log_buf, LOG_SIZE, "AllNet (ad) version %d\n", ALLNET_VERSION);
  log_print ();
  /* allocate both read and write pipes at once, then point write_pipes
   * to the middle of the allocated array
   */
  int * read_pipes  = malloc (sizeof (int) * npipes * 2);
  if (read_pipes == NULL) {
    printf ("allocation error in ad main\n");
    return -1;
  }
  int * write_pipes = read_pipes + npipes;

  int i;
  for (i = 0; i < npipes; i++) {
    read_pipes  [i] = atoi (argv [2 + 2 * i    ]);
    write_pipes [i] = atoi (argv [2 + 2 * i + 1]);
  }
  for (i = 0; i < npipes; i++) {
    snprintf (log_buf, LOG_SIZE, "read_pipes [%d] = %d\n", i, read_pipes [i]);
    log_print ();
  }
  for (i = 0; i < npipes; i++) {
    snprintf (log_buf, LOG_SIZE, "write_pipes [%d] = %d\n", i, write_pipes [i]);
    log_print ();
  }
  main_loop (read_pipes, npipes, write_pipes, npipes, 30, 30000, 5);
  snprintf (log_buf, LOG_SIZE, "ad error: main loop returned, exiting\n");
  log_print ();
}

