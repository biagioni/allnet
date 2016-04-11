/* ad.c: main allnet daemon to forward allnet messages */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

#include "lib/packet.h"
#include "lib/mgmt.h"
#include "social.h"
#include "track.h"
#include "record.h"
#include "lib/pipemsg.h"
#include "lib/priority.h"
#include "lib/allnet_log.h"
#include "lib/util.h"

#define PROCESS_PACKET_DROP	1
#define PROCESS_PACKET_LOCAL	2  /* only forward to alocal */
#define PROCESS_PACKET_OUT	3  /* only forward to aip and the abc's */
#define PROCESS_PACKET_ALL	4  /* forward to alocal, aip, and the abc's */

static struct allnet_log * alog = NULL;

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
  if ((sig_size > 0) && (hsize + sig_size + 2 < size)) {
    char * verify = packet + hsize; 
    int vsize = size - (hsize + sig_size + 2);
    char * sig = packet + hsize + vsize;
    social_distance =
       social_connection (soc, verify, vsize, hp->source, hp->src_nbits,
                          hp->sig_algo, sig, sig_size, &valid);
  } else if (sig_size > 0) {
    snprintf (alog->b, alog->s,
              "invalid sigsize: %d, %d + %d + 2 = %d <? %d\n",
              hp->sig_algo, hsize, sig_size, (hsize + sig_size + 2), size);
    log_print (alog);
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
      if (hp->max_hops == 0)
        return PROCESS_PACKET_DROP;       /* only for us, do not forward */
      return PROCESS_PACKET_OUT;          /* local packet, forward out */
    }
  default:
    snprintf (alog->b, alog->s, "unknown management message type %d\n",
              ahm->mgmt_type);
    log_print (alog);
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
/* if (! is_valid_message (packet, size))
printf ("got invalid %s packet of size %d, priority %d\n",
        (is_local) ? "local" : "remote", size, *priority); */
  if (! is_valid_message (packet, size))
    return PROCESS_PACKET_DROP;

/* skip the hop count in the hash, since it changes at each hop */
#define HEADER_SKIP	3
  int time = record_packet_time (packet + HEADER_SKIP, size - HEADER_SKIP, 0);
#undef HEADER_SKIP
  if ((! is_local) && (time > 0)) {
   /* we have received this packet before, so drop it */
#ifdef LOG_PACKETS
    snprintf (alog->b, alog->s, 
              "packet received in the last %d seconds, dropping\n", time);
    log_print (alog);
#endif /* LOG_PACKETS */
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
#ifdef LOG_PACKETS
  snprintf (alog->b, alog->s, "forwarding %s packet with %d/%d hops\n",
            (is_local ? "local" : "received"), ah->hops, ah->max_hops);
  log_print (alog);
#endif /* LOG_PACKETS */

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
  int i;
#ifdef LOG_PACKETS
  int n = snprintf (alog->b, alog->s,
                    "send_all (%s) sending %d bytes priority %d to %d pipes: ",
                    desc, psize, priority, nwrite);
  for (i = 0; i < nwrite; i++)
    n += snprintf (alog->b + n, alog->s - n, "%d%s", write_pipes [i],
                   (((i + 1) < nwrite) ? ", " : "\n"));
  log_print (alog);
#endif /* LOG_PACKETS */
  for (i = 0; i < nwrite; i++) {
    if (! send_pipe_message (write_pipes [i], packet, psize, priority, alog)) {
      snprintf (alog->b, alog->s, "write_pipes [%d] = %d is no longer valid\n",
                i, write_pipes [i]);
      log_print (alog);
    }
  }
}

/* runs forever, and only returns in case of error. */
/* the first read_pipe and the first write_pipe are from/to alocal.
 * the second read_pipe and write_pipe are from/to aip
 * there may or may not be more pipes.  If there are, there should be
 * as many read as write pipes.
 */
static void main_loop (int npipes, int * read_pipes, int * write_pipes,
                       int update_seconds, int max_social_bytes, int max_checks)
{
  pd p = init_pipe_descriptor (alog);
  int i;
  for (i = 0; i < npipes; i++)
    add_pipe (p, read_pipes [i]);
/* snprintf (alog->b, alog->s, "ad calling init_social\n"); log_print (alog); */
  struct social_info * soc = init_social (max_social_bytes, max_checks, alog);
/*snprintf (alog->b, alog->s, "ad calling update_social\n"); log_print (alog);*/
  time_t next_update = update_social (soc, update_seconds);
/*snprintf (alog->b, alog->s, "ad finished update_social\n");log_print (alog);*/

  while (1) {
    /* read messages from each of the pipes */
    char * packet = NULL;
    int from_pipe;
 /* incoming priorities ignored unless from local */
    int priority = ALLNET_PRIORITY_EPSILON;
    int psize = receive_pipe_message_any (p, PIPE_MESSAGE_WAIT_FOREVER,
                                          &packet, &from_pipe, &priority);
#ifdef LOG_PACKETS
    snprintf (alog->b, alog->s, "ad received %d, fd %d\n", psize, from_pipe);
    log_print (alog);
#endif /* LOG_PACKETS */
    if (psize <= 0) { /* for now exit */
      snprintf (alog->b, alog->s,
                "error: received %d from receive_pipe_message_any, pipe %d",
                psize, from_pipe);
      log_print (alog);
      int abc_pipe = 0;
      for (i = 2; i < npipes; i++)
        if (read_pipes [i] == from_pipe)
          abc_pipe = i;
      if (abc_pipe) {  /* abc may fail, we should not die */
printf ("ad closing [%d] %d %d\n", abc_pipe, read_pipes [abc_pipe], write_pipes [abc_pipe]);
        snprintf (alog->b, alog->s, "ad closing [%d] %d %d\n",
                  abc_pipe, read_pipes [abc_pipe], write_pipes [abc_pipe]);
        log_print (alog);
        remove_pipe (p, read_pipes [abc_pipe]);
        close (read_pipes [abc_pipe]);
        close (write_pipes [abc_pipe]);
        for (i = abc_pipe; i + 1 < npipes; i++) {
          read_pipes [i] = read_pipes [i + 1];
          write_pipes [i] = write_pipes [i + 1];
        }
        npipes--;
        continue;   /* read again */
      } else {  /* some other pipe */
        snprintf (alog->b, alog->s, "  exiting\n");
        log_print (alog);
        return;
      }
    }
    /* packets generated by alocal are local */
    int is_local = (from_pipe == read_pipes [0]);
    int p = process_packet (packet, psize, is_local, soc, &priority);
    switch (p) {
    case PROCESS_PACKET_ALL:
#ifdef LOG_PACKETS
      log_packet ("sending to all", packet, psize);
#endif /* LOG_PACKETS */
      send_all (packet, psize, priority, write_pipes, npipes, "all");
      break;
    case PROCESS_PACKET_OUT:
#ifdef LOG_PACKETS
      log_packet ("sending out", packet, psize);
#endif /* LOG_PACKETS */
/* alocal should be the first pipe, so just skip it */
      send_all (packet, psize, priority, write_pipes + 1, npipes - 1, "out");
      break;
    /* all the rest are not forwarded, so priority does not matter */
    case PROCESS_PACKET_LOCAL:   /* send only to alocal */ 
#ifdef LOG_PACKETS
      log_packet ("sending to alocal", packet, psize);
#endif /* LOG_PACKETS */
/* alocal should be the first pipe, so only write to that */
      send_all (packet, psize, 0, write_pipes, 1, "local");
      break;
    case PROCESS_PACKET_DROP:    /* do not forward */
#ifdef LOG_PACKETS
      log_packet ("dropping packet", packet, psize);
#endif /* LOG_PACKETS */
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
  alog = init_log ("ad");
  if (npipes < 2) {
    printf ("%d pipes, at least 2 needed\n", npipes);
    return;
  }
  snprintf (alog->b, alog->s, "AllNet (ad) version %d\n", ALLNET_VERSION);
  log_print (alog);
  int i;
  for (i = 0; i < npipes; i++) {
    snprintf (alog->b, alog->s,
              "read_pipes [%d] = %d, write_pipes [%d] = %d\n",
              i, rpipes [i], i, wpipes [i]);
    log_print (alog);
  }
  main_loop (npipes, rpipes, wpipes, 30, 30000, 5);
  snprintf (alog->b, alog->s, "ad error: main loop returned, exiting\n");
  log_print (alog);
}

#ifdef DAEMON_MAIN_FUNCTION
/* arguments are: the number of pipes, then pairs of read and write file
 * file descriptors (ints) for each pipe, from/to alocal, aip.
 * any additional pipes will again be pairs from/to each abc.
 */
int main (int argc, char ** argv)
{
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
  snprintf (alog->b, alog->s, "AllNet (ad) version %d\n", ALLNET_VERSION);
  log_print (alog);
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
    snprintf (alog->b, alog->s, "all_pipes [%d] = %d\n", i, all_pipes [i]);
    log_print (alog);
  }
  ad_main (npipes, all_pipes, all_pipes + npipes);
  return 1;
}
#endif /* DAEMON_MAIN_FUNCTION */

