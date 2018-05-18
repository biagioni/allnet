/* ad.c: main allnet daemon to forward allnet messages */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <assert.h>

#include "lib/packet.h"
#include "lib/mgmt.h"
#include "social.h"
#include "track.h"
#include "record.h"
#include "lib/sockets.h"
#include "lib/pipemsg.h"
#include "lib/priority.h"
#include "lib/allnet_log.h"
#include "lib/util.h"
#include "lib/routing.h"
#include "lib/pcache.h"
#include "lib/adht.h"
#include "lib/trace_util.h"
#include "lib/abc.h"
#include "lib/ai.h"

#define PROCESS_PACKET_DROP	0
#define PROCESS_PACKET_LOCAL	1  /* only forward to alocal */
#define PROCESS_PACKET_OUT	2  /* only forward to aip and the abc's */
#define PROCESS_PACKET_ALL	(PROCESS_PACKET_LOCAL | PROCESS_PACKET_OUT)

struct message_process {
  int process;    /* one of PROCESS_PACKET_DROP, _LOCAL, _OUT, or _ALL */
  char * message; /* NULL if PROCESS_PACKET_DROP, otherwise not NULL */
  int msize;
  int priority;
  int allocated;  /* whether the message needs to be freed */
};

/* limit the number of addresses from the routing table to which we send */
#define ROUTING_ADDRS_MAX	4
/* the number is higher for DHT packets, only sent once every 1/2 hour */
#define ROUTING_DHT_ADDRS_MAX	32
#define ADDRS_MAX	((ROUTING_DHT_ADDRS_MAX	> ROUTING_ADDRS_MAX) ? \
			 ROUTING_DHT_ADDRS_MAX : \
			 ROUTING_ADDRS_MAX)

static struct socket_set sockets;
static int sock_v4 = -1;    /* used to send packets to specific addresses */
static int sock_v6 = -1;    /* used to send packets to specific addresses */

/* set the v4 flag for the given socket */
static int set_ipv4 (struct socket_address_set * sock, void * ref)
{
  int sockfd = * ((int *) ref);
  if (sock->sockfd == sockfd)
    sock->is_global_v4 = 1;
  return 1;  /* don't delete */
}

static void initialize_sockets ()
{
  int created_local = 0;
  int created_out = 0;
  struct sockaddr_storage sasv4;
  struct sockaddr_storage sasv6;
  struct sockaddr_in  * sin  = (struct sockaddr_in  *) (&sasv4);
  struct sockaddr_in6 * sin6 = (struct sockaddr_in6 *) (&sasv6);
  socklen_t alen4 = sizeof (struct sockaddr_in );
  socklen_t alen6 = sizeof (struct sockaddr_in6);
  memset (&sasv4, 0, sizeof (sasv4));
  memset (&sasv6, 0, sizeof (sasv6));
  /* first the local port */
  sin6->sin6_family = AF_INET6;
  memcpy (&(sin6->sin6_addr), &(in6addr_loopback), sizeof (sin6->sin6_addr));
  sin6->sin6_port = htons (ALLNET_LOCAL_PORT);
  sin->sin_family = AF_INET;
  sin->sin_addr.s_addr = htonl (INADDR_LOOPBACK);
  sin->sin_port = htons (ALLNET_LOCAL_PORT);
  int local_v6 = socket_create_bind (&sockets, 1, sasv6, alen6, 0);
  if (local_v6 < 0)
    printf ("unable to create and bind to IPv6 local socket\n");
  else
    created_local = 1;
  /* now IPv4 */
  if ((socket_create_bind (&sockets, 1, sasv4, alen4, created_local) < 0) &&
      (! created_local))
    printf ("unable to create and bind to IPv4 local socket\n");
  else                     /* created ipv4 socket, record this */
    created_local = 1;
  /* now the outside port */
  memcpy (&(sin6->sin6_addr), &(in6addr_any), sizeof (sin6->sin6_addr));
  sin6->sin6_port = htons (ALLNET_PORT);
  sin->sin_addr.s_addr = htonl (INADDR_ANY);
  sin->sin_port = htons (ALLNET_PORT);
  sock_v6 = socket_create_bind (&sockets, 0, sasv6, alen6, 0);
  if (sock_v6 < 0)
    printf ("unable to create and bind to IPv6 out socket\n");
  else
    created_out = 1;
  /* now IPv4 */
  sock_v4 = socket_create_bind (&sockets, 0, sasv4, alen4, created_out);
  if ((sock_v4 < 0) && (! created_out))
    printf ("unable to create and bind to IPv4 out socket\n");
  else if (created_out) {  /* ipv6 socket is valid, use it for ipv4 */
    socket_sock_loop (&sockets, set_ipv4, &sock_v6);
    /* sock_v4 = sock_v6; */
  } else                   /* created ipv4 socket, record this */
    created_out = 1;
  int created_bc = add_local_broadcast_sockets (&sockets);
  if ((! created_local) || ((! created_out) && (! created_bc)))
    exit (1);
}

static struct allnet_log * alog = NULL;
static struct social_info * social_net = NULL;
static unsigned char my_address [ADDRESS_SIZE];

/* the virtual clock is updated about every 10s. */
#define VIRTUAL_CLOCK_SECONDS		10
#define SEND_KEEPALIVES_LOCAL		1   /* send keepalive every 10sec */
#define SEND_KEEPALIVES_REMOTE		60  /* send keepalive every 10min */
#define RECV_LIMIT_DEFAULT		5   /* send keepalive every 5 packets */
#define SEND_LIMIT_DEFAULT		10  /* send <= 10 packets before recv */

/* the virtual clock is updated about every 10s. It should never be zero. */
static long long int virtual_clock = 1;

/* update the virtual clock about every 10 seconds */
static void update_virtual_clock ()
{
  static long long int last_update = 0;
  long long int now = allnet_time ();
  if (last_update + 10 < now) {
    virtual_clock++;
    last_update = now;
    unsigned int msize;
    const char * message = keepalive_packet (&msize);
    socket_send_keepalives (&sockets, virtual_clock, SEND_KEEPALIVES_LOCAL,
                            SEND_KEEPALIVES_REMOTE, message, msize);
    socket_update_time (&sockets, virtual_clock);
  }
}

/* sends the ack to the address, given that hp has the packet we are acking */
static void send_ack (const char * ack, const struct allnet_header * hp,
                      int sockfd, struct sockaddr_storage addr, socklen_t alen,
                      int is_local)
{
  char message [ALLNET_HEADER_SIZE + MESSAGE_ID_SIZE + 2];
  int msize = sizeof (message);
  if (! is_local)
    msize -= 2;
  int hops = minz (hp->max_hops, hp->hops) + 2; /* (max_hops - hops) + 2 */
  /* reverse the source and destination addresses in sending back */
  init_packet (message, msize, ALLNET_TYPE_ACK, hops, ALLNET_SIGTYPE_NONE,
               hp->destination, hp->dst_nbits,
               hp->source, hp->src_nbits, NULL, NULL);
  memcpy (message + ALLNET_HEADER_SIZE, ack, MESSAGE_ID_SIZE);
  if (is_local)
    writeb16 (message + (sizeof (message) - 2), ALLNET_PRIORITY_LOCAL);
  /* send this ack back to the sender, no need to ack more widely */
  socket_send_to_ip (sockfd, message, msize, addr, alen, "ad.c/send_ack");
}

static void send_one_keepalive (const char * desc,
                                struct socket_address_set * sock,
                                struct socket_address_validity * sav)
{
  unsigned int msize;
  const char * message = keepalive_packet (&msize);
  socket_send_to (message, msize, ALLNET_PRIORITY_EPSILON, virtual_clock,
                  &sockets, sock, sav);
}

/* send to a limited number of DHT addresses and to socket_send_out */
static void send_out (const char * message, int msize, int max_addrs,
                      const struct sockaddr_storage * except, /* may be NULL */
                      socklen_t elen)  /* should be 0 if except is NULL */
{
  const struct allnet_header * hp = (const struct allnet_header *) message;
  /* only forward out if max_hops is reasonable and hops < max_hops */
  if ((hp->max_hops <= 0) || (hp->hops >= 255) || (hp->hops >= hp->max_hops))
    return;
  assert (max_addrs <= ADDRS_MAX);
  struct sockaddr_storage addrs [ADDRS_MAX];
  socklen_t alens [ADDRS_MAX];
  memset (addrs, 0, sizeof (addrs));
  int num_addrs = routing_top_dht_matches (hp->destination, hp->dst_nbits,
                                           addrs, alens, max_addrs);
  int dht_send_error = 0;
  int i;
  for (i = 0; i < num_addrs; i++) {
    struct sockaddr_storage dest = addrs [i];
    socklen_t alen = alens [i];
    int sockfd = sock_v4;
    if (dest.ss_family == AF_INET6) {
      sockfd = sock_v6;
    } else if (sockfd < 0) {  /* if sock_v4 is not valid, use sock_v6 */
      sockfd = sock_v6;
      ai_embed_v4_in_v6 (&dest, &alen);  /* needed on apple systems */
    }
    if (sockfd >= 0) {
      if (! socket_send_to_ip (sockfd, message, msize, dest, alen,
                               "ad.c/send_out"))
        dht_send_error = 1;
    }
  }
  static struct sockaddr_storage empty;  /* used if except is null */
  socket_send_out (&sockets, message, msize, virtual_clock,
                   ((except == NULL) ? empty : *except), elen);
  if (dht_send_error)
    routing_expire_dht (&sockets);
}

static void update_dht ()
{
  char * dht_message = NULL;
  unsigned int msize = dht_update (&sockets, &dht_message);
  if ((msize > 0) && (dht_message != 0)) {
    struct sockaddr_storage sas;
    memset (&sas, 0, sizeof (sas));
    socket_send_local (&sockets, dht_message, msize, ALLNET_PRIORITY_LOCAL_LOW,
                       virtual_clock, sas, 0);
    send_out (dht_message, msize, ROUTING_DHT_ADDRS_MAX, NULL, 0);
    free (dht_message);
  }
}

extern void check_sav (struct socket_address_validity * sav, const char * desc);

static struct socket_address_validity *
  add_received_address (struct socket_read_result r)
{
  if (is_in_routing_table ((struct sockaddr *) &(r.from), r.alen))
    return NULL;
  long long int limit = virtual_clock + ((r.sock->is_local) ? 6 : 180);
  struct socket_address_validity sav =
    { .alive_rcvd = virtual_clock, .alive_sent = virtual_clock,
      .send_limit = SEND_LIMIT_DEFAULT,
      .send_limit_on_recv = SEND_LIMIT_DEFAULT,
      .recv_limit = RECV_LIMIT_DEFAULT,
      .time_limit = limit, .alen = r.alen };
  memcpy (&(sav.addr), &(r.from), sizeof (r.from));
  struct socket_address_validity * result =
    socket_address_add (&sockets, r.sock, sav);
  if (result == NULL)
    printf ("odd: unable to add new address\n");
  send_one_keepalive ("add_received_address", r.sock, result);
check_sav (result, "add_received_address 4");
  return result;
}

/* return the number of messages sent (r.n), or 0 if none */
static int send_messages_to_one (struct pcache_result r,
                                 struct socket_address_set * sock,
                                 struct socket_address_validity * sav)
{
  if (r.n <= 0)
    return 0;
  int result = r.n;
  int i;
  for (i = 0; i < r.n; i++) {
#ifdef LOG_PACKETS
    snprintf (alog->b, alog->s, "%s %d bytes, prio %d, to pipe %d\n",
              "send_one_message_to", r.messages [i].msize,
              r.messages [i].priority, sock->sockfd);
#ifdef DEBUG_PRINT
    printf ("-> %s", alog->b);
#endif /* DEBUG_PRINT */
    log_print (alog);
    log_packet (alog, "message to pipe",
                r.messages [i].message, r.messages [i].msize);
#endif /* LOG_PACKETS */
    socket_send_to (r.messages [i].message, r.messages [i].msize,
                    r.messages [i].priority, virtual_clock, &sockets,
                    sock, sav);
  }
  free (r.free_ptr);
  return result;
}

/* compute a forwarding priority for non-local messages */
static unsigned int message_priority (char * message, struct allnet_header * hp,
                                     unsigned int size)
{
  unsigned int sig_size = 0;
  if (hp->sig_algo != ALLNET_SIGTYPE_NONE)
    sig_size = readb16 (message + (size - 2));
  int valid = 0;
  unsigned int social_distance = UNKNOWN_SOCIAL_TIER;
  unsigned int rate_fraction = largest_rate ();
  unsigned int hsize = ALLNET_SIZE (hp->transport);
  if ((sig_size > 0) && (hsize + sig_size + 2 < size)) {
    char * verify = message + hsize; 
    int vsize = size - (hsize + sig_size + 2);
    char * sig = message + hsize + vsize;
    social_distance =
       social_connection (social_net, verify, vsize, hp->source, hp->src_nbits,
                          hp->sig_algo, sig, sig_size, &valid);
  } else if (sig_size > 0) {
    snprintf (alog->b, alog->s,
              "invalid sigsize: %d, %d + %d + 2 = %d <? %d\n",
              hp->sig_algo, hsize, sig_size, (hsize + sig_size + 2), size);
    log_print (alog);
  }
  /* track_rate is in track.[hc] */
  if (valid)
    rate_fraction = track_rate (hp->source, hp->src_nbits, size);
  else
    social_distance = UNKNOWN_SOCIAL_TIER;
  int cacheable = ((hp->transport & ALLNET_TRANSPORT_DO_NOT_CACHE) == 0);
  /* compute_priority is in lib/priority.[hc] */
  return compute_priority (size, hp->src_nbits, hp->dst_nbits,
                           hp->hops, hp->max_hops, social_distance,
                           rate_fraction, cacheable);
}

/* special handling, only forward the acks we haven't seen before
 * returns the new size of the message to continue processing,
 * or 0 to drop the message
 * redundant acks are removed from the message, so the returned size may
 * be less than the original size */
static int process_acks (struct allnet_header * hp, int size)
{
  char local_token [PCACHE_TOKEN_SIZE];
  pcache_current_token (local_token);
  char * acks = ALLNET_DATA_START (hp, hp->transport, size);
  char * message = (char *) hp;  /* header size computation must be in bytes */
  int num_acks = minz (size, (int)(acks - message)) / MESSAGE_ID_SIZE;
  int hops_remaining = minz (hp->max_hops, hp->hops + 1);
  pcache_save_acks (acks, num_acks, hops_remaining);
  int new_acks = pcache_acks_for_token (local_token, acks, num_acks);
  if (new_acks <= 0)
    return 0;   /* no new acks, drop the message */
  if (new_acks > num_acks) {    /* this is an error */
    printf ("error, new acks %d, original %d\n", new_acks, num_acks);
    print_buffer (message, new_acks * MESSAGE_ID_SIZE,
                  "message with more acks", size, 1);
    exit (1);
  }
  if (new_acks < num_acks) {
    int debug_size = size;
    size -= ((num_acks - new_acks) * MESSAGE_ID_SIZE);
    if (size <= ALLNET_SIZE (hp->transport)) {  /* this is an error! */
      printf ("ad computed new size %d(%d), should be %d, original %d(%d)\n",
              size, new_acks, (int) (ALLNET_SIZE (hp->transport)),
              debug_size, num_acks);
      exit (1);
    }
  }
  return size;
}

static struct message_process process_mgmt (struct socket_read_result *r)
{
  /* if sent from local, use the priority they gave us */
  /* else set priority to the lowest possible.  Generally the right thing */
  /* unless we know better (and doesn't affect local delivery). */
  if (! r->sock->is_local)
    r->priority = ALLNET_PRIORITY_DEFAULT_LOW;
  struct message_process drop = { .process = PROCESS_PACKET_DROP,
                                  .message = r->message, .msize = r->msize,
                                  .priority = r->priority, .allocated = 0 };
  struct message_process all  = { .process = PROCESS_PACKET_ALL,
                                  .message = r->message, .msize = r->msize,
                                  .priority = r->priority, .allocated = 0 };
  struct allnet_header * hp = (struct allnet_header *) r->message;
  int hs = ALLNET_AFTER_HEADER (hp->transport, r->msize);
  if (r->msize < hs + sizeof (struct allnet_mgmt_header))
    return drop;   /* illegal management message */
  struct allnet_mgmt_header * ahm =
    (struct allnet_mgmt_header *) (r->message + hs);
  char * mgmt_payload = ((char *) ahm) + sizeof (struct allnet_mgmt_header);
  int hdr_size = (int)(mgmt_payload - r->message);
  int mgmt_payload_size = (r->msize > hdr_size ? r->msize - hdr_size : 0);
  char * new_trace_request = NULL;  /* needed inside the switch statement */
  int new_trace_request_size = 0;
  char * trace_reply = NULL;
  int trace_reply_size = 0;
  struct allnet_mgmt_trace_req * in_trace_req =
    (struct allnet_mgmt_trace_req *) mgmt_payload;
  switch (ahm->mgmt_type) {
  case ALLNET_MGMT_BEACON:
  case ALLNET_MGMT_BEACON_REPLY:
  case ALLNET_MGMT_BEACON_GRANT:
  case ALLNET_MGMT_KEEPALIVE:
    return drop;   /* do not forward beacons or keepalives */
  case ALLNET_MGMT_DHT:
    dht_process (r->message, r->msize, (struct sockaddr *) &(r->from), r->alen);
    return all;
  case ALLNET_MGMT_PEER_REQUEST:
  case ALLNET_MGMT_PEERS:
    return all;
#ifdef IMPLEMENT_MGMT_ID_REQUEST  /* not used, so, not implemented */
  case ALLNET_MGMT_ID_REQUEST:
    assert (0);
    struct allnet_mgmt_id_request * id_req = (struct allnet_mgmt_id_request *)
                  (r->message + ALLNET_MGMT_HEADER_SIZE (hp->transport));
    send_messages_to_one (pcache_id_request (id_req), r->sock, r->sav);
    return all;     /* and forward the request*/
#endif /* IMPLEMENT_MGMT_ID_REQUEST */
  case ALLNET_MGMT_TRACE_REQ:
    if (pcache_trace_request (in_trace_req->trace_id))  /* seen before */
      return drop;
    trace_forward (r->message, r->msize, my_address, 16,
                   &new_trace_request, &new_trace_request_size,
                   &trace_reply, &trace_reply_size);
    if ((trace_reply != NULL) && (trace_reply_size > 0)) {
      struct sockaddr_storage empty;
      memset (&empty, 0, sizeof (empty));
      socket_send_local (&sockets, trace_reply, trace_reply_size,
                         ALLNET_PRIORITY_TRACE, virtual_clock, empty, 0);
      if (! r->sock->is_local)
        send_out (trace_reply, trace_reply_size, ROUTING_ADDRS_MAX, NULL, 0);
      pcache_save_packet (trace_reply, trace_reply_size, ALLNET_PRIORITY_TRACE);
      free (trace_reply);
    }
    if (new_trace_request_size > 0) {
      all.msize = new_trace_request_size;
      all.priority = ALLNET_PRIORITY_TRACE;
      if (new_trace_request != NULL) {  /* rewritten trace request */
        all.message = new_trace_request;
        all.allocated = 1;
      } /* else forward the original request */
      pcache_save_packet (all.message, all.msize, ALLNET_PRIORITY_TRACE);
      return all;
    }
    return drop;
  case ALLNET_MGMT_TRACE_REPLY:
    if ((mgmt_payload_size <= 0) ||
        (pcache_trace_reply (mgmt_payload, mgmt_payload_size)))
      return drop;  /* invalid, or seen before */
    all.priority = ALLNET_PRIORITY_TRACE;
    pcache_save_packet (r->message, r->msize, ALLNET_PRIORITY_TRACE);
    return all;
  default:
    snprintf (alog->b, alog->s, "unknown management message type %d\n",
              ahm->mgmt_type);
    log_print (alog);   /* forward unknown management messages */
    all.priority = ALLNET_PRIORITY_TRACE;
    return all;
  }
}

/* return the action to take with the message */
/* process_message may decrease the value of the message size, but
 * never below a message header (unless PROCESS_PACKET_DROP) */
static struct message_process process_message (struct socket_read_result *r)
{
  struct message_process drop =
        { .process = PROCESS_PACKET_DROP,
          .message = NULL, .msize = 0, .priority = r->priority, .allocated = 0};
  struct allnet_header * hp = (struct allnet_header *) r->message;
  int seen_before = 0;
  int save_message = 1;
  if (hp->message_type == ALLNET_TYPE_ACK) {
    r->msize = process_acks (hp, r->msize);
    if (r->msize <= 0)
      return drop;                   /* no new acks, drop the message */
    save_message = 0;                /* already saved the new acks */
  } else {
    char id [MESSAGE_ID_SIZE];
    if (! pcache_message_id (r->message, r->msize, id))
      return drop;          /* no message ID, drop the message */
    char ack [MESSAGE_ID_SIZE];   /* filled in if ack_found */
    if (pcache_id_acked (id, ack)) {  /* ack this message */
      send_ack (ack, hp, r->sock->sockfd, r->from, r->alen, r->sock->is_local);
      seen_before = 1;
    } else {
      seen_before = pcache_id_found (id);
    }
    if ((! r->sock->is_local) && (seen_before))
      return drop;            /* we have seen it before, drop the message */
    if (hp->message_type == ALLNET_TYPE_DATA_REQ) {
      char * data = ALLNET_DATA_START (hp, hp->transport, r->msize);
      struct allnet_data_request * req = (struct allnet_data_request *) data;
      struct socket_address_validity sav_storage;
      struct socket_address_validity * sav = r->sav;
      if (sav == NULL) { /* only addr and alen matter */
        memset (&(sav_storage), 0, sizeof (sav_storage));
        memcpy (&(sav_storage.addr), &(r->from), sizeof (sav_storage.addr));
        sav_storage.alen = r->alen;
        sav = &(sav_storage);  /* sav must be used before the end of the if */
      }
      send_messages_to_one (pcache_request (req), r->sock, sav);
      sav = NULL;   /* in case it pointed to sav_storage, which goes away */
      /* and then do normal packet processing (forward) this data request */
    }
  }
  if (! r->sock->is_local)
    r->priority = message_priority (r->message, hp, r->msize);
  /* below here the message should be valid, forward it */
  struct message_process result =
        { .process = PROCESS_PACKET_ALL, .message = r->message,
          .msize = r->msize, .priority = r->priority, .allocated = 0 };
  if (save_message && (! seen_before)) {
    if ((hp->transport & ALLNET_TRANSPORT_DO_NOT_CACHE) != 0)
      pcache_save_packet (r->message, r->msize, r->priority);
    else
      pcache_record_packet (r->message, r->msize);
  }
  return result;
}

void allnet_daemon_loop ()
{
  while (1) {
    struct socket_read_result r = socket_read (&sockets, 10, virtual_clock);
    if ((r.message == NULL) || (r.msize <= 0) ||
        (! is_valid_message (r.message, r.msize, NULL)))
      continue;   /* no valid message, no action needed, restart the loop */
    if ((r.socket_address_is_new) || (r.sav == NULL))
      r.sav = add_received_address (r);
    else if ((r.sav != NULL) && (r.sav->time_limit != 0))
      r.sav->time_limit = virtual_clock + ((r.sock->is_local) ? 6 : 180);
    struct allnet_header * hp = (struct allnet_header *) r.message;
    if ((hp->hops < 255) && (! r.sock->is_local))  /* for non-local messages */
      hp->hops++;            /* before processing, increment number of hops */
    struct message_process m =
         ((hp->message_type == ALLNET_TYPE_MGMT) ? process_mgmt (&r)
                                                 : process_message (&r));
    if (m.process & PROCESS_PACKET_LOCAL)
      socket_send_local (&sockets, m.message, m.msize, m.priority,
                         virtual_clock, r.from, r.alen);
    if (m.process & PROCESS_PACKET_OUT)
      send_out (m.message, m.msize, ROUTING_ADDRS_MAX, &(r.from), r.alen);
    if ((m.allocated) && (m.message != NULL))
      free (m.message);
    free (r.message);  /* was allocated by socket_read */
    if (r.recv_limit_reached) {
      socket_update_recv_limit (RECV_LIMIT_DEFAULT, &sockets, r.from, r.alen);
      if (r.sav != NULL)
        send_one_keepalive ("update_recv_limit", r.sock, r.sav);
    }
    update_virtual_clock ();
    update_dht ();
  }
}

void allnet_daemon_main ()
{
  alog = init_log ("ad");
  sockets.num_sockets = 0;
  sockets.sockets = NULL;
  social_net = init_social (30000, 5, alog);
  routing_my_address (my_address);
  initialize_sockets ();
  allnet_daemon_loop ();
}
