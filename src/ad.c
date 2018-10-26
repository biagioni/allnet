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
  char * debug_reason;     /* which code decided the packet disposition */
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

#define THROTTLE_SENDING    /* 2018/10/03: try this */
#ifdef THROTTLE_SENDING
/* throttle the number of messages sent by only sending high priority ones */
static int priority_threshold = ALLNET_PRIORITY_EPSILON;
#endif /* THROTTLE_SENDING */

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
  random_bytes (sockets.random_secret, sizeof (sockets.random_secret)); 
  sockets.counter = 1;
}

static struct allnet_log * alog = NULL;
static struct social_info * social_net = NULL;
static unsigned char my_address [ADDRESS_SIZE];

/* send at most 10 packets for every external data request */
#define SEND_EXTERNAL_MAX	10

/* the virtual clock is updated about every 10s. */
#define VIRTUAL_CLOCK_SECONDS		10
#define SEND_KEEPALIVES_LOCAL		1   /* send keepalive every 10sec */
#define SEND_KEEPALIVES_REMOTE		60  /* send keepalive every 10min */
#define RECV_LIMIT_DEFAULT		20  /* send keepalive every 20 packets*/
#define SEND_LIMIT_DEFAULT		99  /* send <= 99 packets before rcv */

/* the virtual clock is updated about every 10s. It should never be zero. */
static long long int virtual_clock = 1;

/* update the virtual clock about every 10 seconds */
/* and do other periodic tasks */
static void update_virtual_clock ()
{
  static long long int last_update = 0;
  long long int now = allnet_time ();
  if (last_update + 10 < now) {
    virtual_clock++;
    last_update = now;
    socket_send_keepalives (&sockets, virtual_clock, SEND_KEEPALIVES_LOCAL,
                            SEND_KEEPALIVES_REMOTE);
    socket_update_time (&sockets, virtual_clock);
    add_local_broadcast_sockets (&sockets);
  }
}

static void update_sender_keepalive (const char * message, int msize,
                                     struct socket_address_validity * sav)
{
  if ((sav == NULL) ||   /* nothing to update */
      (msize < ALLNET_HEADER_SIZE + KEEPALIVE_AUTHENTICATION_SIZE))
    return;              /* or not a keepalive with sender authentication */
  struct allnet_header * hp = (struct allnet_header *) message;
  struct allnet_mgmt_header * mhp =
    (struct allnet_mgmt_header *) (message + ALLNET_SIZE (hp->transport));
  int mhsize = ALLNET_MGMT_HEADER_SIZE (hp->transport);
  if ((msize < mhsize + KEEPALIVE_AUTHENTICATION_SIZE) ||
      (msize > mhsize + 2 * KEEPALIVE_AUTHENTICATION_SIZE) ||
      (hp->message_type != ALLNET_TYPE_MGMT) ||
      (mhp->mgmt_type != ALLNET_MGMT_KEEPALIVE))
    return;   /* not a keepalive with sender authentication */
#ifdef LOG_PACKETS
if (memcmp (sav->keepalive_auth, message + mhsize,
            KEEPALIVE_AUTHENTICATION_SIZE) != 0) {
print_buffer (message + mhsize, KEEPALIVE_AUTHENTICATION_SIZE,
              "new sender secret", 8, 0);
print_buffer (sav->keepalive_auth, KEEPALIVE_AUTHENTICATION_SIZE,
              ", old", 8, 0);
printf (" for ");
print_sockaddr ((struct sockaddr *) (&(sav->addr)), sav->alen);
printf ("\n");
  }
#endif /* LOG_PACKETS */
  /* save the received sender keepalive secret, even if it is the same
   * memcpy should be cheaper than memcmp */
  memcpy (sav->keepalive_auth, message + mhsize,
          KEEPALIVE_AUTHENTICATION_SIZE);
}

/* keep this information for addresses in the routing table, which we
 * don't add to the sockets structure */
struct allnet_keepalive_entry {
  struct sockaddr_storage addr;
  socklen_t alen;
  char keepalive_auth [KEEPALIVE_AUTHENTICATION_SIZE];
};
struct allnet_keepalive_entry routing_keepalives [ADDRS_MAX];
int num_routing_keepalives = 0;

/* return -1 if not found, otherwise the index of the keepalive */
static int routing_keepalive_index (struct sockaddr_storage addr,
                                    socklen_t alen)
{
  int i;
  for (i = 0; i < num_routing_keepalives; i++)
    if (same_sockaddr (&(routing_keepalives [i].addr),
                       routing_keepalives [i].alen, &addr, alen))
      return i;
  return -1;
}

/* returns 1 if this is a new keepalive or for a new address */
static int add_routing_keepalive (struct sockaddr_storage addr, socklen_t alen,
                                  char * keepalive_auth)
{
  int index = routing_keepalive_index (addr, alen);
  if ((index < 0) || (index >= num_routing_keepalives)) {
    if (num_routing_keepalives < ADDRS_MAX)
      index = num_routing_keepalives++;       /* add at the end, increment */
    else
      index = (int) random_int (0, ADDRS_MAX - 1); /* replace a random entry */
  }
  if ((index < 0) || (index >= ADDRS_MAX)) {
    printf ("error in add_routing_keepalive, 0 < %d < %d\n", index, ADDRS_MAX);
exit (1);
  }
  if ((same_sockaddr (&(routing_keepalives [index].addr),
                      routing_keepalives [index].alen, &addr, alen)) &&
      (memcmp (routing_keepalives [index].keepalive_auth, keepalive_auth, 
               KEEPALIVE_AUTHENTICATION_SIZE) == 0))
    return 0;   /* we already have it, no need to resend the keepalive */
  memcpy (routing_keepalives [index].keepalive_auth, keepalive_auth, 
          KEEPALIVE_AUTHENTICATION_SIZE);
  routing_keepalives [index].addr = addr;
  routing_keepalives [index].alen = alen;
  return 1;
}

/* sends the ack to the address, given that hp has the packet we are acking */
static void send_ack (const char * ack, const struct allnet_header * hp,
                      int sockfd, struct sockaddr_storage addr, socklen_t alen,
                      int is_local)
{
  char message [ALLNET_HEADER_SIZE + MESSAGE_ID_SIZE + 4];
  int msize = sizeof (message);
  int expected_allnet_size = msize - 4;  /* the size without priority */
  if (! is_local)
    msize -= 4;
  unsigned int size = 0;
  init_ack (hp, (const unsigned char *) ack, NULL, ADDRESS_BITS,
            message, &size);
  if (size != expected_allnet_size)
    printf ("send_ack: %d != actual size %d, l %d\n",
            expected_allnet_size, size, is_local);
  if (is_local)
    writeb32 (message + (sizeof (message) - 4), ALLNET_PRIORITY_LOCAL);
  /* send this ack back to the sender, no need to ack more widely */
  socket_send_to_ip (sockfd, message, msize, addr, alen, "ad.c/send_ack");
}

static void send_routing_keepalive (int sockfd, struct sockaddr_storage addr,
                                    socklen_t alen)
{
  int index = routing_keepalive_index (addr, alen);
  char * receiver_auth = ((index < 0) ? NULL :
                          routing_keepalives [index].keepalive_auth);
  char message [ALLNET_MTU];
  int msize = keepalive_auth (message, sizeof (message),
                              addr, sockets.random_secret,
                              sizeof (sockets.random_secret),
                              sockets.counter, receiver_auth);
  if (! socket_send_to_ip (sockfd, message, msize, addr, alen, "sending probe"))
    print_buffer ((char *)&(addr), alen, "error sending probe keepalive to",
                  100, 1);
}

static void send_one_keepalive (const char * desc,
                                struct socket_address_set * sock,
                                struct socket_address_validity * sav,
                                const char * secret, int slen, uint64_t counter)
{
  unsigned int msize;
  const char * message = keepalive_packet (&msize);
  char auth_msg [ALLNET_MTU];
  if (sock->is_global_v4 || sock->is_global_v6) {
    msize = keepalive_auth (auth_msg, sizeof (auth_msg),
                            sav->addr, secret, slen, counter,
                            sav->keepalive_auth);
    message = auth_msg;
#ifdef DEBUG_PRINT
    print_buffer (message, msize, "sending larger keepalive", 100, 0);
    print_buffer ((char *)&(sav->addr), sav->alen, ", to", 24, 1);
#endif /* DEBUG_PRINT */
  }
  socket_send_to (message, msize, ALLNET_PRIORITY_EPSILON, virtual_clock,
                  &sockets, sock, sav);
}

/* returns 1 if the address is in the bitmap, otherwise returns 0 and adds it */
static int check_recent_address (struct sockaddr_storage addr)
{
  static int my_modulo = 11;  /* prime number < size of bitmap */
  static uint16_t bitmap = 0;
  static unsigned long long int start_time = 0;
  unsigned long long int now = allnet_time ();
  if (now > start_time + my_modulo) {  /* average at most one per second */
    bitmap = 0;
    start_time = now;
    switch (my_modulo) {
/* to make continuing collisions less likely, switch the modulo around.
 * we can do this because we just reset the bitmap. */
      case 11: my_modulo = 13; break;
      case 13: my_modulo = 7; break;
      case 7:
      default: my_modulo = 11; break;
    }
  }
  /* now get a hash of the address.  For IPv4, the address is the hash */
  uint64_t hash = 0;
  if (addr.ss_family == AF_INET) {
    struct sockaddr_in * sin = (struct sockaddr_in *) (&addr);
    hash = sin->sin_addr.s_addr;
  } else if (addr.ss_family == AF_INET6) {
    struct sockaddr_in6 * sin = (struct sockaddr_in6 *) (&addr);
    hash = readb64 ((char *) sin->sin6_addr.s6_addr) +
           readb64 ((char *) sin->sin6_addr.s6_addr + 8);
  }
  if (hash == 0)
    return 1;      /* weird address, do not send a keepalive */
  while ((hash % my_modulo) == 0)
    hash = hash / my_modulo;
  int pos = hash % my_modulo;
  uint16_t mask = 1 << pos;
  if (bitmap & mask)
    return 1;
  bitmap |= mask;
  return 0;
}

/* if this is a keepalive with only a sender authentication, send back
 * a keepalive with my authentication as well as the sender's authentication */
static void send_auth_response (int sockfd, struct sockaddr_storage addr,
                                socklen_t alen, const char * secret, int slen,
                                uint64_t counter,
                                const char * message, int msize)
{
  if (check_recent_address (addr))
    return;
  if (msize < ALLNET_HEADER_SIZE)
    return;
  const struct allnet_header * hp = (const struct allnet_header *) message;
  int hsize = ALLNET_SIZE (hp->transport);
  if (msize < hsize)
    return;
  int mhsize = ALLNET_MGMT_HEADER_SIZE (hp->transport);
  int wanted_size1 = mhsize + KEEPALIVE_AUTHENTICATION_SIZE;
  int wanted_size2 = wanted_size1 + KEEPALIVE_AUTHENTICATION_SIZE;
  const struct allnet_mgmt_header * mhp =
    (const struct allnet_mgmt_header *) (message + hsize);
  const char * receiver_auth = NULL;
  if (((msize == wanted_size1) || (msize == wanted_size2)) &&
      (hp->message_type == ALLNET_TYPE_MGMT) &&
      (mhp->mgmt_type == ALLNET_MGMT_KEEPALIVE))
    receiver_auth = message + mhsize;
  char response [ALLNET_MTU];
  unsigned int rsize = keepalive_auth (response, sizeof (response),
                                       addr, secret, slen, counter,
                                       receiver_auth);
  socket_send_to_ip (sockfd, response, rsize, addr, alen,
                     "ad.c/send_auth_response");
}

#ifdef THROTTLE_SENDING
static int new_priority_threshold (int old_priority_threshold,
                                   long long int send_start,
                                   long long int bytes_sent)
{
  int new_threshold = old_priority_threshold;  /* default */
  static long long int measurement_start = 0;
  static long long int measurement_time = 0;
  static long long int measurement_bytes = 0;
#define BASIC_MEASUREMENT_INTERVAL	1	/* 60? */
  static long long int measurement_interval = BASIC_MEASUREMENT_INTERVAL;
  long long int now = allnet_time_us ();
  long long int delta = now - send_start;
  measurement_time += delta;
  measurement_bytes += bytes_sent;
  long long int now_s = now / ALLNET_US_PER_S;
  long long int delta_s = now_s - measurement_start;
  /* throttle if we are averaging more than 8KB/second, or 
   * if our send time is more than 1% -- since the measurement_time is
   * in microseconds, the percentage is multiplied by 10,000, i.e. tenK */
  const long long int max_rate = 8000;  /* 8KB/s -- later, configurable */
  const long long int max_percent_tenK = 10000;  /* 1% for now */
  if (now_s > measurement_start + measurement_interval) {
    /* new interval, compute */
#ifdef DEBUG_FOR_DEVELOPER
printf ("measured: %lld / %lld = %lldB/s, t%% %lld / %lld = %lld: thresh %08x",
        measurement_bytes, delta_s, measurement_bytes / delta_s,
        measurement_time, delta_s, measurement_time / delta_s,
        old_priority_threshold);
#endif /* DEBUG_FOR_DEVELOPER */
    if ((bytes_sent > 0) &&
        ((measurement_bytes / delta_s > max_rate) ||
         (measurement_time / delta_s > max_percent_tenK))) {
      new_threshold += (ALLNET_PRIORITY_MAX - old_priority_threshold) / 8;
#ifdef DEBUG_FOR_DEVELOPER
printf (" -> %08x (slower)\n", new_threshold);
#endif /* DEBUG_FOR_DEVELOPER */
    } else if (((new_threshold > ALLNET_PRIORITY_EPSILON) &&
                (measurement_bytes / delta_s < (max_rate / 2)) &&
                (measurement_time / delta_s < (max_percent_tenK / 2))) ||
               (bytes_sent == 0)) {
#ifdef DEBUG_FOR_DEVELOPER
int debug_threshold = new_threshold;
#endif /* DEBUG_FOR_DEVELOPER */
      int decrease = ALLNET_PRIORITY_ONE_EIGHT;
      new_threshold = (new_threshold > decrease) ? (new_threshold - decrease) :
                      ALLNET_PRIORITY_EPSILON;
#ifdef DEBUG_FOR_DEVELOPER
if (debug_threshold > new_threshold)
printf (" -> %08x (faster)\n", new_threshold);
else printf ("\n");
#endif /* DEBUG_FOR_DEVELOPER */
    } else {
#ifdef DEBUG_FOR_DEVELOPER
printf ("\n");
#endif /* DEBUG_FOR_DEVELOPER */
    }
    if (new_threshold <= ALLNET_PRIORITY_EPSILON) { /* start new measurement */
      measurement_start = now_s;
      measurement_time = 0;
      measurement_bytes = 0;
      measurement_interval = BASIC_MEASUREMENT_INTERVAL;
    } else {   /* continue to measure, until we get to less than max_rate */
      measurement_interval = (now_s - measurement_start) +
                             BASIC_MEASUREMENT_INTERVAL;
    }
  }
  return new_threshold;
}
#undef BASIC_MEASUREMENT_INTERVAL

static int skip_this_packet (int priority)
{
  static int skipped = 0;
  int skipping = 10;  /* normally, send 1 in 10 lower-priority packets */
  if (priority_threshold >= ALLNET_ONE_HALF) skipping = 100; /* cut back */
  if (priority_threshold >= ALLNET_PRIORITY_LOCAL_LOW) skipping = 1000; /* !! */
  if ((priority < priority_threshold) && (skipped++ % skipping != 0))
    return 1;
  return 0;
}
#endif /* THROTTLE_SENDING */

/* send to a limited number of DHT addresses and to socket_send_out */
static void send_out (const char * message, int msize, int max_addrs,
                      const struct sockaddr_storage * except, /* may be NULL */
                      socklen_t elen,  /* should be 0 if except is NULL */
                      int priority, int throttle_and_count,
                      /* if sent_to is not NULL, num_sent should also not be */
                      struct sockaddr_storage * sent_to,
                      int * sent_num)
{
  int sent_available = 0;
  int sent_index = 0;
  if (sent_num != NULL) {
    sent_available = *sent_num;
    *sent_num = 0;
  }
#ifdef THROTTLE_SENDING
  if (throttle_and_count && (skip_this_packet (priority)))
    return;
  long long int send_start = allnet_time_us ();
  long long int bytes_sent = 0;
#endif /* THROTTLE_SENDING */
  const struct allnet_header * hp = (const struct allnet_header *) message;
  /* only forward out if max_hops is reasonable and hops < max_hops */
  if ((hp->max_hops <= 0) || (hp->hops >= 255) || (hp->hops >= hp->max_hops))
    return;
  if (max_addrs > ADDRS_MAX) {
    printf ("error: send_out called with %d > %d\n", max_addrs, (int)ADDRS_MAX);
    return;
  }
  struct sockaddr_storage addrs [ADDRS_MAX];
  socklen_t alens [ADDRS_MAX];
  memset (addrs, 0, sizeof (addrs));
  int num_addrs = routing_top_dht_matches (hp->destination, hp->dst_nbits,
                                           addrs, alens, max_addrs);
  int dht_send_error = 0;
  int i;
#ifdef DEBUG_FOR_DEVELOPER_OFF
printf ("ad.c/send_out got %d routing addresses\n", num_addrs);
for (i = 0; i < num_addrs; i++)
print_buffer (&addrs [i], alens [i], NULL, alens [i], 1);
#endif /* DEBUG_FOR_DEVELOPER_OFF */
#define SEND_KEEPALIVES_EVERY	(SEND_LIMIT_DEFAULT / 5)   /* 19 */
  static int sent_count = SEND_KEEPALIVES_EVERY;
  int send_keepalives = 0;
  /* send a keepalive whenever sent_count >= 19 */
  if (sent_count++ >= SEND_KEEPALIVES_EVERY) {
    sent_count = 0;
    send_keepalives = 1;
  }
  for (i = 0; i < num_addrs; i++) {
    struct sockaddr_storage dest = addrs [i];
    socklen_t alen = alens [i];
    int sockfd = sock_v4;
    if (dest.ss_family == AF_INET6) {
      sockfd = sock_v6;
    } else if (sockfd < 0) {  /* if sock_v4 is not valid, use sock_v6 */
      sockfd = sock_v6;
#ifdef __APPLE__
      ai_embed_v4_in_v6 (&dest, &alen);  /* needed on apple systems */
#endif /* __APPLE__ */
    }
    if (sockfd >= 0) {
      if (send_keepalives) {
        send_routing_keepalive (sockfd, dest, alen);
#ifdef THROTTLE_SENDING
        bytes_sent += 48;
#endif /* THROTTLE_SENDING */
      }
      if (! socket_send_to_ip (sockfd, message, msize, dest, alen,
                               "ad.c/send_out")) {
        dht_send_error = 1;
#ifdef THROTTLE_SENDING
        bytes_sent += msize;
#endif /* THROTTLE_SENDING */
      } else {
        if ((sent_to != NULL) && (sent_index < sent_available))
          sent_to [sent_index] = dest;
        sent_index++;
      }
    }
  }
  if (send_keepalives)
    socket_send_keepalives (&sockets, virtual_clock, SEND_KEEPALIVES_LOCAL,
                            SEND_KEEPALIVES_REMOTE);
  static struct sockaddr_storage empty;  /* used if except is null */
  struct sockaddr_storage * my_sent_to = ((sent_to == NULL) ? NULL :
                                          (sent_to + sent_index));
  int my_sent_num = minz (sent_available, sent_index);
  socket_send_out (&sockets, message, msize, virtual_clock,
                   ((except == NULL) ? empty : *except), elen,
                   my_sent_to, &my_sent_num);
  if (dht_send_error)
    routing_expire_dht (&sockets);
  int sent_total = sent_index + my_sent_num;
  if (sent_num != NULL)
    *sent_num = sent_total;
#ifdef THROTTLE_SENDING
  bytes_sent += (msize + 48) * sent_total;
  if (throttle_and_count)  /* don't count locally-sent traffic */
    priority_threshold =
      new_priority_threshold (priority_threshold, send_start, bytes_sent);
#endif /* THROTTLE_SENDING */
}

static void update_dht ()
{
  char * dht_message = NULL;
  unsigned int msize = dht_update (&sockets, &dht_message);
  if ((msize > 0) && (dht_message != NULL)) {
    struct sockaddr_storage sas;
    memset (&sas, 0, sizeof (sas));
    socket_send_local (&sockets, dht_message, msize, ALLNET_PRIORITY_LOCAL_LOW,
                       virtual_clock, sas, 0);
    send_out (dht_message, msize, ROUTING_DHT_ADDRS_MAX, NULL, 0,
              ALLNET_PRIORITY_LOCAL_LOW, 0, NULL, NULL);
    free (dht_message);
  }
}

static struct socket_address_validity *
  add_received_address (struct socket_read_result r)
{
  int send_keepalive = 0;
  long long int limit = virtual_clock + ((r.sock->is_local) ? 6 : 180);
  struct socket_address_validity sav =
    { .alive_rcvd = virtual_clock, .alive_sent = virtual_clock,
      .send_limit = SEND_LIMIT_DEFAULT,
      .send_limit_on_recv = SEND_LIMIT_DEFAULT,
      .recv_limit = RECV_LIMIT_DEFAULT,
      .time_limit = limit, .alen = r.alen };
  memset (&(sav.keepalive_auth), 0, sizeof (sav.keepalive_auth));
  /* send a keepalive if: (a) this is a new keepalive, or (b) this is a
   * new (non-routing) address */
  const struct allnet_header * hp = (const struct allnet_header *) r.message;
  int hsize = ALLNET_MGMT_HEADER_SIZE (hp->transport);
  if ((r.msize >= hsize + KEEPALIVE_AUTHENTICATION_SIZE) &&
      (is_auth_keepalive (r.from, sockets.random_secret,
                         sizeof (sockets.random_secret), sockets.counter,
                         r.message, r.msize))) {
    memcpy (&(sav.keepalive_auth), r.message + hsize,  /* sender auth */
            sizeof (sav.keepalive_auth));
    if ((is_in_routing_table ((struct sockaddr *) &(r.from), r.alen)) &&
        (add_routing_keepalive (r.from, r.alen, sav.keepalive_auth)))
      send_keepalive = 1;
  }
  memcpy (&(sav.addr), &(r.from), sizeof (r.from));
  struct socket_address_validity * result = NULL;
  if (! is_in_routing_table ((struct sockaddr *) &(r.from), r.alen)) {
    result = socket_address_add (&sockets, r.sock->sockfd, sav);
    if (result == NULL)
      printf ("odd: unable to add new address\n");
    send_keepalive = 1;
  }
  if (send_keepalive)
    send_one_keepalive ("add_received_address", r.sock,
                        ((result != NULL) ? result : &sav),
                        sockets.random_secret, sizeof (sockets.random_secret),
                        sockets.counter);
  return result;
}

static int send_message_to_one (const char * message, int msize, int priority,
                                const unsigned char * token,
                                struct socket_address_set * sock,
                                struct sockaddr_storage addr, socklen_t alen)
{
#ifdef THROTTLE_SENDING
  if (skip_this_packet (priority))
    return 0;
  long long int send_start = allnet_time_us ();
  long long int bytes_sent = 0;
#endif /* THROTTLE_SENDING */
#ifdef LOG_PACKETS
  snprintf (alog->b, alog->s, "%s (%d bytes, prio %d, to pipe %d)\n",
            "send_one_message_to", msize, priority, sock->sockfd);
#ifdef DEBUG_FOR_DEVELOPER_OFF
  printf ("-> %s", alog->b);
  print_buffer (&addr, alen, " to", alen, 1);
#endif /* DEBUG_FOR_DEVELOPER_OFF */
  log_print (alog);
  log_packet (alog, "message to pipe", message, msize);
#endif /* LOG_PACKETS */
  char message_with_priority [ALLNET_MTU + 2];
  if (sock->is_local) {
    memcpy (message_with_priority, message, msize);
    writeb16 (message_with_priority + msize, priority);
    message = message_with_priority;
    msize += 2;
  }
  if (token != NULL)
    pcache_mark_token_sent ((const char * ) token, message, msize);
  int result = socket_send_to_ip (sock->sockfd, message, msize, addr, alen,
                                  "ad.c/send_message_to_one");
#ifdef THROTTLE_SENDING
  if (! sock->is_local) {
    bytes_sent += msize;
    priority_threshold =
      new_priority_threshold (priority_threshold, send_start, bytes_sent);
  }
#endif /* THROTTLE_SENDING */
  return result;
}

/* return the number of messages sent (r.n), or 0 if none */
static int send_messages_to_one (struct pcache_result r,
                                 const unsigned char * token,
                                 struct socket_address_set * sock,
                                 struct sockaddr_storage addr, socklen_t alen)
{
  if (r.n <= 0)
    return 0;
  if ((! sock->is_local) && (r.n > SEND_EXTERNAL_MAX))
    r.n = SEND_EXTERNAL_MAX;
  int result = 0;
  int i;
  for (i = 0; i < r.n; i++)
    result += send_message_to_one (r.messages [i].message, r.messages [i].msize,
                                   r.messages [i].priority, token,
                                   sock, addr, alen);
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
  char local_token [ALLNET_TOKEN_SIZE];
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
                                  .priority = r->priority, .allocated = 0,
                                  .debug_reason = "process_mgmt generic drop" };
  struct message_process all  = { .process = PROCESS_PACKET_ALL,
                                  .message = r->message, .msize = r->msize,
                                  .priority = r->priority, .allocated = 0,
                                  .debug_reason = "process_mgmt generic all" };
  struct allnet_header * hp = (struct allnet_header *) r->message;
  int hs = ALLNET_AFTER_HEADER (hp->transport, r->msize);
  drop.debug_reason = "process_mgmt too small for mgmt header";
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
    drop.debug_reason = "beacon";
  case ALLNET_MGMT_BEACON_REPLY:
    if (ahm->mgmt_type == ALLNET_MGMT_BEACON_REPLY)
      drop.debug_reason = "beacon_reply";
  case ALLNET_MGMT_BEACON_GRANT:
    if (ahm->mgmt_type == ALLNET_MGMT_BEACON_GRANT)
      drop.debug_reason = "beacon_grant";
  case ALLNET_MGMT_KEEPALIVE:
    if (ahm->mgmt_type == ALLNET_MGMT_KEEPALIVE)
      drop.debug_reason = "keepalive";
    return drop;   /* do not forward beacons or keepalives */
  case ALLNET_MGMT_DHT:
    dht_process (r->message, r->msize, (struct sockaddr *) &(r->from), r->alen);
    all.debug_reason = "dht";
    return all;
  case ALLNET_MGMT_PEER_REQUEST:
  case ALLNET_MGMT_PEERS:
    all.debug_reason = "peers or peer request";
    return all;
#ifdef IMPLEMENT_MGMT_ID_REQUEST  /* not used, so, not implemented */
  case ALLNET_MGMT_ID_REQUEST:
    assert (0);
    struct allnet_mgmt_id_request * id_req = (struct allnet_mgmt_id_request *)
                  (r->message + ALLNET_MGMT_HEADER_SIZE (hp->transport));
    send_messages_to_one (pcache_id_request (id_req), NULL, r->sock,
                          r->from, r->alen);
    all.debug_reason = "id request";
    return all;     /* and forward the request*/
#endif /* IMPLEMENT_MGMT_ID_REQUEST */
  case ALLNET_MGMT_TRACE_REQ:
    drop.debug_reason = "trace request seen before";
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
      if (! r->sock->is_local) {
        struct allnet_header * thp = (struct allnet_header *) trace_reply;
        if (thp->max_hops == 1)    /* just return to the sender */
          send_message_to_one (trace_reply, trace_reply_size,
                               ALLNET_PRIORITY_TRACE, NULL, r->sock,
                               r->from, r->alen);
        else
          send_out (trace_reply, trace_reply_size, ROUTING_ADDRS_MAX,
                    NULL, 0, ALLNET_PRIORITY_TRACE, 1, NULL, NULL);
      }
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
      all.debug_reason = "trace request forward";
      return all;
    }
    drop.debug_reason = "trace request do not forward";
    return drop;
  case ALLNET_MGMT_TRACE_REPLY:
    drop.debug_reason = "trace_reply do not forward";
    if (mgmt_payload_size <= 0)
      drop.debug_reason = "trace_reply payload too small";
    if ((mgmt_payload_size <= 0) ||
        (pcache_trace_reply (mgmt_payload, mgmt_payload_size)))
      return drop;  /* invalid, or seen before */
    all.priority = ALLNET_PRIORITY_TRACE;
    pcache_save_packet (r->message, r->msize, ALLNET_PRIORITY_TRACE);
    all.debug_reason = "trace_reply";
    return all;
  default:
    snprintf (alog->b, alog->s, "unknown management message type %d\n",
              ahm->mgmt_type);
    log_print (alog);   /* forward unknown management messages */
    all.priority = ALLNET_PRIORITY_TRACE;
    all.debug_reason = "unknown management packet";
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
          .message = NULL, .msize = 0, .priority = r->priority, .allocated = 0,
          .debug_reason = "process_message generic drop" };
  struct allnet_header * hp = (struct allnet_header *) r->message;
  int seen_before = 0;
  int save_message = 1;
  if (hp->message_type == ALLNET_TYPE_ACK) {
    r->msize = process_acks (hp, r->msize);
    drop.debug_reason = "message size 0 or less";
    if (r->msize <= 0)
      return drop;                   /* no new acks, drop the message */
    save_message = 0;                /* already saved the new acks */
  } else {
    char id [MESSAGE_ID_SIZE];
    drop.debug_reason = "message does not have an ID";
    if (! pcache_message_id (r->message, r->msize, id))
      return drop;          /* no message ID, drop the message */
    char ack [MESSAGE_ID_SIZE];   /* filled in if ack_found */
    if (pcache_id_acked (id, ack)) {  /* ack this message */
      send_ack (ack, hp, r->sock->sockfd, r->from, r->alen, r->sock->is_local);
      seen_before = 1;
    } else {
      seen_before = pcache_id_found (id);
    }
    if ((! r->sock->is_local) && (seen_before)) {
      struct message_process local_forward =
        { .process = PROCESS_PACKET_LOCAL,
          .message = r->message, .msize = r->msize, .priority = r->priority,
          .allocated = 0, .debug_reason = "nonlocal message seen before" };
      return local_forward; /* we have seen it before, only forward locally */
    }
    if (hp->message_type == ALLNET_TYPE_DATA_REQ) {
      static int none_until = 0;
      if ((! r->sock->is_local) &&
          (none_until != 0) && (allnet_time () < none_until)) {
        drop.debug_reason = "data request within 10s of the last data request";
        return drop;
      }
      if (! r->sock->is_local)
        none_until = allnet_time () + 10;
      char * data = ALLNET_DATA_START (hp, hp->transport, r->msize);
      struct allnet_data_request * req = (struct allnet_data_request *) data;
      struct sockaddr_storage saddr = ((r->sav != NULL) ? r->sav->addr
                                                        : r->from);
      socklen_t salen = ((r->sav != NULL) ? r->sav->alen : r->alen);
      int max_messages = ((r->sock->is_local) ? 0 : SEND_EXTERNAL_MAX);
#ifdef DEBUG_FOR_DEVELOPER
#ifdef DEBUG_PRINT
print_packet (r->message, r->msize, "received data request", 1);
#endif /* DEBUG_PRINT */
#endif /* DEBUG_FOR_DEVELOPER */
      char request_buffer [50000];
      struct pcache_result cached_messages =
        pcache_request (req, max_messages,
                        request_buffer, sizeof (request_buffer));
      send_messages_to_one (cached_messages, req->token, r->sock, saddr, salen);
      /* replace the token in the message with our own token */
      pcache_current_token ((char *) (req->token));
      /* and then do normal packet processing (forward) this data request */
    }
  }
  if (! r->sock->is_local)
    r->priority = message_priority (r->message, hp, r->msize);
  /* below here the message should be valid, forward it */
#define DEBUG_MESSAGE_FORMAT "process_message success, save %d, seen %d      "
  static char debug_message [] = DEBUG_MESSAGE_FORMAT;
  snprintf (debug_message, sizeof (debug_message), DEBUG_MESSAGE_FORMAT,
            save_message, seen_before);
  struct message_process result =
        { .process = PROCESS_PACKET_ALL, .message = r->message,
          .msize = r->msize, .priority = r->priority, .allocated = 0,
          .debug_reason = debug_message };
  if (save_message && (! seen_before)) {
    if ((hp->transport & ALLNET_TRANSPORT_DO_NOT_CACHE) == 0)
      pcache_save_packet (r->message, r->msize, r->priority);
    else
      pcache_record_packet (r->message, r->msize);
  }
  return result;
}

void allnet_daemon_loop ()
{
  while (1) {
    char message [SOCKET_READ_MIN_BUFFER];
    struct socket_read_result r = socket_read (&sockets, message,
                                               10, virtual_clock);
    char * reason_not_valid = "size less than 24";
    if ((! r.success) || (r.message == NULL) ||
        (r.msize < ALLNET_HEADER_SIZE) ||
        (! is_valid_message (r.message, r.msize, &reason_not_valid))) {
#ifdef LOG_PACKETS
if ((r.success) && (r.message != NULL) &&
    (strcmp (reason_not_valid, "hops > max_hops") != 0) &&
    (strcmp (reason_not_valid, "expired packet") != 0))
printf ("invalid message of size %d, %s\n", r.msize, reason_not_valid);
#endif /* LOG_PACKETS */
      continue;   /* no valid message, no action needed, restart the loop */
    }
#ifdef DEBUG_FOR_DEVELOPER
#ifdef DEBUG_PRINT
printf ("received %d bytes\n", r.msize);
if (is_in_routing_table ((struct sockaddr *) &(r.from), r.alen))
print_buffer (&(r.from), r.alen, "routing address", r.alen, 0);
else if (r.socket_address_is_new)
print_buffer (&(r.from), r.alen, "new address", r.alen, 0);
else
print_buffer (&(r.from), r.alen, "existing address", r.alen, 0);
print_packet (r.message, r.msize, ", packet", 1);
print_socket_set (&sockets);
#endif /* DEBUG_PRINT */
#endif /* DEBUG_FOR_DEVELOPER */
    if (! r.socket_address_is_new)
      update_sender_keepalive (r.message, r.msize, r.sav);
    if ((r.socket_address_is_new) &&
        ((r.sock->is_global_v4) || (r.sock->is_global_v6)) &&
        (! is_auth_keepalive (r.from, sockets.random_secret,
                              sizeof (sockets.random_secret),
                              sockets.counter, r.message, r.msize))) {
      /* respond with a challenge, see if they get back to us */
      send_auth_response (r.sock->sockfd, r.from, r.alen, sockets.random_secret,
                          sizeof (sockets.random_secret),
                          sockets.counter, r.message, r.msize);
#ifdef DEBUG_FOR_DEVELOPER
#define STRICT_AUTHENTICATION
#endif /* DEBUG_FOR_DEVELOPER */
#ifdef STRICT_AUTHENTICATION
      if (! is_in_routing_table ((struct sockaddr *) &(r.from), r.alen)) {
#ifdef LOG_PACKETS
printf ("%d-byte message from unauthenticated sender: %02x -> %02x, ", r.msize,
        (r.msize >= 24) ? (r.message [8] & 0xff) : 0,
        (r.msize >= 24) ? (r.message [16] & 0xff) : 0);
print_sockaddr ((struct sockaddr *) (&(r.from)), r.alen);
printf ("\n");
#endif /* LOG_PACKETS */
        continue;   /* not authenticated, do not process this packet */
      }
#endif /* STRICT_AUTHENTICATION */
    }
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
    if ((m.process & PROCESS_PACKET_LOCAL) && (hp->hops <= hp->max_hops))
      socket_send_local (&sockets, m.message, m.msize, m.priority,
                         virtual_clock, r.from, r.alen);
#define MAX_SENT_ADDRS	1000
    int num_sent_addrs = MAX_SENT_ADDRS;
    struct sockaddr_storage sent_addrs [MAX_SENT_ADDRS];
#undef MAX_SENT_ADDRS
    if ((m.process & PROCESS_PACKET_OUT) && (hp->hops <= hp->max_hops))
      send_out (m.message, m.msize, ROUTING_ADDRS_MAX,
                &(r.from), r.alen, m.priority, (! r.sock->is_local),
                sent_addrs, &num_sent_addrs);
    else
      num_sent_addrs = -1;
    if ((m.allocated) && (m.message != NULL))
      free (m.message);
    if (r.recv_limit_reached) {  /* time to send a keepalive */
      socket_update_recv_limit (RECV_LIMIT_DEFAULT, &sockets, r.from, r.alen);
      if (r.sav != NULL)
        send_one_keepalive ("update_recv_limit", r.sock, r.sav,
                            sockets.random_secret,
                            sizeof (sockets.random_secret), sockets.counter);
    }
    update_virtual_clock ();
    update_dht ();
    int debug_priority = 0;
#ifdef THROTTLE_SENDING
    debug_priority = priority_threshold;
#endif /* THROTTLE_SENDING */
    sockets_log_addresses ("ad.c at end of cycle", &sockets,
                           (num_sent_addrs >= 0 ? sent_addrs : NULL),
                           num_sent_addrs, debug_priority);
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
  update_virtual_clock ();  /* 2018/08/03: not sure if this is useful */
  allnet_daemon_loop ();
}
