/* util.c: a place for useful functions used by different programs */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <time.h>
#include <assert.h>
#include <errno.h>
#include <netdb.h>  /* h_errno */
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#ifndef __APPLE__
#include <netpacket/packet.h>
#endif /* __APPLE__ */
#include <arpa/inet.h>

#include "packet.h"
#include "mgmt.h"
#include "log.h"
#include "util.h"
#include "ai.h"
#include "sha.h"

/* print up to max of the count characters in the buffer.
 * desc is printed first unless it is null
 * a newline is printed after if print_eol
 */
void print_buffer (const char * buffer, int count, char * desc,
                   int max, int print_eol)
{
  int i;
  if (desc != NULL)
    printf ("%s (%d bytes):", desc, count);
  else
    printf ("%d bytes:", count);
  if (buffer == NULL)
    printf ("(null)");
  else {
    for (i = 0; i < count && i < max; i++)
      printf (" %02x", buffer [i] & 0xff);
    if (i < count)
      printf (" ...");
  }
  if (print_eol)
    printf ("\n");
}

/* same as print_buffer, but prints to the given string */
int buffer_to_string (const char * buffer, int count, char * desc,
                      int max, int print_eol, char * to, int tsize)
{
  int i;
  int offset;
  if (desc != NULL)
    offset = snprintf (to, tsize, "%s (%d bytes):", desc, count);
  else
    offset = snprintf (to, tsize, "%d bytes:", count);
  if (buffer == NULL)
    offset += snprintf (to + offset, tsize - offset, "(null)");
  else {
    for (i = 0; i < count && i < max; i++)
      offset += snprintf (to + offset, tsize - offset,
                          " %02x", buffer [i] & 0xff);
    if (i < count)
      offset += snprintf (to + offset, tsize - offset, " ...");
  }
  if (print_eol)
    offset += snprintf (to + offset, tsize - offset, "\n");
  return offset;
}

static char * mtype_to_string (int mtype)
{
  switch (mtype) {
  case ALLNET_TYPE_DATA:
    return "data";
  case ALLNET_TYPE_ACK:
    return "ack";
  case ALLNET_TYPE_DATA_REQ:
    return "data request";
  case ALLNET_TYPE_KEY_XCHG:
    return "key exchange";
  case ALLNET_TYPE_KEY_REQ:
    return "key request";
  case ALLNET_TYPE_CLEAR:
    return "clear";
  case ALLNET_TYPE_MGMT:
    return "mgmt";
  default:
    return "unknown message type";
  }
}

#if 0
static char * mgmt_type_to_string (int mtype)
{
  switch (mtype) {
  case ALLNET_MGMT_BEACON:
    return "beacon";
  case ALLNET_MGMT_BEACON_REPLY:
    return "beacon reply";
  case ALLNET_MGMT_BEACON_GRANT:
    return "beacon grant";
  case ALLNET_MGMT_PEER_REQUEST:
    return "peer request";
  case ALLNET_MGMT_PEERS:
    return "peers";
  case ALLNET_MGMT_DHT:
    return "DHT";
  case ALLNET_MGMT_TRACE_REQ:
    return "trace request";
  case ALLNET_MGMT_TRACE_REPLY:
    return "trace reply";
  default:
    return "unknown management type";
  }
}
#endif /* 0 */

/* returned buffer is statically allocated */
static char * b2s (const char * buffer, int count)
{
  static char result [10000];
  *result = '\0';    /* set result to the empty string */
  if ((buffer == NULL) || (count < 1))
    return result;
  if (count + 1 >= sizeof (result) / 2)
    count = sizeof (result) / 2 - 1;
  result [0] = '\0';   /* in case count <= 0 */
  int i;
  int offset = 0;
  for (i = 0; i < count; i++) {
    offset += snprintf (result + offset, sizeof (result) - offset,
                        "%02x", buffer [i] & 0xff);
  }
  return result;
}

static char * b2su (const unsigned char * buffer, int count)
{
  return b2s ((const char *) buffer, count);
}

static int trace_entry_to_string (const struct allnet_mgmt_trace_entry * e,
                                  char * to, int tsize)
{
  return snprintf (to, tsize, "%d %lld.%lld@%d %s/%d, ", e->precision,
                   readb64 ((const char *) (e->seconds)),
                   readb64 ((const char *) (e->seconds_fraction)),
                   e->nbits, b2s ((const char *) (e->address), ADDRESS_SIZE),
                   e->hops_seen);
}

static int mgmt_to_string (int mtype, const char * hp, int hsize,
                          char * to, int tsize)
{
  int r = snprintf (to, tsize, " mt %d ", mtype);

  switch (mtype) {
  case ALLNET_MGMT_BEACON:
    if (hsize < sizeof (struct allnet_mgmt_beacon)) {
      r += snprintf (to + r, tsize - r, "beacon size %d, min %zd\n",
                     hsize, sizeof (struct allnet_mgmt_beacon));
    } else {
      const struct allnet_mgmt_beacon * amb =
        (const struct allnet_mgmt_beacon *) hp;
      r += snprintf (to + r, tsize - r, "beacon %s (%lldns)",
                     b2su (amb->receiver_nonce, NONCE_SIZE),
                     readb64 ((char *) (amb->awake_time)));
    }
    break;
  case ALLNET_MGMT_BEACON_REPLY:
    if (hsize < sizeof (struct allnet_mgmt_beacon_reply)) {
      r += snprintf (to + r, tsize - r, "beacon reply size %d, min %zd\n",
                     hsize, sizeof (struct allnet_mgmt_beacon_reply));
    } else {
      const struct allnet_mgmt_beacon_reply * ambr =
        (const struct allnet_mgmt_beacon_reply *) hp;
      r += snprintf (to + r, tsize - r, "beacon reply r %s ",
                     b2su (ambr->receiver_nonce, NONCE_SIZE));
      r += snprintf (to + r, tsize - r, "s %s",
                     b2su (ambr->sender_nonce, NONCE_SIZE));
    }
    break;
  case ALLNET_MGMT_BEACON_GRANT:
    if (hsize < sizeof (struct allnet_mgmt_beacon_grant)) {
      r += snprintf (to + r, tsize - r, "beacon grant size %d, min %zd\n",
                     hsize, sizeof (struct allnet_mgmt_beacon_grant));
    } else {
      const struct allnet_mgmt_beacon_grant * ambg =
        (const struct allnet_mgmt_beacon_grant *) hp;
      r += snprintf (to + r, tsize - r, "beacon grant r %s ",
                     b2su (ambg->receiver_nonce, NONCE_SIZE));
      r += snprintf (to + r, tsize - r, "s %s %lldns",
                     b2su (ambg->sender_nonce, NONCE_SIZE),
                     readb64 ((char *) (ambg->send_time)));
    }
    break;
  case ALLNET_MGMT_PEER_REQUEST:
    if (hsize < 0) {
      r += snprintf (to + r, tsize - r, "peer req size %d, min 0\n", hsize);
    } else {
      r += snprintf (to + r, tsize - r, "peer request");
    }
    break;
  case ALLNET_MGMT_PEERS:
    if (hsize < sizeof (struct allnet_mgmt_peers)) {
      r += snprintf (to + r, tsize - r, "peer size %d, min %zd\n",
                     hsize, sizeof (struct allnet_mgmt_peers));
    } else {
      const struct allnet_mgmt_peers * amp =
        (const struct allnet_mgmt_peers *) hp;
      int needed = sizeof (struct allnet_mgmt_peers) +
                   amp->num_peers * sizeof (struct internet_addr);
      if (hsize < needed) {
        r += snprintf (to + r, tsize - r, "peer size %d, needed %d\n",
                       hsize, needed);
      } else {
        r += snprintf (to + r, tsize - r, "peers %d ", amp->num_peers);
        int i;
        for (i = 0; i < amp->num_peers; i++) {
          char local [100];
          ia_to_string (amp->peers + i, local, sizeof (local));
          char * nl = index (local, '\n');
          *nl = '\0';   /* segfault if no newline */
          r += snprintf (to + r, tsize - r, "%s", local);
          if (i + 1 < amp->num_peers)
            r += snprintf (to + r, tsize - r, ", ");
        }
      }
    }
    break;
  case ALLNET_MGMT_DHT:
    if (hsize < sizeof (struct allnet_mgmt_dht)) {
      r += snprintf (to + r, tsize - r, "peer size %d, min %zd\n",
                     hsize, sizeof (struct allnet_mgmt_dht));
    } else {
      const struct allnet_mgmt_dht * dht = (const struct allnet_mgmt_dht *) hp;
      int needed = sizeof (struct allnet_mgmt_dht) +
                   dht->num_dht_nodes * sizeof (struct addr_info);
      if (hsize < needed) {
        r += snprintf (to + r, tsize - r, "dht size %d, needed %d\n",
                       hsize, needed);
      } else {
        char time_string [100];
        allnet_time_string (readb64 ((char *) (dht->timestamp)), time_string);
        r += snprintf (to + r, tsize - r, "dht %d+%d @%s ",
                       dht->num_sender, dht->num_dht_nodes, time_string);
        int i;
        for (i = 0; i < dht->num_sender + dht->num_dht_nodes; i++) {
          char local [100];
          ia_to_string (&(dht->nodes [i].ip), local, sizeof (local));
          char * nl = index (local, '\n');
          *nl = '\0';   /* segfault if no newline */
          r += snprintf (to + r, tsize - r, "%s %s",
                         b2su (dht->nodes [i].destination,
                               ADDRESS_SIZE), local);
          if (i + 1 < dht->num_sender + dht->num_dht_nodes)
            r += snprintf (to + r, tsize - r, ", ");
        }
      }
    }
    break;
  case ALLNET_MGMT_TRACE_REQ:
    if (hsize < sizeof (struct allnet_mgmt_trace_req)) {
      r += snprintf (to + r, tsize - r, "trace req size %d, min %zd\n",
                     hsize, sizeof (struct allnet_mgmt_trace_req));
    } else {
      const struct allnet_mgmt_trace_req * amt =
        (const struct allnet_mgmt_trace_req *) hp;
      int ks = readb16 ((char *) (amt->pubkey_size));
      int needed = sizeof (struct allnet_mgmt_trace_req) + ks +
                   amt->num_entries * sizeof (struct allnet_mgmt_trace_entry);
      if (hsize < needed) {
        r += snprintf (to + r, tsize - r,
                       "trace req size %d, needed %d (ks %d, %d entries)\n",
                       hsize, needed, ks, amt->num_entries);
      } else {
        r += snprintf (to + r, tsize - r, "trace request %d %d %s ",
                       amt->num_entries, ks,
                       ((amt->intermediate_replies != 0) ? "all" : "final"));
        r += buffer_to_string ((char *) (amt->trace_id), NONCE_SIZE, "id",
                               6, 0, to + r, tsize - r);
        int i;
        for (i = 0; i < amt->num_entries; i++)
          r += trace_entry_to_string (amt->trace + i, to + r, tsize - r);
      }
    }
    break;
  case ALLNET_MGMT_TRACE_REPLY:
    if (hsize < 1) {
      r += snprintf (to + r, tsize - r, "trace reply size %d, min 1\n", hsize);
    } else if (*hp == 1) {
      r += snprintf (to + r, tsize - r, "%d-byte encrypted trace replyd\n",
                     hsize);
    } else if (hsize < sizeof (struct allnet_mgmt_trace_reply)) {
      r += snprintf (to + r, tsize - r, "trace reply size %d, min %zd\n",
                     hsize, sizeof (struct allnet_mgmt_trace_reply));
    } else {
      const struct allnet_mgmt_trace_reply * amt =
        (const struct allnet_mgmt_trace_reply *) hp;
      int needed = sizeof (struct allnet_mgmt_trace_reply) +
                   amt->num_entries * sizeof (struct allnet_mgmt_trace_entry);
      if (hsize < needed) {
        r += snprintf (to + r, tsize - r, "trace reply size %d, needed %d\n",
                       hsize, needed);
      } else {
        r += snprintf (to + r, tsize - r, "trace reply %d %s ",
                       amt->num_entries,
                       ((amt->intermediate_reply != 0) ? "int" : "final"));
        r += buffer_to_string ((char *) (amt->trace_id), NONCE_SIZE, "id",
                               6, 0, to + r, tsize - r);
        int i;
        for (i = 0; i < amt->num_entries; i++)
          r += trace_entry_to_string (amt->trace + i, to + r, tsize - r);
      }
    }
    break;
  default:
    r += snprintf (to + r, tsize - r, "unknown management type %d", mtype);
    break;
  }
  return r;
}

/* same as print_buffer, but prints to the given string */
void packet_to_string (const char * buffer, int bsize, char * desc,
                       int print_eol, char * to, int tsize)
{
  int off = 0;
  if ((desc != NULL) && (strlen (desc) > 0))
    off = snprintf (to, tsize, "%s ", desc);
  if (! is_valid_message (buffer, bsize)) {
    snprintf (to + off, tsize - off, "invalid message of size %d", bsize);
    return;
  }
  struct allnet_header * hp = (struct allnet_header *) buffer;
  if (hp->version != ALLNET_VERSION)
    off += snprintf (to + off, tsize - off, "v %d (current %d) ",
                     hp->version, ALLNET_VERSION);
  int t = hp->transport;
  off += snprintf (to + off, tsize - off,
                   "(%dB) %d/%s: %d/%d hops, sig %d, t %x", bsize,
                   hp->message_type, mtype_to_string (hp->message_type),
                   hp->hops, hp->max_hops, hp->sig_algo, t);

  /* print the addresses, if any */
  if (hp->src_nbits != 0)
    off += snprintf (to + off, tsize - off, " from %s/%d",
                     b2su (hp->source, (hp->src_nbits + 7) / 8), hp->src_nbits);
  else
    off += snprintf (to + off, tsize - off, " from X");
  if (hp->dst_nbits != 0)
    off += snprintf (to + off, tsize - off, " to %s/%d",
                     b2su (hp->destination, (hp->dst_nbits + 7) / 8),
                     hp->dst_nbits);
  else
    off += snprintf (to + off, tsize - off, " to Y");

  /* print the transport information */
  if (t != 0) {
    if ((t & ALLNET_TRANSPORT_STREAM) != 0)
      off += snprintf (to + off, tsize - off,
                       " s %s",
                       b2s (ALLNET_STREAM_ID (hp, t, bsize), MESSAGE_ID_SIZE));
    if ((t & ALLNET_TRANSPORT_ACK_REQ) != 0)
      off += snprintf (to + off, tsize - off,
                       " a %s", b2s (ALLNET_MESSAGE_ID (hp, t, bsize),
                                     MESSAGE_ID_SIZE));
    if ((t & ALLNET_TRANSPORT_LARGE) != 0) {
      off += snprintf (to + off, tsize - off,
                          " l %s", b2s (ALLNET_PACKET_ID (hp, t, bsize),
                                        MESSAGE_ID_SIZE));
      off += snprintf (to + off, tsize - off,
                          "/n%lld",
                          readb64 (ALLNET_NPACKETS (hp, t, bsize) + 8));
      off += snprintf (to + off, tsize - off,
                          "/s%lld",
                          readb64 (ALLNET_SEQUENCE (hp, t, bsize) + 8));
    }
    if ((t & ALLNET_TRANSPORT_EXPIRATION) != 0)
      off += snprintf (to + off, tsize - off,
                       " e %lld", readb64 (ALLNET_EXPIRATION (hp, t, bsize)));
  }
  if (hp->message_type == ALLNET_TYPE_MGMT) {
    if (bsize < ALLNET_MGMT_HEADER_SIZE(t)) {
      off += snprintf (to + off, tsize - off, " mgmt size %d, need %zd", 
                       bsize, ALLNET_MGMT_HEADER_SIZE(t));
    } else {
      struct allnet_mgmt_header * mp =
        (struct allnet_mgmt_header *) (buffer + ALLNET_SIZE(t));
      const char * next = buffer + ALLNET_MGMT_HEADER_SIZE(t);
      int nsize = bsize - ALLNET_MGMT_HEADER_SIZE(t);
      off += mgmt_to_string (mp->mgmt_type, next, nsize,
                             to + off, tsize - off);
    }
  } else if (bsize > ALLNET_SIZE (hp->transport)) {
    int dsize = bsize - ALLNET_SIZE (hp->transport);
    off += snprintf (to + off, tsize - off, ", %d bytes of payload", dsize);
    if (hp->sig_algo != ALLNET_SIGTYPE_NONE) {
      int ssize = readb16 (buffer + bsize - 2);
      dsize -= ssize + 2;
      off += snprintf (to + off, tsize - off, " = %d data, %d + 2 sig", 
                       dsize, ssize);
    }
    if (hp->message_type == ALLNET_TYPE_ACK) {
      int num_acks = dsize / MESSAGE_ID_SIZE;
      if (num_acks * MESSAGE_ID_SIZE == dsize)
        off += snprintf (to + off, tsize - off, " = %d acks", num_acks);
      else
        off += snprintf (to + off, tsize - off, " = %d acks + %d bytes",
                         num_acks, dsize - num_acks * MESSAGE_ID_SIZE);
      int i;
      for (i = 0; i < num_acks; i++)
        off += buffer_to_string (buffer + ALLNET_SIZE (hp->transport) +
                                 i * MESSAGE_ID_SIZE, MESSAGE_ID_SIZE,
                                 ", ", 5, 0, to + off, tsize - off);
    }
  }
  if (print_eol)
    off += snprintf (to + off, tsize - off, "\n");
}

void print_packet (const char * packet, int psize, char * desc, int print_eol)
{
  static char buffer [10000];
  packet_to_string (packet, psize, desc, print_eol, buffer, sizeof (buffer));
  printf ("%s", buffer);
}

/* buffer must be at least ALLNET_SIZE(transport) bytes long */
/* returns a pointer to the buffer, but cast to an allnet_header */
/* returns NULL if any of the parameters are invalid (e.g. message_type) */
/* if sbits is zero, source may be NULL, and likewise for dbits and dest */
/* if ack is not NULL it must refer to MESSAGE_ID_SIZE bytes, and */
/* transport will be set to ALLNET_TRANSPORT_ACK_REQ */
/* if ack is NULL, transport will be set to 0 */
struct allnet_header *
  init_packet (char * packet, int psize,
               int message_type, int max_hops, int sig_algo,
               unsigned char * source, int sbits,
               unsigned char * dest, int dbits, unsigned char * ack)
{
  struct allnet_header * hp = (struct allnet_header *) packet;
  if (psize < ALLNET_HEADER_SIZE)
    return NULL;
  if ((ack != NULL) && (psize < ALLNET_SIZE(ALLNET_TRANSPORT_ACK_REQ)))
    return NULL;
  if ((message_type < ALLNET_TYPE_DATA) || (message_type > ALLNET_TYPE_MGMT))
    return NULL;
  if ((max_hops < 1) || (max_hops > 255))
    return NULL;
  if ((sig_algo < ALLNET_SIGTYPE_NONE) || (sig_algo > ALLNET_SIGTYPE_secp128r1))
    return NULL;
  if ((sbits < 0) || (sbits > ADDRESS_BITS) ||
      (dbits < 0) || (dbits > ADDRESS_BITS))
    return NULL;
  bzero (packet, psize);   /* clear all unused fields */
  hp->version = ALLNET_VERSION;
  hp->message_type = message_type;
  hp->hops = 0;
  hp->max_hops = max_hops;
  hp->src_nbits = sbits;
  hp->dst_nbits = dbits;
  hp->sig_algo = sig_algo;
  if ((sbits > 0) && (source != NULL))
    memcpy (hp->source, source, (sbits + 7) / 8);
  if ((dbits > 0) && (dest != NULL))
    memcpy (hp->destination, dest, (dbits + 7) / 8);
  hp->transport = ALLNET_TRANSPORT_NONE;
  if (ack != NULL) {
    hp->transport = ALLNET_TRANSPORT_ACK_REQ;
    sha512_bytes ((char *) ack, MESSAGE_ID_SIZE,
                  ALLNET_MESSAGE_ID(hp, hp->transport, psize), MESSAGE_ID_SIZE);
  }
  return hp;
}

/* malloc's (must be free'd), initializes, and returns a packet with the
 * given data size.
 * If ack is not NULL, the data size parameter should NOT include the
 * MESSAGE_ID_SIZE bytes of the ack.
 * *size is set to the size to send */
struct allnet_header *
  create_packet (int data_size, int message_type, int max_hops, int sig_algo,
                 unsigned char * source, int sbits,
                 unsigned char * dest, int dbits, unsigned char * ack,
                 int * size)
{
  int alloc_size = data_size + ALLNET_HEADER_SIZE;
  if (ack != NULL)
    alloc_size = ALLNET_SIZE(ALLNET_TRANSPORT_ACK_REQ)
               + MESSAGE_ID_SIZE + data_size;
  char * result = malloc_or_fail (alloc_size, "util.c create_packet");
  *size = alloc_size;
  return init_packet (result, alloc_size, message_type, max_hops, sig_algo,
                      source, sbits, dest, dbits, ack);
  
}

/* malloc, initialize, and return an ack message for a received packet.
 * The message_ack bytes are taken from the argument, not from the packet.*/
/* *size is set to the size to send */
/* if from is NULL, the source address is taken from packet->destination */
struct allnet_header *
  create_ack (struct allnet_header * packet, unsigned char * ack,
              unsigned char * from, int nbits, int * size)
{
  *size = 0;   /* in case of early return */
  int alloc_size = ALLNET_HEADER_SIZE + MESSAGE_ID_SIZE;
  char * result = malloc_or_fail (alloc_size, "util.c create_ack");
  if (from == NULL) {
    from = packet->destination;
    if (nbits > packet->dst_nbits)
      nbits = packet->dst_nbits;
  }
  struct allnet_header * hp =
    init_packet (result, alloc_size, ALLNET_TYPE_ACK, packet->hops + 3,
                 ALLNET_SIGTYPE_NONE, from, nbits,
                 packet->source, packet->src_nbits, NULL);
  char * ackp = ALLNET_DATA_START(hp, hp->transport, alloc_size);
  if (alloc_size - (ackp - result) != MESSAGE_ID_SIZE) {
    printf ("coding error in create_ack!!!! %d %p %p %d %d\n",
            alloc_size, ackp, result, (int) (alloc_size - (ackp - result)),
            MESSAGE_ID_SIZE);
    return NULL;
  }
  memcpy (ackp, ack, MESSAGE_ID_SIZE);
  *size = alloc_size;
  return hp;
}

int print_sockaddr_str (struct sockaddr * sap, int addr_size, int tcp,
                        char * s, int len)
{
  char * proto = "";
  if (tcp == 1)
    proto = "/tcp";
  else if (tcp == 0)
    proto = "/udp";
  if (sap == NULL)
    return snprintf (s, len, "(null %s)", proto);
  struct sockaddr_in  * sin  = (struct sockaddr_in  *) sap;
  struct sockaddr_in6 * sin6 = (struct sockaddr_in6 *) sap;
  struct sockaddr_un  * sun  = (struct sockaddr_un  *) sap;
#ifndef __APPLE__
  struct sockaddr_ll  * sll  = (struct sockaddr_ll  *) sap;
#endif /* __APPLE__ */
  /* char str [INET_ADDRSTRLEN]; */
  int num_initial_zeros = 0;  /* for printing ipv6 addrs */
  int n = 0;   /* offset for printing */
  int i;
  switch (sap->sa_family) {
  case AF_INET:
    n += snprintf (s + n, len - n, "ip4%s %s %d/%x",
                   proto, inet_ntoa (sin->sin_addr),
                   ntohs (sin->sin_port), ntohs (sin->sin_port));
    if ((addr_size != 0) && (addr_size < sizeof (struct sockaddr_in)))
      n += snprintf (s + n, len - n, " (size %d rather than %zd)",
                     addr_size, sizeof (struct sockaddr_in));
    break;
  case AF_INET6:
    /* inet_ntop (AF_INET6, sap, str, sizeof (str)); */
    n += snprintf (s + n, len - n, "ip6%s ", proto);
    for (i = 0; i + 1 < sizeof (sin6->sin6_addr); i++)
      if ((sin6->sin6_addr.s6_addr [i] & 0xff) == 0)
        num_initial_zeros++;
      else
        break;
    if ((num_initial_zeros & 0x1) > 0)  /* make it even */
      num_initial_zeros--;
    if (num_initial_zeros > 0)
      n += snprintf (s + n, len - n, "::");
    for (i = num_initial_zeros; i < sizeof (sin6->sin6_addr); i += 2) {
      int two_byte = ((sin6->sin6_addr.s6_addr [i] & 0xff) << 8) |
                      (sin6->sin6_addr.s6_addr [i + 1] & 0xff);
      n += snprintf (s + n, len - n, "%x", two_byte);
      if (i + 2 < sizeof (sin6->sin6_addr)) /* last one is not followed by : */
        n += snprintf (s + n, len - n, ":");
    }
    n += snprintf (s + n, len - n, " %d/%x",
                   ntohs (sin6->sin6_port), ntohs (sin6->sin6_port));
    if ((addr_size != 0) && (addr_size < sizeof (struct sockaddr_in6)))
      n += snprintf (s + n, len - n, " (size %d rather than %zd)",
                     addr_size, sizeof (struct sockaddr_in6));
    break;
  case AF_UNIX:
    n += snprintf (s + n, len - n, "unix%s %s", proto, sun->sun_path);
    if ((addr_size != 0) && (addr_size < sizeof (struct sockaddr_un)))
      n += snprintf (s + n, len - n, " (size %d rather than %zd)",
                     addr_size, sizeof (struct sockaddr_un));
    break;
#ifndef __APPLE__
  case AF_PACKET:
    n += snprintf (s + n, len - n,
                   "packet protocol%s 0x%x if %d ha %d pkt %d address (%d)",
                   proto, sll->sll_protocol, sll->sll_ifindex, sll->sll_hatype,
                   sll->sll_pkttype, sll->sll_halen);
    for (i = 0; i < sll->sll_halen; i++)
      n += snprintf (s + n, len - n, " %02x", sll->sll_addr [i] & 0xff);
    if ((addr_size != 0) && (addr_size != sizeof (struct sockaddr_ll)))
      n += snprintf (s + n, len - n, " (size %d rather than %zd)",
                     addr_size, sizeof (struct sockaddr_ll));
    break;
#endif /* __APPLE__ */
  default:
    n += snprintf (s + n, len - n, "unknown address family %d%s",
                   sap->sa_family, proto);
    break;
  }
  return n;
}

/* tcp should be 1 for TCP, 0 for UDP, -1 for neither */
void print_sockaddr (struct sockaddr * sap, int addr_size, int tcp)
{
  char buffer [1000];
  print_sockaddr_str (sap, addr_size, tcp, buffer, sizeof (buffer));
  printf ("%s", buffer);
}

/* print a message with the current time */
void print_timestamp (char * message)
{
  struct timeval now;
  gettimeofday (&now, NULL);
  printf ("%s at %ld.%06ld\n", message, now.tv_sec, (long) (now.tv_usec));
}

static int get_bit (const unsigned char * data, int pos)
{
  int byte = data [pos / 8];
  int shift = 7 - (pos % 8);
  int bit = byte;
  if (shift > 0)
    bit = (byte >> shift);
  return bit & 0x1;
}

/* returns the number of matching bits starting from the front of the
 * bitstrings, not to exceed xbits or ybits.  Returns 0 for no match */
int matching_bits (const unsigned char * x, int xbits,
                   const unsigned char * y, int ybits)
{
  int nbits = xbits;
  if (nbits > ybits)
    nbits = ybits;
  int i;
  for (i = 0; i < nbits; i++)
    if (get_bit (x, i) != get_bit (y, i))
      return i;
  return nbits;
}

/* return nbits+1 if the first nbits of x match the first nbits of y, else 0 */
/* where nbits is the lesser of xbits and ybits */
int matches (const unsigned char * x, int xbits,
             const unsigned char * y, int ybits)
{
  int nbits = xbits;
  if (nbits > ybits)
    nbits = ybits;
  int bytes = nbits / 8;  /* rounded-down number of bytes */
/*
  printf ("matching %d bits, %d bytes, of ", nbits, bytes);
  print_buffer (x, bytes + 1, NULL, 6, 0);
  printf (", ");
  print_buffer (y, bytes + 1, NULL, 6, 1);
*/
  int i;
  for (i = 0; i < bytes; i++)
    if (x [i] != y [i])
      return 0;
/* if ((nbits % 8) == 0) printf ("matches!!!\n"); */
  if ((nbits % 8) == 0)   /* identical */
    return nbits + 1;
  int shift = 8 - nbits % 8;
  if ((((x [bytes]) & 0xff) >> shift) == (((y [bytes]) & 0xff) >> shift)) {
    /* printf ("bits match!!!\n"); */
    return nbits + 1;
  }
  return 0;
}

void print_bitstring (const unsigned char * x, int xoff, int nbits,
                      int print_eol)
{
  int i;
  for (i = 0; i < nbits; i++) {
    if ((i > 0) && (i % 4 == 0))
      printf (" ");
    int byte = x [(xoff + i) / 8];
    int mask = 1 << (7 - (xoff + i) % 8);
    if (byte & mask)
      printf ("1");
    else
      printf ("0");
  }
  if (print_eol)
    printf ("\n");
}

/* return 1 if the first nbits of x after xoff bits match
 * the first nbits of y after yoff bits, else 0 */
int bitstring_matches (const unsigned char * x, int xoff,
                       const unsigned char * y, int yoff, int nbits)
{
  int i;
  for (i = 0; i < nbits; i++)
    if (get_bit (x, xoff + i) != get_bit (y, yoff + i))
      return 0;
  return 1;
}

/* AllNet time begins January 1st, 2000.  This may be different from
 * the time bases (epochs) on other systems, including specifically
 * Unix (Jan 1st, 1970) and Windows (Jan 1st, 1980).  I believe somebody
 * also has an epoch of Jan 1st, 1900.  Anyway, these functions return
 * the current AllNet time.  The usual caveats apply about OS time accuracy.
 * The 64-bit value returned will be good for 584,000 years worth of
 * microseconds.
 */
unsigned long long allnet_time ()     /* seconds since Y2K */
{
  unsigned long long result = time (NULL);
  return result - ALLNET_Y2K_SECONDS_IN_UNIX;
}

unsigned long long allnet_time_us ()  /* microseconds since Y2K */
{
  struct timeval tv;
  gettimeofday (&tv, NULL);
  unsigned long long result = tv.tv_sec;
  result -= ALLNET_Y2K_SECONDS_IN_UNIX;
  result *= ALLNET_US_PER_S;
  result += tv.tv_usec;
  return result;
}

unsigned long long allnet_time_ms ()  /* milliseconds since Y2K */
{
  return allnet_time_us () / ALLNET_US_PER_MS;
}

/* returns the result of calling ctime_r on the given allnet time. */
/* the result buffer must be at least 30 bytes long */
/* #define ALLNET_TIME_STRING_SIZE		30 */
void allnet_time_string (unsigned long long int allnet_seconds, char * result)
{
  /* in case of errors */
  snprintf (result, 30, "bad time %lld\n", allnet_seconds);

  time_t unix_seconds = allnet_seconds + ALLNET_Y2K_SECONDS_IN_UNIX;
  struct tm detail_time;
  if (gmtime_r (&unix_seconds, &detail_time) == NULL)
    return;
  asctime_r (&detail_time, result);
  if (result [24] == '\n')   /* overwrite the newline */
    snprintf (result + 24, 5, " UTC");
}

void allnet_localtime_string (unsigned long long int allnet_seconds,
                              char * result)
{
  /* in case of errors */
  snprintf (result, 30, "bad time %lld\n", allnet_seconds);

  time_t unix_seconds = allnet_seconds + ALLNET_Y2K_SECONDS_IN_UNIX;
  struct tm * detail_time = localtime (&unix_seconds);  /* sets tzname */
  if (detail_time == NULL)
    return;
  asctime_r (detail_time, result);
  if (result [25] == '\0')
    snprintf (result + 25, 5, " %s", tzname [0]);
}

/* useful time functions */
/* if t1 < t2, returns 0, otherwise returns t1 - t2 */
unsigned long long delta_us (const struct timeval * t1, const struct timeval * t2)
{
  if ((t1->tv_sec < t2->tv_sec) ||
      ((t1->tv_sec == t2->tv_sec) &&
       (t1->tv_usec < t2->tv_usec)))  /* t1 before t2, return 0 */
    return 0LL;
  unsigned long long result = t1->tv_usec - t2->tv_usec;
  result += (t1->tv_sec - t2->tv_sec) * ALLNET_US_PER_S;
  return result;
}

/* returns 1 if now is before the given time, and 0 otherwise */
int is_before (struct timeval * t)
{
  struct timeval now;
  gettimeofday (&now, NULL);
  if (now.tv_sec < t->tv_sec)
    return 1;
  if (now.tv_sec > t->tv_sec)
    return 0;
  /* now.tv_sec == t->tv_sec */
  if (now.tv_usec < t->tv_usec)
    return 1;
  return 0;
}

void add_us (struct timeval * t, unsigned long long us)
{
  t->tv_usec += us % ALLNET_US_PER_S;         /* add microseconds to tv_usec */
  t->tv_sec += t->tv_usec / ALLNET_US_PER_S;  /* any carry goes into tv_sec */
  t->tv_usec = t->tv_usec % ALLNET_US_PER_S;  /* make tv_usec < 1,000,000 */
  t->tv_sec += us / ALLNET_US_PER_S;       /* whole seconds added to tv_sec */
}

/* computes the next time that is a multiple of granularity.  If immediate_ok,
 * returns 0 if the current time is already a multiple of granularity */
time_t compute_next (time_t from, time_t granularity, int immediate_ok)
{
  time_t delta = from % granularity;
  if ((immediate_ok) && (delta == 0))
    /* already at the beginning of the interval */
    return from;
/*
  printf ("compute_next returning %ld = %ld + (%ld - %ld)\n",
          from + (granularity - delta), from, granularity, delta);
*/
  return from + (granularity - delta);
}

/* set result to a random time between start + min and start + max */
void set_time_random (const struct timeval * start, unsigned long long min,
                      unsigned long long max, struct timeval * result)
{
  if (min <= max) {
    *result = *start;
    return;
  }
  unsigned long long int delta = max - min;
  unsigned long long int r = random ();
  unsigned long long int us = min + r % delta;
  *result = *start;
  add_us (result, us);
}

/* if malloc is not successful, exit after printing */
void * malloc_or_fail (int bytes, char * desc)
{
  void * result = malloc (bytes);
  if (result == NULL) {
    printf ("unable to allocate %d bytes for %s\n", bytes, desc);
    assert (0);               /* cause a crash and core dump */
    /* if NDEBUG is set, assert will do nothing.  segfault instead */
    * ((int *) result) = 3;   /* cause a segmentation fault */
    exit (1);   /* we should never get here */
  }
  return result;
}

/* copy a string to new storage, using malloc_or_fail to get the memory */
char * strcpy_malloc (char * string, char * desc)
{
  int size = strlen (string) + 1;
  char * result = malloc_or_fail (size, desc);
  snprintf (result, size, "%s", string);
  return result;
}

char * strcat_malloc (char * s1, char * s2, char * desc)
{
  int size = strlen (s1) + strlen (s2) + 1;
  char * result = malloc_or_fail (size, desc);
  snprintf (result, size, "%s%s", s1, s2);
  return result;
}

char * strcat3_malloc (char * s1, char * s2, char * s3, char * desc)
{
  int size = strlen (s1) + strlen (s2) + strlen (s3) + 1;
  char * result = malloc_or_fail (size, desc);
  snprintf (result, size, "%s%s%s", s1, s2, s3);
  return result;
}

/* copy memory to new storage, using malloc_or_fail to get the memory */
void * memcpy_malloc (void * bytes, int bsize, char * desc)
{
  char * result = malloc_or_fail (bsize, desc);
  memcpy (result, bytes, bsize);
  return result;
}

/* returns the file size, and if content_p is not NULL, allocates an
 * array to hold the file contents and assigns it to content_p.
 * in case of problems, returns 0
 */
int read_file_malloc (char * file_name, char ** content_p, int print_errors)
{
  struct stat st;
  if (stat (file_name, &st) < 0) {
    if (print_errors) {
      perror ("stat");
      printf ("read_file_malloc: unable to stat %s\n", file_name);
    }
    return 0;
  }
  if (st.st_size == 0)
    return 0;
  if (content_p == NULL) {   /* just make sure could read the file */
    if (access (file_name, R_OK) == 0)
      return st.st_size;
    else
      return 0;
  }
  char * result = malloc (st.st_size);
  if (result == NULL) {
    if (print_errors)
      printf ("unable to allocate %ld bytes for contents of file %s\n",
              st.st_size, file_name);
    return 0;
  }
  int fd = open (file_name, O_RDONLY);
  if (fd < 0) {
    if (print_errors) {
      perror ("open");
      printf ("unable to open file %s for reading\n", file_name);
    }
    free (result);
    return 0;
  }
  int n = read (fd, result, st.st_size);
  if (n != st.st_size) {
    if (print_errors) {
      perror ("read");
      printf ("unable to read %ld bytes from %s, got %d\n",
              st.st_size, file_name, n);
    }
    free (result);
    close (fd);
    return 0;
  }
  close (fd);
  *content_p = result;
  return st.st_size;
}

/* low-grade randomness, in case the other calls don't work */
static void computed_random_bytes (char * buffer, int bsize)
{
  int i;
  for (i = 0; i < bsize; i++)
    buffer [i] = random () % 256;
}

/* returns 1 if succeeds, 0 otherwise */
static int dev_urandom_bytes (char * buffer, int bsize)
{
  int fd = open ("/dev/urandom", O_RDONLY);
  if (fd < 0) {
    perror ("open /dev/urandom");
    return 0;
  }
  int r = read (fd, buffer, bsize);
  if (r < bsize) {
    perror ("read /dev/urandom");
    return 0;
  }
  close (fd);
  return 1;
}

/* fill this array with random bytes */
void random_bytes (char * buffer, int bsize)
{
  if (! dev_urandom_bytes (buffer, bsize))
    computed_random_bytes (buffer, bsize);
}

/* fill this array with random alpha characters.  The last byte is set to \0 */
void random_string (char * buffer, int bsize)
{
  if (bsize <= 0)
    return;
  int i;
  for (i = 0; i + 1 < bsize; i++)
    buffer [i] = 'a' + (random () % 26);
  buffer [bsize - 1] = '\0';
}

/* place the values 0..n-1 at random within the given array */
void random_permute_array (int n, int * array)
{
  int i;
  for (i = 0; i < n; i++)
    array [i] = i;
  if (n <= 1)  /* done */
    return;
  /* now assign to each element a random selection of the other elements */
  for (i = 0; i < n; i++) {
    int r = random () % n;
    int swap = array [i];   /* this code works even if r == i */
    array [i] = array [r];
    array [r] = swap;
  }
/* printf ("permutation of %d is", n);
  for (i = 0; i < n; i++)
    printf (" %d", array [i]);
  printf ("\n"); */
}

/* malloc and return an n-element int array containing the values 0..n-1
 * in some random permuted order */
int * random_permute (int n)
{
  int * result = malloc_or_fail (n * sizeof (int), "random_permute");
  random_permute_array (n, result);
  return result;
}

/* read a big-endian n-bit number into an unsigned int */
/* if the pointer is NULL, returns 0 */
unsigned int readb16 (const char * p)
{
  unsigned int result = 0;
  if (p == NULL)
    return result;
  result = (((unsigned int) ((p [0]) & 0xff)) <<  8) |
           (((unsigned int) ((p [1]) & 0xff))      );
  return result;
}

unsigned long int readb32 (const char * p)
{
  unsigned long int result = 0;
  if (p == NULL)
    return result;
  result = (((unsigned long int) ((p [0]) & 0xff)) << 24) |
           (((unsigned long int) ((p [1]) & 0xff)) << 16) |
           (((unsigned long int) ((p [2]) & 0xff)) <<  8) |
           (((unsigned long int) ((p [3]) & 0xff))      );
  return result;
}

unsigned long long int readb48 (const char * p)
{
  unsigned long long int result = 0;
  if (p == NULL)
    return result;
  result = (((unsigned long long int) ((p [0]) & 0xff)) << 40) |
           (((unsigned long long int) ((p [1]) & 0xff)) << 32) |
           (((unsigned long long int) ((p [2]) & 0xff)) << 24) |
           (((unsigned long long int) ((p [3]) & 0xff)) << 16) |
           (((unsigned long long int) ((p [4]) & 0xff)) <<  8) |
           (((unsigned long long int) ((p [5]) & 0xff))      );
  return result;
}

unsigned long long int readb64 (const char * p)
{
  unsigned long long int result = 0;
  if (p == NULL)
    return result;
  result = (((unsigned long long int) ((p [0]) & 0xff)) << 56) |
           (((unsigned long long int) ((p [1]) & 0xff)) << 48) |
           (((unsigned long long int) ((p [2]) & 0xff)) << 40) |
           (((unsigned long long int) ((p [3]) & 0xff)) << 32) |
           (((unsigned long long int) ((p [4]) & 0xff)) << 24) |
           (((unsigned long long int) ((p [5]) & 0xff)) << 16) |
           (((unsigned long long int) ((p [6]) & 0xff)) <<  8) |
           (((unsigned long long int) ((p [7]) & 0xff))      );
  return result;
}

/* write an n-bit number in big-endian order into an array.  If the pointer
 * is NULL, does nothing */
void writeb16 (char * p, unsigned int value)
{
  if (p == NULL)
    return;
  p [0] = (value >>  8) & 0xff; p [1] =  value        & 0xff;
}

void writeb32 (char * p, unsigned long int value)
{
  if (p == NULL)
    return;
  p [0] = (value >> 24) & 0xff; p [1] = (value >> 16) & 0xff;
  p [2] = (value >>  8) & 0xff; p [3] =  value        & 0xff;
}

void writeb48 (char * p, unsigned long long int value)
{
  if (p == NULL)
    return;
  p [0] = (value >> 40) & 0xff; p [1] = (value >> 32) & 0xff;
  p [2] = (value >> 24) & 0xff; p [3] = (value >> 16) & 0xff;
  p [4] = (value >>  8) & 0xff; p [5] =  value        & 0xff;
}

void writeb64 (char * p, unsigned long long int value)
{
  if (p == NULL)
    return;
  p [0] = (value >> 56) & 0xff; p [1] = (value >> 48) & 0xff;
  p [2] = (value >> 40) & 0xff; p [3] = (value >> 32) & 0xff;
  p [4] = (value >> 24) & 0xff; p [5] = (value >> 16) & 0xff;
  p [6] = (value >>  8) & 0xff; p [7] =  value        & 0xff;
}

/* the same functions on arrays of unsigned characters */
unsigned int readb16u (const unsigned char * p)
{
  return readb16 ((const char *) p);
}

unsigned long int readb32u (const unsigned char * p)
{
  return readb32 ((const char *) p);
}

unsigned long long int readb48u (const unsigned char * p)
{
  return readb48 ((const char *) p);
}

unsigned long long int readb64u (const unsigned char * p)
{
  return readb64 ((const char *) p);
}

void writeb16u (unsigned char * p, unsigned int value)
{
  writeb16 ((char *) p, value);
}

void writeb32u (unsigned char * p, unsigned long int value)
{
  writeb32 ((char *) p, value);
}

void writeb48u (unsigned char * p, unsigned long long int value)
{
  writeb48 ((char *) p, value);
}

void writeb64u (unsigned char * p, unsigned long long int value)
{
  writeb64 ((char *) p, value);
}

/* returns 1 if the message is valid, 0 otherwise */
int is_valid_message (const char * packet, int size)
{
  if (size < ALLNET_HEADER_SIZE) {
    snprintf (log_buf, LOG_SIZE, 
              "received a packet with %d bytes, %zd required\n",
              size, ALLNET_HEADER_SIZE);
    log_print ();
    return 0;
  }
/* received a message with a header */
  struct allnet_header * ah = (struct allnet_header *) packet;
/* make sure version, address bit counts and hops are sane */
  if ((ah->version != ALLNET_VERSION) ||
      (ah->src_nbits > ADDRESS_BITS) || (ah->dst_nbits > ADDRESS_BITS) ||
      (ah->hops > ah->max_hops)) {
    snprintf (log_buf, LOG_SIZE, 
              "received version %d addr sizes %d, %d (max %d), hops %d, %d\n",
              ah->version, ah->src_nbits, ah->dst_nbits, ADDRESS_BITS,
              ah->hops, ah->max_hops);
    log_print ();
    return 0;
  }
/* check the validity of the packet, as defined in packet.h */
  if (((ah->message_type == ALLNET_TYPE_ACK) ||
       (ah->message_type == ALLNET_TYPE_DATA_REQ)) &&
      (ah->transport != 0)) {
    snprintf (log_buf, LOG_SIZE, 
              "received message type %d, transport 0x%x != 0\n",
              ah->message_type, ah->transport);
    log_print ();
    return 0;
  }
  int payload_size = size - ALLNET_AFTER_HEADER (ah->transport, size);
  if ((ah->message_type == ALLNET_TYPE_ACK) &&
      ((payload_size % MESSAGE_ID_SIZE) != 0)) {
    snprintf (log_buf, LOG_SIZE, 
              "received ack message, but size %d(%d) mod %d == %d != 0\n",
              payload_size, size, MESSAGE_ID_SIZE,
              payload_size % MESSAGE_ID_SIZE);
    log_print ();
    return 0;
  }
  if (((ah->transport & ALLNET_TRANSPORT_ACK_REQ) != 0) &&
      (payload_size < MESSAGE_ID_SIZE)) {
    snprintf (log_buf, LOG_SIZE, "message has size %d (%d), min %d\n",
              payload_size, size, MESSAGE_ID_SIZE);
    log_print ();
    return 0;
  }
  if (((ah->transport & ALLNET_TRANSPORT_ACK_REQ) == 0) &&
      ((ah->transport & ALLNET_TRANSPORT_LARGE) != 0)) {
    snprintf (log_buf, LOG_SIZE, "large message missing ack bit\n");
    log_print ();
    return 0;
  }
  if (((ah->transport & ALLNET_TRANSPORT_EXPIRATION) != 0)) {
    time_t now = time (NULL);
    char * ep = ALLNET_EXPIRATION (ah, ah->transport, size);
    if ((now <= ALLNET_Y2K_SECONDS_IN_UNIX) || (ep == NULL) ||
        (readb64 (ep) < (now - ALLNET_Y2K_SECONDS_IN_UNIX))) {
      snprintf (log_buf, LOG_SIZE, "expired packet, %lld < %ld (ep %p)\n",
                readb64 (ep), now - ALLNET_Y2K_SECONDS_IN_UNIX, ep);
      log_print ();
      return 0;
    }
  }
  return 1;
}

void print_gethostbyname_error (char * hostname)
{
  switch (h_errno) {
  case HOST_NOT_FOUND:
    snprintf (log_buf, LOG_SIZE,
              "error resolving host name %s: host not found\n", hostname);
    break;
#if defined NO_ADDRESS
  case NO_ADDRESS:  /* same as NO_DATA */
#else
  case NO_DATA:
#endif
    snprintf (log_buf, LOG_SIZE,
              "error resolving host name %s: no address/no data\n", hostname);
    break;
  case NO_RECOVERY:
    snprintf (log_buf, LOG_SIZE,
              "error resolving host name %s: unrecoverable error\n", hostname);
    break;
  case TRY_AGAIN:
    snprintf (log_buf, LOG_SIZE,
              "error resolving host name %s: try again\n", hostname);
    break;
  default:
    snprintf (log_buf, LOG_SIZE,
              "error resolving host name %s: unknown %d\n", hostname, h_errno);
    break;
  }
  log_print ();
}

/* assuming option_letter is 'v', returns 1 if argv has '-v', 0 otherwise
 * if it returns 1, removes the -v from the argv, and decrements *argcp.
 */
int get_option (char option_letter, int * argcp, char ** argv)
{
  char buf [] = "-o";  /* o for option */
  buf [1] = option_letter;
  int orig_argc = *argcp;
  int i;
  for (i = 1; i < orig_argc; i++) {
    if (strcmp (argv [i], buf) == 0) {  /* found a match */
      int j;
      for (j = i; j + 1 < orig_argc; j++)
        argv [j] = argv [j + 1];
      *argcp = orig_argc - 1;
      return 1;
    }
  }
  return 0;
}

/* set user_callable to 1 for astart and allnetx, to 0 for all others */
void print_usage (int argc, char ** argv, int user_callable, int do_exit)
{
  if (user_callable)
    printf ("usage: %s [-v] [interface1 [interface2]]\n", argv [0]);
  else
    printf ("%s should only be called from astart or allnetx\n", argv [0]);
  if (do_exit)
    exit (1);
}

