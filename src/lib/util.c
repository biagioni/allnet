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
#include <dirent.h>  /* h_errno */
#include <inttypes.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "packet.h"
#include "mgmt.h"
#include "allnet_log.h"
#include "util.h"
#include "ai.h"
#include "sha.h"

#ifdef ALLNET_NETPACKET_SUPPORT
#include <netpacket/packet.h>
#endif /* ALLNET_NETPACKET_SUPPORT */

/* print up to max of the count characters in the buffer.
 * desc is printed first unless it is null
 * a newline is printed after if print_eol
 */
void print_buffer (const void * vb, unsigned int count, const char * desc,
                   unsigned int max, int print_eol)
{
  const char * buffer = (const char *) vb;
  unsigned int i;
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

/* compute a power of two */
static unsigned int p2 (unsigned int exponent)
{
  return 1 << exponent;
}

/* returns from - subtract if from >= subtract, otherwise returns 0 */
int minz (int from, int subtract)
{
  if (from >= subtract)
    return from - subtract;
  return 0;
}
/* returns (from - subtract) if from >= subtract, otherwise returns 0 */
ssize_t minzs (ssize_t from, ssize_t subtract)
{
  if (from >= subtract)
    return from - subtract;
  return 0;
}

/* returns the number of bits needed to represent the number in binary,
 * and 0 for 0 */
/* e.g. returns
   0 for 0
   1 for 1
   2 for 2 or 3
   3 for 4-7
   4 for 8-15
   etc
 */
int binary_log (unsigned long long int value)
{
  if (value <= 1)
    return (int)value;
  return 1 + binary_log (value / 2);
}

/* crash, generally creating a core dump.  If to_print is not NULL,
 * prints it before crashing */
void allnet_crash (const char * to_print)
{
  if (to_print != NULL)
    printf ("intended allnet crash: %s\n\n", to_print);
  else
    printf ("intended allnet crash\n\n");
  char * null_ptr = NULL;
  /* next line should never print */
  printf ("allnet crash: null pointer dereference, %c\n", *null_ptr);
}

/* same as print_buffer, but prints to the given string */
int buffer_to_string (const char * buffer, unsigned int count,
                      const char * desc,
                      unsigned int max, int print_eol, char * to, size_t tsize)
{
  if (tsize <= 0)
    return 0;
  unsigned int i;
  unsigned int offset = 0;
  unsigned int itsize = (unsigned int)tsize;
  if (desc != NULL)
    offset = snprintf (to, tsize, "%s (%d bytes):", desc, count);
  else
    offset = snprintf (to, tsize, "%d bytes:", count);
  if (buffer == NULL) {
    offset += snprintf (to + offset, minz (itsize, offset), "(null)");
  } else {
    for (i = 0; i < count && i < max; i++)
      offset += snprintf (to + offset, minz (itsize, offset),
                          " %02x", buffer [i] & 0xff);
    if (i < count)
      offset += snprintf (to + offset, minz (itsize, offset), " ...");
  }
  if (print_eol)
    offset += snprintf (to + offset, minz (itsize, offset), "\n");
  return offset;
}

static char * mtype_to_string (int mtype, int mgmt_type)
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
    switch (mgmt_type) {
      case ALLNET_MGMT_BEACON:
        return "mgmt(beacon)";
      case ALLNET_MGMT_BEACON_REPLY:
        return "mgmt(beacon_reply)";
      case ALLNET_MGMT_BEACON_GRANT:
        return "mgmt(beacon_grant)";
      case ALLNET_MGMT_PEER_REQUEST:
        return "mgmt(peer_request)";
      case ALLNET_MGMT_PEERS:
        return "mgmt(peers)";
      case ALLNET_MGMT_DHT:
        return "mgmt(dht)";
      case ALLNET_MGMT_TRACE_REQ:
        return "mgmt(trace_req)";
      case ALLNET_MGMT_TRACE_REPLY:
        return "mgmt(trace_reply)";
      case ALLNET_MGMT_KEEPALIVE:
        return "mgmt(keepalive)";
#ifdef IMPLEMENT_MGMT_ID_REQUEST  /* not used, so, not implemented */
      case ALLNET_MGMT_ID_REQUEST:
        return "mgmt(id_request)";
#endif /* IMPLEMENT_MGMT_ID_REQUEST */
    }
    return "mgmt";
  default:
    return "unknown message type";
  }
}

/* returned buffer is statically allocated */
static char * b2s (const char * buffer, int count)
{
  static char result [10000];
  *result = '\0';    /* set result to the empty string */
  if ((buffer == NULL) || (count < 1))
    return result;
  if (count + 1 >= ((int) (sizeof (result) / 2)))
    count = sizeof (result) / 2 - 1;
  result [0] = '\0';   /* in case count <= 0 */
  int i;
  int offset = 0;
  for (i = 0; i < count; i++) {
    offset += snprintf (result + offset, minz (sizeof (result), offset),
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
  if (tsize <= 0)
    return 0;
  return snprintf (to, tsize, "%d %lld.%lld@%d %s/%d, ", e->precision,
                   readb64 ((const char *) (e->seconds)),
                   readb64 ((const char *) (e->seconds_fraction)),
                   e->nbits, b2s ((const char *) (e->address), ADDRESS_SIZE),
                   e->hops_seen);
}

static int mgmt_to_string (int mtype, const char * hp, unsigned int hsize,
                          char * to, size_t tsize)
{
  int r = snprintf (to, tsize, " mt %d ", mtype);
  unsigned int itsize = (unsigned int)tsize;

  switch (mtype) {
  case ALLNET_MGMT_BEACON:
    if (hsize < sizeof (struct allnet_mgmt_beacon)) {
      r += snprintf (to + r, minz (itsize, r), "beacon size %d, min %zd\n",
                     hsize, sizeof (struct allnet_mgmt_beacon));
    } else {
      const struct allnet_mgmt_beacon * amb =
        (const struct allnet_mgmt_beacon *) hp;
      r += snprintf (to + r, minz (itsize, r), "beacon %s (%lldns)",
                     b2su (amb->receiver_nonce, NONCE_SIZE),
                     readb64 ((char *) (amb->awake_time)));
    }
    break;
  case ALLNET_MGMT_BEACON_REPLY:
    if (hsize < sizeof (struct allnet_mgmt_beacon_reply)) {
      r += snprintf (to + r, minz (itsize, r),
                     "beacon reply size %d, min %zd\n",
                     hsize, sizeof (struct allnet_mgmt_beacon_reply));
    } else {
      const struct allnet_mgmt_beacon_reply * ambr =
        (const struct allnet_mgmt_beacon_reply *) hp;
      r += snprintf (to + r, minz (itsize, r), "beacon reply r %s ",
                     b2su (ambr->receiver_nonce, NONCE_SIZE));
      r += snprintf (to + r, minz (itsize, r), "s %s",
                     b2su (ambr->sender_nonce, NONCE_SIZE));
    }
    break;
  case ALLNET_MGMT_BEACON_GRANT:
    if (hsize < sizeof (struct allnet_mgmt_beacon_grant)) {
      r += snprintf (to + r, minz (itsize, r),
                     "beacon grant size %d, min %zd\n",
                     hsize, sizeof (struct allnet_mgmt_beacon_grant));
    } else {
      const struct allnet_mgmt_beacon_grant * ambg =
        (const struct allnet_mgmt_beacon_grant *) hp;
      r += snprintf (to + r, minz (itsize, r), "beacon grant r %s ",
                     b2su (ambg->receiver_nonce, NONCE_SIZE));
      r += snprintf (to + r, minz (itsize, r), "s %s %lldns",
                     b2su (ambg->sender_nonce, NONCE_SIZE),
                     readb64 ((char *) (ambg->send_time)));
    }
    break;
  case ALLNET_MGMT_PEER_REQUEST:
    r += snprintf (to + r, minz (itsize, r), "peer request");
    break;
  case ALLNET_MGMT_PEERS:
    if (hsize < sizeof (struct allnet_mgmt_peers)) {
      r += snprintf (to + r, minz (itsize, r), "peer size %d, min %zd\n",
                     hsize, sizeof (struct allnet_mgmt_peers));
    } else {
      const struct allnet_mgmt_peers * amp =
        (const struct allnet_mgmt_peers *) hp;
      unsigned int needed = sizeof (struct allnet_mgmt_peers) +
                            amp->num_peers *
                              sizeof (struct allnet_internet_addr);
      if (hsize < needed) {
        r += snprintf (to + r, minz (itsize, r), "peer size %d, needed %d\n",
                       hsize, needed);
      } else {
        r += snprintf (to + r, minz (itsize, r), "peers %d ", amp->num_peers);
        int i;
        for (i = 0; i < amp->num_peers; i++) {
          char local [100];
          ia_to_string (amp->peers + i, local, sizeof (local));
          char * nl = strchr (local, '\n');
          if (nl == NULL)
            allnet_crash ("allnet_mgmt_peers: no newline from ia_to_string");
          else
            *nl = '\0';
          r += snprintf (to + r, minz (itsize, r), "%s", local);
          if (i + 1 < amp->num_peers)
            r += snprintf (to + r, minz (itsize, r), ", ");
        }
      }
    }
    break;
  case ALLNET_MGMT_DHT:
    if (hsize < sizeof (struct allnet_mgmt_dht)) {
      r += snprintf (to + r, minz (itsize, r), "dht rcvd size %d, min %zd\n",
                     hsize, sizeof (struct allnet_mgmt_dht));
    } else {
      const struct allnet_mgmt_dht * dht = (const struct allnet_mgmt_dht *) hp;
      unsigned int needed = sizeof (struct allnet_mgmt_dht) +
                            (dht->num_sender + dht->num_dht_nodes) *
                            sizeof (struct allnet_addr_info);
      const struct allnet_addr_info * nodes = dht->nodes;
      int print_status = 1;  /* normal print */
      if (hsize < needed) {
        r += snprintf (to + r, minz (itsize, r), "size %d, needed %d\n",
                       hsize, needed);
        print_status = 0;  /* already printed */
      }
      if (print_status != 0) {
        char time_string [100];
        char address_string [200];
        allnet_time_string (readb64 ((char *) (dht->timestamp)), time_string);
        if ((print_status != 2) &&
            (ia_to_string (&(dht->sending_to_ip), address_string,
                           sizeof (address_string)))) {
          /* remove the newline placed by ia_to_string */
          address_string [strlen (address_string) - 1] = '\0';
          r += snprintf (to + r, minz (itsize, r), "sent to %s dht %d+%d @%s",
                         address_string, dht->num_sender,
                         dht->num_dht_nodes, time_string);
        } else {
          r += snprintf (to + r, minz (itsize, r), "dht %d+%d @%s",
                         dht->num_sender, dht->num_dht_nodes, time_string);
        }
        int i;
        for (i = 0; i < dht->num_sender + dht->num_dht_nodes; i++) {
          char local [100];
          ia_to_string (&(nodes [i].ip), local, sizeof (local));
          char * nl = strchr (local, '\n');
          if (nl == NULL)
            allnet_crash ("allnet_mgmt_dht: no newline from ia_to_string");
          else
            *nl = '\0';
          char * dht_type =
            ((nodes [i].type == ALLNET_ADDR_INFO_TYPE_RP) ? "rp" :
             ((nodes [i].type == ALLNET_ADDR_INFO_TYPE_DHT) ? "dht" :
              "unknown"));
          r += snprintf (to + r, minz (itsize, r),
                         "\n%d: %s/%d, dist %d, type %s, %s",
                         i, b2su (nodes [i].destination, ADDRESS_SIZE),
                         nodes [i].nbits, nodes [i].hops, dht_type, local);
        }
      }
    }
    break;
  case ALLNET_MGMT_TRACE_REQ:
    if (hsize < sizeof (struct allnet_mgmt_trace_req)) {
      r += snprintf (to + r, minz (itsize, r),
                     "illegal trace request size %d, min %zd\n",
                     hsize, sizeof (struct allnet_mgmt_trace_req));
    } else {
      const struct allnet_mgmt_trace_req * amt =
        (const struct allnet_mgmt_trace_req *) hp;
      int ks = readb16 ((char *) (amt->pubkey_size));
      unsigned int needed =
        sizeof (struct allnet_mgmt_trace_req) + ks +
        amt->num_entries * sizeof (struct allnet_mgmt_trace_entry);
      if (hsize < needed) {
        r += snprintf (to + r, minz (itsize, r),
                       "%s %d, needed %d (ks %d, %d entries)\n",
                       "illegal trace req size", hsize, needed, ks,
                       amt->num_entries);
      } else {
        r += snprintf (to + r, minz (itsize, r), "trace request %d %d %s ",
                       amt->num_entries, ks,
                       ((amt->intermediate_replies != 0) ? "all" : "final"));
        r += buffer_to_string ((char *) (amt->trace_id), NONCE_SIZE, "id",
                               6, 0, to + r, minz (itsize, r));
        int i;
        for (i = 0; i < amt->num_entries; i++)
          r += trace_entry_to_string (amt->trace + i, to + r, minz (itsize, r));
      }
    }
    break;
  case ALLNET_MGMT_TRACE_REPLY:
    if (hsize < 1) {
      r += snprintf (to + r, minz (itsize, r), "trace reply size %d, min 1\n",
                     hsize);
    } else if (*hp == 1) {
      r += snprintf (to + r, minz (itsize, r),
                     "%d-byte encrypted trace replyd\n",
                     hsize);
    } else if (hsize < sizeof (struct allnet_mgmt_trace_reply)) {
      r += snprintf (to + r, minz (itsize, r), "trace reply size %d, min %zd\n",
                     hsize, sizeof (struct allnet_mgmt_trace_reply));
    } else {
      const struct allnet_mgmt_trace_reply * amt =
        (const struct allnet_mgmt_trace_reply *) hp;
      unsigned int needed =
        sizeof (struct allnet_mgmt_trace_reply) +
        amt->num_entries * sizeof (struct allnet_mgmt_trace_entry);
      if (hsize < needed) {
        r += snprintf (to + r, minz (itsize, r),
                       "trace reply size %d, needed %d\n", hsize, needed);
      } else {
        r += snprintf (to + r, minz (itsize, r), "trace reply %d %s ",
                       amt->num_entries,
                       ((amt->intermediate_reply != 0) ? "int" : "final"));
        r += buffer_to_string ((char *) (amt->trace_id), NONCE_SIZE, "id",
                               6, 0, to + r, minz (itsize, r));
        int i;
        for (i = 0; i < amt->num_entries; i++)
          r += trace_entry_to_string (amt->trace + i, to + r, minz (itsize, r));
      }
    }
    break;
  case ALLNET_MGMT_KEEPALIVE:
    r += snprintf (to + r, minz (itsize, r), "keepalive");
    if (hsize >= KEEPALIVE_AUTHENTICATION_SIZE)
      r += buffer_to_string (hp, KEEPALIVE_AUTHENTICATION_SIZE,
                             ", sender auth", 20, 0, to + r, minz (itsize, r));
    if (hsize >= 2 * KEEPALIVE_AUTHENTICATION_SIZE)
      r += buffer_to_string (hp + KEEPALIVE_AUTHENTICATION_SIZE,
                             KEEPALIVE_AUTHENTICATION_SIZE, ", receiver auth",
                             20, 0, to + r, minz (itsize, r));
    break;
  default:
    r += snprintf (to + r, minz (itsize, r),
                   "unknown management type %d", mtype);
    break;
  }
  return r;
}

static int bitmap_to_string (char * to, unsigned int tsize,
                             unsigned int exponent,
                             unsigned char ** my_bitmap, int add_slash)
{
  int off = 0;
  if (add_slash)
    off = snprintf (to, tsize, " /");
  off += snprintf (to + off, minz (tsize, off), " %d(%d)",
                   exponent, p2 (exponent));
  if (exponent <= 0)
    return off;
  off += snprintf (to + off, minz (tsize, off), ": ");
  int num_bits = p2 (exponent);  /* already checked exponent > 0 */
  int num_bytes = (num_bits + 7) / 8;
  unsigned char * bitmap = *my_bitmap;
  *my_bitmap = bitmap + num_bytes;  /* return value */
  int found = 0;  /* did we find anything? */
  int i;
  for (i = 0; i < num_bits; i++) {
    int sixteen = i;  /* the index/mask functions always require 16 bits */
    if (exponent < 16)
      sixteen = sixteen << (16 - exponent);
    else if (exponent > 16)
      sixteen = sixteen << (exponent - 16);
    int index = allnet_bitmap_byte_index (exponent, sixteen);
    int mask = allnet_bitmap_byte_mask (exponent, sixteen);
    if (bitmap [index] & mask) {
      off += snprintf (to + off, minz (tsize, off), "%s%x",
                       ((found) ? ", " : ""), i);
      found = 1;
    }
  }
  if (! found)
    off += snprintf (to + off, minz (tsize, off), "(empty)");
  return off;
}

/* same as print_buffer, but prints to the given string */
void packet_to_string (const char * buffer, unsigned int bsize,
                       const char * desc, int print_eol,
                       char * to, size_t tsize)
{
  if (tsize <= 0)
    return;
  unsigned int itsize = (unsigned int) tsize;
  int off = 0;
  if ((desc != NULL) && (strlen (desc) > 0))
    off = snprintf (to, itsize, "%s ", desc);
  char * reason = NULL;
  if (! is_valid_message (buffer, bsize, &reason)) {
    off += snprintf (to + off, minz (itsize, off),
                     "invalid message (%s, hops %d/%d) of size %d%s",
                     reason, buffer [2], buffer [3], bsize,
                     (print_eol) ? "\n" : "");
    if (off < itsize)
      off += buffer_to_string (buffer, bsize, NULL, 100, 0,
                               to + off, minz (itsize, off));;
    if ((off < itsize) && (bsize > 4))
      off += buffer_to_string (buffer + bsize - 4, 4, "(last)", 4, print_eol,
                               to + off, minz (itsize, off));;
    return;
  }
  struct allnet_header * hp = (struct allnet_header *) buffer;
  if (hp->version != ALLNET_VERSION)
    off += snprintf (to + off, minz (itsize, off), "v %d (current %d) ",
                     hp->version, ALLNET_VERSION);
  int t = hp->transport;
  int hsize = ALLNET_SIZE (t);
  int mgmt_type = ((bsize > hsize) ? (buffer [hsize] & 0xff) : -1);
  off += snprintf (to + off, minz (itsize, off),
                   "(%dB) %d/%s: %d/%d hops, sig %d, t %x", bsize,
                   hp->message_type,
                   mtype_to_string (hp->message_type, mgmt_type),
                   hp->hops, hp->max_hops, hp->sig_algo, t);

  /* print the addresses, if any */
  if (hp->src_nbits != 0)
    off += snprintf (to + off, minz (itsize, off), " from %s/%d",
                     b2su (hp->source, (hp->src_nbits + 7) / 8), hp->src_nbits);
  else
    off += snprintf (to + off, minz (itsize, off), " from X");
  if (hp->dst_nbits != 0)
    off += snprintf (to + off, minz (itsize, off), " to %s/%d",
                     b2su (hp->destination, (hp->dst_nbits + 7) / 8),
                     hp->dst_nbits);
  else
    off += snprintf (to + off, minz (itsize, off), " to Y");

  /* print the transport information */
  if (t != 0) {
    if ((t & ALLNET_TRANSPORT_STREAM) != 0)
      off += snprintf (to + off, minz (itsize, off),
                       " s %s",
                       b2s (ALLNET_STREAM_ID (hp, t, (unsigned int) bsize),
                            MESSAGE_ID_SIZE));
    if ((t & ALLNET_TRANSPORT_ACK_REQ) != 0)
      off += snprintf (to + off, minz (itsize, off),
                       " a %s", b2s (ALLNET_MESSAGE_ID (hp, t,
                                                        (unsigned int) bsize),
                                     MESSAGE_ID_SIZE));
    if ((t & ALLNET_TRANSPORT_LARGE) != 0) {
      off += snprintf (to + off, minz (itsize, off),
                          " l %s", b2s (ALLNET_PACKET_ID (hp, t,
                                                          (unsigned int) bsize),
                                        MESSAGE_ID_SIZE));
      off += snprintf (to + off, minz (itsize, off),
                          "/n%lld",
                          readb64 (ALLNET_NPACKETS (hp, t,
                                                    (unsigned int) bsize) + 8));
      off += snprintf (to + off, minz (itsize, off),
                          "/s%lld",
                          readb64 (ALLNET_SEQUENCE (hp, t,
                                                    (unsigned int) bsize) + 8));
    }
    if ((t & ALLNET_TRANSPORT_EXPIRATION) != 0) {
      unsigned long long tull = 0;  /* avoids a silly compiler warning */
      tull = readb64 (ALLNET_EXPIRATION (hp, t, (unsigned int) bsize));
      time_t tt = (time_t) (tull + ALLNET_Y2K_SECONDS_IN_UNIX);
      char time_buf [100];
      ctime_r (&tt, time_buf);
      time_buf [24] = '\0';   /* get rid of the newline */
      off += snprintf (to + off, minz (itsize, off),
                       " e %lld (%s, in %lld s)", tull, time_buf,
                       tull - allnet_time ());
    }
    if ((t & ALLNET_TRANSPORT_DO_NOT_CACHE) != 0)
      off += snprintf (to + off, minz (itsize, off), " do-not-cache");
  }
  if (hp->message_type == ALLNET_TYPE_MGMT) {
    int data_offset = ALLNET_MGMT_HEADER_SIZE (t);
    if (bsize < data_offset) {
      off += snprintf (to + off, minz (itsize, off), " mgmt size %d, need %d", 
                       bsize, data_offset);
    } else {
      struct allnet_mgmt_header * mp =
        (struct allnet_mgmt_header *) (buffer + ALLNET_SIZE(t));
      const char * next = buffer + data_offset;
      unsigned int nsize = minz (bsize, data_offset);
      off += mgmt_to_string (mp->mgmt_type, next, nsize,
                             to + off, minz (itsize, off));
    }
  } else if (bsize > (ALLNET_SIZE (hp->transport))) {
    unsigned int dsize = bsize - ALLNET_SIZE (hp->transport);
    off += snprintf (to + off, minz (itsize, off),
                     ", %d bytes of payload", dsize);
    if ((hp->sig_algo != ALLNET_SIGTYPE_NONE) && (bsize > 2) && (dsize > 2)) {
      unsigned int ssize = readb16 (buffer + bsize - 2);
      if (dsize > ssize + 2) {
        dsize -= ssize + 2;
        off += snprintf (to + off, minz (itsize, off), " = %d data, %d + 2 sig",
                         dsize, ssize);
      } else {
        off += snprintf (to + off, minz (itsize, off),
                         " = %d overall with unreasonable %d + 2 sig", 
                         dsize, ssize);
      }
    }
    if (hp->message_type == ALLNET_TYPE_ACK) {
      unsigned int num_acks = dsize / MESSAGE_ID_SIZE;
      if (num_acks * MESSAGE_ID_SIZE == dsize)
        off += snprintf (to + off, minz (itsize, off), " = %u acks", num_acks);
      else
        off += snprintf (to + off, minz (itsize, off), " = %u acks + %u bytes",
                         num_acks, dsize - num_acks * MESSAGE_ID_SIZE);
      unsigned int i;
      for (i = 0; i < num_acks; i++) {
        const char * ackp = buffer + ALLNET_SIZE (hp->transport) +
                            i * MESSAGE_ID_SIZE;
        off += buffer_to_string (ackp, MESSAGE_ID_SIZE,
                                 ", ", 5, 0, to + off, minz (itsize, off));
        char hash [MESSAGE_ID_SIZE];
        sha512_bytes (ackp, MESSAGE_ID_SIZE, hash, sizeof (hash));
        off += buffer_to_string (hash, MESSAGE_ID_SIZE,
                                 " -> ", 5, 0, to + off, minz (itsize, off));
      }
    } else if (hp->message_type == ALLNET_TYPE_DATA_REQ) {
      struct allnet_data_request * adrp =
        (struct allnet_data_request *) (buffer + (ALLNET_SIZE (hp->transport)));
      char token_string [200];
      buffer_to_string ((char *) adrp->token, sizeof (adrp->token), "token",
                        100, 0, token_string, sizeof (token_string));
      char time_string [100];
      allnet_time_string (readb64u (adrp->since), time_string);
      off += snprintf (to + off, minz (itsize, off),
                       ", %s, requesting since %s, ",
                       token_string, time_string);
      off += snprintf (to + off, minz (itsize, off), "dst/src/mid bitmaps");
      unsigned char * bitmap = adrp->dst_bitmap;
      off += bitmap_to_string (to + off, minz (itsize, off),
                               adrp->dst_bits_power_two, &bitmap, 0);
      off += bitmap_to_string (to + off, minz (itsize, off),
                               adrp->src_bits_power_two, &bitmap, 1);
      off += bitmap_to_string (to + off, minz (itsize, off),
                               adrp->mid_bits_power_two, &bitmap, 1);
    }
  }
  if (print_eol)
    off += snprintf (to + off, minz (itsize, off), "\n");
}

void print_packet (const char * packet, unsigned int psize, const char * desc,
                   int print_eol)
{
  static char buffer [10000];
  packet_to_string (packet, psize, desc, print_eol, buffer, sizeof (buffer));
  printf ("%s", buffer);
}

/* buffer must be at least ALLNET_SIZE(transport) bytes long
 * returns a pointer to the buffer, but cast to an allnet_header
 * returns NULL if any of the parameters are invalid (e.g. message_type)
 * if sbits is zero, source may be NULL, and likewise for dbits and dest
 * if stream is not NULL it must refer to STREAM_ID_SIZE bytes, and
 * transport will include ALLNET_TRANSPORT_STREAM
 * if ack is not NULL it must refer to MESSAGE_ID_SIZE bytes, and 
 * transport will include ALLNET_TRANSPORT_ACK_REQ
 * if ack and stream are both NULL, transport will be set to 0 
 *
 * ALLNET_TRANSPORT_LARGE packets are not supported by this call */
struct allnet_header *
  init_packet (char * packet, unsigned int psize, unsigned int message_type,
               unsigned int max_hops, unsigned int sig_algo,
               const unsigned char * source, unsigned int sbits,
               const unsigned char * dest, unsigned int dbits,
               const unsigned char * stream, const unsigned char * ack)
{
  int transport = 0;
  if (stream != NULL)
    transport |= ALLNET_TRANSPORT_STREAM;
  if (ack != NULL)
    transport |= ALLNET_TRANSPORT_ACK_REQ;
  struct allnet_header * hp = (struct allnet_header *) packet;
  if ((psize < ALLNET_HEADER_SIZE) ||
      (psize < (ALLNET_SIZE (transport))))
    return NULL;
  if ((message_type < ALLNET_TYPE_DATA) || (message_type > ALLNET_TYPE_MGMT))
    return NULL;
  if ((max_hops < 1) || (max_hops > 255))
    return NULL;
  if ((sig_algo < ALLNET_SIGTYPE_NONE) ||
      (sig_algo > ALLNET_SIGTYPE_HMAC_SHA512))
    return NULL;
  if ((sbits > ADDRESS_BITS) || (dbits > ADDRESS_BITS))
    return NULL;
  memset (packet, 0, psize);   /* clear all unused fields */
  hp->version = ALLNET_VERSION;
  hp->message_type = message_type;
  hp->hops = 0;
  hp->max_hops = max_hops;
  hp->src_nbits = sbits;
  hp->dst_nbits = dbits;
  hp->sig_algo = sig_algo;
  if ((sbits > 0) && (sbits <= MESSAGE_ID_BITS) && (source != NULL))
    memcpy (hp->source, source, (sbits + 7) / 8);
  if ((dbits > 0) && (dbits <= MESSAGE_ID_BITS) && (dest != NULL))
    memcpy (hp->destination, dest, (dbits + 7) / 8);
  hp->transport = transport;
  char * sid = ALLNET_STREAM_ID (hp, hp->transport, (unsigned int) psize);
  if ((stream != NULL) && (sid != NULL))
    memcpy (sid, stream, STREAM_ID_SIZE);
  if (ack != NULL) {
    sha512_bytes ((const char *) ack, MESSAGE_ID_SIZE,
                  ALLNET_MESSAGE_ID (hp, hp->transport, (unsigned int) psize),
                  MESSAGE_ID_SIZE);
  }
  return hp;
}

/* malloc's (must be free'd), initializes, and returns a packet with the
 * given data size.
 * If ack is not NULL, the data size parameter should NOT include the
 * MESSAGE_ID_SIZE bytes of the ack.
 * *size is set to the size to send */
struct allnet_header *
  create_packet (unsigned int data_size, unsigned int message_type,
                 unsigned int max_hops, unsigned int sig_algo,
                 const unsigned char * source, unsigned int sbits,
                 const unsigned char * dest, unsigned int dbits,
                 const unsigned char * stream, const unsigned char * ack,
                 unsigned int * size)
{
  int transport = 0;
  if (stream != NULL)
    transport |= ALLNET_TRANSPORT_STREAM;
  if (ack != NULL)
    transport |= ALLNET_TRANSPORT_ACK_REQ;
  unsigned int alloc_size = ALLNET_SIZE (transport) + data_size;
  if (ack != NULL)
    alloc_size += MESSAGE_ID_SIZE;
  char * buffer = malloc_or_fail (alloc_size, "util.c create_packet");
  *size = alloc_size;
  struct allnet_header * result =
    init_packet (buffer, alloc_size, message_type, max_hops, sig_algo,
                 source, sbits, dest, dbits, stream, ack);
  if (result != NULL)
    return result;
  free (buffer);
  return NULL;
}

/* return a keepalive packet, which is in a static buffer
 * (do not change or free) and fill in the size to send */
const char * keepalive_packet (unsigned int * size)
{
#define KEEPALIVE_SIZE (ALLNET_MGMT_HEADER_SIZE (ALLNET_TRANSPORT_DO_NOT_CACHE))
  static char result [KEEPALIVE_SIZE];
  static int msize = 0;
  if (msize == 0) {
    struct allnet_header * hp =
      init_packet (result, sizeof (result),
                   ALLNET_TYPE_MGMT, 1, ALLNET_SIGTYPE_NONE,
                   NULL, 0, NULL, 0, NULL, NULL);
    hp->transport = ALLNET_TRANSPORT_DO_NOT_CACHE;
    msize = sizeof (result);
    char * data = ALLNET_DATA_START (hp, hp->transport, msize);
    struct allnet_mgmt_header * amh = (struct allnet_mgmt_header *) data;
    amh->mgmt_type = ALLNET_MGMT_KEEPALIVE;
  }
  *size = msize;
  return result;
}

/* return a larger keepalive packet in the given buffer, computing the
 * sender authentication and filling in the receiver authentication
 * (must be of size KEEPALIVE_AUTHENTICATION_SIZE), or
 * if receiver_auth is NULL or all zeros, the packet is shorter
 * returns the size to send, always <= bsize (0 for errors) */
int keepalive_auth (char * buffer, int bsize,
                    struct sockaddr_storage addr,
                    const char * secret, int slen,
                    long long int counter,
                    const char * receiver_auth)
{
  unsigned int hsize = 0;
  const char * header = keepalive_packet (&hsize);  /* header is from above */
  int rsize = hsize + KEEPALIVE_AUTHENTICATION_SIZE;
  int larger = 0;
  if ((receiver_auth != NULL) &&
      (! (memget (receiver_auth, 0, KEEPALIVE_AUTHENTICATION_SIZE))))
    larger = 1;
  if (larger)
    rsize += KEEPALIVE_AUTHENTICATION_SIZE;
  if ((rsize > bsize) || ((rsize != 40) && (rsize != 48)) || (hsize != 32)) {
printf ("likely error: keepalive size %d, buffer size %d, hsize %d, large %d\n",
rsize, bsize, hsize, larger);
    return 0;
  }
  memcpy (buffer, header, hsize);
  compute_sender_auth (addr, secret, slen, counter,
                       buffer + hsize, KEEPALIVE_AUTHENTICATION_SIZE);
  if (larger)
    memcpy (buffer + hsize + KEEPALIVE_AUTHENTICATION_SIZE,
            receiver_auth, KEEPALIVE_AUTHENTICATION_SIZE);
  return rsize;
}

/* malloc, initialize, and return an ack message for a received packet.
 * The message_ack bytes are taken from the argument, not from the packet.
 * *size is set to the size to send
 * if from is NULL, the source address is taken from packet->destination,
 * and then nbits is the minimum of the nbits parameter and the destination
 * bits from the packet -- use ADDRESS_BITS to use all the bits in packet */
struct allnet_header *
  create_ack (struct allnet_header * packet, const unsigned char * ack,
              const unsigned char * from, unsigned int nbits,
              unsigned int * size)
{
  *size = 0;   /* in case of early return */
  unsigned int alloc_size = ALLNET_ACK_MIN_SIZE;
  char * buffer = malloc_or_fail (alloc_size, "util.c create_ack");
  struct allnet_header * result =
    init_ack (packet, ack, from, nbits, buffer, size);
  if (result != NULL)
    return result;
  free (buffer);
  return NULL;
}

/* the same, without malloc.  buffer must have ALLNET_ACK_MIN_SIZE bytes,
 * and the return value points directly to buffer */
struct allnet_header *
  init_ack (const struct allnet_header * packet, const unsigned char * ack,
            const unsigned char * from, unsigned int nbits,
            char * buffer, unsigned int * size)
{
  *size = 0;   /* in case of early return */
  if (from == NULL) {
    from = packet->destination;
    if (nbits > packet->dst_nbits)
      nbits = packet->dst_nbits;
  }
  struct allnet_header * hp =
    init_packet (buffer, ALLNET_ACK_MIN_SIZE, ALLNET_TYPE_ACK, packet->hops + 3,
                 ALLNET_SIGTYPE_NONE, from, nbits,
                 packet->source, packet->src_nbits, NULL, NULL);
  char * ackp = ALLNET_DATA_START(hp, hp->transport, ALLNET_ACK_MIN_SIZE);
  if (ALLNET_ACK_MIN_SIZE - (ackp - buffer) != MESSAGE_ID_SIZE) {
    printf ("coding error in init_ack!!!! %d %p %p %d %d\n",
            (int) ALLNET_ACK_MIN_SIZE, ackp, buffer,
            (int) (ALLNET_ACK_MIN_SIZE - (ackp - buffer)), MESSAGE_ID_SIZE);
    return NULL;
  }
  memcpy (ackp, ack, MESSAGE_ID_SIZE);
  *size = ALLNET_ACK_MIN_SIZE;
  return hp;
}

int print_sockaddr_str (const struct sockaddr * sap, socklen_t addr_size,
                        char * s, unsigned int len)
{
  if (len <= 0)
    return 0;
  if (sap == NULL)
    return snprintf (s, len, "(null sockaddr)");
  const struct sockaddr_in  * sin  = (const struct sockaddr_in  *) sap;
  const struct sockaddr_in6 * sin6 = (const struct sockaddr_in6 *) sap;
  const struct sockaddr_un  * sun  = (const struct sockaddr_un  *) sap;
#ifdef ALLNET_NETPACKET_SUPPORT
  struct sockaddr_ll  * sll  = (struct sockaddr_ll  *) sap;
#endif /* ALLNET_NETPACKET_SUPPORT */
  /* char str [INET_ADDRSTRLEN]; */
  int num_initial_zeros = 0;  /* for printing ipv6 addrs */
  int n = 0;   /* offset for printing */
  int i;
  switch (sap->sa_family) {
  case AF_INET:
    n += snprintf (s + n, minz (len, n), "ip4 %s %d/%x",
                   inet_ntoa (sin->sin_addr),
                   ntohs (sin->sin_port), ntohs (sin->sin_port));
    if ((addr_size != 0) && (addr_size < (int) (sizeof (struct sockaddr_in))))
      n += snprintf (s + n, minz (len, n), " (size %d rather than %zd)",
                     addr_size, sizeof (struct sockaddr_in));
    break;
  case AF_INET6:
    /* inet_ntop (AF_INET6, sap, str, sizeof (str)); */
    n += snprintf (s + n, minz (len, n), "ip6 ");
    for (i = 0; i + 1 < (int) (sizeof (sin6->sin6_addr)); i++)
      if ((sin6->sin6_addr.s6_addr [i] & 0xff) == 0)
        num_initial_zeros++;
      else
        break;
    if ((num_initial_zeros == 10) &&
        ((sin6->sin6_addr.s6_addr [10] & 0xff) == 0xff) &&
        ((sin6->sin6_addr.s6_addr [11] & 0xff) == 0xff)) { /* ipv4 in v6 */
      const unsigned char * p = &(sin6->sin6_addr.s6_addr [12]);
      n += snprintf (s + n, minz (len, n), "::ffff:%u.%u.%u.%u",
                     p [0], p [1], p [2], p [3]);
    } else {
      if ((num_initial_zeros & 0x1) > 0)  /* make it even */
        num_initial_zeros--;
      if (num_initial_zeros > 0)
        n += snprintf (s + n, minz (len, n), "::");
      for (i = num_initial_zeros; i < (int) (sizeof (sin6->sin6_addr));
           i += 2) {
        int two_byte = ((sin6->sin6_addr.s6_addr [i] & 0xff) << 8) |
                        (sin6->sin6_addr.s6_addr [i + 1] & 0xff);
        n += snprintf (s + n, minz (len, n), "%x", two_byte);
        if (i + 2 < (int) (sizeof (sin6->sin6_addr)))
          /* need the "if" because the last one is not followed by : */
          n += snprintf (s + n, minz (len, n), ":");
      }
    }
    n += snprintf (s + n, minz (len, n), " %d/%x",
                   ntohs (sin6->sin6_port), ntohs (sin6->sin6_port));
    if ((addr_size != 0) && (addr_size < (int) (sizeof (struct sockaddr_in6))))
      n += snprintf (s + n, minz (len, n), " (size %d rather than %zd)",
                     addr_size, sizeof (struct sockaddr_in6));
    break;
  case AF_UNIX:
    n += snprintf (s + n, minz (len, n), "unix %s", sun->sun_path);
    if ((addr_size != 0) && (addr_size < (int) (sizeof (struct sockaddr_un))))
      n += snprintf (s + n, minz (len, n), " (size %d rather than %zd)",
                     addr_size, sizeof (struct sockaddr_un));
    break;
#ifdef ALLNET_NETPACKET_SUPPORT
  case AF_PACKET:
    n += snprintf (s + n, minz (len, n),
                   "packet protocol 0x%x if %d ha %d pkt %d address (%d)",
                   ntohs (sll->sll_protocol), sll->sll_ifindex, sll->sll_hatype,
                   sll->sll_pkttype, sll->sll_halen);
    for (i = 0; i < sll->sll_halen; i++)
      n += snprintf (s + n, minz (len, n), " %02x", sll->sll_addr [i] & 0xff);
    if ((addr_size != 0) && (addr_size != sizeof (struct sockaddr_ll)))
      n += snprintf (s + n, minz (len, n), " (size %d rather than %zd)",
                     addr_size, sizeof (struct sockaddr_ll));
    break;
#endif /* ALLNET_NETPACKET_SUPPORT */
  default:
    n += snprintf (s + n, minz (len, n), "unknown address family %d",
                   sap->sa_family);
    break;
  }
  return n;
}

/* tcp should be 1 for TCP, 0 for UDP, -1 for neither */
void print_sockaddr (const struct sockaddr * sap, socklen_t addr_size)
{
  char buffer [1000];
  print_sockaddr_str (sap, addr_size, buffer, sizeof (buffer));
  printf ("%s", buffer);
}

/* the argument should be an errno.  Returns 0 if the errno is net/host
 * unreachable, net down/reset, or addr not available, 1 otherwise */
int unusual_sendto_error (int e)
{
  return ((e != ENETUNREACH) && (e != EHOSTUNREACH) &&
          (e != ENETDOWN) && (e != ENETRESET) &&
          (e != EADDRNOTAVAIL));
}

/* print a message with the current time */
void print_timestamp (const char * message)
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

/* functions used to modify and read data request bitmaps
 * power_two is the size of the bitmap, in bits.
 * first_sixteen holds the first sixteen bits of the address or ID.
 * these functions return a byte index, 0 <= index < 2^power_two,
 * or a mask equal to 1 << offset, where 0 <= offset < 8,
 * as long as: 0 < power_two <= 16, and 0 <= first_sixteen < 2^16,
 * (if these constraints are not respected, these functions return -1) */

static void compute_index_mask (int power_two, int first_sixteen,
                                int * indexp, int * maskp)
{
#define MASK_SIXTEEN	0xffff
  *indexp = -1;
  *maskp = -1;
  if ((power_two <= 0) || (power_two > 16))
    return;
  if ((first_sixteen < 0) || (first_sixteen > MASK_SIXTEEN))
    return;
  int significant_bits = (first_sixteen & MASK_SIXTEEN) >> (16 - power_two);
  int index = significant_bits / 8;
  int offset = significant_bits % 8;
  int mask = (1 << (7 - offset)) & 0xff;
  *indexp = index;
  *maskp = mask;
#undef MASK_SIXTEEN
}

int allnet_bitmap_byte_index (int power_two, int first_sixteen)
{
  int index;
  int mask;
  compute_index_mask (power_two, first_sixteen, &index, &mask);
  return index;
}

int allnet_bitmap_byte_mask (int power_two, int first_sixteen)
{
  int index;
  int mask;
  compute_index_mask (power_two, first_sixteen, &index, &mask);
  return mask;
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
  if (result > ALLNET_Y2K_SECONDS_IN_UNIX)
    return result - ALLNET_Y2K_SECONDS_IN_UNIX;
  else
    return 0;
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
  snprintf (result, ALLNET_TIME_STRING_SIZE, "bad time %lld\n", allnet_seconds);

  time_t unix_seconds = (time_t) (allnet_seconds + ALLNET_Y2K_SECONDS_IN_UNIX);
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
  snprintf (result, ALLNET_TIME_STRING_SIZE, "bad time %lld\n", allnet_seconds);

  time_t unix_seconds = (time_t) (allnet_seconds + ALLNET_Y2K_SECONDS_IN_UNIX);
  struct tm * detail_time = localtime (&unix_seconds);  /* sets tzname */
  if (detail_time == NULL)
    return;
  asctime_r (detail_time, result);
  if (result [24] == '\n')
    snprintf (result + 24, 5, " %s", tzname [0]);
}

/* useful time functions */
/* if t1 < t2, returns 0, otherwise returns t1 - t2 */
unsigned long long delta_us (const struct timeval * t1,
                             const struct timeval * t2)
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

static unsigned long long int random_mod (unsigned long long int mod)
{
  int nbytes = 1;
  unsigned long long int rand_max = 255;
  while (rand_max < mod) {
    nbytes++;
    rand_max = rand_max * 256 + 255;  /* 0xff..ff */
  }
  /* if rand_max + 1 is not a multiple of mod, there will be some bias
   * in favor of values 0..(rand_max + 1) % mod.  This corrects for the bias.
   * ideas from
       http://zuttobenkyou.wordpress.com/2012/10/18/generating-random-numbers-without-modulo-bias/
   */
  unsigned long long int rand_excess = (rand_max % mod) + 1;
  if (rand_excess == mod)
    rand_excess = 0;
  /* now get the random value */
  char rbytes [8];
  if (nbytes > (int) (sizeof (rbytes))) {
    printf ("unable to compute random number > 8 bytes (%d %zd)\n", nbytes,
            sizeof (rbytes));
    exit (1); /* long long ints greater than 8 bytes? might break many things */
  }
  while (1) {  /* loop until random value <= rand_max - rand_excess */
               /* usually one loop is enough */
    memset (rbytes, 0, sizeof (rbytes));
    /* set the low order nbytes of rbytes to random values */
    random_bytes (rbytes + (sizeof (rbytes) - nbytes), nbytes);
    unsigned long long int result = readb64 (rbytes);
/* printf ("got result %lld (%lld), max %lld - excess %lld = %lld\n",
        result, result % mod, rand_max, rand_excess, rand_max - rand_excess); */
    if (result <= rand_max - rand_excess)
      return result % mod;
/* printf ("...looping\n"); */
  }
  return 0;   /* we should never get here */
}

/* set result to a random time between start + min and start + max */
void set_time_random (const struct timeval * start, unsigned long long min,
                      unsigned long long max, struct timeval * result)
{
  *result = *start;
  if (min >= max)
    return;
  unsigned long long int us = min + random_mod (max - min);
  add_us (result, us);
}

/* sleep between 0 and us microseconds */
void sleep_time_random_us (unsigned long long us)
{
  usleep ((useconds_t) (random_mod (us)));
}

/* return true if comparison > multiplier * 2^exp */
static int is_greater_than_power_two (unsigned long long int comparison,
                                      unsigned long long int multiplier,
                                      unsigned long long int exp)
{
  if (exp <= 0)
    return comparison > multiplier;   /* 2^0 = 1 */
  unsigned long long int power = 1;
  while (exp-- > 0) {
    power *= 2;
    if (comparison <= multiplier * power)
      return 0;
  }
  return 1;
}

/* return 1 and update num_true_calls and last_true_time if one or more of:
 * the time since the last call is greater than max (or max is 0)
 * the time since the last call is greater than min * 2^num_true_calls
 * otherwise return 0 and num_true_calls and last_true_time are unchanged
 * all times are in microseconds */
int time_exp_interval (unsigned long long int * last_true_time,
                       unsigned long long int * num_true_calls,
                       unsigned long long int min,
                       unsigned long long int max)
{
  unsigned long long int now = allnet_time_us ();
  unsigned long long int delta = 0;
  if (now > *last_true_time)
    delta = now - *last_true_time;
  if ((*last_true_time == 0) || (delta > max) ||
      (is_greater_than_power_two (delta, min, *num_true_calls))) {
/* printf ("%p has value %llu, ", num_true_calls, *num_true_calls); */
    *num_true_calls = *num_true_calls + 1; 
/* printf ("updated to %p/%llu\n", num_true_calls, *num_true_calls); */
    *last_true_time = now; 
    return 1;
  }
  return 0;
}

/* if malloc is not successful, exit after printing */
void * malloc_or_fail (size_t bytes, const char * desc)
{
/* if (bytes > 1000000) printf ("malloc_or_fail %zd bytes for %s\n", bytes, desc); */
  void * result = malloc (bytes);
  if (result == NULL) {
    printf ("unable to allocate %zu bytes for %s\n", bytes, desc);
    assert (0);               /* cause a crash and core dump */
    /* if NDEBUG is set, assert will do nothing.  segfault instead */
    * ((int *) result) = 3;   /* cause a segmentation fault */
    exit (1);   /* we should never get here */
  }
  return result;
}

/* copy a string to new storage, using malloc_or_fail to get the memory */
char * strcpy_malloc (const char * string, const char * desc)
{
  size_t size = strlen (string) + 1;
  char * result = malloc_or_fail (size, desc);
  snprintf (result, size, "%s", string);
  return result;
}

char * strcat_malloc (const char * s1, const char * s2, const char * desc)
{
  size_t size = strlen (s1) + strlen (s2) + 1;
  char * result = malloc_or_fail (size, desc);
  snprintf (result, size, "%s%s", s1, s2);
  return result;
}

char * strcat3_malloc (const char * s1, const char * s2, const char * s3,
                       const char * desc)
{
  size_t size = strlen (s1) + strlen (s2) + strlen (s3) + 1;
  char * result = malloc_or_fail (size, desc);
  snprintf (result, size, "%s%s%s", s1, s2, s3);
  return result;
}

/* returns the new string with the first occurrence of pattern replaced
 * by repl.
 * If the pattern is not found in the original, the new string is a copy
 * of the old, and optionally an error message is printed
 * result is malloc'd, must be free'd (unless the original was NULL) */
char * string_replace_once (const char * original, const char * pattern,
                            const char * repl, int print_not_found)
{
  if (original == NULL) {
    if (print_not_found)
      printf ("error: empty string does not contain '%s'\n", pattern);
    return NULL;
  }
  char * p = strstr (original, pattern);
  if (p == NULL) {
    if (print_not_found)
      printf ("error: string %s does not contain '%s'\n", original, pattern);
    return strcpy_malloc (original, "string_replace_one copy");
  }
  size_t olen = strlen (original);
  size_t plen = strlen (pattern);
  size_t rlen = strlen (repl);
  size_t size = olen + 1 + rlen - plen;
  char * result = malloc_or_fail (size, "string_replace_one");
  size_t prelen = p - original;
  memcpy (result, original, prelen);
  memcpy (result + prelen, repl, rlen);
  char * postpos = p + plen;
  size_t postlen = olen - (postpos - original);
  memcpy (result + prelen + rlen, postpos, postlen);
  result [size - 1] = '\0';
/*  printf ("replacing %s with %s in %s gives %s\n",
          pattern, repl, original, result); */
  return result;
}

/* copy memory to new storage, using malloc_or_fail to get the memory */
void * memcpy_malloc (const void * bytes, size_t bsize, const char * desc)
{
  if (bsize <= 0)
    return NULL;
  char * result = malloc_or_fail (bsize, desc);
  memcpy (result, bytes, bsize);
  return result;
}

/* copy two buffers to new storage, using malloc_or_fail to get the memory */
void * memcat_malloc (const void * bytes1, size_t bsize1,
                      const void * bytes2, size_t bsize2,
                      const char * desc)
{
  if (bsize1 <= 0)
    return memcpy_malloc (bytes2, bsize2, desc);
  if (bsize2 <= 0)
    return memcpy_malloc (bytes1, bsize1, desc);
  /* from here, bsize1 and bsize2 are both greater than 0 */
  char * result = malloc_or_fail (bsize1 + bsize2, desc);
  memcpy (result, bytes1, bsize1);
  memcpy (result + bsize1, bytes2, bsize2);
  return result;
}

/* returns true if all the bytes of memory are set to value (or bsize is 0) */
int memget (const void * bytes, int value, size_t bsize)
{
  value = value & 0xff; /* otherwise an unsigned value of 255 becomes -1 */
  const char * p = bytes;
  int i;
  for (i = 0; i < bsize; i++)
    if ((p [i] & 0xff) != value)
      return 0;
  return 1;
}

/* returns -1 in case of errors, usually if the file doesn't exist */
long long int file_size (const char * file_name)
{
  struct stat st;
  if (stat (file_name, &st) < 0)
    return -1;
  return st.st_size;
}

long long int fd_size (int fd)
{
  struct stat st;
  if (fstat (fd, &st) < 0)
    return -1;
  return st.st_size;
}

/* return the number of deleted files, -1 in case of errors */
/* pattern is a literal. The file is rm'd if part of the file name matches it */
int rmdir_matching (const char * dirname, const char * pattern)
{
  int deleted = 0;
  DIR * dir = opendir (dirname);
  if (dir == NULL)  /* cannot open */
    return -1;
  struct dirent * de;
  while ((de = readdir (dir)) != NULL) {
    if ((strcmp (de->d_name, ".") == 0) || (strcmp (de->d_name, "..") == 0))
      continue;  /* don't delete current and parent directories */
    if (strstr (de->d_name, pattern) == NULL)
      continue;  /* no match, don't delete current */
    char * name = strcat3_malloc (dirname, "/", de->d_name, "rmdir_matching");
    if (unlink (name) == 0) /* recursively remove it, in case it's a dir */
      deleted++;
    else
      printf ("rmdir_matching unable to delete %s\n", name);
    free (name);
  }
  closedir (dir);
  return deleted;
}

/* return 1 if successful, 0 in case of errors, e.g. if the dir doesn't exist */
int rmdir_and_all_files (const char * dirname)
{
  DIR * dir = opendir (dirname);
  if (dir == NULL)  /* cannot open */
    return 0;
  struct dirent * de;
  while ((de = readdir (dir)) != NULL) {
    if ((strcmp (de->d_name, ".") == 0) || (strcmp (de->d_name, "..") == 0))
      continue;  /* don't delete current and parent directories */
    char * name = strcat3_malloc (dirname, "/", de->d_name,
                                  "rmdir_and_all_files");
    if (unlink (name) < 0) /* recursively remove it, in case it's a dir */
      rmdir_and_all_files (name);
    free (name);
  }
  closedir (dir);
  if (rmdir (dirname) == 0) /* only succeeds if all files and subdirs deleted */
    return 1;
  return 0;
}

static int read_fd_malloc_noclose (int fd, char ** content_p, int print_errors,
                                   const char * file_name)
{
  if (file_name == NULL)
    file_name = "(file name not available)";
  int size = (int)fd_size (fd);
  if (content_p == NULL)  /* just return the size */
    return minz (size, 0);
  *content_p = NULL;
  if (size <= 0)
    return 0;
  /* allocate one more so we can put a \0 at the end */
  /* (useful for text files, which can then be used as strings) */
  char * result = malloc (size + 1);
  if (result == NULL) {
    if (print_errors)
      printf ("unable to allocate %d bytes for contents of file %s\n",
              size, file_name);
    return 0;
  }
  ssize_t n = read (fd, result, size);
  if (n != size) {
    if (print_errors) {
      perror ("read");
      printf ("unable to read %d bytes from %s, got %zd\n",
              size, file_name, n);
    }
    free (result);
    return 0;
  }
  result [size] = '\0';   /* make sure it is a C string */
  *content_p = result;
  return size;
}

/* same as read_file_malloc, but fd must have been opened, and is closed
 * if close_fd is nonzero*/
int read_fd_malloc (int fd, char ** content_p, int print_errors, int close_fd,
                    const char * fname)
{
  int result = read_fd_malloc_noclose (fd, content_p, print_errors, fname);
  if (close_fd)
    close (fd);
  return result;
}

/* returns the file size, and if content_p is not NULL, allocates an
 * array to hold the file contents and assigns it to content_p.
 * one extra byte is allocated at the end and the content is null terminated.
 * in case of problems, returns -1, and prints the error if print_errors != 0 */
int read_file_malloc (const char * file_name, char ** content_p,
                      int print_errors)
{
  if (content_p != NULL)
    *content_p = NULL;
  long long int size = file_size (file_name);
  if (size < 0) {
    if (print_errors)
      printf ("%s: file not found\n", file_name);
    return -1;
  }
  if (content_p == NULL) {  /* if we can read it, just return the size */
    if (access (file_name, R_OK) == 0)
      return (int)size;  /* size >= 0 */
    else
      return -1;
  }
  *content_p = NULL;
  int fd = open (file_name, O_RDONLY);
  if (fd < 0) {
    if (print_errors) {
      perror ("open");
      printf ("unable to open file %s for reading\n", file_name);
    }
    return 0;
  }
  return read_fd_malloc (fd, content_p, print_errors, 1, file_name);
}

static int write_to_fd (int fd, const char * contents, int len,
                        int print_errors, const char * fname)
{
  int retval = 1;
  if (fd < 0) {
    if (print_errors) {
      perror ("open in write_to_fd");
      printf ("unable to open %s\n", fname);
    }
    retval = 0;
  } else if (len > 0) {
    ssize_t n = write (fd, contents, len);
    if (n < len) {
      if (print_errors) {
        perror ("write in write_to_fd");
        printf ("tried to write %d bytes to %s, wrote %zd\n", len, fname, n);
      }
      retval = 0;
    }
  }
  return retval;
}

int write_file (const char * fname, const char * contents, int len,
                int print_errors)
{
  int fd = open (fname, O_WRONLY | O_CREAT | O_TRUNC, 0600);
  if (fd < 0) {
    if (print_errors) {
      perror ("open in write_file");
      printf ("unable to open %s\n", fname);
    }
    return 0;
  }
  int result = write_to_fd (fd, contents, len, print_errors, fname);
  close (fd);
  return result;
}

int append_file (const char * fname, const char * contents, int len,
                 int print_errors)
{
  int fd = open (fname, O_WRONLY | O_CREAT | O_APPEND, 0600);
  int result = write_to_fd (fd, contents, len, print_errors, fname); 
  close (fd);
  return result;
}

/* low-grade randomness, in case the other calls don't work */
static void computed_random_bytes (char * buffer, size_t bsize)
{
  static int initialized = 0;
  if (! initialized) {  /* not very random, but better than nothing */
    struct timeval now;
    gettimeofday (&now, NULL);
    srandom ((unsigned)now.tv_sec ^ (unsigned)now.tv_usec);
    initialized = 1;
  }
  size_t i;
#ifdef __APPLE__
#define RANDOM	arc4random
#else /* __APPLE__ */
#define RANDOM	random
#endif /* __APPLE__ */
  for (i = 0; i < bsize; i++)
    buffer [i] = RANDOM () % 256;
#undef RANDOM
}

/* returns 1 if succeeds, 0 otherwise */
static int dev_urandom_bytes (char * buffer, size_t bsize)
{
  int fd = open ("/dev/urandom", O_RDONLY);
  if (fd < 0) {
    perror ("open /dev/urandom in lib/util.c");
    return 0;
  }
  ssize_t r = read (fd, buffer, bsize);
  if ((r < 0) || (((size_t) r) < bsize)) {
    perror ("read /dev/urandom");
    close (fd);
    return 0;
  }
  close (fd);
  return 1;
}

/* fill this array with random bytes */
void random_bytes (char * buffer, size_t bsize)
{
  if (! dev_urandom_bytes (buffer, bsize))
    computed_random_bytes (buffer, bsize);
}

/* a random int between min and max (inclusive) */
/* returns min if min >= max */
unsigned long long int random_int (unsigned long long int min, 
                                   unsigned long long int max)
{
  if (min >= max)
    return min;
#define ULLI_SIZE	(sizeof (unsigned long long int))
  char buffer [ULLI_SIZE];
  int size = ULLI_SIZE;
#undef ULLI_SIZE
  unsigned long long int delta = max - min + 1;
  if ((delta <= 0xffffffff) && (delta > 0) && (size > 4))
    size = 4;
  if ((delta <= 0xffff) && (delta > 0) && (size > 2))
    size = 2;
  if ((delta <= 0xff) && (delta > 0) && (size > 1))
    size = 1;
  random_bytes (buffer, size);
  unsigned long long int result = readb64 (buffer);
  if (size == 4)
    result = readb32 (buffer);
  if (size == 2)
    result = readb16 (buffer);
  if (size == 1)
    result = buffer [0] & 0xff;
  if (delta == 0)  /* min is 0, max is maxint, and % would fail */
    return result;
  return (result % delta) + min;
}

/* fill this array with random alpha characters.  The last byte is set to \0 */
void random_string (char * buffer, size_t bsize)
{
  if (bsize <= 0)
    return;
  size_t i;
  for (i = 0; i + 1 < bsize; i++)
    buffer [i] = 'a' + (random_mod (26));
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
    unsigned long long int r = random_mod (n);
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

int allnet_htons (int hostshort)
{
  char buffer [2];
  uint16_t * p = (uint16_t *) buffer;
  *p = (hostshort & 0xffff);
  return readb16 (buffer);
}

int allnet_htonl (int hostlong)
{
  char buffer [4];
  uint32_t * p = (uint32_t *) buffer;
  *p = (hostlong & 0xffffffff);
  return (int)(readb32 (buffer));
}

/* returns 1 if the message is expired, 0 otherwise (including if
 * the message never expires). */
int is_expired_message (const char * packet, unsigned int size)
{
  if (size < (int) ALLNET_HEADER_SIZE)
    return 0;    /* message too small to have even just a header */
  struct allnet_header * hp = (struct allnet_header *) packet;
  if ((hp->transport & ALLNET_TRANSPORT_EXPIRATION) == 0)
    return 0;    /* message never expires */
  if (size < (int) ALLNET_SIZE_HEADER (hp))
    return 0;    /* message too small to have an expiration header */
  uint64_t exp = readb64 (ALLNET_EXPIRATION (hp, hp->transport, size));
  if (exp < allnet_time ())
    return 1;    /* message is expired */
  return 0;      /* message is not expired */
}

#define return_valid_err(s) { if (error_desc != NULL) *error_desc = (s); \
			      return 0; }

/* returns 1 if the message is valid, 0 otherwise
 * If returns zero and error_desc is not NULL, it is filled with
 * a description of the error -- do not modify in any way. */
extern int is_valid_message (const char * packet, unsigned int size,
                             char ** error_desc)
{
  if (size < (int) ALLNET_HEADER_SIZE)
    return_valid_err ("packet size less than header size");
/* received a message with a header */
  const struct allnet_header * ah = (const struct allnet_header *) packet;
/* make sure version, address bit counts and hops are sane */
  if ((ah->version != ALLNET_VERSION) ||
      (ah->src_nbits > ADDRESS_BITS) || (ah->dst_nbits > ADDRESS_BITS) ||
      (ah->hops > ah->max_hops)) {
#if 0
    printf ("received version %d addr sizes %d %d / %d, hops %d/%d, pid %d\n",
            ah->version, ah->src_nbits, ah->dst_nbits, ADDRESS_BITS,
            ah->hops, ah->max_hops, getpid ());
    print_buffer (packet, size, "received bytes", size, 1);
sleep (60);
ah->version = 0;
printf ("time to crash %d\n", 1000 / ah->version);
#endif /* 0 */
    if (ah->hops > ah->max_hops) return_valid_err ("hops > max_hops");
    if (ah->dst_nbits > ADDRESS_BITS) return_valid_err ("dst_nbits > 64");
    if (ah->src_nbits > ADDRESS_BITS) return_valid_err ("src_nbits > 64");
    if (ah->version != ALLNET_VERSION) return_valid_err ("version number");
    return_valid_err ("unknown error");
  }
  if ((ah->message_type < ALLNET_TYPE_DATA) ||
      (ah->message_type > ALLNET_TYPE_MGMT))    /* nonsense packet */
    return_valid_err ("bad message type");
/* check the validity of the packet, as defined in packet.h */
  if ((ah->message_type == ALLNET_TYPE_ACK) && (ah->transport != 0)) {
    /* printf ("received ack, transport 0x%x != 0", ah->transport); */
    return_valid_err ("ack with nonzero transport");
  }
  if (ah->message_type == ALLNET_TYPE_DATA_REQ) {
/* do not enforce for now -- still experimental  2018/07/25
    if ((ah->transport & ALLNET_TRANSPORT_DO_NOT_CACHE) == 0)
      return_valid_err ("req fails to specify do-not-cache");
 */
    /* check the sizes */
    const struct allnet_data_request * rp = (const struct allnet_data_request *)
      ALLNET_DATA_START (ah, ah->transport, size);
    int wanted = sizeof (struct allnet_data_request);
    if (wanted > size) {
printf ("got data request of size %d, min %d\n", size, wanted);
      return_valid_err ("data request too small");
    }
    if (rp->dst_bits_power_two > 16)    /* size doesn't fit in an ALLNET_MTU */
      return_valid_err ("data request dst > 16");
    if (rp->src_bits_power_two > 16)    /* size doesn't fit in an ALLNET_MTU */
      return_valid_err ("data request src > 16");
    if (rp->mid_bits_power_two > 16)    /* size doesn't fit in an ALLNET_MTU */
      return_valid_err ("data request mid > 16");
/* add 6 (rather than 7) so that if power_two is 0, we add 0 bytes
 * for that bitmap */
    wanted += (p2 (rp->dst_bits_power_two) + 6) / 8;
    wanted += (p2 (rp->src_bits_power_two) + 6) / 8;
    wanted += (p2 (rp->mid_bits_power_two) + 6) / 8;
    if (wanted > size)
      return_valid_err ("data request too small");
  }
  int payload_size = size -
                     ALLNET_AFTER_HEADER (ah->transport, (unsigned int) size);
  if ((ah->message_type == ALLNET_TYPE_ACK) &&
      ((payload_size % MESSAGE_ID_SIZE) != 0)) {
    printf ("received ack message, but size %d(%d) mod %d == %d != 0\n",
            payload_size, size, MESSAGE_ID_SIZE,
            payload_size % MESSAGE_ID_SIZE);
    print_buffer (packet, size, NULL, 100, 1);
    return_valid_err ("ack size not a multiple of 16");
  }
  if (((ah->transport & ALLNET_TRANSPORT_ACK_REQ) != 0) &&
      (payload_size < MESSAGE_ID_SIZE)) {
    printf ("message has size %d (%d), min %d\n",
            payload_size, size, MESSAGE_ID_SIZE);
    return_valid_err ("insufficient room for message ID");
  }
  if (((ah->transport & ALLNET_TRANSPORT_ACK_REQ) == 0) &&
      ((ah->transport & ALLNET_TRANSPORT_LARGE) != 0)) {
    printf ("large message missing ack bit\n");
    return_valid_err ("large message missing ack bit");
  }
  if (((ah->transport & ALLNET_TRANSPORT_EXPIRATION) != 0)) {
    time_t now = time (NULL);
    char * ep = ALLNET_EXPIRATION (ah, ah->transport, (unsigned int) size);
    if ((now <= ALLNET_Y2K_SECONDS_IN_UNIX) || (ep == NULL) ||
        (((time_t) readb64 (ep)) < (now - ALLNET_Y2K_SECONDS_IN_UNIX)))
      return_valid_err ("expired packet");
  }
  if (ah->sig_algo != ALLNET_SIGTYPE_NONE) {
    unsigned int hsize = ALLNET_SIZE (ah->transport);
    if (size <= hsize + 2)   /* not enough room for signature length */
      return_valid_err ("too small for signature length");
    unsigned int siglen = readb16 (packet + (size - 2));
    if (siglen < 16)         /* not enough room for a signature */ 
      return_valid_err ("signature length too small for signature");
    if (size <= siglen + 2)   /* not enough room for any data */ 
      return_valid_err ("signature leaves no room for data");
  }
  return 1;
}

/* computes the sender authentication into the given buffer */
void compute_sender_auth (struct sockaddr_storage addr,
                          const char * secret, int slen,
                          long long int counter,
                          char * to, int tsize)
{
  if (tsize <= 0)
    return;
  memset (to, 0, tsize);
  char buffer [sizeof (counter) + sizeof (struct sockaddr_storage)];
  writeb64 (buffer, counter);
  int off = sizeof (counter);
  struct sockaddr * sap = (struct sockaddr *) (&addr);
  if (sap->sa_family == AF_INET) {
    struct sockaddr_in * sin = (struct sockaddr_in *) (&addr);
    memcpy (buffer + off, &(sin->sin_addr), 4);
    off += 4;
    memcpy (buffer + off, &(sin->sin_port), 2);
    off += 2;
  } else if (sap->sa_family == AF_INET6) {
    struct sockaddr_in6 * sin = (struct sockaddr_in6 *) (&addr);
    if (memget (sin->sin6_addr.s6_addr, 0, 10) &&
        memget (sin->sin6_addr.s6_addr + 10, 0xff, 2)) {  /* ipv4 in ipv6 */
      memcpy (buffer + off, (sin->sin6_addr.s6_addr + 12), 4);
      off += 4;
    } else {   /* regular ipv6 */
      memcpy (buffer + off, sin->sin6_addr.s6_addr, 16);
      off += 16;
    }
    memcpy (buffer + off, &(sin->sin6_port), 2);
    off += 2;
  } else
    return;   /* not an IP address */
  char result [SHA512_SIZE];
  sha512hmac (buffer, off, secret, KEEPALIVE_AUTHENTICATION_SIZE, result);
  int csize = tsize;   /* copy size, for memcpy */
  if (csize > sizeof (result))
    csize = sizeof (result);
  memcpy (to, result, csize);
}

/* returns whether this keepalive has the right authentication */
int is_auth_keepalive (struct sockaddr_storage addr,
                       const char * secret, int slen,
                       long long int counter,
                       const char * message, int msize)
{
  if (msize < ALLNET_HEADER_SIZE)
    return 0;   /* not a valid packet */
  struct allnet_header * hp = (struct allnet_header *) message;
  if (hp->hops > 1)
    return 0;   /* only accept single-hop keepalives */
  int hsize = ALLNET_MGMT_HEADER_SIZE (hp->transport);
  if (msize != (hsize + 2 * KEEPALIVE_AUTHENTICATION_SIZE))
    return 0;   /* not a valid authentication packet */
  char verification [KEEPALIVE_AUTHENTICATION_SIZE];
  compute_sender_auth (addr, secret, slen, counter,
                       verification, sizeof (verification));
  return (memcmp (message + hsize + KEEPALIVE_AUTHENTICATION_SIZE,
                  verification, KEEPALIVE_AUTHENTICATION_SIZE) == 0);
}

void print_gethostbyname_error (const char * hostname, struct allnet_log * log)
{
  switch (h_errno) {
  case HOST_NOT_FOUND:
    if (log != NULL)
      snprintf (log->b, log->s,
                "error resolving host name %s: host not found\n", hostname);
    else
      printf ("error resolving host name %s: host not found\n", hostname);
    break;
#if defined NO_ADDRESS
  case NO_ADDRESS:  /* same as NO_DATA */
#else
  case NO_DATA:
#endif
    if (log != NULL)
      snprintf (log->b, log->s,
                "error resolving host name %s: no address/no data\n", hostname);
    else
      printf ("error resolving host name %s: no address/no data\n", hostname);
    break;
  case NO_RECOVERY:
    if (log != NULL)
      snprintf (log->b, log->s,
                "error resolving host name %s: unrecoverable\n", hostname);
    else
      printf ("error resolving host name %s: unrecoverable error\n", hostname);
    break;
  case TRY_AGAIN:
    if (log != NULL)
      snprintf (log->b, log->s,
                "error resolving host name %s: try again\n", hostname);
    else
      printf ("error resolving host name %s: try again\n", hostname);
    break;
  default:
    if (log != NULL)
      snprintf (log->b, log->s,
                "error resolving host name %s: %d\n", hostname, h_errno);
    else
      printf ("error resolving host name %s: unknown %d\n", hostname, h_errno);
    break;
  }
  if (log != NULL)
    log_print (log);
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
      for (j = i; j < orig_argc; j++)
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

