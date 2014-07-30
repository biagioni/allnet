/* acache.c: cache all data messages and respond to requests */
/* only one thread, listening on a pipe from ad, and responding
 * acache takes two arguments, the fd of a pipe from AD and of a pipe to AD
 */
/* for now, simply dcache all the packets, return them if they are in the
 * cache.  Later on, maybe provide persistent storage */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <inttypes.h>

#include "lib/packet.h"
#include "lib/pipemsg.h"
#include "lib/priority.h"
#include "lib/util.h"
#include "lib/app_util.h"
#include "lib/dcache.h"
#include "lib/log.h"
#include "lib/sha.h"

#define CACHE_SIZE	1024
/* #define CACHE_SIZE	4  */ /* for testing only */
struct cache_entry {
  char * message;
  int msize;
  unsigned char rcvd_at [ALLNET_TIME_SIZE];
};

static struct cache_entry cache_storage [CACHE_SIZE];

static void return_cache_entry (void * arg)
{
  struct cache_entry * cep = (struct cache_entry *) arg;
  free (cep->message);
  cep->msize = 0;   /* mark it as free */
  snprintf (log_buf, LOG_SIZE,
            "cleared msize %p, index %ld = (%p - %p) / %zd\n",
            cep, (long int) ((cep - cache_storage) / sizeof (cache_storage)),
            cep, cache_storage, sizeof (cache_storage));
  log_print ();
#ifdef DEBUG_PRINT
  int i;
  for (i = 0; i < CACHE_SIZE; i++) {
    if (cache_storage [i].msize > 0) {
      snprintf (log_buf, LOG_SIZE, "cache %d has msize %d\n",
                i, cache_storage [i].msize);
      log_print ();
    }
  }
#endif /* DEBUG_PRINT */
}

/* if the header includes an id, returns a pointer to the ID field of hp */
static char * get_id (char * message, int size)
{
  struct allnet_header * hp = (struct allnet_header *) message;
  char * id = ALLNET_PACKET_ID (hp, hp->transport, size);
  if (id == NULL)
    id = ALLNET_MESSAGE_ID (hp, hp->transport, size);
  /* ack messages may have multiple IDs, we only use the first */
  if ((id == NULL) && (hp->message_type == ALLNET_TYPE_ACK) &&
      (size >= ALLNET_SIZE (hp->transport) + MESSAGE_ID_SIZE))
    id = ALLNET_DATA_START (hp, hp->message_type, size);
  /* key messages usually don't have IDs, but do have hmac or fingerprints */
  if ((id == NULL) && (size >= ALLNET_SIZE (hp->transport) + 1)) {
    int nbytes = message [ALLNET_SIZE (hp->transport) + 1] & 0xff;
    if ((size >= ALLNET_SIZE (hp->transport) + 1 + nbytes) &&
        (nbytes >= MESSAGE_ID_SIZE)) {
      if ((hp->message_type == ALLNET_TYPE_KEY_XCHG) ||
          (hp->message_type == ALLNET_TYPE_KEY_REQ))
        id = message + ALLNET_SIZE (hp->transport) + 1;
    }
  }
  return id;  /* a pointer (if any) into hp */ 
}

static int match_packet_id (void * packet_id, void * cache_entry)
{
  struct cache_entry * cep = (struct cache_entry *) cache_entry;
  char * id = get_id (cep->message, cep->msize);
  if ((id != NULL) && (memcmp (id, packet_id, MESSAGE_ID_SIZE) == 0))
    return 1;
  return 0;
}

/* returns 1 if successful, 0 otherwise */
static int save_packet (void * cache, char * message, int msize)
{
  struct allnet_header * hp = (struct allnet_header *) message;
#ifdef DEBUG_PRINT
  snprintf (log_buf, LOG_SIZE, "save_packet: size %d\n", msize);
  log_print ();
#endif /* DEBUG_PRINT */
  char * id = get_id (message, msize);
  if (id == NULL)   /* no sort of message or packet ID found */
    return 0;
  int i;
#ifdef DEBUG_PRINT
  buffer_to_string (id, MESSAGE_ID_SIZE, "id", MESSAGE_ID_SIZE, 1,
                    log_buf + off, LOG_SIZE - off);
  log_print ();
  for (i = 0; i < CACHE_SIZE; i++) {
    if ((cache_storage [i].msize > 0) && (cache_storage [i].message != NULL)) {
      int xoff = snprintf (log_buf, LOG_SIZE,
                           "cache entry %d has msize %d, id ",
                           i, cache_storage [i].msize);
      struct allnet_header * xhp = 
               (struct allnet_header *) cache_storage [i].message;
      char * xid = get_id ((char *) xhp, cache_storage [i].msize);
      buffer_to_string (xid, MESSAGE_ID_SIZE, NULL, 8, 1,
                        log_buf + xoff, LOG_SIZE - xoff);
      log_print ();
    }
  }
#endif /* DEBUG_PRINT */
  if ((cache_get_match (cache, match_packet_id, id)) != NULL) {
    /* already in cache */
    snprintf (log_buf, LOG_SIZE, "packet found in cache, not saving\n");
    log_print ();
    return 0;
  }
  static int cache_search = 0;
  for (i = 0; i < CACHE_SIZE; i++) {
    if (cache_storage [(i + cache_search) % CACHE_SIZE].msize == 0) {
      /* found a free slot -- since the dcache has CACHE_SIZE - 1 entries,
         there should always be a free slot. */
      snprintf (log_buf, LOG_SIZE, "saving message of type %d, %d bytes\n",
                hp->message_type, msize);
      log_print ();
      struct cache_entry * cep = 
        cache_storage + ((i + cache_search) % CACHE_SIZE);
      cache_search = i;
      cep->message = message;
      cep->msize = msize;
      writeb64u (cep->rcvd_at, time (NULL) - ALLNET_Y2K_SECONDS_IN_UNIX);
      cache_add (cache, cep);  /* may call return_cache_entry */
      return 1;
    }
  }
  free (message);
  snprintf (log_buf, LOG_SIZE,
            "unable to find a free slot!!!  message not saved\n");
  log_print ();
  return 0;
}

struct request_details {
  int src_nbits;
  unsigned char source [ADDRESS_SIZE];
  int empty;     /* the other details are only filled in if emtpy is zero */
  unsigned char * since;
  int dpower_two;
  int dbits;
  unsigned char * dbitmap;
  int spower_two;
  int sbits;
  unsigned char * sbitmap;
};

/* all the pointers point into message */
static void build_request_details (char * message, int msize, 
                                   struct request_details * result)
{
  struct allnet_header * hp = (struct allnet_header *) message;
  int hsize = ALLNET_SIZE (hp->transport);
  int drsize = ALLNET_TIME_SIZE + 8;
  result->src_nbits = hp->src_nbits;
  if (result->src_nbits > ADDRESS_BITS)
    result->src_nbits = ADDRESS_BITS;
  if (result->src_nbits < 0)
    result->src_nbits = 0;
  memcpy (result->source, hp->source, ADDRESS_SIZE);
  if (msize <= hsize + drsize) {
    result->empty = 1;
  } else {
    result->empty = 0;
    struct allnet_data_request * drp =
      (struct allnet_data_request *) (message + hsize);
    result->since = drp->since;
    char empty_time [ALLNET_TIME_SIZE];
    bzero (empty_time, sizeof (empty_time));
    if (memcmp (empty_time, result->since, sizeof (empty_time)) == 0)
      result->since = NULL;  /* time is zero, so don't use in comparisons */
    result->dpower_two = 0;
    result->dbits = 0;
    result->dbitmap = NULL;
    result->spower_two = 0;
    result->sbits = 0;
    result->sbitmap = NULL;
    int dbits = 0;
    int dbytes = 0;
    int sbits = 0;
    int sbytes = 0;
    if (drp->dst_bits_power_two > 0) {
      dbits = 1 << (drp->dst_bits_power_two - 1);
      dbytes = (dbits + 7) / 8;
      if (hsize + drsize + dbytes <= msize) {
        result->dpower_two = drp->dst_bits_power_two;
        result->dbits = dbits;
        result->dbitmap = (unsigned char *) (message + (hsize + drsize));
      }
    }
    if (drp->src_bits_power_two > 0) {
      sbits = 1 << (drp->src_bits_power_two - 1);
      sbytes = (sbits + 7) / 8;
      if (hsize + drsize + dbytes + sbytes <= msize) {
        result->spower_two = drp->src_bits_power_two;
        result->sbits = sbits;
        result->sbitmap =
          (unsigned char *) (message + (hsize + drsize + dbytes));
      }
    }
  }
}

static uint64_t get_nbits (unsigned char * bits, int nbits)
{
  uint64_t result = 0;
  while (nbits >= 8) {
    result = ((result << 8) | ((*bits) & 0xff));
    nbits = nbits - 8;
    bits++;
  }
  if (nbits > 0)
    result = ((result << nbits) | (((*bits) & 0xff) >> (8 - nbits)));
  return result;
}

/* returns 1 if the address is (or may be) in the bitmap, 0 otherwise */
static int match_bitmap (int power_two, int bitmap_bits, unsigned char * bitmap,
                         unsigned char * address, int abits)
{
  if ((power_two <= 0) || (bitmap_bits <= 0) || (bitmap == NULL))
    return 1;   /* an empty bitmap matches every address */
  if (abits <= 0)
    return 1;   /* empty address matches every bitmap, even one with all 0's */
  uint64_t start_index = get_nbits (address, abits);
  uint64_t end_index = start_index;
  if (abits > power_two) {
    start_index = (start_index >> (abits - power_two));
  } else if (abits < power_two) {
    /* make end_index have all 1s in the last (power_two - abits)) bits */
    end_index = ((start_index + 1) << (power_two - abits)) - 1;
    start_index = (start_index << (power_two - abits));
  }
  if ((start_index > end_index) ||
      (start_index > bitmap_bits) || (end_index > bitmap_bits)) {
    snprintf (log_buf, LOG_SIZE,
              "match_bitmap error: index %" PRIu64 "-%" PRIu64 ", %d bits\n",
              start_index, end_index, bitmap_bits);
    printf ("%s", log_buf);
    log_print ();
    return 1;
  }
  while (start_index <= end_index) {
    int byte = bitmap [start_index / 8] & 0xff;
    int i;
    for (i = start_index % 8;
         (i < 8) && (i < (end_index - (start_index / 8) * 8)); i++)
      if (((i == 7) && (( byte                   & 0x1) == 0x1)) ||
          ((i <  7) && (((byte >> (8 - (i + 1))) & 0x1) == 0x1)))
        return 1;
    start_index = (start_index - (start_index % 8)) + 8;
  }
  return 0;  /* did not match any bit in the bitmap */
}

static int request_matches_packet (void * rs_void, void * cache_entry)
{
  struct cache_entry * cep = (struct cache_entry *) cache_entry;
  struct allnet_header * chp = (struct allnet_header *) (cep->message);
  struct request_details * req = (struct request_details *) rs_void;
  if (req->empty) {
    if (matches (req->source, req->src_nbits, chp->destination, chp->dst_nbits))
      return 1;
    return 0;
  }
  /* anything not matching leads to the packet being excluded */
  if (req->since != NULL) {
    uint64_t since = readb64u (req->since);
    uint64_t rcvd_at = readb64u (cep->rcvd_at);
    if (since > rcvd_at)
      return 0;
  }
  if ((req->dbits > 0) && (req->dbitmap != NULL) &&
      (! match_bitmap (req->dpower_two, req->dbits, req->dbitmap,
                       chp->destination, chp->dst_nbits)))
    return 0;
  if ((req->sbits > 0) && (req->sbitmap != NULL) &&
      (! match_bitmap (req->spower_two, req->sbits, req->sbitmap,
                       chp->source, chp->src_nbits)))
    return 0;
  return 1;
}

/* returns 1 if it sent a response, 0 otherwise */
static int respond_to_packet (void * cache, char * message,
                              int msize, int fd)
{
  struct request_details rd;
  build_request_details (message, msize, &rd);
  void * * matches;
  int nmatches =
    cache_all_matches (cache, request_matches_packet, &rd, &matches);
  if (nmatches == 0)
    return 0;
  snprintf (log_buf, LOG_SIZE, "respond_to_packet: %d matches\n", nmatches);
  log_print ();
  struct cache_entry * * cep = (struct cache_entry * *) matches;
  struct allnet_header * hp = (struct allnet_header *) (message);
  int local_request = 0;
  if (hp->hops == 0)   /* local request, do not forward elsewhere */
    local_request = 1;
  int i;
  int priority = ALLNET_PRIORITY_CACHE_RESPONSE;
  for (i = 0; i < nmatches; i++) {
    snprintf (log_buf, LOG_SIZE,
              "sending %d-byte cached response at [%d]\n", cep [i]->msize, i);
    log_print ();
    int saved_max;
    struct allnet_header * send_hp =
      (struct allnet_header *) (cep [i]->message);
    if (local_request) {  /* only forward locally */
      saved_max = send_hp->max_hops;
      send_hp->max_hops = send_hp->hops;
    }
    /* send, no need to even check the return value of send_pipe_message */
    send_pipe_message (fd, cep [i]->message, cep [i]->msize, priority);
    if (local_request)  /* restore the packet as it was */
      send_hp->max_hops = saved_max;
    if (priority > ALLNET_PRIORITY_EPSILON)
      priority--;
  }
  free (matches);
  return 1;
}

static void ack_packets (void * cache, char * message, int msize)
{
  struct allnet_header * hp = (struct allnet_header *) message;
  char * ack = ALLNET_DATA_START (hp, hp->transport, msize);
  msize -= (ack - message);
  while (msize >= MESSAGE_ID_SIZE) {
    char hash [MESSAGE_ID_SIZE];
    sha512_bytes (ack, MESSAGE_ID_SIZE, hash, MESSAGE_ID_SIZE);
    void * found;
    while ((found = cache_get_match (cache, match_packet_id, hash)) != NULL)
      cache_remove (cache, found);
    ack += MESSAGE_ID_SIZE;
    msize -= MESSAGE_ID_SIZE;
  }
}

void main_loop (int sock)
{
  bzero (cache_storage, sizeof (cache_storage));
  void * cache = cache_init (CACHE_SIZE - 1, return_cache_entry);
  while (1) {
    char * message;
    int priority;
    int result = receive_pipe_message (sock, &message, &priority);
    struct allnet_header * hp = (struct allnet_header *) message;
    /* unless we save it, free the message */
    int mfree = 1;
    if (result <= 0) {
      snprintf (log_buf, LOG_SIZE, "ad pipe %d closed, result %d\n",
                sock, result);
      log_print ();
      mfree = 0;  /* is this ever needed or useful? */
      break;
    } else if ((result >= ALLNET_HEADER_SIZE) &&
               (result >= ALLNET_SIZE (hp->transport))) {
      /* valid message from ad: save, respond, or ignore */
      if (hp->message_type == ALLNET_TYPE_DATA_REQ) { /* respond */
        if (respond_to_packet (cache, message, result, sock))
          snprintf (log_buf, LOG_SIZE, "responded to data request packet\n");
        else
          snprintf (log_buf, LOG_SIZE, "no response to data request packet\n");
      } else {   /* not a data request */
        if (hp->message_type == ALLNET_TYPE_ACK) /* erase if have */
          ack_packets (cache, message, result);
        if (save_packet (cache, message, result)) {
          mfree = 0;   /* saved, so do not free */
          snprintf (log_buf, LOG_SIZE, "saved packet of type %d, size %d\n",
                    hp->message_type, result);
        } else {
          snprintf (log_buf, LOG_SIZE,
                    "did not save packet, type %d, size %d\n",
                    hp->message_type, result);
        }
      }
      log_print ();
    } else {
      snprintf (log_buf, LOG_SIZE, "ignoring packet of size %d\n", result);
      log_print ();
    }
    if (mfree)
      free (message);
  }
}

int main (int argc, char ** argv)
{
  int sock = connect_to_local ("acache", argv [0]);
  main_loop (sock);
  snprintf (log_buf, LOG_SIZE, "end of acache\n");
  log_print ();
  return 0;
}
