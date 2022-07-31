/* pcache.h: central cache for messages */

/* a few principles:
   each message has an ID that is very likely distinct from other messages.
   each system  has an ID (token) that is very likely distinct
     from other systems.  The token can change whenever the system
     discards (part of) the cached messages
   we want to forward each message (and each ack) to each system at most once.
   if we get a data request, we want to forward based on that.

   since acks aren't acked, they are removed when they are replaced by
   a new ack that hashes to the same location
 */

#ifndef PACKET_CACHE_H
#define PACKET_CACHE_H

#include "packet.h"
#include "mgmt.h"

/* return 0 for failure, 1 if the message has a single ID, 2 if it is
 * a large message with both a message ID and a packet ID.  The first
 * ID is filled in if returning 1, both are filled in when returning 2.
 * Each of the IDs must have room for MESSAGE_ID_SIZE bytes. */
extern int pcache_message_ids (const char * message, int msize,
                               char * result_id1, char * result_id2);

/* save this (received) packet */
extern void pcache_save_packet (const char * message, int msize, int priority);
/* record this packet ID, without actually saving the message */
extern void pcache_record_packet (const char * message, int msize);

/* return 1 if the ID is in the cache, 0 otherwise
 * ID is MESSAGE_ID_SIZE bytes. */
extern int pcache_id_found (const char * id);

/* a structure to record data about an individual message */
struct pcache_message {
  char * message;   /* points into the buffer supplied to pcache_request */
  int msize;
  int priority;
};

/* a structure to record the result of a call to request cached messages. */
struct pcache_result {
  int n;           /* number of messages, may be zero (-1 for errors) */
  struct pcache_message * messages;   /* points into the buffer */
};

/* if successful, return the messages.
   return a result with n = 0 if there are no messages,
   and n = -1 in case of failure
   messages are in order of descending priority.
   If max > 0, at most max messages will be returned.
   If rlen <= 0, only returns messages addressed to addr/nbits --
   and if nbits is 0 or source is NULL, returns all messages
   The memory used by pcache_result is allocated in the given buffer
   If the request includes a token, the token is marked as having received
   these messages.
 */
extern struct pcache_result
  pcache_request (const struct allnet_data_request *req, int rlen,
                  int nbits, const unsigned char * addr, int max,
                  char * buffer, int bsize);

/* acks */

/* each ack has size MESSAGE_ID_SIZE */
/* record all these acks and delete (stop caching) corresponding messages */
extern void pcache_save_acks (const char * acks, int num_acks, int max_hops);

/* return 1 if we have the ack, 0 if we do not */
extern int pcache_ack_found (const char * ack);

/* return 1 if we have the ack for this ID, 0 if we do not
 * if returning 1, fill in the ack */
extern int pcache_id_acked (const char * id, char * ack);

/* return 1 if the ack has not yet been sent to this token,
 * and mark it as sent to this token.
 * otherwise, return 0 */
extern int pcache_ack_for_token (const unsigned char * token, const char * ack);

/* call pcache_ack_for_token repeatedly for all these acks,
 * moving the new ones to the front of the array and returning the
 * number that are new (0 for none, -1 for errors) */
extern int pcache_acks_for_token (const unsigned char * token,
                                  char * acks, int num_acks);

/* return 1 if the trace request/reply has been seen before, or otherwise
 * return 0 and save the ID.  Trace ID should be MESSAGE_ID_SIZE bytes */
extern int pcache_trace_request (const char * id);
/* for replies, we look at the entire packet, without the header */
extern int pcache_trace_reply (const char * msg, int msize);

/* save cached information to disk */
extern void pcache_write (void);

#endif /* PACKET_CACHE_H */
