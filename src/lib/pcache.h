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

/* fills in the first ALLNET_TOKEN_SIZE bytes of token with the current token */
extern void pcache_current_token (char * token);

/* return 1 for success, 0 for failure.
 * look inside a message and fill in its ID (MESSAGE_ID_SIZE bytes). */
extern int pcache_message_id (const char * message, int msize, char * id);

/* save this (received) packet */
extern void pcache_save_packet (const char * message, int msize, int priority);
/* record this packet ID, without actually saving it */
extern void pcache_record_packet (const char * message, int msize);

/* return 1 if the ID is in the cache, 0 otherwise
 * ID is MESSAGE_ID_SIZE bytes. */
extern int pcache_id_found (const char * id);

/* a structure to record data about an individual message */
struct pcache_message {
  char * message;
  int msize;
  int priority;
};

/* a structure to record the result of a call to request cached messages. */
struct pcache_result {
  int n;           /* number of messages, may be zero (-1 for errors) */
  struct pcache_message * messages;
/* calling free (free_ptr) is enough to free all the memory allocated
 * for all the messages.  Caller must first free (messages) */
  void * free_ptr;
};

/* if successful, return the messages.
   return a result with n = 0 if there are no messages,
   and n = -1 in case of failure -- in both of these cases, free_ptr is NULL.
   messages are in order of descending priority.
   If max > 0, at most max messages will be returned.  */
extern struct pcache_result
  pcache_request (const struct allnet_data_request *req, int max);

#ifdef IMPLEMENT_MGMT_ID_REQUEST  /* not used, so, not implemented */
/* similar to pcache_request.
   Modifies req to reflect any IDs (may be 0) that are found */
extern struct pcache_result
  pcache_id_request (struct allnet_mgmt_id_request * req);
#endif /* IMPLEMENT_MGMT_ID_REQUEST */

/* mark that this message need never again be sent to this token */
extern void
  pcache_mark_token_sent (const char * token,  /* ALLNET_TOKEN_SIZE bytes */
                          const char * message, int msize);

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
extern int pcache_ack_for_token (const char * token, const char * ack);

/* call pcache_ack_for_token repeatedly for all these acks,
 * moving the new ones to the front of the array and returning the
 * number that are new (0 for none, -1 for errors) */
extern int pcache_acks_for_token (const char * token,
                                  char * acks, int num_acks);

/* return 1 if the trace request/reply has been seen before, or otherwise
 * return 0 and save the ID.  Trace ID should be MESSAGE_ID_SIZE bytes */
extern int pcache_trace_request (const unsigned char * id);
/* for replies, we look at the entire packet, without the header */
extern int pcache_trace_reply (const char * msg, int msize);

/* save cached information to disk */
extern void pcache_write (void);

#endif /* PACKET_CACHE_H */
