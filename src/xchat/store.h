/* store.h: provide non-volatile storage of chat names, messages, and keys */

/* messages are stored in each contact's data directory, e.g.
 * ~/.allnet/xchat/20130101174522.data/00000000000000000001
 * ~/.allnet/xchat/20130101174522.data/00000000000000000002, and so on
 * group messages are stored in that group's directory.
 */

#ifndef ALLNET_CHAT_STORE_H
#define ALLNET_CHAT_STORE_H

#include "chat.h"

/* returns 0 if the contact cannot be found */
extern unsigned long long int get_counter (const char * contact);

/* returns 0 if the contact cannot be found or matches more than one contact
 * or none received yet */
extern unsigned long long int get_last_received (char * contact);

/* save an outgoing message */
extern void save_outgoing (char * contact, struct chat_descriptor * cp,
                           char * text, int tsize);

/* return the (malloc'd) outgoing message with the given sequence number,
 * or NULL if there is no such message.
 * if there is more than one such message, returns the latest.
 * Also fills in the size, time and message_ack -- message_ack must have
 * at least MESSAGE_ID_SIZE bytes */
extern char * get_outgoing (char * contact, unsigned long long int seq,
                            int * size, unsigned long long int * time,
                            char * message_ack);

/* save a received message */
extern void save_incoming (char * contact, struct chat_descriptor * cp,
                           char * text, int tsize);

/* mark a previously sent message as acknowledged */
/* return the sequence number > 0 if this is an ack for a known contact, */
/* return 0 ... never, hopefully */
/* return -1 if this ack is not recognized */
/* return -2 if this ack was previously received */
/* fill in *contact (to a malloc'd string -- must free) if return > 0 or -2 */
/* otherwise set *contact to NULL */
extern long long int ack_received (char * message_id, char * * contact);

/* returns a new (malloc'd) array, or NULL in case of error */
/* the new array has (singles + 2 * ranges) * COUNTER_SIZE bytes. */
/* the first *singles * COUNTER_SIZE bytes are individual sequence numbers
 * that we never received.
 * the next *ranges * 2 * COUNTER_SIZE bytes are pairs of sequence numbers a, b
 * such that any seq such that we never received a <= seq <= b */
extern char * get_missing (char * contact, int * singles, int * ranges);

/* returns a new (malloc'd) array, or NULL in case of error */
/* the new array has (singles + 2 * ranges) * COUNTER_SIZE bytes. */
/* the first *singles * COUNTER_SIZE bytes are individual sequence numbers
 * that were never acknowledged.
 * the next *ranges * 2 * COUNTER_SIZE bytes are pairs of sequence numbers a, b
 * such that any seq such that a <= seq <= b has no acknowledged */
extern char * get_unacked (char * contact, int * singles, int * ranges);

/* returns 1 if this sequence number has been acked, 0 otherwise */
extern int is_acked (char * contact, long long int seq);

/* returns 1 if this sequence number has been received, 0 otherwise */
extern int was_received (char * contact, long long int seq);

#endif /* ALLNET_CHAT_STORE_H */
