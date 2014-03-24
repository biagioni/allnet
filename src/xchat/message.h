/* message.h: provide non-volatile storage of chat messages */

/* messages are stored in each contact's directory under a day file, e.g.
 * ~/.allnet/xchat/20130101174522/20140302
 * group messages are stored in that group's directory (not yet implemented).
 *
 * each contact may have multiple keys, and thus multiple directories.
 * Directories are indirectly identified by keys.
 * keys.c/key_dir returns a directory x as ~/.allnet/contacts/x,
 * in which case the chat information is stored under ~/.allnet/xchat/x
 *
 * note that:
 * - messages we send are sent to all instances of a given contact,
 *   so sequence numbers (and messages) we send are the same across
 *   all directories of a contact
 * - messages we receive are sent independently by each of the instances
 *   of a contact, so their sequence numbers are independent.
 */

#ifndef ALLNET_CHAT_MESSAGE_H
#define ALLNET_CHAT_MESSAGE_H

#include "chat.h"
#include "lib/keys.h"

/* return the lowest unused counter, used as sequence number when sending
 * messages to this contact.  returns 0 if the contact cannot be found */
extern uint64_t get_counter (char * contact);

/* return the largest received counter, or 0 if the contact cannot be found
 * or the keyset is not valid. */
extern uint64_t get_last_received (char * contact, keyset k);

/* save an outgoing message to a specific directory for this contact.
 * the directory is specific because the message ack is different for
 * each copy of the message */
extern void save_outgoing (char * contact, keyset k,
                           struct chat_descriptor * cp,
                           char * text, int tsize);

/* return the (malloc'd) outgoing message with the given sequence number,
 * or NULL if there is no such message.
 * if there is more than one such message, returns the latest.
 * Also fills in the size, time and message_ack -- message_ack must have
 * at least MESSAGE_ID_SIZE bytes */
extern char * get_outgoing (char * contact, keyset k, uint64_t seq,
                            int * size, uint64_t * time, char * message_ack);

/* save a received message */
extern void save_incoming (char * contact, keyset k,
                           struct chat_descriptor * cp, char * text, int tsize);

/* mark a previously sent message as acknowledged
 * return the sequence number > 0 if this is an ack for a known contact,
 * return 0 if this ack is not recognized
 */
extern uint64_t ack_received (char * message_id);

/* returns a new (malloc'd) array, or NULL in case of error */
/* the new array has (singles + 2 * ranges) * COUNTER_SIZE bytes. */
/* the first *singles sequence numbers are individual sequence numbers
 * that we never received.
 * the next *ranges * 2 sequence numbers are pairs a, b such that we have
 * not received any of the sequence numbers a <= seq <= b */
extern char * get_missing (char * contact, keyset k,
                           int * singles, int * ranges);

/* returns a new (malloc'd) array, or NULL in case of error */
/* the new array has (singles + 2 * ranges) * COUNTER_SIZE bytes. */
/* the first *singles * COUNTER_SIZE bytes are individual sequence numbers
 * that were never acknowledged by this contact ID.
 * the next *ranges * 2 * COUNTER_SIZE bytes are pairs of sequence numbers a, b
 * such that any seq such that a <= seq <= b has no acknowledged */
extern char * get_unacked (char * contact, keyset k,
                           int * singles, int * ranges);

/* returns 1 if this sequence number has been acked by all the recipients,
 * 0 otherwise */
extern int is_acked (char * contact, uint64_t seq);

/* returns 1 if this sequence number has been acked by this specific recipient,
 * 0 otherwise */
extern int is_acked_one (char * contact, keyset k, uint64_t seq);

/* returns 1 if this sequence number has been received, 0 otherwise */
extern int was_received (char * contact, keyset k, uint64_t seq);

#endif /* ALLNET_CHAT_MESSAGE_H */
