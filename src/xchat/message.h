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
extern uint64_t get_counter (const char * contact);

/* return the largest received counter, or 0 if the contact cannot be found
 * or the keyset is not valid. */
extern uint64_t get_last_received (const char * contact, keyset k);

/* save an outgoing message to a specific directory for this contact.
 * the directory is specific because the message ack is different for
 * each copy of the message */
extern void save_outgoing (const char * contact, keyset k,
                           struct chat_descriptor * cp,
                           char * text, int tsize);

/* return the (malloc'd) outgoing message with the given sequence number,
 * or NULL if there is no such message.
 * if there is more than one such message, returns the latest.
 * Also fills in the size, time and message_ack -- message_ack must have
 * at least MESSAGE_ID_SIZE bytes */
extern char * get_outgoing (const char * contact, keyset k, uint64_t seq,
                            int * size, uint64_t * time, char * message_ack);

/* save a received message */
extern void save_incoming (const char * contact, keyset k,
                           struct chat_descriptor * cp, char * text, int tsize);

/* mark a previously sent message as acknowledged
 * return the sequence number > 0 if this is an ack for a known contact,
 * return 0 if this ack is not recognized
 * if result > 0:
 * if contact is not NULL, the contact is set to point to the
 * contact name (dynamically allocated, must be free'd) and
 * if kset is not null, the location it points to is set to the keyset
 * if new_ack is not null, the location it points to is set 1 if
 * this is an ack we have not seen before
 */
extern uint64_t ack_received (const char * message_ack,
                              char ** contact, keyset * kset, int * new_ack);

/* returns a new (malloc'd) array, or NULL in case of error */
/* the new array has (singles + 2 * ranges) * COUNTER_SIZE bytes. */
/* the first *singles sequence numbers are individual sequence numbers
 * that we never received.
 * the next *ranges * 2 sequence numbers are pairs a, b such that we have
 * not received any of the sequence numbers a <= seq <= b */
extern char * get_missing (const char * contact, keyset k,
                           int * singles, int * ranges);

/* returns a new (malloc'd) array, or NULL in case of error */
/* the new array has (singles + 2 * ranges) * COUNTER_SIZE bytes. */
/* the first *singles * COUNTER_SIZE bytes are individual sequence numbers
 * that were never acknowledged by this contact ID.
 * the next *ranges * 2 * COUNTER_SIZE bytes are pairs of sequence numbers a, b
 * such that any seq such that a <= seq <= b has no acknowledged */
extern char * get_unacked (const char * contact, keyset k,
                           int * singles, int * ranges);
/* if there is a cache of unacked messages, reload.
 * call if you send a message to this contact or
 * if you get a new ack for this contact */
extern void reload_unacked_cache (const char * contact, keyset k);

/* returns 1 if this sequence number has been acked by all the recipients,
 * 0 otherwise */
extern int is_acked (const char * contact, uint64_t seq);

/* returns 1 if this sequence number has been acked by this specific recipient,
 * 0 otherwise */
/* if timep is not NULL, it is set to the time of the message with the wanted
 * sequence number, if any */
extern int is_acked_one (const char * contact, keyset k, uint64_t seq,
                         uint64_t * timep);

/* returns 1 if this sequence number has been received, 0 otherwise */
extern int was_received (const char * contact, keyset k, uint64_t seq);

/* returns 1 if this message ID is in the (limited size) saved cache,
 * 0 otherwise
 * in other words, may return 0 even though the message was saved,
 * just because it is not in the cache
 * if it returns 1, also fills message_ack with the corresponding ack */
extern int message_id_is_in_saved_cache (const char * message_id,
                                         char * message_ack);

#endif /* ALLNET_CHAT_MESSAGE_H */
