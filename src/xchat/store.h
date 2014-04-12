
#ifndef ALLNET_CHAT_STORE_H
#define ALLNET_CHAT_STORE_H

#include "lib/keys.h"

/* start_iter and prev_message define an iterator over messages.
 * the iterator proceeds backwards, setting type to MSG_TYPE_DONE
 * after the last message has been read. */
/* the iterator should be deallocated with free_iter after it is used */
/* for a single record, use most_recent record. */

#define MSG_TYPE_DONE	0
#define MSG_TYPE_ANY	0
#define MSG_TYPE_RCVD	1
#define MSG_TYPE_SENT	2
#define MSG_TYPE_ACK	3

extern struct msg_iter * start_iter (char * contact, keyset k);

/* returns the message type, or MSG_TYPE_DONE if we've reached the end */
/* in case of SENT or RCVD, sets *seq, message_ack (which must have
 * MESSAGE_ID_SIZE bytes), and sets *message to point to newly
 * allocated memory containing the message (caller must free this).
 * for ACK, sets message_ack only, sets *seq to 0 and *message to NULL
 * for DONE, sets *seq to 0, clears message_ack, and sets *message to NULL */
extern int prev_message (struct msg_iter * iter, uint64_t * seq,
                         uint64_t * time, int * tz_min,
                         char * message_ack, char ** message, int * msize);

extern void free_iter (struct msg_iter * iter);

/* returns the message type, or MSG_TYPE_DONE if none are available */
extern int highest_seq_record (char * contact, keyset k, int type_wanted,
                               uint64_t * seq, uint64_t * time, int * tz_min,
                               char * message_ack,
                               char ** message, int * msize);

/* returns the message type, or MSG_TYPE_DONE if none are available.
 * most recent refers to the most recently saved in the file.  This may
 * not be very useful, highest_seq_record may be more useful */ 
extern int most_recent_record (char * contact, keyset k, int type_wanted,
                               uint64_t * seq, uint64_t * time, int * tz_min,
                               char * message_ack,
                               char ** message, int * msize);

extern void save_record (char * contact, keyset k, int type, uint64_t seq,
                         uint64_t time, int tz_min, char * message_ack,
                         char * message, int msize);

#endif /* ALLNET_CHAT_STORE_H */
