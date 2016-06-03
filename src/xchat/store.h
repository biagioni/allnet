
#ifndef ALLNET_CHAT_STORE_H
#define ALLNET_CHAT_STORE_H

#include "lib/keys.h"

/* start_iter and prev_message define an iterator over messages.
 * the iterator proceeds backwards, setting type to MSG_TYPE_DONE
 * after the last message has been read. */
/* the iterator should be deallocated with free_iter after it is used */
/* for a single record, use most_recent record. */

#define MSG_TYPE_DONE   0
#define MSG_TYPE_ANY    0
#define MSG_TYPE_RCVD   1
#define MSG_TYPE_SENT   2
#define MSG_TYPE_ACK    3

extern struct msg_iter * start_iter (const char * contact, keyset k);

/* returns the message type, or MSG_TYPE_DONE if we've reached the end */
/* in case of SENT or RCVD, sets *seq, message_ack (which must have
 * MESSAGE_ID_SIZE bytes), and sets *message to point to newly
 * allocated memory containing the message (caller must free this).
 * for ACK, sets message_ack only, sets *seq to 0 and *message to NULL
 * for DONE, sets *seq to 0, clears message_ack, and sets *message to NULL */
extern int prev_message (struct msg_iter * iter, uint64_t * seq,
                         uint64_t * time, int * tz_min, uint64_t * rcvd_time,
                         char * message_ack, char ** message, int * msize);

extern void free_iter (struct msg_iter * iter);

/* returns the message type, or MSG_TYPE_DONE if none are available */
extern int highest_seq_record (const char * contact, keyset k, int type_wanted,
                               uint64_t * seq, uint64_t * time, int * tz_min,
                               uint64_t * rcvd_time, char * message_ack,
                               char ** message, int * msize);

/* returns the message type, or MSG_TYPE_DONE if none are available.
 * most recent refers to the most recently saved in the file.  This may
 * not be very useful, highest_seq_record may be more useful */ 
extern int most_recent_record (const char * contact, keyset k, int type_wanted,
                               uint64_t * seq, uint64_t * time, int * tz_min,
                               uint64_t * rcvd_time, char * message_ack,
                               char ** message, int * msize);

extern void save_record (const char * contact, keyset k, int type, uint64_t seq,
                         uint64_t time, int tz_min, uint64_t rcvd_time,
                         const char * message_ack, const char * message,
                         int msize);

/* all the information about a message, for list_all_messages */
struct message_store_info {
  int msg_type;  /* never includes MSG_TYPE_ACK */
  uint64_t seq;
  uint64_t prev_missing;        /* only for MSG_TYPE_RCVD, number of sequence
                                 * numbers missing before this one */
  uint64_t time; /* sender's idea of when sent */
  int tz_min;    /* sender's idea of timezone, in minutes */
  uint64_t rcvd_time;
  int message_has_been_acked;  /* for MSG_TYPE_SENT, 1 if acked, 0 otherwise */
  const char * message;
  size_t msize;
};

/* get all the messages for a contact.
 *
 * *msgs must be NULL or pointing to num_alloc (malloc'd or realloc'd) records
 * of type struct message_store_info.  list_all_messages may realloc this if
 * more space is needed.  Initially, *num_used must be 0.  After returning,
 * *num_used <= *num_alloc (both numbers may have changed)
 * if *msgs was previously used, its messages should have been freed
 * by calling free_all_messages
 * return 1 if successful, 0 if not */
extern int list_all_messages (const char * contact,
                              struct message_store_info ** msgs,
                              int * num_alloc, int * num_used);
/* frees the message storage pointed to by each message entry */
extern void free_all_messages (struct message_store_info * msgs, int num_used);

/* add an individual message, modifying msgs, num_alloc or num_used as needed
 * 0 <= position <= *num_used
 * normally call after calling save_record
 * return 1 if successful, 0 if not */
extern int add_message (struct message_store_info ** msgs, int * num_alloc,
                        int * num_used, int position,
                        int type, uint64_t seq, uint64_t missing,
                        uint64_t time, int tz_min,
                        uint64_t rcvd_time, int acked,
                        const char * message, int msize);

#endif /* ALLNET_CHAT_STORE_H */
