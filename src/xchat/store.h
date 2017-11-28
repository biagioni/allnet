
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

/* returns the sequence number, or 0 if none are available */
/* type_wanted must be MSG_TYPE_ANY, MSG_TYPE_RCVD, or MSG_TYPE_SENT,
 * otherwise returns 0 */
extern uint64_t highest_seq_value (const char * contact, keyset k,
                                   int type_wanted);

/* returns the sequence number, or 0 if none are available */
/* type_wanted must be MSG_TYPE_ANY, MSG_TYPE_RCVD, or MSG_TYPE_SENT,
 * otherwise returns 0 */
extern uint64_t highest_seq_any_key (const char * contact, int type_wanted);

/* returns the message type, or MSG_TYPE_DONE if none are available */
/* not used anywhere, I think */
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
  keyset keyset;  /* which keyset for this contact */
  int msg_type;   /* only MSG_TYPE_SENT or MSG_TYPE_RCVD, never MSG_TYPE_ACK */
  uint64_t seq;
  uint64_t prev_missing;        /* only for MSG_TYPE_RCVD, number of sequence
                                 * numbers missing before this one */
  uint64_t time; /* sender's idea of when sent */
  int tz_min;    /* sender's idea of timezone, in minutes */
  uint64_t rcvd_ackd_time;     /* time received or acked, or 0 if neither */
                               /* 2017/11/22: ack times not supported yet */
  int message_has_been_acked;  /* for MSG_TYPE_SENT, 1 if acked, 0 otherwise */
  char ack [MESSAGE_ID_SIZE];  /* for acked MSG_TYPE_SENT, the ack */
  const char * message;
  size_t msize;
};

/* get all the messages for a contact.
 *
 * *msgs must be NULL or pointing to num_alloc (malloc'd or realloc'd) records
 * of type struct message_store_info.  list_all_messages may realloc this if
 * more space is needed.  Initially, *num_used must be 0.  After returning,
 * *num_used <= *num_alloc (both numbers may have changed)
 * if *msgs was previously used, caller must have freed its messages
 * by calling free_all_messages before calling list_all_messages
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
                        int * num_used, int position, keyset keyset,
                        int type, uint64_t seq, uint64_t missing,
                        uint64_t time, int tz_min, uint64_t rcvd_time,
                        int acked, const char * ack,
                        const char * message, int msize);

/* returns an estimate of the number of bytes used to save the
 * conversation information for this contact.
 * returns -1 if the contact does not exist or for other errors */
extern int64_t conversation_size (const char * contact);

/* remove older files one by one until the remaining conversation size
 * is less than or equal to max_size
 * returns 1 for success, 0 for failure. */
extern int reduce_conversation (const char * contact, uint64_t max_size);
/* delete conversation deletes the entire conversation with its directory.
 * clear conversation deletes the contents of the conversation, but
 * keeps enough information (particularly sequence numbers) to allow the
 * conversation to continue. */
/* these return 1 for success, 0 for failure. */
extern int delete_conversation (const char * contact);
extern int clear_conversation (const char * contact);

/* manipulate config files in an xchat directory */

/* return -1 if the file does not exist, the size otherwise.
 * if content is not NULL, malloc's enough space to hold the
 * content (with null termination), and returns it */
extern int xchat_file_get (const char * contact, keyset k,
                           const char * fname, char ** content);
/* write the content to the file, returning 0 in case of error, 1 otherwise */
extern int xchat_file_write (const char * contact, keyset k,
                             const char * fname, char * content, int clength);
/* useful to find out when the file was last written
 * time returned is allnet microseconds (see lib/util.h), or 0 for errors */
extern long long int xchat_file_time (const char * contact, keyset k,
                                      const char * fname);
/* return 1 if the file was deleted, 0 otherwise */
extern int xchat_file_delete (const char * contact, keyset k,
                              const char * fname);

#endif /* ALLNET_CHAT_STORE_H */
