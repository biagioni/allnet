/* cutil.h: interfaces of functions provided by cutil.c */

#ifndef ALLNET_CHAT_UTIL_H
#define ALLNET_CHAT_UTIL_H

#include <inttypes.h>

#include "chat.h"
#include "lib/keys.h"
#include "lib/crypt_sel.h"

/* returns 1 if successful, 0 otherwise */
extern int init_chat_descriptor (struct chat_descriptor * cp,
                                 const char * contact);

/* send to the contact, returning the sequence number if successful, else 0 */
/* unless ack_and_save is 0, requests an ack, and calls save_outgoing. */
/* if contact is a group, sends to each member of the group and returns
 * the largest sequence number sent */
/* the message must include room for the chat descriptor
 * and (if ack_and_save) for the ack, both initialized by this call. */
extern unsigned long long int send_to_contact (char * data, unsigned int dsize,
                                               const char * contact, int sock,
                                               unsigned int hops,
                                               unsigned int priority,
                                               int ack_and_save);

/* send to the contact's specific key, returning 1 if successful, 0 otherwise */
/* the xchat_descriptor must already have been initialized */
/* expiration may be NULL */
extern int send_to_key (char * data, unsigned int dsize,
                        const char * contact, keyset key,
                        int sock, unsigned int hops, unsigned int priority,
                        const char * expiration, int do_ack, int do_save);

/* same as send_to_contact, but only sends to the one key corresponding
 * to key, and does not save outgoing.  Does request ack, and
 * uses the addresses saved for the contact. */
extern int resend_packet (char * data, unsigned int dsize,
                          const char * contact, keyset key,
                          int sock, unsigned int hops, unsigned int priority);

/* the times that follow must be arrays of TIMESTAMP_SIZE chars */

/* if static_result is 0, returned string is statically allocated, should
 * not be free'd and should not be used by multithreaded programs */
/* otherwise, returned string is dynamically allocated, must be free'd */
extern char * chat_time_to_string (unsigned char * t, int static_result);

extern char * chat_descriptor_to_string (struct chat_descriptor * cdp,
                                         int show_id, int static_result);

/* when did a user last read messages from this contact?
 * returns 0 if never read or for other errors */
extern unsigned long long int last_read_time (const char * contact);
extern void set_last_read_time (const char * contact);  /* all messages read */

/* strip most non-alphabetic characters, and convert the rest to uppercase */
extern void normalize_secret (char * s);

/* creates a chat descriptor for a new chat */
extern void new_chat_descriptor (struct chat_descriptor * cd);

/* increments the counter part of the chat descriptor, and sets the time */
extern void update_chat_descriptor (struct chat_descriptor * cd);

/* only sets the time -- used for corrections */
extern void update_chat_descriptor_time (struct chat_descriptor * cd);

/* the chat descriptor stores time with the main part in the first 48 bits,
 * and the time zone (in signed minutes from UTC -- positive is East) in
 * the lower 16 bits */
extern void get_time_tz (uint64_t raw, uint64_t * time, int * tz);

extern uint64_t make_time_tz (uint64_t time, int tz);

/* selector for fill_bits */
#define FILL_LOCAL_ADDRESS	1
#define FILL_REMOTE_ADDRESS	0
#define FILL_ACK		2

/* there must be 2^power_two bits in the bitmap (2^(power_two - 3) bytes),
 * and power_two must be less than 32.
 * selector should be FILL_LOCAL/REMOTE_ADDRESS or FILL_ACK
 * returns the number of bits filled, or -1 for errors */
extern int fill_bits (unsigned char * bitmap, int power_two, int selector);

/* place in the given buffer a push request, and return the size
 * push requests are similar to data requests from packet.h, but
 * instead of the 16-byte token they carry (a) a push protocol ID,
 * (b) the number of bytes in the token, (c) the token itself, and
 * (d) padding to make this a multiple of 16 bytes
   struct push_request {
     unsigned short id;
     unsigned short token_size;
     unsigned char token [.token_size];
     unsigned char token_padding [0..15];
     unsigned char since [ALLNET_TIME_SIZE];  -- from since param, if not NULL
     unsigned char dst_bits_power_two;  -- 8
     unsigned char src_bits_power_two;  -- 8
     unsigned char mid_bits_power_two;  -- 0 if mid param is NULL, 8 otherwise
     unsigned char padding [5];
     unsigned char dst_bitmap [32];
     unsigned char src_bitmap [32];
     unsigned char mid_bitmap [(mid != NULL) ? 32 : 0];
   }; 
   the mid parameter, if not NULL, must be a pointer to a 32-byte array
   containing the message ID bitmap */
#define ALLNET_PUSH_APNS_ID	1	/* Apple Push Notification Service */
#define ALLNET_PUSH_FCM_ID	2	/* Firebase Cloud Messaging (Android) */
extern int create_push_request (allnet_rsa_pubkey rsa, int id,
				const char * device_token, int tsize,
                                const char * since, const char * mid,
                                char * result, int rsize);

#endif /* ALLNET_CHAT_UTIL_H */
