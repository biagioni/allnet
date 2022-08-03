/* format of chat messages */

#ifndef ALLNET_CHAT_H
#define ALLNET_CHAT_H

#include "lib/packet.h"	/* MESSAGE_ID_SIZE, struct app_media_header */

/* messages are indexed by a 64-bit counter, which must be forever unique over
 * all messages between a given pair of sender and receiver, or for a given
 * sender and group.  Messages also have a date/time and timezone.
 *
 * the first counter in any exchange has the value 1.
 *
 * a repeated counter value with a later timestamp means a correction
 * or deletion is requested for a previously sent message.
 *
 * control messages have a counter value of 0xffffffffffffffff, followed
 * by the control message header.
 *
 * the time is encoded as
 * 6 bytes of seconds since midnight GMT on 01/01/2000,
 * 2 bytes of +- minute offset from GMT, set to 0x8000 if not known
 *      (in which case local time is sent)
 *
 * all these values are sent in big-endian order, that is, with the
 * most significant byte first, so counter [0], timestamp [0] and timestamp [6]
 * each have the most significant byte of their value.
 *
 * like any data message, the first MESSAGE_ID_SIZE of any message are the
 * random bytes which hash to the packet ID sent in the clear (only the
 * first MESSAGE_ID_SIZE of the sha512 are sent).
 *
 */

#define XCHAT_ALLNET_APP_ID	0x58434854 /* XCHT */

#define XCHAT_SOCKET_PORT 	(htons (0xa11c))  /* ALLnet Chat, 41244 */

/* the chat descriptor is sent before the user text, in the first
 * 40 bytes of the data of the AllNet packet */

#define COUNTER_SIZE	8
#define TIMESTAMP_SIZE	8

struct chat_descriptor {
  unsigned char message_ack   [MESSAGE_ID_SIZE];  /* if no ack, random or 0 */
  struct allnet_app_media_header app_media;
  unsigned char counter       [   COUNTER_SIZE];  /* sequence number */
  unsigned char timestamp     [ TIMESTAMP_SIZE];  /* sender's local time */
};

#define CHAT_DESCRIPTOR_SIZE	(sizeof (struct chat_descriptor)) /* 40 bytes */

/* a large packet (ALLNET_TRANSPORT_LARGE in the allnet header)
 * only includes the message ack.  The packet ack is the inverted
 * message ack XOR'd with the sequence number.
 * Because the packet ack is computed, knowing the message ack lets
 * anyone reconstruct packet acks.  This is not a vulnerability
 * since sending the message ack automatically acks all packets,
 * and only secret used in computing the packet acks is the message ack.
 * The computed packet acks are the same when sending as when
 * retransmitting, which is desirable. */

/* a counter value of COUNTER_FLAG indicates a control message rather than
 * a data message */
#define COUNTER_FLAG	0xffffffffffffffffLL

struct chat_control {
  unsigned char message_ack [MESSAGE_ID_SIZE];  /* if no ack, random or 0 */
  struct allnet_app_media_header app_media;
  unsigned char counter     [   COUNTER_SIZE];  /* always COUNTER_FLAG */
  unsigned char type;
};

/* values for the chat_control.type */
#define CHAT_CONTROL_TYPE_REQUEST	1
#define CHAT_CONTROL_TYPE_KEY_ACK	2
#define CHAT_CONTROL_TYPE_REKEY		3

/* a CHAT_CONTROL_TYPE_REQUEST packet requests delivery of all
   packets that fit one or more of:
   - counter value > last_received
   - counter value listed in one of the first num_singles counters
   - for each pair (start, finish) of counters after the first num_singles,
     start <= counter <= finish */
/* for example, if num_singles is 3, num_ranges is 1, last_received is 99,
   counters is { 91, 89, 95, 77, 82 }, and the sender has sent up to
   counter 105, it is hereby invited to resend:
   77, 78, 79, 80, 81, 82           (listed in the range)
   89, 91, 95                       (listed as single counter values)
   100, 101, 102, 103, 104, and 105 (implied by last_received)
 */
struct chat_control_request {
  unsigned char message_ack [MESSAGE_ID_SIZE];  /* if no ack, random or 0 */
  /* app should be XCHAT_ALLNET_APP_ID, media should be ALLNET_MEDIA_DATA */
  struct allnet_app_media_header app_media;
  unsigned char counter     [   COUNTER_SIZE];  /* always COUNTER_FLAG */
  unsigned char type;                   /* always CHAT_CONTROL_TYPE_REQUEST */
  unsigned char num_singles;
  unsigned char num_ranges;
  unsigned char padding [5];   /* sent as zeros, ignored on receipt */
  unsigned char last_received [COUNTER_SIZE];
  /* counters has COUNTER_SIZE * (num_singles + 2 * num_ranges) bytes */
  unsigned char counters  [0];
};

/* a CHAT_CONTROL_TYPE_KEY_ACK packet completes a key exchange.
 * this will normally be the first packet sent to a new contact as
 * soon as the key exchange is complete.
 * if I receive a chat_control_key_ack, I may start using the new key
 */
struct chat_control_key_ack {
  unsigned char message_ack [MESSAGE_ID_SIZE];  /* random */
  /* app should be XCHAT_ALLNET_APP_ID, media should be random */
  struct allnet_app_media_header app_media;
  unsigned char counter     [   COUNTER_SIZE];  /* always COUNTER_FLAG */
  unsigned char type;                   /* always CHAT_CONTROL_TYPE_KEY_ACK */
};

/* a CHAT_CONTROL_TYPE_REKEY packet initiates or completes a new key exchange.
 * if I send a chat_control_rekey, I may start using the new key(s) once
 * I receive a chat_control_rekey from the other side.
 */
struct chat_control_rekey {
  unsigned char message_ack [MESSAGE_ID_SIZE];  /* if no ack, random or 0 */
  /* app should be XCHAT_ALLNET_APP_ID, media should be ALLNET_MEDIA_DATA */
  struct allnet_app_media_header app_media;
  unsigned char counter     [   COUNTER_SIZE];  /* always COUNTER_FLAG */
  unsigned char type;                   /* always CHAT_CONTROL_TYPE_REKEY */
  unsigned char key [0];  /* 513-byte public key for RSA, or
                             97-byte code+key+secret DH for AES/secret */
};

#endif /* ALLNET_CHAT_H */
