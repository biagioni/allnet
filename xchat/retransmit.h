/* retransmit.h: support requesting and resending chat messages */

#ifndef RETRANSMIT_H
#define RETRANSMIT_H

#include "chat.h"

/* allocates and returns a buffer containing a chat_control message that
 * may be sent to request retransmission.
 * The buffer includes the allnet header.
 * if always_generate is 1, always returns such a buffer (except in
 * case of errors, when NULL is returned.
 * if always_generate is 0, only returns the buffer if there are known
 * gaps in the sequence numbers received from this contact.
 * returns NULL in case of error or if no buffer is returned..
 */
extern unsigned char * retransmit_request (char * contact, int alway_generate,
                                           char * src, int sbits,
                                           char * dst, int dbits, int hops,
                                           int * msize);

struct retransmit_messages {
  int num_messages;
  char * * messages;
  int * message_lengths;
};

/* returns a collection of messages that may be sent to the contact that
 * sent us the retransmit message.  The number of messages may be 0 or more.
 * After it has been used, the pointers in the retransmit_messages should
 * be freed by calling free_retransmit.
 */
extern struct retransmit_messages
    retransmit_received (char * contact, char * retransmit_message, int mlen,
                         int hops);

/* returns 0 or more of the messages that were sent, but not acked */
extern struct retransmit_messages retransmit_unacked (char * contact, int hops);

extern void free_retransmit (struct retransmit_messages info);

/* retransmit any requested messages */
extern void do_chat_control (int sock, char * contact, char * msg, int msize,
                             int hops);

#endif /* RETRANSMIT_H */
