/* retransmit.h: support requesting and resending chat messages */

#ifndef RETRANSMIT_H
#define RETRANSMIT_H

#include "chat.h"

/* sends a chat_control message to request retransmission.
 * returns 1 for success, 0 in case of error. */ 
extern int send_retransmit_request (char * contact, int sock,
                                    int hops, int priority);

/* resends the messages requested by the retransmit message */
extern void resend_messages (char * retransmit_message, int mlen,
                             char * contact, int sock,
                             int hops, int top_priority);

/* resends any unacked messages */
extern void resend_unacked (char * contact, int sock,
                            int hops, int priority);

/* retransmit any requested messages */
extern void do_chat_control (char * contact, char * msg, int msize, int sock,
                             int hops);

#endif /* RETRANSMIT_H */
