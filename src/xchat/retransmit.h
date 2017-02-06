/* retransmit.h: support requesting and resending chat messages */

#ifndef RETRANSMIT_H
#define RETRANSMIT_H

#include "chat.h"
#include "lib/keys.h"

/* sends a chat_control message to request retransmission.
 * returns 1 for success, 0 in case of error. */ 
extern int send_retransmit_request (char * contact, keyset k, int sock,
                                    int hops, int priority);

/* resends up to max unacked messages */
extern void resend_unacked (char * contact, keyset k, int sock, int hops,
                            int priority, int max);

/* retransmit any requested messages */
extern void do_chat_control (char * contact, keyset k,
                             char * msg, int msize, int sock, int hops);

#endif /* RETRANSMIT_H */
