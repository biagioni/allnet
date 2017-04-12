/* retransmit.h: support requesting and resending chat messages */

#ifndef RETRANSMIT_H
#define RETRANSMIT_H

#include "chat.h"
#include "lib/keys.h"

/* sends a chat_control message to request retransmission.
 * returns 1 for success, 0 in case of error. */ 
extern int send_retransmit_request (const char * contact, keyset k, int sock,
                                    int hops, int priority,
                                    const char * expiration);

/* resends up to max unacked messages */
/* returns the number of messages sent, or 0 */
extern int resend_unacked (const char * contact, keyset k, int sock, int hops,
                           int priority, int max);

/* retransmit any requested messages */
extern void do_chat_control (const char * contact, keyset k,
                             char * msg, int msize, int sock, int hops);

#endif /* RETRANSMIT_H */
