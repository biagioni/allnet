/* xcommon.h: send and receive messages for xchat */

#ifndef ALLNET_XCHAT_COMMON_H
#define ALLNET_XCHAT_COMMON_H

#include "chat.h"

/* returns the socket if successful, -1 otherwise */
extern int xchat_init ();
/* optional... */
extern void xchat_end (int sock);

/* handle an incoming packet, acking it if it is a data packet for us */
/* if it is a data or ack, it is saved in the xchat log */
/* fills in peer, message, desc (all to point to malloc'd buffers, must
 * be freed) and verified, and returns the message length > 0 if this was
 * a valid data message from a peer.  Otherwise returns 0 */
/* the data message (if any) is null-terminated */
extern int handle_packet (int sock, char * packet, int psize,
                          char ** peer, char ** message, char ** desc,
                          int * verified, time_t * sent, int * duplicate);

/* send this message and save it in the xchat log. */
/* returns the sequence number of this message, or 0 for errors */
extern long long int send_data_message (int sock, char * peer,
                                        char * message, int mlen);

/* if there is anyting unacked, resends it.  If any sequence number is known
 * to be missing, requests it */
extern void request_and_resend (int sock, char * peer);

#endif /* ALLNET_XCHAT_COMMON_H */
