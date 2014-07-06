/* xcommon.h: send and receive messages for xchat */

#ifndef ALLNET_XCHAT_COMMON_H
#define ALLNET_XCHAT_COMMON_H

#include "chat.h"
#include "lib/keys.h"

/* returns the socket if successful, -1 otherwise */
extern int xchat_init ();
/* optional... */
extern void xchat_end (int sock);

/* handle an incoming packet, acking it if it is a data packet for us
 * returns the message length > 0 if this was a valid data message from a peer.
 * if it gets a valid key, returns -1 (details below)
 * Otherwise returns 0 and does not fill in any of the following results.
 *
 * if it is a data or ack, it is saved in the xchat log
 * if it is a valid data message from a peer or a broadcaster,
 * fills in verified and broadcast
 * fills in contact, message (to point to malloc'd buffers, must be freed)
 * if not broadcast, fills in desc (also malloc'd), sent (if not null)
 * and duplicate.
 * if verified and not broadcast, fills in kset.
 * the data message (if any) is null-terminated
 *
 * if kcontact and ksecret1 are not NULL, assumes we are also looking
 * for key exchange messages sent to us matching either of ksecret1 or
 * (if not NULL) ksecret2.  If such a key is found, returns -1.
 * there are two ways of calling this:
 * - if the user specified the peer's secret, first send initial key,
 *   then call handle_packet with our secret in ksecret1, and our
 *   peer's secret in ksecret2.
 * - otherwise, put our secret in ksecret1, make ksecret2 NULL,
 *   and handle_packet is ready to receive a key.
 * In either case, if a matching key is received, it is saved and a
 * response is sent (if a response is a duplicate, it does no harm).
 * kmax_hops specifies the maximum hop count of incoming acceptable keys,
 * and the hop count used in sending the key.
 */
extern int handle_packet (int sock, char * packet, int psize,
                          char ** contact, keyset * kset,
                          char ** message, char ** desc, int * verified,
                          time_t * sent, int * duplicate, int * broadcast,
                          char * kcontact, char * ksecret1, char * ksecret2,
                          int kmax_hops);

/* send this message and save it in the xchat log. */
/* returns the sequence number of this message, or 0 for errors */
extern long long int send_data_message (int sock, char * peer,
                                        char * message, int mlen);

/* if there is anyting unacked, resends it.  If any sequence number is known
 * to be missing, requests it */
extern void request_and_resend (int sock, char * peer, keyset kset);

/* create the contact and key, and send
 * the public key followed by
 *   the hmac of the public key using the secret as the key for the hmac.
 * secret2 may be NULL, secret1 should not be.
 * return 1 if successful, 0 for failure (usually if the contact already
 * exists, but other errors are possible) */

extern int create_contact_send_key (int sock, char * contact, char * secret1,
                                    char * secret2, int hops);

#endif /* ALLNET_XCHAT_COMMON_H */
