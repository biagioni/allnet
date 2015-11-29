/* xcommon.h: send and receive messages for xchat */

#ifndef ALLNET_XCHAT_COMMON_H
#define ALLNET_XCHAT_COMMON_H

#include "chat.h"
#include "lib/keys.h"
#include "lib/pipemsg.h"

/* returns the socket if successful, -1 otherwise */
extern int xchat_init (char * program_name, pd p);
/* optional... */
extern void xchat_end (int sock);

struct allnet_ack_info {
  int num_acks;        /* num acks received */
  long long int acks [ALLNET_MAX_ACKS];
  char * peers [ALLNET_MAX_ACKS];
};

/* handle an incoming packet, acking it if it is a data packet for us
 * returns the message length > 0 if this was a valid data message from a peer.
 * if it gets a valid key, returns -1 (details below)
 * if it gets a new valid ack, returns -2 (details below)
 * Otherwise returns 0 and does not fill in any of the following results.
 *
 * if it is a data, it is saved in the xchat log
 * if it is a valid data message from a peer or a broadcaster,
 * fills in verified and broadcast
 * fills in contact, message (to point to malloc'd buffers, must be freed)
 * if not broadcast, fills in desc (also malloc'd), sent (if not null)
 * and duplicate.
 * if verified and not broadcast, fills in kset.
 * the data message (if any) is null-terminated
 *
 * if it is an ack to something we sent, saves it in the xchat log
 * and if acks is not null, fills it in.
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
 *
 * if subscription is not null, listens for a reply containing a key
 * matching the subscription, returning -2 if a match is found.
 */
extern int handle_packet (int sock, char * packet, int psize,
                          char ** contact, keyset * kset,
                          struct allnet_ack_info * acks,
                          char ** message, char ** desc, int * verified,
                          time_t * sent, int * duplicate, int * broadcast,
                          char * kcontact, char * ksecret1, char * ksecret2,
                          unsigned char * kaddr, int kbits, int kmax_hops,
                          char * subscription,
                          unsigned char * addr, int nbits);

/* send this message and save it in the xchat log. */
/* returns the sequence number of this message, or 0 for errors */
extern long long int send_data_message (int sock, char * peer,
                                        char * message, int mlen);

/* if a previously received key matches one of the secrets, returns 1,
 * otherwise returns 0 */
extern int key_received (int sock, char * contact, char * secret1,
                         char * secret2, unsigned char * addr, int bits,
                         int max_hops);

/* if there is anyting unacked, resends it.  If any sequence number is known
 * to be missing, requests it */
extern void request_and_resend (int sock, char * peer, keyset kset);

/* create the contact and key, and send
 * the public key followed by
 *   the hmac of the public key using the secret as the key for the hmac.
 * the address (at least ADDRESS_SIZE bytes) and the number of bits are
 * filled in, should not be NULL.
 * secret2 may be NULL, secret1 should not be.
 * return 1 if successful, 0 for failure (usually if the contact already
 * exists, but other errors are possible) */
extern int create_contact_send_key (int sock, const char * contact,
                                    const char * secret1,
                                    const char * secret2,
                                    unsigned char * addr, int * abits,
                                    int hops);

/* sends out a request for a key matching the subscription.
 * returns 1 for success (and fills in my_addr and nbits), 0 for failure */
extern int subscribe_broadcast (int sock, char * ahra,
                                unsigned char * my_addr, int * nbits);

#endif /* ALLNET_XCHAT_COMMON_H */
