/* xcommon.h: send and receive messages for xchat */

#ifndef ALLNET_XCHAT_COMMON_H
#define ALLNET_XCHAT_COMMON_H

#include <inttypes.h>

#include "chat.h"
#include "lib/keys.h"
#include "lib/mgmt.h"  /* struct allnet_mgmt_trace_reply */

/* returns the socket if successful, -1 otherwise */
/* path is usually NULL.  It should be non-null only when the system
 * has a hard-to-find path to config files, and the caller can
 * specify the path to the directory to use. */
extern int xchat_init (const char * program_name, const char * path);
/* optional... */
extern void xchat_end (int sock);

/* only returns new acks, discarding acks received previously */
struct allnet_ack_info {
  int num_acks;        /* num acks received */
  uint64_t acks [ALLNET_MAX_ACKS];  /* seq numbers acknowledged */
  char * peers [ALLNET_MAX_ACKS];   /* for these peers */
};

/* handle an incoming packet, acking it if it is a data packet for us
 * if psize is 0, checks internal buffer for previously unprocessed packets
 * and behaves as if a data packet was received.
 *
 * returns the message length > 0 if this was a valid data message from a peer.
 * if it gets a valid key, returns -1 (details below)
 * if it gets a new valid subscription, returns -2 (details below)
 * if it gets a new valid ack, returns -3 (details below)
 * if it gets a new valid trace message, returns -4 (details below)
 * Otherwise returns 0 and does not fill in any of the following results.
 *
 * if it is a data message, it is saved in the xchat log
 * if it is a valid data message from a peer or a broadcaster,
 * fills in verified and broadcast
 * fills in contact, message (to point to malloc'd buffers, must be freed)
 * if not broadcast, fills in desc (also malloc'd), seq, sent (if not null)
 * and duplicate.
 * if verified and not broadcast, fills in kset.
 * the data message (if any) is null-terminated
 *
 * if it is a key exchange message matching one of my pending key
 * exchanges, saves the key, fills in *peer, and returns -1.
 *
 * if it is a broadcast key message matching a pending key request,
 * saves the key, fills in *peer, and returns -2.
 *
 * if it is a new ack to something we sent, saves it in the xchat log
 * and if acks is not null, fills it in.  Returns -3
 *
 * if it is a trace reply, fills in trace_reply if not null (must be free'd),
 * and returns -4
 */
extern int handle_packet (int sock, char * packet, unsigned int psize,
                          unsigned int priority,
                          char ** contact, keyset * kset,
                          char ** message, char ** desc, int * verified,
                          uint64_t * seq, time_t * sent,
                          int * duplicate, int * broadcast,
                          struct allnet_ack_info * acks,
                          struct allnet_mgmt_trace_reply ** trace_reply);

/* send this message and save it in the xchat log. */
/* returns the sequence number of this message, or 0 for errors */
extern uint64_t send_data_message (int sock, const char * peer,
                                   const char * message, int mlen);

/* if a previously received key matches one of the secrets, returns 1,
 * otherwise returns 0 */
extern int key_received_before (int sock, char ** peer, keyset * kset);

/* returns 1 for a successful parse, 0 otherwise */
/* *s1 and *s2, if not NULL, are malloc'd (as needed), should be free'd */
extern int parse_exchange_file (const char * contact, int * nhops,
                                char ** s1, char ** s2);

/* if there is anyting unacked, resends it.  If any sequence number is known
 * to be missing, requests it */
/* returns:
 *    -1 if it is too soon to request again
 *    0 if it it did not send a retransmit request for this contact/key
 *      (e.g. if nothing is known to be missing)
 *    1 if it sent a retransmit request
 */
/* eagerly should be set when there is some chance that our peer is online,
 * i.e. when we've received a message or an ack from the peer.  In this
 * case, we retransmit and request data right away, independently of the
 * time since the last request */
extern int request_and_resend (int sock, char * peer, keyset kset, int eagerly);

/* call every once in a while, e.g. every 1-10s, to poke all our
 * contacts and get any outstanding messages. */
/* each time it is called, queries a different contact or keyset */
extern void do_request_and_resend (int sock);

/* create the contact and key, and send
 * the public key followed by
 *   the hmac of the public key using the secret as the key for the hmac.
 * the secrets should be normalized by the caller
 * secret2 may be NULL, secret1 should not be.
 * return 1 if successful, 0 for failure (usually if the contact already
 * exists, but other errors are possible) */
extern int create_contact_send_key (int sock, const char * contact,
                                    const char * secret1,
                                    const char * secret2,
                                    unsigned int hops);
/* for an incomplete key exchange, resends the key
 * return 1 if successful, 0 for failure (e.g. the key exchange is complete) */
extern int resend_contact_key (int sock, const char * contact);
/* return the number of secrets returned, 0, 1 (only s1), or 2 */
/* the secret(s) are malloc'd (must be freed) and assigned to s1
 * and s2 if not NULL */
extern int key_exchange_secrets (const char * contact, char ** s1, char ** s2);

/* sends out a request for a key matching the subscription.
 * returns 1 for success (and fills in my_addr and nbits), 0 for failure */
extern int subscribe_broadcast (int sock, char * ahra);

#endif /* ALLNET_XCHAT_COMMON_H */
