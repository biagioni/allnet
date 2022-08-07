/* reassembly.h: interfaces of reassembly.c */

#ifndef ALLNET_CHAT_REASSEMBLY_H
#define ALLNET_CHAT_REASSEMBLY_H

#include "lib/packet.h"

/* returns the message if this packet completes the reassembly,
 * NULL otherwise
 * if this call returns a complete message, the message should be free'd.
 * either way, this call free's text */
extern char * record_message_packet (const struct allnet_header * hp, int psize,
                                     const char * text, int * tsize);

/* given the ack for an entire large message, compute the individual
 * ack for a given packet sequence number
 * the message_ack, packet_ack, and packet_id must each have
 * ALLNET_MESSAGE_ID_SIZE, (packet_id maybe NULL), the sequence
 * must have ALLNET_SEQUENCE_SIZE */
extern void compute_ack (const char * message_ack, const char * sequence,
                         char * packet_ack, char * packet_id);

#endif /* ALLNET_CHAT_REASSEMBLY_H */
