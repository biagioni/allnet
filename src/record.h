/* record.h: keep track of recently received packets */

#ifndef RECORD_H
#define RECORD_H

/* return 0 if this is a new packet, and the number of seconds (at least 1)
 * since it has been seen, if it has been seen before on this connection */
extern int record_packet_time (char * data, int dsize, int conn);

/* clear all packets sent on this connection */
extern void record_packet_clear (int conn);

/* possibly useful elsewhere */
extern int allnet_record_simple_hash_fn (char * data, int bits);

#endif /* RECORD_H */
