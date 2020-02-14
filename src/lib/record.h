/* record.h: keep track of recently received packets */

#ifndef RECORD_H
#define RECORD_H

/* return 0 if this is a new packet, and the number of seconds (at least 1)
 * since it has been seen, if it has been seen before */
extern unsigned int record_packet (char * packet, unsigned int psize);

/* possibly useful elsewhere. */
/* data must have at least ((bits + 7) / 8) bytes, and bits should be > 0 */
extern int allnet_record_simple_hash_fn (char * data, unsigned int bits);

#endif /* RECORD_H */
