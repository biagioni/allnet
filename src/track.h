/* track.h: keep track of how much bandwidth is going to each destination */

#ifndef TRACK_H
#define TRACK_H

/* record that this source is sending this packet of given size */
/* return an integer, as a fraction of ALLNET_PRIORITY_MAX, to indicate what
 * fraction of the available bandwidth this source is using.
 * ALLNET_PRIORITY_MAX is defined in priority.h
 */
extern unsigned int track_rate (unsigned char * src, unsigned int sbits,
                                unsigned int packet_size);

/* return the rate of the sender that is sending the most at this time */
/* used by default when we cannot prove who the sender is */
extern unsigned int largest_rate ();

#endif /* TRACK_H */

