/* priority.h: compute with fractions using integers */

#ifndef PRIORITY_H
#define PRIORITY_H

/* 1 is 2^30, 0.5 is 2^30 / 2 = 2^29, and so on */
#define MAX_PRIORITY	(1 << 30)

/* same, but for uses other than priority */
#define MAX_FRACTION	MAX_PRIORITY

/* common fractions to use */
#define ONE_HALF	(MAX_PRIORITY >> 1)
#define ONE_QUARTER	(MAX_PRIORITY >> 2)
#define ONE_EIGHT	(MAX_PRIORITY >> 3)

#define THREE_QUARTERS	(ONE_HALF + ONE_QUARTER)
#define THREE_EIGHTS	(ONE_QUARTER + ONE_EIGHT)
#define FIVE_EIGHTS	(ONE_HALF + ONE_EIGHT)
#define SEVEN_EIGHTS	(ONE_HALF + ONE_QUARTER + ONE_EIGHT)

#define EPSILON		1
#define CACHE_RESPONSE_PRIORITY		ONE_EIGHT

/* computes priority as a fraction of MAX_PRIORITY.  For example, a
 * priority of 3/4 is MAX_PRIORITY / 4 * 3
 */
extern int compute_priority (int is_local, int size, int sbits, int dbits,
                             int hops_already, int hops_max,
                             int social_distance, int rate_fraction);

/* for use with priorities and also other fractions */
extern void print_fraction (int value, char * str);

extern int power_half_fraction (int power);

extern int multiply (int p1, int p2);

#endif /* PRIORITY_H */
