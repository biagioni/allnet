/* priority.c: priorities of received packets, for use throughout AllNet */
/*             includes operations on fractions */

#ifndef PRIORITY_H
#define PRIORITY_H

/* keep track of people up to distance 3, friends of friends of friends */
#define MAX_SOCIAL_TIER         3
#define UNKNOWN_SOCIAL_TIER     (MAX_SOCIAL_TIER + 1)
#define COMPLETE_STRANGER       (MAX_SOCIAL_TIER * 2)

/* 1 is 2^30, 0.5 is 2^30 / 2 = 2^29, and so on */
#define ALLNET_PRIORITY_MAX	(1 << 30)

/* common fractions to use */
#define ALLNET_ONE_HALF	(ALLNET_PRIORITY_MAX >> 1)
#define ALLNET_ONE_QUARTER	(ALLNET_PRIORITY_MAX >> 2)
#define ALLNET_ONE_EIGHT	(ALLNET_PRIORITY_MAX >> 3)

#define ALLNET_THREE_QUARTERS	(ALLNET_ONE_HALF + ALLNET_ONE_QUARTER)
#define ALLNET_THREE_EIGHTS	(ALLNET_ONE_QUARTER + ALLNET_ONE_EIGHT)
#define ALLNET_FIVE_EIGHTS	(ALLNET_ONE_HALF + ALLNET_ONE_EIGHT)
#define ALLNET_SEVEN_EIGHTS	(ALLNET_PRIORITY_MAX - ALLNET_ONE_EIGHT)

#define ALLNET_PRIORITY_SEVEN_EIGHTS	ALLNET_SEVEN_EIGHTS
#define ALLNET_PRIORITY_THREE_QUARTERS	ALLNET_THREE_QUARTERS
#define ALLNET_PRIORITY_FIVE_EIGHTS	ALLNET_FIVE_EIGHTS
#define ALLNET_PRIORITY_ONE_HALF	ALLNET_ONE_HALF
#define ALLNET_PRIORITY_THREE_EIGHTS	ALLNET_THREE_EIGHTS
#define ALLNET_PRIORITY_ONE_QUARTER	ALLNET_ONE_QUARTER
#define ALLNET_PRIORITY_ONE_EIGHT	ALLNET_ONE_EIGHT

#define ALLNET_PRIORITY_EPSILON		1

/* in allnet, local traffic should have the highest priority, unless there
 * is a reason to use a lower priority -- locally-generated traffic on behalf
 * of others typically has priority less than ALLNET_PRIORITY_LOCAL_LOW */
#define ALLNET_PRIORITY_LOCAL_HIGH	ALLNET_PRIORITY_MAX
#define ALLNET_PRIORITY_LOCAL		ALLNET_PRIORITY_SEVEN_EIGHTS
#define ALLNET_PRIORITY_LOCAL_LOW	ALLNET_PRIORITY_THREE_QUARTERS

/* traffic from friends gets priority between ALLNET_PRIORITY_FRIENDS_MAX
 * and ALLNET_PRIORITY_FRIENDS_MIN */
/* it is hard to tell whether traffic allegedly "to" friends is actually
 * for them, so the destination of a message does not affect the priority */
#define ALLNET_PRIORITY_FRIENDS_HIGH	ALLNET_PRIORITY_FIVE_EIGHTS
#define ALLNET_PRIORITY_FRIENDS_LOW	ALLNET_PRIORITY_ONE_HALF

/* default priorities for other traffic -- if not sure, use
 * ALLNET_PRIORITY_DEFAULT */
#define ALLNET_PRIORITY_DEFAULT_HIGH	ALLNET_PRIORITY_THREE_EIGHTS
#define ALLNET_PRIORITY_DEFAULT		ALLNET_PRIORITY_ONE_QUARTER
#define ALLNET_PRIORITY_DEFAULT_LOW	ALLNET_PRIORITY_ONE_EIGHT

#define ALLNET_PRIORITY_TRACE		ALLNET_PRIORITY_EPSILON
#define ALLNET_PRIORITY_TRACE_FWD	(ALLNET_PRIORITY_EPSILON + 1)
 
/* used by acache */
#define ALLNET_PRIORITY_CACHE_RESPONSE	ALLNET_PRIORITY_DEFAULT_LOW

/* computes priority as a fraction of ALLNET_PRIORITY_MAX.  For example, a
 * priority of 3/4 is ALLNET_PRIORITY_MAX / 4 * 3
 */
extern int compute_priority (int size, int sbits, int dbits,
                             int hops_already, int hops_max,
                             int social_distance, int rate_fraction,
                             int cacheable);

/* for use with priorities and also other fractions */
extern void print_fraction (int value, char * str);

extern int power_half_fraction (int power);

extern int allnet_multiply (int p1, int p2);

/* if n1 < n2,  returns n1 / n2 */
/* if n1 >= n2, returns ALLNET_PRIORITY_MAX */
extern int allnet_divide (int n1, int n2);

#endif /* PRIORITY_H */
