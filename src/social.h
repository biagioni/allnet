/* social.h: transmit messages over pipes */

#ifndef SOCIAL_H
#define SOCIAL_H

#include <time.h>

/* these constants are now defined in priority.h */
/* keep track of people up to distance 3, friends of friends of friends */
/* #define MAX_SOCIAL_TIER */
/* #define UNKNOWN_SOCIAL_TIER */
/* #define COMPLETE_STRANGER */

/* opaque type used to store social information */
/* struct social_info; */

/* max bytes is the maximum size for the data structure.
 * max_checks is the maximum number of times signature verification
 * should be attempted per call to social_connection */
extern struct social_info * init_social (int max_bytes, int max_checks);

extern time_t update_social (struct social_info * soc, int update_seconds);

/* checks the signature, and sets valid accordingly.
 * returns the social distance if known, and UNKNOWN_SOCIAL_TIER otherwise */
extern int social_connection (struct social_info * soc,
                              char * verify, int vsize,
                              unsigned char * src, int sbits,
                              int algo, char * sig, int ssize, int * valid);

#endif /* SOCIAL_H */
