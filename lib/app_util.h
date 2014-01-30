/* app_util.h: utilities for apps */

#ifndef ALLNET_APP_UTIL_H
#define ALLNET_APP_UTIL_H

/* returns the socket, or -1 in case of failure */
extern int connect_to_local ();

#if 0
/* use writeb64 and readb64 from util.h/util.c instead */

/* used to convert from array (external) to internal representation and back */
extern void write_big_endian16 (char * array, int value);
extern void write_big_endian32 (char * array, long int value);
extern void write_big_endian48 (char * array, long long int value);
extern void write_big_endian64 (char * array, long long int value);

extern int read_big_endian16 (char * array);
extern long int read_big_endian32 (char * array);
extern long long int read_big_endian48 (char * array);
extern long long int read_big_endian64 (char * array);

#endif /* 0 */

#endif /* ALLNET_APP_UTIL_H */
