/* util.h: useful functions used by different programs */

#ifndef ALLNET_UTIL_H
#define ALLNET_UTIL_H

#include <sys/time.h>
#include <sys/socket.h>

/* print up to max of the count characters in the buffer.
 * desc is printed first unless it is null
 * a newline is printed after if print_eol
 */
extern void print_buffer (const char * buffer, int count, char * desc,
                          int max, int print_eol);
/* same as print_buffer, but prints to the given string */
extern void buffer_to_string (const char * buffer, int count, char * desc,
                              int max, int print_eol, char * to, int tsize);

/* print an arbitrary socket address */
/* tcp should be 1 for TCP, 0 for UDP, -1 for neither */
extern void print_sockaddr (struct sockaddr * sap, int addr_size, int tcp);
extern int print_sockaddr_str (struct sockaddr * sap, int addr_size, int tcp,
                               char * string, int string_size);

/* print a message with the current time */
extern void print_timestamp (char * message);

/* return nbits if the first nbits of x match the first nbits of y, else 0 */
/* where nbits is the lesser of xbits and ybits */
extern int matches (unsigned char * x, int xbits, unsigned char * y, int ybits);

/* useful time functions and constants */
#define US_PER_S        1000000    /* microseconds in a second */
#define ONE_SECOND      US_PER_S
#define HALF_SECOND     (US_PER_S / 2)

extern unsigned long long delta_us (struct timeval * t1, struct timeval * t2);

extern void add_us (struct timeval * t, unsigned long long us);

/* set result to a random time between start + min and start + max */
extern void set_time_random (struct timeval * start, unsigned long long min,
                             unsigned long long max, struct timeval * result);

/* if malloc is not successful, exit after printing */
extern void * malloc_or_fail (int bytes, char * desc);
/* copy a string to new storage, using malloc_or_fail to get the memory */
extern char * strcpy_malloc (char * string, char * desc);
extern char * strcat_malloc (char * s1, char * s2, char * desc);
extern char * strcat3_malloc (char * s1, char * s2, char * s3, char * desc);
/* copy memory to new storage, using malloc_or_fail to get the memory */
extern void * memcpy_malloc (void * bytes, int bsize, char * desc);

/* fill this array with random bytes */
extern void random_bytes (char * buffer, int bsize);

/* place the values 0..n-1 at random within the given array */
extern void random_permute_array (int n, int * array);

/* malloc and return an n-element int array containing the values 0..n-1
 * in some random permuted order */
extern int * random_permute (int n);

#endif /* ALLNET_UTIL_H */
