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
/* if all goes well, returns the number of characters printed */
extern int buffer_to_string (const char * buffer, int count, char * desc,
                             int max, int print_eol, char * to, int tsize);

extern void print_packet (const char * buffer, int count, char * desc,
                          int print_eol);
/* same as print_buffer, but prints to the given string */
extern void packet_to_string (const char * buffer, int count, char * desc,
                              int print_eol, char * to, int tsize);

/* buffer must be at least ALLNET_SIZE(transport) bytes long */
/* returns a pointer to the buffer, but cast to an allnet_header */
/* returns NULL if any of the parameters are invalid (e.g. message_type) */
/* if sbits is zero, source may be NULL, and likewise for dbits and dest */
/* if ack is not NULL it must refer to MESSAGE_ID_SIZE bytes, and */
/* transport will be set to ALLNET_TRANSPORT_ACK_REQ */
/* if ack is NULL, transport will be set to 0 */
extern struct allnet_header *
  init_packet (char * packet, int psize,
               int message_type, int max_hops, int sig_algo,
               char * source, int sbits, char * dest, int dbits, char * ack);

/* malloc's (must be free'd), initializes, and returns a packet with the
/* given data size. */
/* If ack is not NULL, the data size parameter should NOT include the */
/* MESSAGE_ID_SIZE bytes of the ack. */
/* *size is set to the size to send */
extern struct allnet_header *
  create_packet (int data_size, int message_type, int max_hops, int sig_algo,
                 char * source, int sbits, char * dest, int dbits, char * ack,
                 int * size);

/* malloc, initialize, and return an ack message for a received packet.
 * The message_ack bytes are taken from the argument, not from the packet.*/
/* *size is set to the size to send */
extern struct allnet_header *
  create_ack (struct allnet_header * packet, char * ack, int * size);

/* print a string of bits as 1s and 0s, in groups of 4.  xoff is the
 * offset (in bits) within x, nbits the number of bits to print */
extern char * print_bitstring (unsigned char * x, int xoff, int nbits,
                               int print_eol);

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

/* return 1 if the first nbits of x after xoff bits match
 * the first nbits of y after yoff bits, else 0 */
extern int bitstring_matches (unsigned char * x, int xoff,
                              unsigned char * y, int yoff, int nbits);

/* AllNet time begins January 1st, 2000.  This may be different from
 * the time bases (epochs) on other systems, including specifically
 * Unix (Jan 1st, 1970) and Windows (Jan 1st, 1980).  I believe somebody
 * also has an epoch of Jan 1st, 1900.  Anyway, these functions return
 * the current AllNet time.  The usual caveats apply about OS time accuracy.
 * The 64-bit value returned will be good for 584,000 years worth of
 * microseconds.
 */
extern unsigned long long int allnet_time ();     /* seconds since Y2K */
extern unsigned long long int allnet_time_ms ();  /* milliseconds since Y2K */
extern unsigned long long int allnet_time_us ();  /* microseconds since Y2K */

/* returns the result of calling ctime_r on the given allnet time. */
/* the result buffer must be at least 30 bytes long */
#define ALLNET_TIME_STRING_SIZE		30
extern void allnet_time_string (unsigned long long int allnet_seconds,
                                char * result);
extern void allnet_localtime_string (unsigned long long int allnet_seconds,
                                     char * result);

/* useful time functions and constants */
#define ALLNET_US_PER_S           1000000    /* microseconds in a second */
#define ALLNET_US_PER_MS          1000       /* microseconds in a millisecond */
#define ALLNET_ONE_SECOND_IN_US   ALLNET_US_PER_S
#define ALLNET_HALF_SECOND_IN_US  (ALLNET_US_PER_S / 2)

/* if t1 < t2, returns 0, otherwise returns t1 - t2 */
extern unsigned long long delta_us (struct timeval * t1, struct timeval * t2);

extern void add_us (struct timeval * t, unsigned long long us);

/* returns 1 if now is before the given time, and 0 otherwise */
extern int is_before (struct timeval * t);

/* computes the next time that is a multiple of granularity.  If immediate_ok,
 * returns 0 if the current time is already a multiple of granularity */
extern time_t compute_next (time_t from, time_t granularity, int immediate_ok);

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

/* returns the file size, and if content_p is not NULL, allocates an
 * array to hold the file contents and assigns it to content_p.
 * in case of problems, returns 0, and prints the error if print_errors != 0 */
extern int read_file_malloc (char * file_name, char ** content_p,
                             int print_errors);

/* fill this array with random bytes */
extern void random_bytes (char * buffer, int bsize);

/* place the values 0..n-1 at random within the given array */
extern void random_permute_array (int n, int * array);

/* malloc and return an n-element int array containing the values 0..n-1
 * in some random permuted order */
extern int * random_permute (int n);

/* read a big-endian n-bit number into an unsigned int */
/* if the pointer is NULL, returns 0 */
extern unsigned int readb16 (const char * p);
extern unsigned long int readb32 (const char * p);
extern unsigned long long int readb48 (const char * p);
extern unsigned long long int readb64 (const char * p);

/* write an n-bit number in big-endian order into an array.  If the pointer
 * is NULL, does nothing */
extern void writeb16 (char * p, unsigned int value);
extern void writeb32 (char * p, unsigned long int value);
extern void writeb48 (char * p, unsigned long long int value);
extern void writeb64 (char * p, unsigned long long int value);

/* returns 1 if the message is valid, 0 otherwise */
extern int is_valid_message (const char * packet, int size);

#endif /* ALLNET_UTIL_H */
