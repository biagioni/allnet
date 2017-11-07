/* util.h: useful functions used by different programs */

#ifndef ALLNET_UTIL_H
#define ALLNET_UTIL_H

#include <sys/time.h>
#include <sys/socket.h>

#include "allnet_log.h"

/* print up to max of the count characters in the buffer.
 * desc is printed first unless it is null
 * a newline is printed after if print_eol
 */
extern void print_buffer (const char * buffer, unsigned int count,
                          const char * desc,
                          unsigned int max, int print_eol);
/* same as print_buffer, but prints to the given string */
/* if all goes well, returns the number of characters printed */
extern int buffer_to_string (const char * buffer, unsigned int count,
                             const char * desc, unsigned int max, int print_eol,
                             char * to, size_t tsize);

extern void print_packet (const char * buffer, unsigned int count,
                          const char * desc, int print_eol);
/* same as print_buffer, but prints to the given string */
extern void packet_to_string (const char * buffer, unsigned int count,
                              const char * desc, int print_eol,
                              char * to, size_t tsize);

/* buffer must be at least ALLNET_SIZE(transport) bytes long
 * returns a pointer to the buffer, but cast to an allnet_header
 * returns NULL if any of the parameters are invalid (e.g. message_type)
 * if sbits is zero, source may be NULL, and likewise for dbits and dest
 * if stream is not NULL it must refer to STREAM_ID_SIZE bytes, and
 * transport will include ALLNET_TRANSPORT_STREAM
 * if ack is not NULL it must refer to MESSAGE_ID_SIZE bytes, and
 * transport will include ALLNET_TRANSPORT_ACK_REQ
 * if ack and stream are both NULL, transport will be set to 0
 *
 * ALLNET_TRANSPORT_LARGE packets are not supported by this call */
extern struct allnet_header *
  init_packet (char * packet, unsigned int psize, unsigned int message_type,
               unsigned int max_hops, unsigned int sig_algo,
               const unsigned char * source, unsigned int sbits,
               const unsigned char * dest, unsigned int dbits,
               const unsigned char * stream, const unsigned char * ack);

/* malloc's (must be free'd), initializes, and returns a packet with the
 * given data size.
 * If ack is not NULL, the data size parameter should NOT include the
 * MESSAGE_ID_SIZE bytes of the message ID
 * *size is set to the size to send
 * note that if sig_algo is ALLNET_SIGTYPE_RSA_PKCS1, data_size must
 * include 2 + the size of the signature, and for ALLNET_SIGTYPE_HMAC_SHA512
 * must include the size of the signature.  In other words, create_packet
 * does NOT add the signature size to data_size.
 */
extern struct allnet_header *
  create_packet (unsigned int data_size, unsigned int message_type,
                 unsigned int max_hops, unsigned int sig_algo,
                 const unsigned char * source, unsigned int sbits,
                 const unsigned char * dest, unsigned int dbits,
                 const unsigned char * stream, const unsigned char * ack,
                 unsigned int * size);

/* malloc, initialize, and return an ack message for a received packet.
 * The message_ack bytes are taken from the argument, not from the packet.*/
/* *size is set to the size to send */
/* if from is NULL, the source address is taken from packet->destination */
extern struct allnet_header *
  create_ack (struct allnet_header * packet, const unsigned char * ack,
              const unsigned char * from, unsigned int nbits,
              unsigned int * size);

/* print a string of bits as 1s and 0s, in groups of 4.  xoff is the
 * offset (in bits) within x, nbits the number of bits to print */
extern void print_bitstring (const unsigned char * x, int xoff, int nbits,
                             int print_eol);

/* print an arbitrary socket address */
/* tcp should be 1 for TCP, 0 for UDP, -1 for neither */
extern void print_sockaddr (const struct sockaddr * sap, socklen_t addr_size,
                            int tcp);
extern int print_sockaddr_str (const struct sockaddr * sap,
                               socklen_t addr_size, int tcp,
                               char * string, unsigned int string_size);

/* print a message with the current time */
extern void print_timestamp (const char * message);

/* it is a good idea to understand the difference between the next three
 * functions, and use the correct one.
 * - matches MUST match n = min(xbits, ybits), and otherwise returns 0
 * - bitstring_matches is the same, except n=nbits, and bit offset are allowed
 * - matching_bits returns the number of bits that do match, up to n bits
 */

/* return nbits if the first nbits of x match the first nbits of y, else 0 */
/* where nbits is the lesser of xbits and ybits */
extern int matches (const unsigned char * x, int xbits,
                    const unsigned char * y, int ybits);

/* return 1 if the first nbits of x after xoff bits match
 * the first nbits of y after yoff bits, else 0 */
extern int bitstring_matches (const unsigned char * x, int xoff,
                              const unsigned char * y, int yoff, int nbits);

/* returns the number of matching bits starting from the front of the
 * bitstrings, not to exceed xbits or ybits.  Returns 0 for no match */
extern int matching_bits (const unsigned char * x, int xbits,
                          const unsigned char * y, int ybits);

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
extern unsigned long long delta_us (const struct timeval * t1,
                                    const struct timeval * t2);

extern void add_us (struct timeval * t, unsigned long long us);

/* returns 1 if now is before the given time, and 0 otherwise */
extern int is_before (struct timeval * t);

/* computes the next time that is a multiple of granularity.  If immediate_ok,
 * returns 0 if the current time is already a multiple of granularity */
extern time_t compute_next (time_t from, time_t granularity, int immediate_ok);

/* set result to a random time between start + min and start + max */
/* it's ok for start and result to refer to the same struct */
extern void set_time_random (const struct timeval * start,
                             unsigned long long min,
                             unsigned long long max, struct timeval * result);
/* sleep between 0 and us microseconds */
extern void sleep_time_random_us (unsigned long long us);

/* return 1 and update num_true_calls and last_true_time if one or more of:
 * the time since the last call is greater than max (or max is 0)
 * the time since the last call is greater than min * 2^num_true_calls
 * otherwise return 0 and num_true_calls and last_true_time are unchanged
 * all times are in microseconds */
extern int time_exp_interval (unsigned long long int * last_true_time,
                              unsigned long long int * num_true_calls,
                              unsigned long long int min,
                              unsigned long long int max);

/* if malloc is not successful, exit after printing */
extern void * malloc_or_fail (size_t bytes, const char * desc);
/* copy a string to new storage, using malloc_or_fail to get the memory */
extern char * strcpy_malloc (const char * string, const char * desc);
extern char * strcat_malloc (const char * s1, const char * s2,
                             const char * desc);
extern char * strcat3_malloc (const char * s1, const char * s2,
                              const char * s3, const char * desc);
/* returns the new string with the first occurrence of pattern replaced
 * by repl.
 * If the pattern is not found in the original, the new string is a copy
 * of the old, and optionally an error message is printed
 * result is malloc'd, must be free'd (unless the original was NULL) */
extern char * string_replace_once (const char * original, const char * pattern,
                                   const char * repl, int print_not_found);
/* copy memory to new storage, using malloc_or_fail to get the memory */
extern void * memcpy_malloc (const void * bytes, size_t bsize,
                             const char * desc);
/* copy two buffers to new storage, using malloc_or_fail to get the memory */
extern void * memcat_malloc (const void * bytes1, size_t bsize1,
                             const void * bytes2, size_t bsize2,
                             const char * desc);

/* returns the file size, and if content_p is not NULL, allocates an
 * array to hold the file contents and assigns it to content_p.
 * one extra byte is allocated at the end and the content is null terminated.
 * in case of problems, returns -1, and prints the error if print_errors != 0 */
extern int read_file_malloc (const char * file_name, char ** content_p,
                             int print_errors);
/* same, but fd must have been opened, and is closed if close_fd is nonzero */
/* the optional file name is used for printing errors, may be NULL */
extern int read_fd_malloc (int fd, char ** content_p,
                           int print_errors, int close_fd, const char * fname);
/* return 1, except in case of error when they return 0 */
extern int write_file (const char * file_name, const char * content, int clen,
                       int print_errors);
extern int append_file (const char * file_name, const char * content, int clen,
                        int print_errors);
/* return -1 in case of errors, usually if the file doesn't exist */
extern long long int file_size (const char * file_name);
extern long long int fd_size (int fd);
/* return 1 if successful, 0 in case of errors, e.g. if the dir doesn't exist */
extern int rmdir_and_all_files (const char * dirname);
/* return the number of deleted files, -1 in case of errors */
/* pattern is a literal. The file is rm'd if part of the file name matches it */
extern int rmdir_matching (const char * dirname, const char * pattern);

/* fill this array with random bytes */
extern void random_bytes (char * buffer, size_t bsize);

/* a random int between min and max (inclusive) */
/* returns min if min >= max */
extern unsigned long long int random_int (unsigned long long int min, 
                                          unsigned long long int max);

/* fill this array with random alpha characters.  The last byte is set to \0 */
extern void random_string (char * buffer, size_t bsize);

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

/* the same functions on arrays of unsigned characters */
extern unsigned int readb16u (const unsigned char * p);
extern unsigned long int readb32u (const unsigned char * p);
extern unsigned long long int readb48u (const unsigned char * p);
extern unsigned long long int readb64u (const unsigned char * p);
extern void writeb16u (unsigned char * p, unsigned int value);
extern void writeb32u (unsigned char * p, unsigned long int value);
extern void writeb48u (unsigned char * p, unsigned long long int value);
extern void writeb64u (unsigned char * p, unsigned long long int value);

/* essentially the same as htons, but sometimes easier to find */
extern int allnet_htons (int hostshort);

/* returns 1 if the message is valid, 0 otherwise.
 * If returns zero and error_desc is not NULL, it is filled with
 * a description of the error -- do not modify in any way. */
extern int is_valid_message (const char * packet, unsigned int size,
                             char ** error_desc);

extern void print_gethostbyname_error (const char * hostname,
                                       struct allnet_log * log);

/* assuming option_letter is 'v', returns 1 if argv has '-v', 0 otherwise
 * if it returns 1, removes the -v from the argv, and decrements *argcp.
 */
extern int get_option (char option_letter, int * argcp, char ** argv);

/* set user_callable to 1 for astart and allnetx, to 0 for all others */
extern void print_usage (int argc, char ** argv, int user_callable,
                         int do_exit);
/* returns (from - subtract) if from >= subtract, otherwise returns 0 */
extern int minz (int from, int subtract);

/* returns the number of bits needed to represent the number in binary,
 * and 0 for 0 */
/* e.g. returns
   0 for 0
   1 for 1
   2 for 2 or 3
   3 for 4-7
   4 for 8-15
   etc
 */
extern int binary_log (unsigned long long int value);

/* 2017/09/20: android seems to support fork, so only use threads for iOS */
#if defined(__IPHONE_OS_VERSION_MIN_REQUIRED) || defined(ANDROID)
#include <pthread.h>
/* in case of error on iOS, don't kill the process, only the thread (since
 * in iOS, we only have one process */
#define exit(n)        pthread_exit(NULL)
#define ALLNET_USE_THREADS
#else  /* ! __IPHONE_OS_VERSION_MIN_REQUIRED || ANDROID */
/* we use fork except on systems that don't support it */
#define ALLNET_USE_FORK
#endif /* __IPHONE_OS_VERSION_MIN_REQUIRED */

/* defined in pipemsg.c, but used in files that don't #include pipemsg.h */
extern void pipemsg_debug_last_received (const char * message);

#endif /* ALLNET_UTIL_H */
