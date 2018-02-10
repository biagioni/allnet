/* trace_util.h: utilities for apps */

#ifndef ALLNET_TRACE_UTIL_H
#define ALLNET_TRACE_UTIL_H

#include "allnet_log.h"
#include "allnet_queue.h"

/* returns the output incrementally on fd_out */
/* 0, 1, or multiple addresses may be specified in a single array
 * of size naddrs * ADDRESS_SIZE.  likewise, abits has naddrs int's */
extern void do_trace_loop (int sock, pd p,
                           int naddrs, unsigned char * addresses, int * abits,
                           int repeat, int sleep, int nhops, int match_only,
                           int no_intermediates, int wide, int null_term,
                           int fd_out, int reset_counts,
                           struct allnet_queue * queue,
                           struct allnet_log * alog);

/* returns a (malloc'd) string representation of the trace result */
extern char * trace_string (const char * tmp_dir, int sleep,
                            const char * dest, int nhops,
                            int no_intermediates, int match_only, int wide);

/* either queue is not null, or pipe is a valid file descriptor */
void trace_pipe (int pipe, struct allnet_queue * queue,
                 int sleep, const char * dest, int nhops, int no_intermediates,
                 int match_only, int wide);

/* see if adht has an address, if so, use that */
extern void get_my_addr (unsigned char * my_addr, int my_addr_size,
                         struct allnet_log * alog);

/* print to stdout the summary line for a trace */
extern void trace_print_summary (int signal);

/* just start a trace, returning 1 for success, 0 failure
 * trace_id must have MESSAGE_ID_SIZE or be NULL */
extern int start_trace (int sock,
                        const unsigned char * addr, unsigned int nbits,
                        unsigned int nhops, int record_intermediates,
                        char * trace_id);

#endif /* ALLNET_TRACE_UTIL_H */
