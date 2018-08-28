/* trace_util.h: utilities for apps */

#ifndef ALLNET_TRACE_UTIL_H
#define ALLNET_TRACE_UTIL_H

#include "allnet_log.h"
#include "mgmt.h"
#include "pcache.h"   /* struct pcache_result */

/* see if adht has an address, if so, use that */
extern void get_my_addr (unsigned char * my_addr, int my_addr_size,
                         struct allnet_log * alog);

/* assuming that message is a valid trace request, fills in "req" and "reqsize"
 * with the trace request to forward, and reply to send back
 * req is NULL and req_size is 0 if the request should not be forwarded
 * req is NULL and req_size is > 0 if the original request should be forwarded
 * reply is NULL and *reply_size is 0 if there is no reply */
extern void trace_forward (char * message, int msize,
                           unsigned char * my_address, unsigned int abits,
                           char ** req, int * req_size, /* out: forward */
                           char ** reply, int * reply_size); /* out: reply */

/* print to stdout the summary line for a trace */
extern void trace_print_summary (int signal);

/* returns the output incrementally on fd_out */
/* 0, 1, or multiple addresses may be specified in a single array
 * of size naddrs * ADDRESS_SIZE.  likewise, abits has naddrs int's */
extern void do_trace_loop (int sock,
                           int naddrs, unsigned char * addresses, int * abits,
                           int repeat, int sleep, int nhops, int match_only,
                           int no_intermediates, int wide, int null_term,
                           int fd_out, int reset_counts,
                           struct allnet_log * alog);

/* returns a (malloc'd) string representation of the trace result */
extern char * trace_string (const char * tmp_dir, int sleep,
                            const char * dest, int nhops,
                            int no_intermediates, int match_only, int wide);

/* just start a trace, returning 1 for success, 0 failure
 * trace_id must have MESSAGE_ID_SIZE or be NULL */
extern int start_trace (int sock,
                        const unsigned char * addr, unsigned int nbits,
                        unsigned int nhops, int record_intermediates,
                        char * trace_id);

/* convert to a string (of size slen) the result of a trace,
 * eliminating duplicates of past received traces */
extern void trace_to_string (char * string, size_t slen,
                             struct allnet_mgmt_trace_reply * trace,
                             int trace_count,
                             unsigned long long int trace_start_time);

#endif /* ALLNET_TRACE_UTIL_H */
