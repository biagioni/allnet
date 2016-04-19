/* trace_util.h: utilities for apps */

#ifndef ALLNET_TRACE_UTIL_H
#define ALLNET_TRACE_UTIL_H

#include "allnet_log.h"

/* returns the output incrementally on fd_out */
extern void do_trace_loop (int sock, pd p, unsigned char * address, int abits,
                           int repeat, int sleep, int nhops, int match_only,
                           int no_intermediates, int wide, int fd_out,
                           struct allnet_log * alog);

/* returns a (malloc'd) string representation of the trace result */
extern char * trace_string (const char * tmp_dir, int sleep,
                            const char * dest, int nhops,
                            int no_intermediates, int match_only, int wide);

/* see if adht has an address, if so, use that */
extern void get_my_addr (unsigned char * my_addr, int my_addr_size,
                         struct allnet_log * alog);

/* print to stdout the summary line for a trace */
extern void trace_print_summary (int signal);

#endif /* ALLNET_TRACE_UTIL_H */
