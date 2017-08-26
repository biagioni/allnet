/* log.h: log allnet interactions for easier debugging */

#ifndef ALLNET_LOG_H
#define ALLNET_LOG_H

#include <stdlib.h>    /* PATH_MAX */

#define LOG_SIZE    1024

#ifndef PATH_MAX        /* just define it */
#define PATH_MAX        4096
#endif /* PATH_MAX */

/* given struct allnet_log * log, typically:
 *      snprintf (log->b, log->s, ...); log_print (log); */
struct allnet_log {
    char * debug_info;  /* name from init_log, do not modify!! */
    char b [LOG_SIZE];  /* buffer */
    unsigned int s;     /* buffer length -- always LOG_SIZE, do not modify! */
    int log_to_output;   /* default 0, set as desired */
};

/* call at the very beginning of "main" with the module name */
extern struct allnet_log * init_log (const char * module_name);
/* call at the very end of a thread or a process, if possible */
extern void close_log (struct allnet_log * log);

extern void log_print (struct allnet_log * log); /* log whatever is in b */
extern void log_print_str (struct allnet_log * log,
                           char * string);  /* log string and b */

/* log desc followed by a description of the packet (packet type, ID, etc) */
extern void log_packet (struct allnet_log * log,
                        char * desc, char * packet, int plen);

/* log the error number for the given system call, followed by whatever
   is in the buffer */
extern void log_error (struct allnet_log * log, char * syscall);

/* output everything to stdout as well as the log file if on != 0.
 * if on == 0, only output to the log file unless log->log_to_output is 1 */
extern void log_to_output (int on);

#endif /* ALLNET_LOG_H */
