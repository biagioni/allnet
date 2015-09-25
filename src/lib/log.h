/* log.h: log allnet interactions for easier debugging */

#ifndef ALLNET_LOG_H
#define ALLNET_LOG_H

/* call at the very beginning of "main" with the module name */
extern void init_log (char * module_name);
/* call at the very end of a thread or a process, if possible */
/* argument is ignored, used to make usable with pthread_cleanup_push */
extern void close_log (void * ignored);

/* to use:     snprintf (log_buffer, LOG_SIZE, "...", ...);
   then        log_print ();    */
#define LOG_SIZE	1000
extern char log_buf [LOG_SIZE];

extern void log_print ();                   /* log whatever is in log_buf */
extern void log_print_str (char * string);  /* log whatever is in string */

/* log desc followed by a description of the packet (packet type, ID, etc) */
extern void log_packet (char * desc, char * packet, int plen);

/* log the error number for the given system call, followed by whatever
   is in the buffer */
extern void log_error (char * syscall);

/* output everything to stdout as well as the log file if on != 0.
 * if on == 0, only output to the log file. */
extern void log_to_output (int on);

#endif /* ALLNET_LOG_H */
