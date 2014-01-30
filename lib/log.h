/* log.h: log allnet interactions for easier debugging */

#ifndef ALLNET_LOG_H
#define ALLNET_LOG_H

/* call at the very beginning of "main" with the module name */
extern void init_log (char * module_name);

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

#endif /* ALLNET_LOG_H */
