/* config.h: give access to config files */

#ifndef CONFIG_H
#define CONFIG_H

#include <time.h>

/* returns the number of characters in the full path name of the given file. */
/* (including the null character at the end) */
/* if name is not NULL, also malloc's the string and copies the path into it */
/* returns -1 if the allocation fails or for any other errors */
extern int config_file_name (char * program, char * file, char ** name);

/* returns the (system) time of last modification of the config file, or 0
 * if the file does not exist */
extern time_t config_file_mod_time (char * program, char * file);

/* returns a file descriptor, or -1 in case of errors */
extern int open_read_config (char * program, char * file, int print_errors);

/* returns a file descriptor, or -1 in case of errors */
extern int open_write_config (char * program, char * file, int print_errors);

/* returns a file descriptor, or -1 in case of errors */
extern int open_rw_config (char * program, char * file, int print_errors);

/* attempts to create the directory.  returns 1 for success, 0 for failure */
extern int create_dir (char * path);

#endif /* CONFIG_H */
