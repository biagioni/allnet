/* configfiles.h: give access to config files */

#ifndef CONFIG_FILES_H
#define CONFIG_FILES_H

#include <time.h>

#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
#define HOME_ENV	"USERPROFILE"
#else
#define HOME_ENV	"HOME"
#endif


/* returns the number of characters in the full path name of the given file. */
/* (including the null character at the end) */
/* if name is not NULL, also malloc's the string and copies the path into it */
/* returns -1 if the allocation fails or for any other errors */
extern int config_file_name (const char * program, const char * file,
                             char ** name);

/* returns the (system) time of last modification of the config file, or 0
 * if the file does not exist */
extern time_t config_file_mod_time (const char * program, const char * file);

/* returns a file descriptor, or -1 in case of errors */
extern int open_read_config (const char * program, const char * file,
                             int print_errors);

/* returns a file descriptor, or -1 in case of errors */
extern int open_write_config (const char * program, const char * file,
                              int print_errors);

/* returns a file descriptor, or -1 in case of errors */
extern int open_rw_config (const char * program, const char * file,
                           int print_errors);

/* attempts to create the directory.  returns 1 for success, 0 for failure */
extern int create_dir (const char * path);

/* tell configfiles where the home directory is.  Should be called
 * before calling any other function */
extern void set_home_directory (const char * root);

#endif /* CONFIG_FILES_H */
