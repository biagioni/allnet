/* configfiles.h: give access to config files */

#ifndef CONFIG_FILES_H
#define CONFIG_FILES_H

#include <time.h>

#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
#define HOME_ENV	"USERPROFILE"
#else
#define HOME_ENV	"HOME"
#endif

/* returns the number of characters in the full path name of the given dir */
/* (including the null character at the end) */
/* if name is not NULL, also malloc's the string and copies the path into it */
/* returns -1 if the allocation fails or there is some other problem */
/* if it allocates the name, also checks to make sure the directory exists,
 * and if not, creates it if possible. */
extern int config_dir_name (const char * program, char ** name,
                            int print_errors);

/* returns the number of characters in the full path name of the given file. */
/* (including the null character at the end) */
/* if name is not NULL, also malloc's the string and copies the path into it */
/* returns -1 if the allocation fails or for any other errors */
extern int config_file_name (const char * program, const char * file,
                             char ** name, int print_errors);

/* returns the (system) time of last modification of the config file, or 0
 * if the file does not exist */
extern time_t config_file_mod_time (const char * program, const char * file,
                                    int print_errors);

/* returns a file descriptor, or -1 in case of errors */
extern int open_read_config (const char * program, const char * file,
                             int print_errors);

/* returns a file descriptor, or -1 in case of errors */
extern int open_write_config (const char * program, const char * file,
                              int print_errors);

/* returns a file descriptor, or -1 in case of errors */
extern int open_rw_config (const char * program, const char * file,
                           int print_errors);

/* the next 3 calls simply call the corresponding call in util.h/c
 * with the name from config_file_name */
/* returns the file size, and if content_p is not NULL, allocates an
 * array to hold the file contents and assigns it to content_p.
 * one extra byte is allocated at the end and the content is null terminated.
 * in case of problems, returns -1, and prints the error if print_errors != 0 */
extern int read_config_file_malloc (const char * program, const char * file,
                                    char ** content_p, int print_errors);
/* return 1, except in case of error when they return 0 */
extern int write_config_file (const char * program, const char * file_name,
                              const char * content, int clen,
                              int print_errors);
extern int append_config_file (const char * program, const char * file_name,
                               const char * content, int clen,
                               int print_errors);

/* attempts to create the directory.  returns 1 for success, 0 for failure */
extern int create_dir (const char * path, int print_errors);

/* tell configfiles where the home directory is.  Should be called
 * before calling any other function */
extern void set_home_directory (const char * root);

#endif /* CONFIG_FILES_H */
