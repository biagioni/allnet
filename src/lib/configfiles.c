/* configfiles.c: give access to config files */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "allnet_log.h"
#include "configfiles.h"
#include "util.h"

#define ROOT		"~/.allnet"
#define HOME_EXT	"/.allnet"
/* check to see if IOS_ROOT exists, if so, use that. */
#define IOS_ROOT	"Library/Application Support/allnet/"
/* and if it does, maybe save xchat files in Documents/allnet */
/* and log files in Library/Caches/" */
/* except chat files are done in xchat/store.c... */

static char * global_home_directory = NULL;

/* attempts to create the directory.  returns 1 for success, 0 for failure */
int create_dir (const char * path, int print_errors)
{
  DIR * d = opendir (path);
  if (d != NULL) {  /* exists, done */
    closedir (d);
    return 1;
  }
  if (errno != ENOENT) {
    int saved_errno = errno;
    if (print_errors) {
      perror ("opendir in create_dir");
      printf ("unable to open %s, error %d\n", path, saved_errno);
    }
    return 0;
  }
  /* path does not exist, attempt to create it */
  if (mkdir (path, 0700) == 0) /* created */
    return 1;
  if (errno != ENOENT) { /* some other error, give up */
    int saved_errno = errno;
    if (print_errors) {
      perror ("1-mkdir");
      printf ("unable to create %s, error %d\n", path, saved_errno);
    }
    return 0;
  }

  /* ENOENT: a previous component does not exist, attempt to create it */
  char * last_slash = strrchr (path, '/');
  if (last_slash == NULL) /* nothing we can try to create, give up */
    return 0;
  *last_slash = '\0';
  /* now try to create the parent directory */
  if (create_dir (path, print_errors)) {
    /* and try again to create this directory */
    *last_slash = '/';
    if (mkdir (path, 0700) == 0) {
      return 1;
    }
    if (print_errors)
      perror ("mkdir");
  }
  return 0;
}

static char * global_root = NULL;
static void init_global_root ()
{
  static int initialized = 0;
  if ((initialized) && (global_root != NULL))
    return;
  initialized = 1;
  char * allnet_config_env = getenv ("ALLNET_CONFIG");
  char * home_env = getenv (HOME_ENV);
  global_root = NULL;
  int has_ios_home = 0;
  DIR * d = opendir (IOS_ROOT);
  if (d != NULL) {  /* exists */
    closedir (d);
    has_ios_home = 1;
  }
  if (global_home_directory != NULL) {  /* use global_home_directory */
    global_root = strcpy_malloc (global_home_directory,
                                 "config_file_name global home directory");
  } else if (allnet_config_env != NULL) {
    global_root = allnet_config_env;
  } else if (has_ios_home) {
    global_root = IOS_ROOT;
  } else if ((home_env != NULL) && (strcmp (home_env, "/nonexistent") != 0)) {
    global_root = strcat_malloc (home_env, HOME_EXT,
                                 "config_file_name home directory");
  } else {  /* use ROOT -- probably equal to home_env + "/.allnet" */
    global_root = ROOT;
  }
/* printf ("root is %s of length %d\n", global_root, (int) strlen (global_root)); */
}

/* returns the number of characters in the full path name of the given file. */
/* (including the null character at the end) */
/* if name is not NULL, also malloc's the string and copies the path into it */
/* returns -1 if the allocation fails or there is some other problem */
/* if it allocates the name, also checks to make sure the directory exists,
 * and if not, creates it if possible.  Does not create the file. */
int config_file_name (const char * program, const char * file, char ** name,
                      int print_errors)
{
  if (name != NULL)
    *name = NULL;  /* in case we return error, make sure it is initialized */
  init_global_root ();
  if (global_root == NULL)
    return -1;  /* no config files */
  int total_length = (int)(strlen (global_root) + strlen ("/") +
                           strlen (program) + strlen ("/") + strlen (file) + 1);
  if (name == NULL)   /* finished */
    return total_length;
  *name = malloc (total_length);
  if (*name == NULL) {
    printf ("unable to allocate %d bytes for config_file_name\n", total_length);
    return -1;
  }
  /* check for the existence of the directory, or create it */
  snprintf (*name, total_length, "%s/%s", global_root, program);
  create_dir (*name, print_errors);
  snprintf (*name, total_length, "%s/%s/%s", global_root, program, file);
/* printf ("file path for %s %s is %s\n", program, file, *name); */
  return total_length;
}

/* returns the (system) time of last modification of the config file, or 0
 * if the file does not exist */
time_t config_file_mod_time (const char * program, const char * file,
                             int print_errors)
{
  char * name = NULL;
  int size = config_file_name (program, file, &name, print_errors);
  if (size < 0) {
    if (name != NULL)
      free (name);
    return 0;
  }
  struct stat st;
  int result = stat (name, &st);
  if (name != NULL)
    free (name);
  if (result < 0)
    return 0;
  return st.st_mtime;
}

static int open_config (const char * program, const char * file, int flags,
                        int print_errors, char * caller)
{
  char * name;
  int size = config_file_name (program, file, &name, print_errors);
  if (size < 0)
    return -1;
  int result = open (name, flags, 0600);
  if (result < 0) {
    if ((print_errors) &&
        (errno != ENOENT)) {   /* ENOENT is file not found, do not print */
      perror ("open_config open");
      printf ("%s unable to open file %s, flags %x\n", caller, name, flags);
    }
    result = -1;
  }
  free (name);
  return result;
}

/* returns a file descriptor, -1 if the file does not exist,
 * or -2 in case of errors */
int open_read_config (const char * program, const char * file,
                      int print_errors)
{
  return open_config (program, file, O_RDONLY, print_errors,
                      "open_read_config");
}
/* returns a file descriptor, or -1 in case of errors */
int open_write_config (const char * program, const char * file,
                       int print_errors)
{
  int flags = O_WRONLY | O_CREAT | O_TRUNC;
  return open_config (program, file, flags, print_errors, "open_write_config");
}

/* returns a file descriptor, or -1 in case of errors */
int open_rw_config (const char * program, const char * file, int print_errors)
{
  int flags = O_RDWR | O_CREAT;
  return open_config (program, file, flags, print_errors, "open_write_config");
}

/* tell configfiles where the home directory is.  Should be called
 * before calling any other function */
void set_home_directory (const char * root)
{
printf ("setting global home directory to %s\n", root);
  if (global_home_directory != NULL)
    free (global_home_directory);
  global_home_directory = strcpy_malloc (root, "set_home_directory");
}

