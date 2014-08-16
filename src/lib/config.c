/* config.c: give access to config files */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>

#define ROOT		"~/.allnet"
#define HOME_EXT	"/.allnet"

/* attempts to create the directory.  returns 1 for success, 0 for failure */
int create_dir (char * path)
{
  DIR * d = opendir (path);
  if (d != NULL) {  /* exists, done */
    closedir (d);
    return 1;
  }

  /* path does not exist, attempt to create it */
  if (mkdir (path, 0700) == 0) /* created */
    return 1;
  if (errno != ENOENT) { /* some other error, give up */
    perror ("1-mkdir");
    printf ("unable to create %s\n", path);
    return 0;
  }

  /* ENOENT: a previous component does not exist, attempt to create it */
  char * last_slash = rindex (path, '/');
  if (last_slash == NULL) /* nothing we can try to create, give up */
    return 0;
  *last_slash = '\0';
  /* now try to create the parent directory */
  if (create_dir (path)) {
    /* and try again to create this directory */
    *last_slash = '/';
    if (mkdir (path, 0700) == 0) {
      return 1;
    }
    perror ("mkdir");
  }
  return 0;
}

/* returns the number of characters in the full path name of the given file. */
/* (including the null character at the end) */
/* if name is not NULL, also malloc's the string and copies the path into it */
/* returns -1 if the allocation fails or there is some other problem */
/* if it allocates the name, also checks to make sure the directory exists,
 * and if not, creates it if possible.  Does not create the file. */
int config_file_name (char * program, char * file, char ** name)
{
  if (name != NULL)
    *name = NULL;  /* in case we return error, make sure it is initialized */
  char * root = ROOT;
  int free_root = 0;    /* in case root points to allocated memory */
  int root_length = strlen (ROOT);
  char * allnet_config_env = getenv ("ALLNET_CONFIG");
  if (allnet_config_env != NULL) {
    root = allnet_config_env;
    root_length = strlen (ROOT);
  } else {
    char * home_env = getenv ("HOME");
    if ((home_env == NULL) || (strcmp (home_env, "/nonexistent") == 0)) {
      static int printed = 0;
      if (! printed)
        printf ("no home environment (%s), running without configs\n",
                home_env);
      printed = 1;
      return -1;
    }
    /* printf ("no ALLNET_CONFIG, home is %s\n", home_env); */
    int size = strlen (home_env) + strlen (HOME_EXT) + 1;
    if (name != NULL) {
      char * home = malloc (size);
      if (home == NULL) {
        printf ("unable to allocate %d bytes for home\n", size);
        return -1;
      }
      snprintf (home, size, "%s%s", home_env, HOME_EXT);
      root = home;
      free_root = 1;
      root_length = strlen (root);
    } else {   /* do not allocate, just record the length */
      root_length = size;
    }
  }
  /* printf ("root is %s of length %d (free %d)\n",
          root, root_length, free_root); */

  int total_length = root_length + strlen ("/") + strlen (program)
                   + strlen ("/") + strlen (file) + 1;
  if (name == NULL) {
    if (free_root) free (root);
    return total_length;
  }
  * name = malloc (total_length);
  if (*name == NULL) {
    printf ("unable to allocate %d bytes for config_file_name\n", total_length);
    if (free_root) free (root);
    return -1;
  }
  /* check for the existence of the directory, or create it */
  snprintf (*name, total_length, "%s/%s", root, program);
  create_dir (*name);
  snprintf (*name, total_length, "%s/%s/%s", root, program, file);
  /* printf ("file path is %s\n", *name); */
  if (free_root) free (root);
  return total_length;
}

/* returns the (system) time of last modification of the config file, or 0
 * if the file does not exist */
time_t config_file_mod_time (char * program, char * file)
{
  char * name = NULL;
  int size = config_file_name (program, file, &name);
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

static int open_config (char * program, char * file, int flags,
                        int print_errors, char * caller)
{
  char * name;
  int size = config_file_name (program, file, &name);
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
int open_read_config (char * program, char * file, int print_errors)
{
  return open_config (program, file, O_RDONLY, print_errors,
                      "open_read_config");
}
/* returns a file descriptor, or -1 in case of errors */
int open_write_config (char * program, char * file, int print_errors)
{
  int flags = O_WRONLY | O_CREAT | O_TRUNC;
  return open_config (program, file, flags, print_errors, "open_write_config");
}

/* returns a file descriptor, or -1 in case of errors */
int open_rw_config (char * program, char * file, int print_errors)
{
  int flags = O_RDWR | O_CREAT;
  return open_config (program, file, flags, print_errors, "open_write_config");
}
