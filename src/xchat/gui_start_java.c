/* gui_start_java.c: start the java process */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <dirent.h>
#include <signal.h>
#include <sys/types.h>

#include "lib/util.h"

#ifdef DEBUG_PRINT
#define DEBUG_EXEC_JAVA
#endif /* DEBUG_PRINT */

static void find_path (const char * arg, char ** path)
{
  if (strrchr (arg, '/') == NULL) {
    *path = strcpy_malloc (".", "gui_start_java.c find_path 0");
  } else {
    *path = strcpy_malloc (arg, "gui_start_java.c find_path");
    char * slash = strrchr (*path, '/');
    if (slash != NULL)
      *slash = '\0';
  }
}

/* windows Java is often in a directory named
     "C:\\Program Files\\Java\\jdk*\\bin\\java" */
static char * find_program_files_java ()
{
#define PREFIX "\\Program Files\\Java"
  char * result = "";  /* if nothing found, return this */
  DIR * dir = opendir (PREFIX);
  if (dir != NULL) {
    struct dirent * ent = NULL;
    while ((ent = readdir (dir)) != NULL) {  /* for each dir/file in PREFIX */
      if (strstr (ent->d_name, "jdk") != NULL) {  /* if it contains "jdk" */
        /* copy the name (with strcat3_malloc) since the next call
           to readdir will overwrite it with something else */
        char * candidate = strcat3_malloc (PREFIX "\\", ent->d_name, "\\bin",
                                           "find_program_files_java");
        /* make sure PREFIX\jdk-whatever\bin has an executable java program */
        char * java = strcat_malloc (candidate, "\\java",
                                     "find_program_files: java");
        if ((access (java, X_OK) == 0) &&
            ((strlen (result) == 0) ||             /* first one */
             (strcmp (candidate, result) > 0))) {  /* not first, use latest */
          if (strlen (result) != 0)                /* was malloc'd */
            free (result);
          result = candidate;
        } else {
          free (candidate);
        }
        free (java);
      }
    }
    closedir (dir);
  }
  return result;
#undef PREFIX
}

static char * find_java_path ()
{
  static char * result = NULL;
  if (result != NULL)   /* found it before */
    return result;
  char * path_env = getenv ("PATH");
  if (path_env == NULL)
    return result;
  char * path = strcpy_malloc (getenv ("PATH"), "find_java_path");
/* windows Java is often in a directory named
     "C:\\Program Files\\Java\\jdk*\\bin\\java"
   If found, add the latest of these at the end of the path */
  char * extra = find_program_files_java ();
  if (strlen (extra) > 0) {
    char * new_path = strcat3_malloc (path, ":", extra, "find_java_path extra");
    free (path);
    free (extra);
    path = new_path;
  }
  char * free_path = path;   /* for calls to free, free the original */
  char * colon = strchr (path, ':');
  do {   /* look at each part of the path */
    char * next = NULL;
    if (colon != NULL) {
      next = colon + 1;
      *colon = '\0';  /* terminate the path at the first colon */
    }
    char * entry = path;
    char * test = strcat_malloc (entry, "/java", "find_java_path 2");
/* printf ("looking for java in %s\n", test); */
    if (access (test, X_OK) == 0) {
      free (free_path);
      return test;   /* found! */
    }

/* windows compiled under cygwin has a path of the form "/cygdrive/c/..."  
   We rewrite it to "C:\...", replacing all / with \ */
#define CYGDRIVE_STR	"/cygdrive/"
#define CYGDRIVE_LEN	(strlen (CYGDRIVE_STR))
    if (strncmp (test, CYGDRIVE_STR, CYGDRIVE_LEN) == 0) {
      char drive [] = "C:";  /* usually the C drive, but you never know */
      /* use whatever letter follows /cygdrive/, not necessarily C */
      drive [0] = toupper (test [CYGDRIVE_LEN]);
      char * test2 =
        strcat_malloc (drive, test + CYGDRIVE_LEN + 1, "find_java_path 3");
      free (test);
      test = test2;
      char * cp = test;
      while (*cp != '\0') {
        if (*cp == '/')
          *cp = '\\';
        cp++;
      }
/* printf ("looking for java in %s\n", test); */
      if (access (test, X_OK) == 0) {
        free (free_path);
        return test;   /* found! */
      }
    }
    path = next;
    if (path != NULL)
      colon = strchr (path, ':');
  } while (path != NULL);
  return NULL;
}

static char * find_java ()
{
  char * path = find_java_path ();
  if (path != NULL)
    return path;
  char * candidates [] = { "/usr/bin/java", "C:\\winnt\\system32\\java",
                           "C:\\windows\\system\\java",
                           "C:\\windows\\system32\\java" };
  unsigned int i;
  for (i = 0; i < sizeof (candidates) / sizeof (char *); i++) {
    /* printf ("trying %s\n", candidates [i]); */
    if (access (candidates [i], X_OK) == 0)
      return candidates [i];
  }
  printf ("no java runtime found, unable to run xchat\n");
  return NULL;
}

/* #define HIDE_JAVA_OUTPUT */
#ifdef HIDE_JAVA_OUTPUT
#define LOG_FILE_NAME	"xchat-java-log.txt"
#define TMP_DIR_INITIALIZER	"/tmp"
static char * tmp_dir = TMP_DIR_INITIALIZER;
#endif /* HIDE_JAVA_OUTPUT */

static pid_t exec_java_ui (const char * arg)
{
#define JAR_FILE_NAME	"AllNetUI.jar"
  char * path = NULL;
#ifdef DEBUG_EXEC_JAVA
  printf ("exec_java_ui: arg is %s\n", arg);
#endif /* DEBUG_EXEC_JAVA */
  find_path (arg, &path);
#ifdef DEBUG_EXEC_JAVA
  printf ("exec_java_ui: path is %s\n", path);
#endif /* DEBUG_EXEC_JAVA */
  char * jarfile = strcat3_malloc (path, "/", JAR_FILE_NAME, "exec_java_ui 1");
#ifdef DEBUG_EXEC_JAVA
  printf ("exec_java_ui: jarfile is %s\n", jarfile);
#endif /* DEBUG_EXEC_JAVA */
  if (access (jarfile, R_OK) != 0) {
    int plen = strlen (path);
    if ((plen > 1) && (path [plen - 1] == '/'))
      path [--plen] = '\0';   /* eliminate any trailing slash */
    if ((plen > 6) && (strcmp (path + plen - 6, "/.libs") == 0)) {
      /* try without .libs */
      path [plen - 6] = '\0';
#ifdef DEBUG_EXEC_JAVA
      printf ("exec_java_ui: new path is %s\n", path);
#endif /* DEBUG_EXEC_JAVA */
      jarfile = strcat3_malloc (path, "/", JAR_FILE_NAME, "exec_java_ui 2");
#ifdef DEBUG_EXEC_JAVA
      printf ("exec_java_ui: new jarfile is %s\n", jarfile);
#endif /* DEBUG_EXEC_JAVA */
    }
  }
  if (access (jarfile, R_OK) != 0) {
    perror ("access");
    printf ("unable to start Java gui %s\n", jarfile);
    return -1;
  }
  pid_t pid = fork ();
  if (pid < 0) {
    perror ("fork");
    return pid;
  }
  if (pid == 0) {   /* child process */
    char * args [5];
    args [0] = find_java ();
    /* if jarfile name is absolute, go to that directory and use a relative
     * name instead.  This is because on windows, this code executes as a
     * cygwin process, whereas the java executes as a windows process, and
     * the file tree is different for the two, but relative paths work */
    if ((jarfile [0] == '/') || (jarfile [0] == '\\')) {
      if (chdir (path) == 0)
        jarfile = JAR_FILE_NAME;  /* cd successful, so use just the name */
    }
#ifdef DEBUG_EXEC_JAVA
    char debug [PATH_MAX + 1];
    getcwd (debug, sizeof (debug));
    printf ("exec_java_ui: final jarfile is %s, current dir %s\n",
            jarfile, debug);
#endif /* DEBUG_EXEC_JAVA */

#ifdef HIDE_JAVA_OUTPUT
/* unfortunately, we get lots of messages such as the following:
        ** (java:14856): CRITICAL **: murrine_scrollbar_get_junction: assertion 'GTK_IS_RANGE (widget)' failed
        ** (java:14856): CRITICAL **: murrine_scrollbar_visible_steppers: assertion 'GTK_IS_RANGE (widget)' failed
        (java:14856): Gtk-WARNING **: /build/gtk+2.0-KsZKkB/gtk+2.0-2.24.30/gtk/gtkwidget.c:10000: widget class `GtkSpinButton' has no property named `stepper-size'
        ** (java:14856): CRITICAL **: murrine_scrollbar_get_stepper: assertion 'GTK_IS_RANGE (widget)' failed
        (java:14856): Gtk-WARNING **: /build/gtk+2.0-KsZKkB/gtk+2.0-2.24.30/gtk/gtkwidget.c:10000: widget class `GtkSpinButton' has no property named `stepper-size'
    to avoid these messages, which don't seem to be signaling anything
    actually important, we redirect the stderr messages to a file in /tmp,
    where they are available if desired. */
    char * name = strcat3_malloc (tmp_dir, "/", LOG_FILE_NAME,
                                  "xchat_socket tmp1");
    int log_fd = open (name, O_CREAT | O_TRUNC, 0644);
    free (name);
    if (log_fd < 0) {
      char * env = getenv ("TMP");  /* works on Windows, where /tmp does not */
      if (env != NULL) {
        if ((tmp_dir != NULL) && (strcmp (tmp_dir, TMP_DIR_INITIALIZER) != 0))
          free (tmp_dir);  /* I don't think this code will ever execute */
        tmp_dir = strcpy_malloc (env, "xchat_socket tmp dir");
        name = strcat3_malloc (env, "/", LOG_FILE_NAME, "xchat_socket tmp2");
        log_fd = open (name, O_CREAT | O_TRUNC, 0644);
        free (name);
      }
    }
    if (log_fd >= 0) {   /* not necessary to redirect stdout */
/*      setbuf (stdout, NULL);  */ /* make stdout/stderr unbuffered */
      setbuf (stderr, NULL);  /* so the file is written */
/*      dup2 (log_fd, STDOUT_FILENO); */ /* write stdout to the log file */
      dup2 (log_fd, STDERR_FILENO);  /* write stderr to the log file */
      close (log_fd);  /* no longer needed as a separate fd */
    } else {
#ifdef DEBUG_EXEC_JAVA
      perror ("xchat_socket unable to create or write temp file\n");
#endif /* DEBUG_EXEC_JAVA */
    }
#endif /* HIDE_JAVA_OUTPUT */
    if (args [0] != NULL) {
      args [1] = "-jar";
      args [2] = jarfile;
      args [3] = "nodebug";
      args [4] = NULL;
/* printf ("calling %s %s %s %s\n", args [0], args [1], args [2], args [3]); */
      execv (args [0], args);    /* should never return! */
      perror ("execv returned");
      printf ("execv error calling %s %s %s %s\n", args [0], args [1],
              args [2], args [3]);
    }
/* printf ("java child process exiting and killing parent %d\n", getppid ()); */
    kill (getppid (), SIGKILL);  /* kill the parent process too */
    return -1;
  } else {
    free (jarfile);
  }
  return pid;
}

pid_t start_java (const char * arg)
{
  return exec_java_ui (arg);
}
