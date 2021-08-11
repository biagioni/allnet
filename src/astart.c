/* astart.c: start all the processes used by the allnet daemon */
/* compiles to the executable now called "allnetd" */
/* takes no arguments, I usually run it as bin/allnetd */
/* with -D, runs ad in the main process rather returning immediately */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>
#include <pwd.h>
#include <ifaddrs.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>      /* IFF_LOOPBACK, etc */
#include <arpa/inet.h>   /* inet_addr */

#include "lib/util.h"
#include "lib/allnet_log.h"
#include "lib/packet.h"
#include "lib/configfiles.h"
#include "lib/ai.h"
#include "lib/pcache.h"
#include "lib/routing.h"

extern void allnet_daemon_main (int start);
#ifdef ALLNET_USE_FORK  /* start a keyd process */
extern void keyd_main (char * pname);
#endif /* ALLNET_USE_FORK */
extern void keyd_generate (char * pname);

static struct allnet_log * alog = NULL;

#ifdef ALLNET_USE_FORK 

static int debug_close (int fd, char * loc)
{ /* if needed, keep track of when we close each fd */
  /* printf ("%s: process %d closing fd %d\n", loc, (int)(getpid ()), fd); */
  return close (fd);
}

static const char * process_name = "allnet"; /* changed after each fork */

static void stop_all ();

#else /* ! ALLNET_USE_FORK, e.g. iOS and Android  */

/* fork is not supported under iOS, but threads are */
#include <pthread.h>

struct thread_arg {
  char * name;
  pthread_t id;
  void (*string_function) (char *);
  char * string_arg;
  int start_immediately;
};

static struct thread_arg thread_args [100];
static int free_thread_arg = 0;

static void * generic_thread (void * arg)
{
  if (arg == NULL) {
    printf ("astart generic_thread: null argument\n");
    exit (1);
  }
  struct thread_arg * ta = (struct thread_arg *) arg;
  if (! ta->start_immediately)
    sleep (2);   /* start the allnet daemon first, then run */
  ta->string_function (ta->string_arg);
  printf ("astart generic_thread: %s has ended\n", ta->name);
  /* exit (1);  debugging */
  /* free (ta); should not get here, but if we did, in theory should free ta */
  return NULL;
}

/* stop all of the other threads */
void stop_allnet_threads (void)
{
  allnet_daemon_main (0);  /* stop ad */
  int i;
  for (i = free_thread_arg - 1; i >= 0; i--) {
    if (! pthread_equal (thread_args [i].id, pthread_self ())) {
      pthread_kill (thread_args [i].id, SIGINT);
    }
  }
}

#endif /* ALLNET_USE_FORK */

#define ROOT_USER_ID	0
#ifdef ALLNET_USE_FORK   /* on iOS or android, no point in doing any of this */
/* if astart is called as root, abc should run as root, and everything
 * else should be run as the calling user, if any, and otherwise,
 * user "allnet" (if it exists) or user "nobody" otherwise */
/* running as root can be done in several ways:
 *    sudo astart
 *    sudo chown root:root astart astop; sudo chmod u+s astart astop; ./astart
 * in the first case, both user IDs will be 0 (root).  In the second
 * case, only the effective user ID (euid) will be 0 */
/* setuid is complicated, see
   http://www.cs.berkeley.edu/~daw/papers/setuid-usenix02.pdf
 * however, we only use setuid if we are root, which should be widely portable.
 */
static void make_root_other (int verbose)
{
  if (geteuid () != ROOT_USER_ID)
    return;   /* not root, nothing to do, and cannot change uids anyway */
  uid_t real_uid = getuid ();
  if (real_uid != geteuid ()) {   /* setuid executable, chmod u+s */
    /* setgid first, before dropping uid priviliges */
    gid_t real_gid = getgid ();
    if (real_gid != getegid ()) { /* set group ID as well */
      if ((setgid (real_gid) == 0) && (verbose))
        printf ("set gids %d %d\n", getgid (), getegid ());
    }
    if (setuid (real_uid) == 0) {
      if (verbose) printf ("set uids %d %d\n", getuid (), geteuid ());
      return;
    }
    perror ("setuid/real");   /* and still try to become someone else */
  }
/* find out who we might be, and if not, try to find allnet or nobody */
/* note: linux has a secure_getenv, but it only really matters for setuid
 * programs, which are handled above -- see "man getenv" on a linux system */
  char * home = getenv (HOME_ENV);
  pid_t caller = -1;
  pid_t other = -1;
  char * pw_file = NULL;
  if (read_file_malloc ("/etc/passwd", &pw_file, 1) > 0) {
    char * line = pw_file;
    while ((line != NULL) && (*line != '\0')) {
      char * next_line = NULL;
      char * nl_pos = index (line, '\n');
      if (nl_pos != NULL) {
        *nl_pos = '\0';  /* null terminate, so line refers to just this line */
        next_line = nl_pos + 1;
      }
/* printf ("line '%s', ", line); */
      char * pw_name = NULL;
      pid_t pw_uid = -1;
      char * pw_dir = NULL;
      char * last_entry = line;
      int field = 0;
      int i;
      for (i = 0; line [i] != '\0'; i++) {
        if (line [i] == ':') {
          line [i] = '\0';   /* null terminate */
          if (field == 0)
            pw_name = last_entry;
          else if (field == 2)
            pw_uid = atoi (last_entry);
          else if (field == 5)
            pw_dir = last_entry;
          field++;
          last_entry = line + i + 1;
        }
      }
      if (strcmp (pw_name, "allnet") == 0)
        other = pw_uid;
      else if ((other < 0) && (strcmp (pw_name, "nobody") == 0))
        other = pw_uid;
      else if ((home != NULL) && (strcmp (pw_dir, home) == 0) && (caller == -1))
        caller = pw_uid;
      line = next_line;
    }
    free (pw_file);
  }
  if ((caller != -1) && (caller != 0))
    other = caller;
  if ((other <= 0) || (setuid (other) != 0)) {
    perror ("setuid/other");
    printf ("error: unable to change uid to other %d or %s\n", other, home);
    stop_all ();
  }
  if (verbose) printf ("set uids to %d %d\n", getuid (), geteuid ());
}
#endif /* ALLNET_USE_FORK */

#ifdef ALLNET_USE_FORK
static void print_pid (int fd, int pid)
{
  static int original_fd = -1; /* for debugging */
  char buffer [100];  /* plenty of bytes, easier than being exact */
  int len = snprintf (buffer, sizeof (buffer), "%d\n", pid);
  if (write (fd, buffer, len) != len) {
    perror ("pid file write");
    printf ("writing %d bytes to fd %d, original %d, process id %d\n",
            len, fd, original_fd, (int)(getpid ()));
  } else {
    original_fd = fd;
  }
}
#endif /* ALLNET_USE_FORK */

#ifdef ALLNET_USE_FORK
static char * pid_file_name ()
{
#define PIDS_FILE_NAME	"allnet-pids"
#define UNIX_TEMP	"/tmp"
#define UNIX_TEMP_ROOT	"/var/run"
#define IOS_TEMP	"/Library/Caches"
  char * result = "/tmp/allnet-pids";
  char * temp = UNIX_TEMP;
#if 0
  if (geteuid () == 0)  /* is root */
    temp = UNIX_TEMP_ROOT;
#endif /* 0 */
#ifndef ALLNET_USE_FORK
  DIR * ios_d = opendir (IOS_TEMP);
  if (ios_d != NULL) {  /* directory exists, use it */
    closedir (ios_d);
    temp = IOS_TEMP;
  }
#endif /* ALLNET_USE_FORK */
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
/* from https://en.wikipedia.org/wiki/Temporary_folder
     In MS-DOS and Microsoft Windows, the temporary directory is set by
     the environment variable TEMP.
     ...
     In all versions of Windows the temp location can be accessed, for
     example, in Explorer, Run... boxes and in application's internal
     code by using %temp% */
  temp = getenv ("TEMP");
  if (temp == NULL)
    temp = getenv ("%temp%");
  if (temp == NULL)
    temp = getenv ("temp");
#endif /* _WIN32 || _WIN64 || __CYGWIN__ */
  if (temp != NULL)
    result = strcat3_malloc (temp, "/", PIDS_FILE_NAME, "pids file name");
#ifdef DEBUG
  static int printed = 0;
  if (! printed)
    printf ("new pid temp file name is %s (from %s)\n", result, temp);
  printed = 1;
#endif /* DEBUG */
  return result;
}

/* returns -1 in case of failure */
static int read_pid (int fd)
{
  static char debug [1000];
  debug [0] = '\0';
  unsigned int debug_pos = 0;
  int result = -1;
  char buffer [1];
  while (read (fd, buffer, 1) == 1) {
    if (debug_pos + 1 < sizeof (debug)) {
      debug [debug_pos++] = buffer [0];
      debug [debug_pos] = '\0';
    }
    if ((buffer [0] >= '0') && (buffer [0] <= '9')) {  /* digit */
      if (result == -1)
        result = buffer [0] - '0';
      else
        result = result * 10 + buffer [0] - '0';
    } else if (result == -1) {   /* reading whatever precedes the number */
      /* no need to do anything, just read the next char */
    } else {                     /* done */
      if (result > 1)
        return result;
      printf ("weird result from pid file %d, line %s\n", result, debug);
      result = -1;  /* start over */
    }
  }
  return -1;
}

/* may be used as a signal handler, but really just used by astop to
 * kill all the allnet processes listed in /tmp/allnet-pids. */
static void stop_all_on_signal (int signal)
{
  if (signal != SIGINT)
    printf ("process ID is %d, program %s, signal %d\n", getpid (),
            process_name, signal);
  char * fname = pid_file_name ();
  int fd = -1;
  if (fname != NULL)
    fd = open (fname, O_RDONLY, 0);
  if (fd >= 0) {   /* kill all the pids in the file (except ourselves) */
#define MAX_STOP_PROCS	1000
    static pid_t pids [MAX_STOP_PROCS];
    pid_t pid;
    pid_t my_pid = getpid ();
    int count = 0;
    while ((count < MAX_STOP_PROCS) && ((pid = read_pid (fd)) > 0)) {
      if (pid != my_pid)       /* do not kill myself */
        pids [count++] = pid;
    }
    /* deleting the pid file keeps others from doing what we are doing */
    debug_close (fd, "stop_all_on_signal");
    unlink (fname);
    /* now stop all the other processes */
    int i;
    for (i = count - 1; i >= 0; i--) {
#ifdef DEBUG_PRINT
      printf ("%d killing %d\n", getpid (), pids [i]);
#endif /* DEBUG_PRINT */
      kill (pids [i], SIGINT);
      waitpid (pids [i], NULL, 0);
    }
  }
  exit (0);      /* finally, suicide */
}

static void (*shutdown_function) (int) = NULL;

/* save whatever state needs saving, then stop everything */
static void save_state (int signal)
{
  if (shutdown_function != NULL) {
    shutdown_function (0);  /* the normal case */
  } else {
    printf ("error: astart.c save_state has no shutdown function\n");
    /* do what you can to save state, but why wasn't allnet_daemon_main set
     * as the shutdown function? */
    routing_save_peers ();
    pcache_write ();
    exit (0);
  }
}

static void stop_all ()
{
  char * fname = pid_file_name ();
  if (access (fname, F_OK) == 0) {          /* PID file found */
    stop_all_on_signal (SIGINT);
  } else {                                  /* no PID file, just pkill */
#if ! (defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__))
    /* calling pkill does not seem to be supported on windows */
    printf ("%s: cannot stop allnet (no pid file %s), ", process_name, fname);
    printf ("running 'pkill -x allnetd|allnet-keyd|allnet-kgen|xtime'\n");
    /* send a sigint to all allnet processes */
    /* -x specifies that we only use exact match on process names */
    execlp ("pkill", "pkill", "-x", "allnetd|allnet-keyd|allnet-kgen|xtime",
            ((char *)NULL));
    /* execlp should never return */
    perror ("execlp");
    printf ("unable to pkill\n");
#endif /* _WIN32 || _WIN64 || __CYGWIN__ */
  }
}

/* the following should be all the signals that could terminate a process */
/* list taken from signal(7) */
/* commented-out signals (except SIGPIPE) gave compiler errors */
static int terminating_signals [] =
  { SIGINT, SIGQUIT, SIGILL, SIGABRT, SIGFPE, /* SIGKILL, */
    SIGSEGV, /* SIGPIPE, ignored in astart_main */ SIGBUS, SIGTERM,
    SIGSYS, SIGTRAP, SIGXCPU, SIGXFSZ,
    /* SIGIOT, SIGEMT, */ SIGIO
  };

static void setup_signal_handler (int set)
{
  struct sigaction sa;
  if (set) /* terminate other processes when we are killed */
    sa.sa_handler = save_state;
  else
    sa.sa_handler = SIG_DFL;  /* whatever the default is */
  sigfillset (&(sa.sa_mask)); /* block all signals while sighandler running */
  sa.sa_flags = SA_NOCLDSTOP | SA_RESTART | SA_RESETHAND;
  unsigned int i;
  for (i = 0; i < sizeof (terminating_signals) / sizeof (int); i++) {
    if (sigaction (terminating_signals [i], &sa, NULL) != 0) {
      perror ("sigaction");
      printf ("error setting up signal handler for signal %d [%u]\n",
              terminating_signals [i], i);
      exit (1);
    }
  }
}
/* if !ALLNET_USE_FORK, astart_main tells the system to ignore SIGPIPE.
 * unfortuantely, xcode still catches SIGPIPE.  It is safe to
 * ignore it, and in fact where defined we use setsockopt (..SO_NOSIGPIPE)
 * when we create a socket to tell it we aren't interested.  Unfortunately,
 * not all systems support SO_NOSIGPIPE */

static void child_return (char * executable, pid_t parent, int stop_allnet)
{
  snprintf (alog->b, alog->s, "%s completed\n", executable);
  printf ("%s", alog->b);
  log_print (alog);
  if (stop_allnet) {
    /* kill the parent first, to avoid starting new processes */
    kill (parent, SIGINT);
    stop_all_on_signal (0);   /* stop other AllNet processes if necessary */
  }
  exit (1);  /* at any rate, stop this process */
}

static void replace_command (char * old, int olen, char * new)
{
  /* printf ("replacing %s ", old); */
  /* strncpy, for all its quirks, is just right for this application */
  strncpy (old, new, olen);
  /* printf ("with %s (%s, %d)\n", new, old, olen); */
}
#endif /* ALLNET_USE_FORK */

static void my_call1 (char * argv, int alen, char * program,
                      void (*run_function) (char *), int fd, pid_t parent,
                      int start_immediately, int become_nobody)
{
#ifdef ALLNET_USE_FORK
  pid_t child = fork ();
  if (child == 0) {
    if (become_nobody) /* if we were root, become the caller or allnet/nobody */
      make_root_other (0);
    close (fd);   /* not used in the child */
    replace_command (argv, alen, program);
    snprintf (alog->b, alog->s, "calling %s\n", program);
    log_print (alog);
    if (! start_immediately)
      sleep (2);   /* start the allnet daemon first, then run */
    process_name = program;
    run_function (argv);
    child_return (program, parent, 0);
  } /* parent, not much to do */
  print_pid (fd, child);
#else /* ! ALLNET_USE_FORK */
  struct thread_arg * tap = thread_args + (free_thread_arg++);
  tap->name = strcpy_malloc (program, "astart my_call1");
  tap->string_function = run_function;
  tap->string_arg = strcpy_malloc (argv, "astart my_call1 string");
  tap->start_immediately = start_immediately;
  if (pthread_create (&(tap->id), NULL, generic_thread, (void *) tap)) {
    printf ("pthread_create failed for %s\n", program);
    exit (1);
  }
  pthread_detach (tap->id);
  snprintf (alog->b, alog->s, "parent called %s\n", program);
  log_print (alog);
#endif /* ALLNET_USE_FORK */
}

static void find_path (char * arg, char ** path, char ** program)
{
  char * slash = strrchr (arg, '/');
  if (slash == NULL) {
    *path = ".";
    *program = arg;
  } else {
    *slash = '\0';
    *path = arg;
    *program = slash + 1;
  }
}

static void set_world_readable (const char * file)
{
  struct stat stats;
  if (stat (file, &stats) != 0) {
    snprintf (alog->b, alog->s, "unable to stat for chmod o+r %s\n", file);
    log_print (alog);
  } else if ((stats.st_mode & S_IROTH) == 0) {
    int mode = stats.st_mode | S_IROTH;
    if (chmod (file, mode) != 0) {
      snprintf (alog->b, alog->s, "unable to change mode for %s\n", file);
      log_print (alog);
    }
  }
}

/* miscellaneous things to do while we are still root */
static void do_root_init ()
{
  if (geteuid () != ROOT_USER_ID)
    return;   /* not root or not using fork, nothing to do */
  /* on some systems, /dev/random exists, but is not accessible to non-root
   * processes.  Set it to be accessible. */
  char * set_world_readable_files [] = { "/dev/random", NULL };
  int i;
  for (i = 0; set_world_readable_files [i] != NULL; i++)
    set_world_readable (set_world_readable_files [i]);
#ifdef __linux__ 
  /* on some systems, ipv6 is a module to be added via modprobe */
  if (system ("modprobe ipv6") == -1)
    printf ("unable to modprobe\n");
#endif /* __linux__ */
}

static void call_ad (char * ignored)
{
  allnet_daemon_main (1);
}

int astart_main (int argc, char ** argv)
{
  int ix, jx;
  for (ix = 1; ix + 1 < argc; ix++) {
    if (strcmp (argv [ix], "-d") == 0) {  /* set home directory (configfiles) */
      set_home_directory (argv [ix + 1]);
      for (jx = ix; jx + 1 < argc; jx++) /* replace lower with higher args */
        argv [jx] = argv [jx + 2];
      argc -= 2;   /* and delete */
    }
  }
  log_to_output (get_option ('v', &argc, argv));
  int alen = (int)strlen (argv [0]);
  char * path;
  char * pname;
  find_path (argv [0], &path, &pname);
  if (strstr (pname, "stop") != NULL) {
#ifdef ALLNET_USE_FORK
    process_name = "astop";
    stop_all ();   /* just stop */
#endif /* ALLNET_USE_FORK */
    return 0;
  }
  signal (SIGPIPE, SIG_IGN);  /* we are never interested in SIGPIPE */
  /* printf ("astart path is %s\n", path); */
  pid_t astart_pid = getpid ();
  do_root_init ();

  int pid_fd = 0;
#ifdef ALLNET_USE_FORK  /* only save pids if we do have processes */
  char * fname = pid_file_name ();
  pid_fd = open (fname, O_WRONLY | O_TRUNC | O_CREAT | O_CLOEXEC, 0644);
  if (pid_fd < 0) {
    perror ("open");
    printf ("unable to write pids to %s\n", fname);
    stop_all ();
    exit (1);
  }
  free (fname);
#endif /* ALLNET_USE_FORK */

  alog = init_log ("astart");  /* now we can do logging */
  snprintf (alog->b, alog->s, "astart called with %d arguments\n", argc);
  log_print (alog);
  int i;
  for (i = 0; i < argc + 1; i++) {  /* argc+1 to print the final null pointer */
    snprintf (alog->b, alog->s, "argument %d: %s\n", i, argv [i]);
    log_print (alog);
  }

  /* start the dependent processes, now down to only keyd */
#ifdef ALLNET_USE_FORK /* keyd only works as a separate process */
  my_call1 (argv [0], alen, "allnet-keyd", keyd_main, pid_fd, astart_pid, 0, 1);
#endif /* ALLNET_USE_FORK */
  /* start the allnet daemon */
#ifdef ALLNET_USE_FORK  /* only set up the signal handler for allnetd */
  shutdown_function = allnet_daemon_main;
  setup_signal_handler (1);
  /* print_pid (pid_fd, getpid ()); terminating, so do not save own pid */
#endif /* ALLNET_USE_FORK */
  if ((argc > 1) && (strcmp (argv [1], "-D") == 0)) {
    /* with -D, call ad in the foreground rather than as a separate process */
#ifdef ALLNET_USE_FORK  /* only save pids if we do have processes */
    close (pid_fd);
#endif /* ALLNET_USE_FORK */
    call_ad (NULL);
  } else {
    my_call1 (argv [0], alen, "allnetd", call_ad, pid_fd, astart_pid, 1, 0);
#ifdef ALLNET_USE_FORK  /* only save pids if we do have processes */
    close (pid_fd);
#endif /* ALLNET_USE_FORK */
  }

  return 0;
}

#ifdef ALLNET_USE_FORK

int main (int argc, char ** argv)
{
  return astart_main (argc, argv);
}

#endif /* ALLNET_USE_FORK */
