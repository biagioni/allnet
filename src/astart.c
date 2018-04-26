/* astart.c: start all the processes used by the allnet daemon */
/* compiles to the executable now called "allnet" */
/* takes as arguments:
   - the interface(s) on which to start sending and receiving broadcast packets
   - "defaults" (or any string beginning with "def"), which means to
     broadcast on all local interfaces
   - no arguments, which means to not broadcast on local interfaces
 */
/* in the future this may be automated or from config file */
/* (the config file should also tell us the bandwidth available
 * on each interface) */

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
#include "lib/allnet_queue.h"
#include "lib/ai.h"
#include "lib/pcache.h"

extern void allnet_daemon_main ();
void ad_main (int npipes, int * rpipes, int * wpipes)
{
  printf ("error: dummy ad main called, exiting\n");
  exit (1);
}
extern void abc_main (int pipe1, int pipe2, const char * ifopts);
extern void keyd_main (char * pname);
extern void keyd_generate (char * pname);

#define AIP_UNIX_SOCKET		"/tmp/allnet-addrs"

static struct allnet_log * alog = NULL;

#ifdef ALLNET_USE_FORK 

static const char * debug_process_name = "astart"; /* changed after each fork */

static int debug_close (int fd, char * loc)
{
  /* printf ("%s: process %d closing fd %d\n", loc, (int)(getpid ()), fd); */
  close (fd);
  return 0;
}

static const char * daemon_name = "allnet";

#else /* ALLNET_USE_FORK  */

/* fork is not supported under iOS, but threads are */
#include <pthread.h>

extern void adht_thread (char * pname, int rqueue, int wqueue);
extern void acache_thread (char * pname, int rqueue, int wqueue);
extern void traced_thread (char * pname, int rqueue, int wqueue);
extern void keyd_thread (char * pname, int rqueue, int wqueue);

struct thread_arg {
  char * name;
  int call_type;
  pthread_t id;
#define CALL_STRING		1
  void (*string_function) (char *);
  char * string_arg;
#define CALL_THREAD     	2
  void (*thread_function) (char *, int, int);
#define CALL_ABC		3
  char * ifopts;
};

static struct thread_arg thread_args [100];
static int free_thread_arg = 0;

static int print_n_rw (int num, int * rpipes, int * wpipes, char * buf, int s)
{
  int off = snprintf (buf, s, "%d pipe pairs: ", num);
  int i;
  for (i = 0; i < num; i++)
    off += snprintf (buf + off, s - off, "%d %d%s",
                     rpipes [i], wpipes [i], (i + 1 < num) ? ", " : "");
  return off;
}

static void * generic_thread (void * arg)
{
  if (arg == NULL) {
    printf ("astart generic_thread: null argument\n");
    exit (1);
  }
  struct thread_arg * ta = (struct thread_arg *) arg;
  if (ta->call_type == CALL_STRING) {
    ta->string_function (ta->string_arg);
  } else if (ta->call_type == CALL_THREAD) {
    printf ("calling thread %s (%d, %d)\n",
            ta->string_arg, ta->rpipe, ta->wpipe);
    ta->thread_function (ta->string_arg, ta->rpipe, ta->wpipe);
  } else if (ta->call_type == CALL_AIP) {
    printf ("calling aip_main (%d, %d, %s)\n",
            ta->rpipe, ta->wpipe, ta->extra);
    aip_main (ta->rpipe, ta->wpipe, ta->extra);
  } else if (ta->call_type == CALL_ABC) {
    printf ("threaded environment, not calling abc_main (%d, %d, %s)\n",
            ta->rpipe, ta->wpipe, ta->ifopts);
    /* abc_main (ta->rpipe, ta->wpipe, ta->ifopts); */
  } else if (ta->call_type == CALL_AD) {
    char buf [1000];
    int off = snprintf (buf, sizeof (buf), "calling ad_main (%d, %d): ",
                        ta->rpipe, ta->wpipe);
    off += print_n_rw (ta->num_pipes, ta->rpipes, ta->wpipes,
                       buf + off, sizeof (buf) - off);
    printf ("%s\n", buf);
    ad_main (ta->num_pipes, ta->rpipes, ta->wpipes);
  } else {
    printf ("astart generic_thread: unknown call type %d for %s\n",
            ta->call_type, ta->name);
  }
  printf ("astart generic_thread: error termination of %s, call type %d\n",
          ta->name, ta->call_type);
  /* exit (1);  debugging */
  /* free (ta); should not get here, but if we did, in theory should free ta */
  return NULL;
}

static int noop_fork ()
{
  printf ("using threads instead of fork\n");
  return 0;  /* execute the child code */
}

#define fork  noop_fork

/* stop all of the other threads */
void stop_allnet_threads ()
{
  int i;
  for (i = free_thread_arg - 1; i >= 0; i--) {
    if (! pthread_equal (thread_args [i].id, pthread_self ())) {
      pthread_kill (thread_args [i].id, SIGINT);
    }
  }
}

#ifdef __IPHONE_OS_VERSION_MIN_REQUIRED
static int multipeer_read_queue_index = 0;
static int multipeer_write_queue_index = 0;
static int multipeer_queue_indices_set = 0;

/* called by iOS code to find out which socket to read from.  Waits until
 * the value is available */
void multipeer_queue_indices (int * rpipe, int * wpipe) {
  while (! multipeer_queue_indices_set) {
    printf ("multipeer_read_socket_value waiting for initialization\n");
    sleep (1);
  }
  *rpipe = multipeer_read_queue_index;
  *wpipe = multipeer_write_queue_index;
}
#endif /* __IPHONE_OS_VERSION_MIN_REQUIRED */

#endif /* ALLNET_USE_FORK */

#ifdef ALLNET_USE_FORK
static void stop_all ();
#endif /* ALLNET_USE_FORK */
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
#define ROOT_USER_ID	0
static void make_root_other (int verbose)
{
#ifdef ALLNET_USE_FORK   /* on iOS, no point in doing any of this */
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
#ifndef ANDROID   /* android neither uses /etc/passwd, nor supports *pwent */
  setpwent ();
  struct passwd * pwd;
  while ((pwd = getpwent ()) != NULL) {
    if (strcmp (pwd->pw_name, "allnet") == 0)
      other = pwd->pw_uid;
    else if ((other < 0) && (strcmp (pwd->pw_name, "nobody") == 0))
      other = pwd->pw_uid;
    else if ((home != NULL) && (strcmp (pwd->pw_dir, home) == 0))
      caller = pwd->pw_uid;
  }
  endpwent ();
#endif /* ANDROID */
  if (caller != -1)
    other = caller;
  if ((other < 0) || (setuid (other) != 0)) {
    perror ("setuid/other");
    printf ("error: unable to change uid to other %d or %s\n", other, home);
    stop_all ();
  }
  if (verbose) printf ("set uids to %d %d\n", getuid (), geteuid ());
#endif /* ALLNET_USE_FORK */
}

#ifdef ALLNET_USE_FORK
static void set_nonblock (int fd)
{
  int flags = fcntl (fd, F_GETFL, 0);
  if (flags < 0) {
    printf ("unable to set nonblocking on fd %d (unable to get flags)\n", fd);
    return;
  }
  if (fcntl (fd, F_SETFL, flags | O_NONBLOCK) < 0)
    printf ("unable to set nonblocking on fd %d\n", fd);
}
#endif /* ALLNET_USE_FORK */

static void init_pipes (int * pipes, int num_pipes)
{
  int i;
  for (i = 0; i < num_pipes; i++) {
    int pipefd [2];
#ifdef ALLNET_USE_FORK
#ifdef USE_PIPES
    if (pipe (pipefd) < 0) {
      perror ("pipe");
      printf ("error creating pipe set %d\n", i);
      snprintf (alog->b, alog->s, "error creating pipe set %d\n", i);
      log_print (alog);
      exit (1);
    }
#else /* ! USE_PIPES */
    if (socketpair (AF_LOCAL, SOCK_STREAM, 0, pipefd) < 0) {
      perror ("socketpair");
      printf ("error creating socket pair %d\n", i);
      snprintf (alog->b, alog->s, "error creating socket pair %d\n", i);
      log_print (alog);
      exit (1);
    }
#endif /* USE_PIPES */
    set_nonblock (pipefd [0]);
    set_nonblock (pipefd [1]);
#else /* ! ALLNET_USE_FORK -- create queues instead */
    if (allnet_queues == NULL)
      allnet_queues = malloc_or_fail (2 * num_pipes *
                                      sizeof (struct allnet_queue *),
                                      "allnet_queues in init_pipes");
#define PACKETS		5    		  /* packets per queue */
#define BYTES		PACKETS * ALLNET_MTU    /* bytes per queue */
    char name [1000];
    snprintf (name, sizeof (name), "astart pipe %d/1", i);
    allnet_queues [i] = allnet_queue_new (name, PACKETS, BYTES);
    pipefd[1] = pipefd[0] = - (i + 1);
#undef PACKETS
#undef BYTES
#endif /* ALLNET_USE_FORK */
    pipes [i] = pipefd [0];
    pipes [i + num_pipes] = pipefd [1];
#ifdef DEBUG_PRINT
    printf ("pipes [%d] is %d, pipes [%d] is %d\n",
            i, pipes [i], i + num_pipes, pipes [i + num_pipes]);
#endif /* DEBUG_PRINT */
  }
}

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

static void replace_command (char * old, int olen, char * new)
{
#ifdef ALLNET_USE_FORK
  /* printf ("replacing %s ", old); */
  /* strncpy, for all its quirks, is just right for this application */
  strncpy (old, new, olen);
  /* printf ("with %s (%s, %d)\n", new, old, olen); */
#endif /* ALLNET_USE_FORK */
}

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

static void stop_all_on_signal (int signal)
{
  pcache_write ();
  if (signal != SIGINT)
    printf ("process ID is %d, program %s, signal %d\n", getpid (),
            debug_process_name, signal);
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
    debug_close (fd, "stop_all_on_signal");
    /* deleting the pid file keeps others from doing what we are doing */
    unlink (fname);
    /* now stop all the other processes */
    int i;
    for (i = count - 1; i >= 0; i--) {
#ifdef DEBUG_PRINT
      printf ("%d killing %d\n", getpid (), pids [i]);
#endif /* DEBUG_PRINT */
      kill (pids [i], SIGINT);
    }
    unlink (AIP_UNIX_SOCKET);          /* aip may do this too */
    sleep (1);   /* now kill any processes that haven't died yet */
    for (i = count - 1; i >= 0; i--)
      kill (pids [i], SIGKILL);
  }
  exit (0);      /* finally, suicide */
}

static void stop_all ()
{
  char * fname = pid_file_name ();
  if (access (fname, F_OK) == 0) {          /* PID file found */
    stop_all_on_signal (SIGINT);
  } else {                                  /* no PID file, just pkill */
#if ! (defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__))
    /* calling pkill does not seem to be supported on windows */
    printf ("%s: cannot stop allnet (no pid file %s), ", daemon_name, fname);
    printf ("running 'pkill -x allnet|ad'\n");
    /* send a sigint to all allnet processes */
    /* -x specifies that we only use exact match on process names */
    /* allnet|ad kills processes whether they retain the original name
     * or use the new name */
    execlp ("pkill", "pkill", "-x", "allnet|ad", ((char *)NULL));
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
    sa.sa_handler = stop_all_on_signal;
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
#endif /* ALLNET_USE_FORK */

#ifdef ALLNET_USE_FORK
static void child_return (char * executable, pid_t parent, int stop_allnet)
{
  snprintf (alog->b, alog->s, "%s completed\n", executable);
  log_print (alog);
  if (stop_allnet) {
    /* kill the parent first, to avoid starting new processes */
    kill (parent, SIGINT);
    stop_all_on_signal (0);   /* stop other AllNet processes if necessary */
  }
  exit (1);  /* at any rate, stop this process */
}
#endif /* ALLNET_USE_FORK */

static void my_call1 (char * argv, int alen, char * program,
                      void (*run_function) (char *), int fd, pid_t parent)
{
  pid_t child = fork ();
  if (child == 0) {
    replace_command (argv, alen, program);
    snprintf (alog->b, alog->s, "calling %s\n", program);
    log_print (alog);
#ifdef ALLNET_USE_FORK
    debug_process_name = program;
    daemon_name = program;
    run_function (argv);
    child_return (program, parent, 1);
#else /* ! ALLNET_USE_FORK */
    struct thread_arg * tap = thread_args + (free_thread_arg++);
    tap->name = strcpy_malloc (program, "astart my_call1");
    tap->call_type = CALL_STRING;
    tap->string_function = run_function;
    tap->string_arg = strcpy_malloc (argv, "astart my_call1 string");
    if (pthread_create (&(tap->id), NULL, generic_thread, (void *) tap)) {
      printf ("pthread_create failed for %s\n", program);
      exit (1);
    }
#endif /* ALLNET_USE_FORK */
  }
  /* parent, not much to do */
#ifdef ALLNET_USE_FORK
  print_pid (fd, child);
#endif /* ALLNET_USE_FORK */
  snprintf (alog->b, alog->s, "parent called %s\n", program);
  log_print (alog);
}

#ifndef ALLNET_USE_FORK
static void my_call_thread (char * argv, int alen, char * program,
                            void (*run_function) (char *, int, int),
                            int fd, pid_t parent, int rpipe, int wpipe)
{
  snprintf (alog->b, alog->s, "calling %s (%d, %d)\n",
            program, rpipe, wpipe);
  log_print (alog);
  struct thread_arg * tap = thread_args + (free_thread_arg++);
  tap->name = strcpy_malloc (program, "astart my_call_thread");
  tap->call_type = CALL_THREAD;
  tap->thread_function = run_function;
  tap->string_arg = strcpy_malloc (program, "astart my_call_thread");
  tap->rpipe = rpipe;
  tap->wpipe = wpipe;
  if (pthread_create (&(tap->id), NULL, generic_thread, (void *) tap)) {
    printf ("pthread_create failed for %s\n", program);
  }
}
#endif /* ALLNET_USE_FORK */

static void my_call_abc (int argc, char ** argv, int alen, int alen_arg,
                         char * program,
                         int rpipe, int wpipe, int ppipe1, int ppipe2,
                         char * ifopts, pid_t * pid, pid_t parent)
{
#ifdef ALLNET_USE_FORK
  pid_t child = fork ();
  if (child == 0) {
    debug_process_name = "abc";
    replace_command (argv [0], alen, program);
    if ((argc > 1) && (alen_arg > 0) && (ifopts != NULL))
      replace_command (argv [1], alen_arg, ifopts);
#ifdef DEBUG_PRINT
    printf ("calling %s %s %d %d %d %d %s\n", program, interface, rpipe, wpipe,
               ppipe1, ppipe2, ifopts);
#endif /* DEBUG_PRINT */
    daemon_name = "abc";
    setup_signal_handler (0);  /* abc has its own signal handler */
    usleep (10 * 1000);        /* wait for parent to create log file */
    /* close the pipes used by the parent -- my_call_ad will close them
     * again, which is no big deal */
    debug_close (ppipe1, "my_call_abc");
    debug_close (ppipe2, "my_call_abc wpipe");
    abc_main (rpipe, wpipe, ifopts);
    exit (0);   /* abc can return without us having to disable the rest */
    child_return (program, parent, 0);
  }  /* parent, close the child pipes */
  *pid = child;
  debug_close (rpipe, "my_call_abc parent rpipe");
  debug_close (wpipe, "my_call_abc parent wpipe");
/* snprintf (alog->b, alog->s, "parent called %s %d %d %s, closed %d %d\n",
            program, rpipe, wpipe, ifopts, rpipe, wpipe);
  log_print (alog); */
#else /* ! ALLNET_USE_FORK */
  struct thread_arg * tap = thread_args + (free_thread_arg++);
  tap->name = "abc";
  tap->call_type = CALL_ABC;
  tap->rpipe = rpipe;
  tap->wpipe = wpipe;
  tap->ifopts = ifopts;
  if (pthread_create (&(tap->id), NULL, generic_thread, (void *) tap)) {
    printf ("pthread_create failed for abc\n");
    exit (1);
  }
  *pid = getpid ();
#endif /* ALLNET_USE_FORK */
}

static pid_t my_call_ad (char * argv, int alen, int num_pipes, int * rpipes,
                         int * wpipes, int fd, pid_t parent)
{
  int i;
#ifdef ALLNET_USE_FORK
  pid_t child = fork ();
  if (child == 0) {
    debug_process_name = "ad";
    char * program = "ad";
    replace_command (argv, alen, program);
    snprintf (alog->b, alog->s, "calling %s\n", program);
    log_print (alog);
    daemon_name = "ad";
    /* close the pipes we don't use in the child */
    /* and compress the rest to the start of the respective arrays */
    for (i = 0; i < num_pipes / 2; i++) {
      debug_close (rpipes [2 * i    ], "my_call_ad rpipes");
      debug_close (wpipes [2 * i + 1], "my_call_ad wpipes");
      rpipes [i] = rpipes [2 * i + 1];
      wpipes [i] = wpipes [2 * i    ];  /* may be the same */
    }
/*  printf ("calling ad (%d): %d, read", getpid (), num_pipes / 2);
    for (i = 0; i < num_pipes / 2; i++)
      printf (" %d", rpipes [i]);
    printf (", write");
    for (i = 0; i < num_pipes / 2; i++)
      printf (" %d", wpipes [i]);
    printf ("\n"); */
    ad_main (num_pipes / 2, rpipes, wpipes);
    child_return (program, parent, 1);
  }  /* parent, close the child pipes */
  print_pid (fd, child);
  for (i = 0; i < num_pipes / 2; i++) {
    debug_close (rpipes [2 * i + 1], "my_call_ad parent rpipe");
    debug_close (wpipes [2 * i    ], "my_call_ad parent wpipe");
    rpipes [i] = rpipes [2 * i    ];  /* the same if i is 0 */
    wpipes [i] = wpipes [2 * i + 1];
  }
  return child;
#else /* ! ALLNET_USE_FORK */
  snprintf (alog->b, alog->s, "calling ad_main\n");
  log_print (alog);
  int * rcopy = memcpy_malloc (rpipes, (num_pipes / 2) * sizeof (int),
                               "my_call_ad rpipes");
  int * wcopy = memcpy_malloc (wpipes, (num_pipes / 2) * sizeof (int),
                               "my_call_ad wpipes");
  /* copy the read and write pipes */
  for (i = 0; i < num_pipes / 2; i++) {
    rcopy [i] = rpipes [2 * i + 1];
    wcopy [i] = wpipes [2 * i    ];
    rpipes [i] = rpipes [2 * i    ];  /* the same if i is 0 */
    wpipes [i] = wpipes [2 * i + 1];
  }
  struct thread_arg * tap = thread_args + (free_thread_arg++);
  tap->name = "ad";
  tap->call_type = CALL_AD;
  tap->num_pipes = num_pipes / 2;
  tap->rpipes = rcopy;
  tap->wpipes = wcopy;
  if (pthread_create (&(tap->id), NULL, generic_thread, (void *) tap)) {
    printf ("pthread_create failed for ad\n");
    exit (1);
  }
  return getpid ();
#endif /* ! ALLNET_USE_FORK */
}

#ifdef DEBUG_PRINT
/* typical output when wlan1 is enabled but eth1 is not:
    interface lo has flags 10049: IFF_UP IFF_LOOPBACK IFF_RUNNING 10000
    interface eth1 has flags 1003: IFF_UP IFF_BROADCAST IFF_MULTICAST
    interface wlan1 has flags 11043: IFF_UP IFF_BROADCAST IFF_RUNNING IFF_MULTICAST 10000
*/
static void debug_print_flags (char * name, int flags)
{
  int i;
  /* only print once */
  static int nprinted = 0;
  static char * printed [100];
  for (i = 0; i < nprinted; i++)
    if (strcmp (printed [i], name) == 0)  /* already printed, ignore */
      return;
  printed [nprinted++] = name;  /* save for future reference */
  printf ("interface %s has flags %x:", name, flags);
  for (i = 1; i <= flags; i *= 2) {
    if (i & flags) {
      switch (i) {
      case IFF_UP: printf (" IFF_UP"); break;
      case IFF_BROADCAST: printf (" IFF_BROADCAST"); break;
#ifdef IFF_DEBUG
      case IFF_DEBUG: printf (" IFF_DEBUG"); break;
#endif /* IFF_DEBUG */
      case IFF_LOOPBACK: printf (" IFF_LOOPBACK"); break;
      case IFF_POINTOPOINT: printf (" IFF_POINTOPOINT"); break;
      case IFF_RUNNING: printf (" IFF_RUNNING"); break;
      case IFF_NOARP: printf (" IFF_NOARP"); break;
      case IFF_PROMISC: printf (" IFF_PROMISC"); break;
      case IFF_NOTRAILERS: printf (" IFF_NOTRAILERS"); break;
#ifdef IFF_ALLMULTI
      case IFF_ALLMULTI: printf (" IFF_ALLMULTI"); break;
#endif /* IFF_ALLMULTI */
#ifdef IFF_MASTER
      case IFF_MASTER: printf (" IFF_MASTER"); break;
#endif /* IFF_MASTER */
#ifdef IFF_SLAVE
      case IFF_SLAVE: printf (" IFF_SLAVE"); break;
#endif /* IFF_SLAVE */
      case IFF_MULTICAST: printf (" IFF_MULTICAST"); break;
#ifdef IFF_PORTSEL
      case IFF_PORTSEL: printf (" IFF_PORTSEL"); break;
#endif /* IFF_PORTSEL */
#ifdef IFF_AUTOMEDIA
      case IFF_AUTOMEDIA: printf (" IFF_AUTOMEDIA"); break;
#endif /* IFF_AUTOMEDIA */
#ifdef IFF_DYNAMIC
      case IFF_DYNAMIC: printf (" IFF_DYNAMIC"); break;
#endif /* IFF_DYNAMIC */
      default:       printf (" %x", i);
      }
    }
  }
  printf ("\n");
}
#endif /* DEBUG_PRINT */

#ifdef ALLNET_USE_FORK
static char * interface_extra (struct interface_addr * interface)
{
  if (interface == NULL)  /* can happen */
    return "";
  int i;
  for (i = 0; i < interface->num_addresses; i++) {
    struct sockaddr * sa = (struct sockaddr *) ((interface->addresses) + i);
    if (sa->sa_family == AF_INET) /* || when add ipv6 to abc-ip.c
        (sa->sa_family == AF_INET6)) */
      return "ip";
  }
  if ((strncmp (interface->interface_name, "wlan", 4) == 0) ||
      (strncmp (interface->interface_name, "wlo", 3) == 0) ||
      (strncmp (interface->interface_name, "wlp", 3) == 0) ||
      (strncmp (interface->interface_name, "wlx", 3) == 0)) {
    if (geteuid () == 0)
      return "wifi";
    else
      return ""; /* don't use "wifi,nm" for now, hasn't been thought through */
  }
  return "";
}

static int default_interfaces (char * * * interfaces_p)
{
  struct interface_addr * int_addrs;
  int num_interfaces = interface_addrs (&int_addrs);
  *interfaces_p = NULL;
  int i;
  /* compute the buffer size needed to store all interface information */
  int count = 0;
  size_t length = 0;
  for (i = 0; i < num_interfaces; i++) {
    if ((! int_addrs [i].is_loopback) && (int_addrs [i].is_broadcast)) {
      /* run abc for this interface */
      size_t extra_len = strlen (interface_extra (int_addrs + i));
      if (extra_len != 0) {
        count++; /* and add interface/extra and the null char */
        length += strlen (int_addrs [i].interface_name) + 1 + extra_len + 1;
      }
    }
  }
  int result = 0;
  if (count > 0) {
    size_t size = count * sizeof (char *) + length;
    *interfaces_p = malloc_or_fail (size, "default_interfaces");
    char * * interfaces = *interfaces_p;
    /* copy the names/extra to the malloc'd space after the pointers */
    char * write_to = ((char *) (interfaces + count));
    size_t write_len = length;
    for (i = 0; ((write_len > 0) && (i < num_interfaces)); i++) {
      if ((! int_addrs [i].is_loopback) && (int_addrs [i].is_broadcast)) {
        char * extra = interface_extra (int_addrs + i);
        if (strlen (extra) > 0) {
          interfaces [result++] = write_to;
          off_t slen = snprintf (write_to, write_len, "%s/%s",
                                 int_addrs [i].interface_name, extra)
                   + 1;  /* for the null character */
          write_len -= slen;
          write_to += slen;
        }
      }
    }
    if (result <= 0) {
      free (*interfaces_p);
      *interfaces_p = NULL;
    }
  }
  return result;
}
#endif /* ALLNET_USE_FORK */

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

int astart_main (int argc, char ** argv)
{
  int ix, jx;
  for (ix = 1; ix + 1 < argc; ix++) {
    if (strcmp (argv [ix], "-d") == 0) {
      set_home_directory (argv [ix + 1]);
      for (jx = ix; jx + 1 < argc; jx++) /* replace lower with higher args */
        argv [jx] = argv [jx + 2];
      argc -= 2;   /* and delete */
    }
  }
  log_to_output (get_option ('v', &argc, argv));
  int alen = (int)strlen (argv [0]);
  int alen_arg = ((argc > 1) ? (int)strlen (argv [1]) : 0);
  char * path;
  char * pname;
  find_path (argv [0], &path, &pname);
  if (strstr (pname, "stop") != NULL) {
#ifdef ALLNET_USE_FORK
    debug_process_name = "astop";
    daemon_name = "astop";
    stop_all ();   /* just stop */
#endif /* ALLNET_USE_FORK */
    return 0;
  }
  signal (SIGPIPE, SIG_IGN);  /* we are never interested in SIGPIPE */
  /* printf ("astart path is %s\n", path); */
  pid_t astart_pid = getpid ();
  do_root_init ();

  /* two pipes from ad to alocal and back, plus */
  /* two pipes from ad to aip and back */
#define NUM_FIXED_PIPES		4
  /* two pipes from ad to each abc and back */
#define NUM_INTERFACE_PIPES	2 
  char ** interfaces = NULL;
  int num_interfaces = argc - 1;
#ifdef ALLNET_USE_FORK  /* for now, don't run abc on android and ios */
  if ((argc > 1) && (strncmp (argv [1], "def", 3) == 0))
    num_interfaces = default_interfaces (&interfaces);
  else if (argc == 1)
    num_interfaces = 0;
  else {  /* interfaces specified on the command line */
    int size = (argc - 1) * sizeof (char *);
    interfaces = malloc_or_fail (size, "specified interfaces");
    int i;
    for (i = 0; i < (argc - 1); i++)
      interfaces [i] = strcpy_malloc (argv [i + 1], "specific interface");
  }
#else /* ! ALLNET_USE_FORK */
  num_interfaces = 0;
#endif /* ! ALLNET_USE_FORK */
  int num_pipes = NUM_FIXED_PIPES + NUM_INTERFACE_PIPES * num_interfaces;
#ifdef __IPHONE_OS_VERSION_MIN_REQUIRED
/* ad needs one extra pair of pipes for the multipeer thread */
  int multipeer_pipe_offset = num_pipes / 2;
  num_pipes += 2;
#endif /* __IPHONE_OS_VERSION_MIN_REQUIRED */
  int ad_pipes = num_pipes;
#ifndef ALLNET_USE_FORK  /* create queues for 4 of the 5 daemons and xchat */
#define NUM_DAEMON_PIPES    4
  num_pipes += (NUM_DAEMON_PIPES + 1) * 2;
#endif /* ALLNET_USE_FORK */
/* printf ("adding pipe total %d (ad %d)\n", num_pipes, ad_pipes); */
  /* note: two file descriptors (ints) per pipe */
  int * pipes = malloc_or_fail (num_pipes * 2 * sizeof (int), "astart pipes");
  init_pipes (pipes, num_pipes);
  int * rpipes = pipes;
  int * wpipes = pipes + num_pipes;
  pid_t * abc_pids = NULL;
  if (num_interfaces > 0)
    abc_pids = malloc_or_fail (num_interfaces * sizeof (pid_t), "abc pids");

  /* in case we are root, start abc first, then become non-root, and
   * only after we become non-root start the other daemons */
  int i;
  for (i = 0; i < num_interfaces; i++) {
    char * interface;
    if (interfaces != NULL)
      interface = interfaces [i];
    else
      interface = argv [i + 1];
    int rpipe =  rpipes [2 * i + NUM_FIXED_PIPES];
    int wpipe =  wpipes [2 * i + NUM_FIXED_PIPES + 1];
    int ppipe1 = rpipes [2 * i + NUM_FIXED_PIPES + 1];
    int ppipe2 = wpipes [2 * i + NUM_FIXED_PIPES];
#ifdef DEBUG_PRINT
    printf ("calling abc %s, pipes %d %d %d %d\n", interface,
            rpipe, wpipe, ppipe1, ppipe2);
#endif /* DEBUG_PRINT */
    my_call_abc (argc, argv, alen, alen_arg, "abc",
                 rpipe, wpipe, ppipe1, ppipe2,
                 interface, abc_pids + i, astart_pid);
  }
  make_root_other (0); /* if we were root, become the caller or allnet/nobody */

#ifdef PRODUCTION_CODE
  if (! verbose) {
    /* to go into the background, close all standard file descriptors.
     * use -v or comment this out if trying to debug to stdout/stderr */
    debug_close (0, "astart_main stdin");
    debug_close (1, "astart_main stdout");
    debug_close (2, "astart_main stderr");
  }
#endif /* PRODUCTION_CODE */

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
  for (i = 0; i < num_interfaces; i++)
    print_pid (pid_fd, abc_pids [i]);
#endif /* ALLNET_USE_FORK */
  if (num_interfaces > 0)
    free (abc_pids);

  alog = init_log ("astart");  /* now we can do logging */
  snprintf (alog->b, alog->s, "astart called with %d arguments\n", argc);
  log_print (alog);
  for (i = 0; i < argc + 1; i++) {  /* argc+1 to print the final null pointer */
    snprintf (alog->b, alog->s, "argument %d: %s\n", i, argv [i]);
    log_print (alog);
  }
  for (i = 0; i < num_interfaces; i++) {
    snprintf (alog->b, alog->s, "called abc on interface %d: %s\n",
              i, interfaces [i]);
    log_print (alog);
  }

#ifndef ALLNET_USE_FORK  /* create queues for 4 of the 5 daemons */
  int alocal_numpipes = 0;
  int * alocal_rpipes = NULL;
  int * alocal_wpipes = NULL;
  alocal_numpipes = NUM_DAEMON_PIPES;
  alocal_rpipes = rpipes + ad_pipes;
  alocal_wpipes = wpipes + ad_pipes;
#endif /* ALLNET_USE_FORK */

  /* start ad */
  allnet_daemon_main ();
  exit (0);
  my_call_ad (argv [0], alen, ad_pipes, rpipes, wpipes, pid_fd, astart_pid);
  /* my_call_ad closed half the pipes and put them in the front of the arrays */
  num_pipes = num_pipes / 2;

  /* start all the other programs */
#ifdef ALLNET_USE_FORK  /* daemons connect through sockets */
  /* ad, alocal, and aip don't need signal handlers -- if any
   * of them goes down, the pipes are closed and everyone else goes down too
   * but if the other daemons go down, they should explicitly shut
   * down all the processes listed in the pid file */
  setup_signal_handler (1);
  my_call1 (argv [0], alen, "keyd", keyd_main, pid_fd, astart_pid);
#else /* ! ALLNET_USE_FORK -- daemons use queues to communicate */
  printf ("calling keyd with pipes %d, %d\n",
          alocal_rpipes [6], alocal_wpipes [7]);
  my_call_thread (argv [0], alen, "keyd", keyd_thread, pid_fd, astart_pid,
                  alocal_rpipes [6], alocal_wpipes [7]);
#ifdef __IPHONE_OS_VERSION_MIN_REQUIRED
  multipeer_read_queue_index = rpipes [multipeer_pipe_offset];
  multipeer_write_queue_index = wpipes [multipeer_pipe_offset];
printf ("multipeer pipes are %d, %d, multipeer pipe offset is %d\n",
  multipeer_read_queue_index, multipeer_write_queue_index,
  multipeer_pipe_offset);
  multipeer_queue_indices_set = 1;
#endif /* __IPHONE_OS_VERSION_MIN_REQUIRED */
#endif /* ALLNET_USE_FORK */
  my_call1 (argv [0], alen, "keygen", keyd_generate, pid_fd, astart_pid);

#ifdef WAIT_FOR_CHILD_TERMINATION
  int status;
  pid_t child = wait (&status);  /* wait for one of the children to terminate */
  snprintf (alog->b, alog->s, "child %d terminated, exiting\n", child);
  log_print (alog);
#endif /* WAIT_FOR_CHILD_TERMINATION */
  /* free (pipes);  not necessary if we fork -- harmful if we don't */
  return 0;
}

#ifdef ALLNET_USE_FORK

int main (int argc, char ** argv)
{
  return astart_main (argc, argv);
}

#endif /* ALLNET_USE_FORK */
