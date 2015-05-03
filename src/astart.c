/* astart.c: start all the processes used by the allnet daemon */
/* takes as arguments:
   - the interface(s) on which to start sending and receiving broadcast packets
   - "defaults" (or any string beginning with "def"), which means to
     broadcast on all local interfaces
   - no arguments, which means to not broadcast on local interfaces
 */
/* in the future this may be automated or from config file */
/* (since the config file should tell us the bandwidth on each interface) */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>
#include <pwd.h>
#include <ifaddrs.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <net/if.h>      /* IFF_LOOPBACK, etc */

#include "lib/util.h"
#include "lib/log.h"
#include "lib/packet.h"

extern void ad_main (int npipes, int * rpipes, int * wpipes);
extern void alocal_main (int pipe1, int pipe2);
extern void aip_main (int pipe1, int pipe2, char * fname);
extern void abc_main (int pipe1, int pipe2, const char * ifopts);
extern void adht_main (char * pname);
extern void acache_main (char * pname);
extern void traced_main (char * pname);
extern void keyd_main (char * pname);
extern void keyd_generate (char * pname);

static const char * daemon_name = "allnet";

static void stop_all ();
/* if astart is called as root, abc should run as root, and everything
 * else should be run as the calling user, if any, and otherwise,
 * user "allnet" (if it exists) or user "nobody" otherwise */
/* running as root can be done in several ways:
 *    sudo astart
 *    sudo chown root:root astart astop; sudo chmod u+s astart astop; ./astart
 * in the first case, both user IDs will be 0 (root).  In the second
 * case, only the effective user ID (euid) will be 0 */
#define ROOT_USER_ID	0
static void make_root_other (int verbose)
{
  if (geteuid () != ROOT_USER_ID)
    return;   /* not root, nothing to do, and cannot change uids anyway */
  int real_uid = getuid ();
  if (real_uid != geteuid ()) {   /* setuid executable, chmod u+s */
    if (setuid (real_uid) == 0) {
      if (verbose) printf ("set uids %d %d\n", getuid (), geteuid ());
      int real_gid = getgid ();
      if (real_gid != getegid ()) { /* set group ID as well */
        if ((setuid (real_gid) == 0) && (verbose))
          printf ("set gids %d %d\n", getgid (), getegid ());
      }
      return;
    }
    perror ("setuid/real");   /* and still try to become someone else */
  }
/* try to find out who we might be, and otherwise, try to find root */
/* note: there is a secure_getenv, but it only really matters for setuid
 * programs, which are handled above -- see "man getenv" on a linux system */
  char * home = getenv ("HOME");
  pid_t caller = -1;
  pid_t other = -1;
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
  if (caller != -1)
    other = caller;
  if ((other < 0) || (setuid (other) != 0)) {
    perror ("setuid/other");
    printf ("error: unable to change uid to other %d or %s\n", other, home);
    stop_all ();
  }
  if (verbose) printf ("set uids to %d %d\n", getuid (), geteuid ());
}

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

static void init_pipes (int * pipes, int num_pipes)
{
  int i;
  for (i = 0; i < num_pipes; i++) {
    int pipefd [2];
    if (pipe (pipefd) < 0) {
      perror ("pipe");
      printf ("error creating pipe set %d\n", i);
      snprintf (log_buf, LOG_SIZE, "error creating pipe set %d\n", i);
      log_print ();
      exit (1);
    }
    set_nonblock (pipefd [0]);
    set_nonblock (pipefd [1]);
    pipes [i] = pipefd [0];
    pipes [i + num_pipes] = pipefd [1];
/*  printf ("pipes [%d] is %d, pipes [%d] is %d\n",
            i, pipes [i], i + num_pipes, pipes [i + num_pipes]); */
  }
}

static void print_pid (int fd, int pid)
{
  char buffer [100];  /* plenty of bytes, easier than being exact */
  int len = snprintf (buffer, sizeof (buffer), "%d\n", pid);
  if (write (fd, buffer, len) != len)
    perror ("pid file write");
}

#if 0
/* returned value is malloc'd */
static char * make_program_path (char * path, char * program)
{
  int size = strlen (path) + 1 + strlen (program) + 1;
  char * result = malloc (size);
  if (result == NULL) {
    printf ("error: unable to allocate %d bytes for %s/%s, aborting\n",
            size, path, program);
    exit (1);
  }
  snprintf (result, size, "%s/%s", path, program);
  return result;
}
#endif /* 0 */

static void replace_command (char * old, int olen, char * new)
{
  /* printf ("replacing %s ", old); */
  /* strncpy, for all its quirks, is just right for this application */
  strncpy (old, new, olen);
  /* printf ("with %s (%s, %d)\n", new, old, olen); */
}

static char * pid_file_name ()
{
#define PIDS_FILE_NAME	"allnet-pids"
#define UNIX_TEMP	"/tmp"
#define UNIX_TEMP_ROOT	"/var/run"
  static char * result = "/tmp/allnet-pids";
  static int first_call = 1;
  if (! first_call)
    return result;
  first_call = 0;
  char * temp = UNIX_TEMP;
/*
  if (geteuid () == 0)  / * is root * /
    temp = UNIX_TEMP_ROOT;
  */
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
  if (temp != NULL) {
    int len = strlen (temp) + strlen (PIDS_FILE_NAME) + 2;
    result = malloc_or_fail (len, "pids_file_name");
    snprintf (result, len, "%s/%s", temp, PIDS_FILE_NAME);
  }
#ifdef DEBUG
  printf ("temp file name is %s\n", result);
#endif /* DEBUG */
  return result;
}

/* returns 0 in case of failure */
static int read_pid (int fd)
{
  int result = -1;
  char buffer [1];
  while (read (fd, buffer, 1) == 1) {
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
      printf ("weird result from pid file %d\n", result);
      result = -1;  /* start over */
    }
  }
  return -1;
}

#define AIP_UNIX_SOCKET		"/tmp/allnet-addrs"

static void stop_all_on_signal (int signal)
{
  char * fname = pid_file_name ();
  int fd = open (fname, O_RDONLY, 0);
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
    close (fd);
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
    printf ("%s: cannot stop allnet (no pid file %s), running pkill astart\n",
            daemon_name, fname);
    /* send a sigint to all astart processes */
    execlp ("pkill", "pkill", "astart", ((char *)NULL));
    /* execlp should never return */
    perror ("execlp");
    printf ("unable to pkill\n");
  }
}

/* the following should be all the signals that could terminate a process */
/* list taken from signal(7) */
/* commented-out signals gave compiler errors */
static int terminating_signals [] =
  { SIGINT, SIGQUIT, SIGILL, SIGABRT, SIGFPE, /* SIGKILL, */
    SIGSEGV, SIGPIPE, SIGBUS, SIGTERM,
    SIGSYS, SIGTRAP,
    SIGXCPU, SIGXFSZ,
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
  sa.sa_flags = SA_NOCLDSTOP | SA_RESTART;
  int i;
  for (i = 0; i < sizeof (terminating_signals) / sizeof (int); i++) {
    if (sigaction (terminating_signals [i], &sa, NULL) != 0) {
      perror ("sigaction");
      printf ("error setting up signal handler for signal %d [%d]\n",
              terminating_signals [i], i);
      exit (1);
    }
  }
}

static void child_return (char * executable, pid_t parent, int stop_allnet)
{
  snprintf (log_buf, LOG_SIZE, "%s completed\n", executable);
  log_print ();
  if (stop_allnet) {
    /* kill the parent first, to avoid starting new processes */
    kill (parent, SIGINT);
    stop_all_on_signal (0);   /* stop other AllNet processes if necessary */
  }
  exit (1);  /* at any rate, stop this process */
}

static void my_call1 (char * argv, int alen, char * program,
                      void (*run_function) (char *), int fd, pid_t parent)
{
  pid_t child = fork ();
  if (child == 0) {
    replace_command (argv, alen, program);
    snprintf (log_buf, LOG_SIZE, "calling %s\n", program);
    log_print ();
    daemon_name = program;
    run_function (argv);
    child_return (program, parent, 1);
  } else {  /* parent, not much to do */
    print_pid (fd, child);
    snprintf (log_buf, LOG_SIZE, "parent called %s\n", program);
    log_print ();
  }
}

static int connect_to_local ()
{
  int sock = socket (AF_INET, SOCK_STREAM, 0);
  struct sockaddr_in sin;
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = inet_addr ("127.0.0.1");
  sin.sin_port = ALLNET_LOCAL_PORT;
  int success = (connect (sock, (struct sockaddr *) &sin, sizeof (sin)) == 0);
  close (sock);
  return success;
}

static void my_call_alocal (char * argv, int alen, int rpipe, int wpipe, int fd,
                            pid_t parent)
{
  char * program = "alocal";
  pid_t child = fork ();
  if (child == 0) {
    replace_command (argv, alen, program);
    snprintf (log_buf, LOG_SIZE, "calling %s (%d %d)\n", program, rpipe, wpipe);
    log_print ();
    daemon_name = "alocal";
    alocal_main (rpipe, wpipe);
    child_return (program, parent, 1);
  } else {  /* parent, close the child pipes */
    close (rpipe);
    close (wpipe);
    print_pid (fd, child);
    snprintf (log_buf, LOG_SIZE, "parent called %s %d %d, closed %d %d\n",
              program, rpipe, wpipe, rpipe, wpipe);
    log_print ();
    do {
      usleep (10 * 1000);
    } while (! connect_to_local());
  }
}

static void my_call_aip (char * argv, int alen, char * program,
                         int rpipe, int wpipe, char * extra, int fd,
                         pid_t parent)
{
  pid_t child = fork ();
  if (child == 0) {
    replace_command (argv, alen, program);
    snprintf (log_buf, LOG_SIZE, "calling %s %d %d %s\n",
              program, rpipe, wpipe, extra);
    log_print ();
    daemon_name = "aip";
    aip_main (rpipe, wpipe, extra);
    child_return (program, parent, 1);
  } else {  /* parent, close the child pipes */
    close (rpipe);
    close (wpipe);
    print_pid (fd, child);
    snprintf (log_buf, LOG_SIZE, "parent called %s %d %d %s, closed %d %d\n",
              program, rpipe, wpipe, extra, rpipe, wpipe);
    log_print ();
  }
}

static void my_call_abc (char * argv, int alen, char * program,
                         int rpipe, int wpipe, int ppipe1, int ppipe2,
                         char * ifopts, pid_t * pid, pid_t parent)
{
  pid_t child = fork ();
  if (child == 0) {
    replace_command (argv, alen, program);
    /* printf ("calling %s %d %d %s\n", program, rpipe, wpipe, ifopts); */
    daemon_name = "abc";
    setup_signal_handler (0);  /* abc has its own signal handler */
    usleep (10 * 1000);        /* wait for parent to create log file */
    /* close the pipes used by the parent -- my_call_ad will close them
     * again, which is no big deal */
    close (ppipe1);
    close (ppipe2);
    abc_main (rpipe, wpipe, ifopts);
    child_return (program, parent, 0);
  } else {  /* parent, close the child pipes */
    *pid = child;
    /* print_pid (fd, child); */
    close (rpipe);
    close (wpipe);
/*
    snprintf (log_buf, LOG_SIZE, "parent called %s %d %d %s, closed %d %d\n",
              program, rpipe, wpipe, ifopts, rpipe, wpipe);
    log_print (); */
  }
}

static pid_t my_call_ad (char * argv, int alen, int num_pipes, int * rpipes,
                         int * wpipes, int fd, pid_t parent)
{
  int i;
  pid_t child = fork ();
  if (child == 0) {
    char * program = "ad";
    replace_command (argv, alen, program);
    snprintf (log_buf, LOG_SIZE, "calling %s\n", program);
    log_print ();
    daemon_name = "ad";
    /* close the pipes we don't use in the child */
    /* and compress the rest to the start of the respective arrays */
    for (i = 0; i < num_pipes / 2; i++) {
      close (rpipes [2 * i    ]);
      close (wpipes [2 * i + 1]);
      rpipes [i] = rpipes [2 * i + 1];
      wpipes [i] = wpipes [2 * i    ];  /* may be the same */
    }
/*  printf ("calling ad (%d, read", num_pipes / 2);
    for (i = 0; i < num_pipes / 2; i++)
      printf (" %d", rpipes [i]);
    printf (", write");
    for (i = 0; i < num_pipes / 2; i++)
      printf (" %d", wpipes [i]);
    printf (")\n"); */
    ad_main (num_pipes / 2, rpipes, wpipes);
    child_return (program, parent, 1);
  } else {  /* parent, close the child pipes */
    print_pid (fd, child);
    for (i = 0; i < num_pipes / 2; i++) {
      close (rpipes [2 * i + 1]);
      close (wpipes [2 * i    ]);
      rpipes [i] = rpipes [2 * i    ];  /* the same if i is 0 */
      wpipes [i] = wpipes [2 * i + 1];
    }
  }
  return child;
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

static int is_bc_interface (struct ifaddrs * interface)
{
#ifdef DEBUG_PRINT
  debug_print_flags (interface->ifa_name, interface->ifa_flags);
#endif /* DEBUG_PRINT */
  return (((interface->ifa_flags & IFF_LOOPBACK) == 0) &&
/*          ((interface->ifa_flags & IFF_UP) != 0) && */
          ((interface->ifa_flags & IFF_BROADCAST) != 0));
}

static int in_interface_array (char * name, char ** interfaces, int count)
{
  int i;
  for (i = 0; i < count; i++)
    /* only check that the first |name| characters are the same */
    if (strncmp (name, interfaces [i], strlen (name)) == 0)
      return 1;
  return 0;
}

static char * interface_extra (struct ifaddrs * next)
{
  if (next->ifa_addr->sa_family == AF_INET) /* || when add ipv6 to abc-ip.c
      (next->ifa_addr->sa_family == AF_INET6)) */
    return "ip";
  if (strncmp (next->ifa_name, "wlan", 4) == 0) {
    if (geteuid () == 0)
      return "wifi";
    else
      return ""; /* don't use "wifi,nm" for now, hasn't been thought through */
  }
  return "";
}

static int default_interfaces (char * * * interfaces_p)
{
  *interfaces_p = NULL;
  struct ifaddrs * ap;
  if (getifaddrs (&ap) != 0) {
    perror ("getifaddrs");
    return 0;
  }
  int count = 0;
  int length = 0;
  struct ifaddrs * next = ap;
  /* compute the buffer size needed to store all interface information */
  while (next != NULL) {
    if (is_bc_interface (next)) {
      int extra_len = strlen (interface_extra (next));
      if (extra_len != 0) {
        count++; /* and add interface/extra and the null char */
        length += strlen (next->ifa_name) + 1 + extra_len + 1;
      }
    }
    next = next->ifa_next;
  }
  int size = count * sizeof (char *) + length;
  *interfaces_p = malloc_or_fail (size, "default_interfaces");
  char * * interfaces = *interfaces_p;
  /* copy the names/extra to the malloc'd space after the pointers */
  char * write_to = ((char *) (interfaces + count));
  int index = 0;
  int accept_non_ip;  /* favor /ip over /wifi, so on first pass only take ip */
  for (accept_non_ip = 0; accept_non_ip < 2; accept_non_ip++) {
    next = ap;
    while (next != NULL) {
      char * extra = interface_extra (next);
      if ((! in_interface_array (next->ifa_name, interfaces, index)) &&
          (is_bc_interface (next)) &&
          (strlen (extra) != 0) &&
          ((accept_non_ip) || (strcmp (extra, "ip") == 0))) {
        interfaces [index++] = write_to;
        strcpy (write_to, next->ifa_name);
        strcat (write_to, "/");
        strcat (write_to, interface_extra (next));
        write_to += strlen (write_to) + 1;
      }
      next = next->ifa_next;
    }
  }
  freeifaddrs (ap);
  return index;
}

static void find_path (char * arg, char ** path, char ** program)
{
  char * slash = rindex (arg, '/');
  if (slash == NULL) {
    *path = ".";
    *program = arg;
  } else {
    *slash = '\0';
    *path = arg;
    *program = slash + 1;
  }
}

int astart_main (int argc, char ** argv)
{
  log_to_output (get_option ('v', &argc, argv));
  int alen = strlen (argv [0]);
  char * path;
  char * pname;
  find_path (argv [0], &path, &pname);
  if (strstr (pname, "stop") != NULL) {
    daemon_name = "astop";
    stop_all ();   /* just stop */
    return 0;
  }
  /* printf ("astart path is %s\n", path); */
  pid_t astart_pid = getpid ();

  /* two pipes from ad to alocal and back, plus */
  /* two pipes from ad to aip and back */
#define NUM_FIXED_PIPES		4
  /* two pipes from ad to each abc and back */
#define NUM_INTERFACE_PIPES	2 
  char ** interfaces = NULL;
  int i;
  int num_interfaces = argc - 1;
  if ((argc > 1) && (strncmp (argv [1], "def", 3) == 0))
    num_interfaces = default_interfaces (&interfaces);
  else if (argc == 1)
    num_interfaces = 0;
  int num_pipes = NUM_FIXED_PIPES + NUM_INTERFACE_PIPES * num_interfaces;
  /* note: two file descriptors (ints) per pipe */
  int * pipes = malloc_or_fail (num_pipes * 2 * sizeof (int), "astart pipes");
  init_pipes (pipes, num_pipes);
  int * rpipes = pipes;
  int * wpipes = pipes + num_pipes;
  pid_t * abc_pids =
    malloc_or_fail (num_interfaces * sizeof (pid_t), "abc pids");

  /* in case we are root, start abc first, then become non-root, and
   * only after we become non-root start the other daemons */
  for (i = 0; i < num_interfaces; i++) {
    char * interface;
    if (interfaces != NULL)
      interface = interfaces [i];
    else
      interface = argv [i + 1];
    printf ("calling abc %s\n", interface);
    my_call_abc (argv [0], alen, "abc", rpipes [2 * i + 4], wpipes [2 * i + 5],
                 rpipes [2 * i + 5], wpipes [2 * i + 4],
                 interface, abc_pids + i, astart_pid);
  }
  make_root_other (0); /* if we were root, become the caller or allnet/nobody */

#ifdef PRODUCTION_CODE
  if (! verbose) {
    /* to go into the background, close all standard file descriptors.
     * use -v or comment this out if trying to debug to stdout/stderr */
    close (0);
    close (1);
    close (2);
  }
#endif /* PRODUCTION_CODE */

  int pid_fd = open (pid_file_name (),
                     O_WRONLY | O_TRUNC | O_CREAT | O_CLOEXEC, 0644);
  if (pid_fd < 0) {
    perror ("open");
    printf ("unable to write pids to %s\n", pid_file_name ());
    stop_all ();
    exit (1);
  }
  for (i = 0; i < num_interfaces; i++)
    print_pid (pid_fd, abc_pids [i]);

  init_log ("astart");  /* now we can do logging */
  snprintf (log_buf, LOG_SIZE, "astart called with %d arguments\n", argc);
  log_print ();
  for (i = 0; i < argc + 1; i++) {
    snprintf (log_buf, LOG_SIZE, "argument %d: %s\n", i, argv [i]);
    log_print ();
  }
  for (i = 0; i < num_interfaces; i++) {
    snprintf (log_buf, LOG_SIZE, "called abc on interface %d: %s\n",
              i, interfaces [i]);
    log_print ();
  }

  /* start ad */
  my_call_ad (argv [0], alen, num_pipes, rpipes, wpipes, pid_fd, astart_pid);
  /* my_call_ad closed half the pipes and put them in the front of the arrays */
  num_pipes = num_pipes / 2;

  /* start all the other programs */
  my_call_alocal (argv [0], alen, rpipes [0], wpipes [0], pid_fd, astart_pid);
  my_call_aip (argv [0], alen, "aip", rpipes [1], wpipes [1],
               AIP_UNIX_SOCKET, pid_fd, astart_pid);

  /* ad, alocal, aip, and the abc's don't need signal handlers -- if any
   * of them goes down, the pipes are closed and everyone else goes down too
   * but if the other daemons go down, they should explicitly shut
   * down all the processes listed in the pid file */
  setup_signal_handler (1);
  my_call1 (argv [0], alen, "adht", adht_main, pid_fd, astart_pid);
  my_call1 (argv [0], alen, "acache", acache_main, pid_fd, astart_pid);
  my_call1 (argv [0], alen, "traced", traced_main, pid_fd, astart_pid);
  my_call1 (argv [0], alen, "keyd", keyd_main, pid_fd, astart_pid);
  my_call1 (argv [0], alen, "keygen", keyd_generate, pid_fd, astart_pid);

#ifdef WAIT_FOR_CHILD_TERMINATION
  int status;
  pid_t child = wait (&status);  /* wait for one of the children to terminate */
  snprintf (log_buf, LOG_SIZE, "child %d terminated, exiting\n", child);
  log_print ();
#endif /* WAIT_FOR_CHILD_TERMINATION */
  return 1;
}

#ifndef __IPHONE_OS_VERSION_MIN_REQUIRED

int main (int argc, char ** argv)
{
  return astart_main (argc, argv);
}

#endif /* __IPHONE_OS_VERSION_MIN_REQUIRED */
