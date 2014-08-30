/* allnet.c: start all the processes used by the allnet daemon */
/* takes as argument the interface(s) on which to start
 * sending and receiving broadcast packets */
/* in the future this may be automated or from config file */
/* (since the config file should tell us the bandwidth on each interface) */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <netinet/in.h>

#include "lib/util.h"
#include "lib/log.h"
#include "lib/packet.h"

extern void ad_main (int npipes, int * rpipes, int * wpipes);
extern void alocal_main (int pipe1, int pipe2);
extern void aip_main (int pipe1, int pipe2, char * fname);
extern void abc_main (int pipe1, int pipe2, const char * fname,
                        const char * iface_type, const char * iface_type_args);
static void abc_main_wrapper (int pipe1, int pipe2, char * fname, char * iface_type) {
  abc_main (pipe1, pipe2, fname, iface_type, NULL);
}
extern void adht_main (char * pname);
extern void acache_main (char * pname);
extern void traced_main (char * pname);
extern void keyd_main (char * pname);

/* global debugging variable -- if 1, expect more debugging output */
/* set in main */
int allnet_global_debugging = 0;

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

static char * itoa (int n)
{
  char * result = malloc (12);  /* plenty of bytes, easier than being exact */
  snprintf (result, 10, "%d", n);
  return result;
}

static void print_pid (int fd, int pid)
{
  char * buffer = itoa (pid);
  int len = strlen (buffer);
  if (write (fd, buffer, len) != len)
    perror ("pid file write");
  buffer [0] = '\n';
  if (write (fd, buffer, 1) != 1)
    perror ("pid file newline write");
  free (buffer);
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
  int is_root = (geteuid () == 0);
  if (is_root)
    return "/var/run/allnet-pids";
  else
    return "/tmp/allnet-pids";
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
      snprintf (log_buf, LOG_SIZE, "weird result from pid file %d\n", result);
      log_print ();
      result = -1;  /* start over */
    }
  }
  return -1;
}

#define AIP_UNIX_SOCKET		"/tmp/allnet-addrs"

static void stop_all (int signal)
{
  char * fname = pid_file_name ();
  int fd = open (fname, O_RDONLY, 0);
  if (fd < 0) {
    if ((signal > -1) && (signal != 2)) {
      printf ("%d: unable to stop allnet daemon, missing pid file %s\n",
              signal, fname);
      printf ("running pkill bin/ad\n");
    }
    execlp ("pkill", "pkill", "-f", "bin/ad", ((char *)NULL));
    /* execl should never return */
    printf ("unable to pkill\n");
/*
    if (geteuid () == 0)
      printf ("if it is running, perhaps it was started as a user process\n");
    else
      printf ("if it is running, perhaps it was started as a root process\n");
*/
    return;
  }
  if (signal > -1)
    printf ("stopping allnet daemon\n");
  int pid;
  while ((pid = read_pid (fd)) > 0)
    kill (pid, SIGINT);
  close (fd);
  unlink (fname);
  unlink (AIP_UNIX_SOCKET);
}
/* the following should be all the signals that could terminate a process */
/* list taken from signal(7) */
/* commented-out signals gave compiler errors */
static int terminating_signals [] =
  { SIGHUP, SIGINT, SIGQUIT, SIGILL, SIGABRT, SIGFPE, /* SIGKILL, */
    SIGSEGV, SIGPIPE, SIGALRM, SIGTERM, SIGUSR1, SIGUSR2,
    SIGBUS, 
#ifndef __APPLE__
    SIGPOLL,
#endif /* __APPLE__ */
    SIGPROF, SIGSYS, SIGTRAP, SIGVTALRM,
    SIGXCPU, SIGXFSZ,
    SIGIOT, /* SIGEMT, */ SIGIO
#ifndef __APPLE__
    , SIGSTKFLT, SIGPWR,
    /* SIGINFO, SIGLOST, */ SIGUNUSED
#endif /* __APPLE__ */
  };

static void setup_signal_handler (int set)
{
  struct sigaction sa;
  if (set)
    sa.sa_handler = stop_all; /* terminate other processes when we are killed */
  else
    sa.sa_handler = SIG_DFL;  /* whatever the default is */
  sigfillset (&(sa.sa_mask)); /* block all signals */
  sa.sa_flags = SA_NOCLDSTOP | SA_NOCLDWAIT | SA_RESTART;
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

static void child_return (char * executable, pid_t ad, pid_t parent)
{
  printf ("%s completed\n", executable);
  static char buf [100000];
  char * pwd = getcwd (buf, sizeof (buf));
  printf ("current directory is %s\n", pwd);
  if (ad > 0)
    kill (ad, SIGTERM);
  if (parent > 0)
    kill (parent, SIGTERM);
  stop_all (-1);
  exit (1);
}

static void my_call1 (char * argv, int alen, char * program,
                      void (*run_function) (char *),
                      int fd, pid_t ad)
{
  pid_t self = getpid ();
  pid_t child = fork ();
  if (child == 0) {
    replace_command (argv, alen, program);
    snprintf (log_buf, LOG_SIZE, "calling %s\n", program);
    log_print ();
    run_function (argv);
    child_return (program, ad, self);
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

static void my_call_alocal (char * argv, int alen, int rpipe, int wpipe,
                            int fd, pid_t ad)
{
  char * program = "alocal";
  pid_t self = getpid ();
  pid_t child = fork ();
  if (child == 0) {
    replace_command (argv, alen, program);
    snprintf (log_buf, LOG_SIZE, "calling %s (%d %d)\n", program, rpipe, wpipe);
    log_print ();
    /* close the pipes we don't use in the child */
    alocal_main (rpipe, wpipe);
    child_return (program, ad, self);
  } else {  /* parent, close the child pipes */
    close (rpipe);
    close (wpipe);
    print_pid (fd, child);
    snprintf (log_buf, LOG_SIZE, "parent called %s %d %d, closed %d %d\n",
              program, rpipe, wpipe, rpipe, wpipe);
    log_print ();
    while (! connect_to_local())
      usleep (10 * 1000);
  }
}

static void my_call3 (char * argv, int alen, char * program,
                      void (*run_function) (int, int, char *),
                      int rpipe, int wpipe, char * extra, int fd, pid_t ad)
{
  pid_t self = getpid ();
  pid_t child = fork ();
  if (child == 0) {
    replace_command (argv, alen, program);
    snprintf (log_buf, LOG_SIZE, "calling %s %d %d %s\n",
              program, rpipe, wpipe, extra);
    log_print ();
    run_function (rpipe, wpipe, extra);
    child_return (program, ad, self);
  } else {  /* parent, close the child pipes */
    close (rpipe);
    close (wpipe);
    print_pid (fd, child);
    snprintf (log_buf, LOG_SIZE, "parent called %s %d %d %s, closed %d %d\n",
              program, rpipe, wpipe, extra, rpipe, wpipe);
    log_print ();
  }
}

static void my_call4 (char * argv, int alen, char * program,
                      void (*run_function) (int, int, char *, char *),
                      int rpipe, int wpipe, char * extra, char * extra2,
                      int fd, pid_t ad)
{
  pid_t self = getpid ();
  pid_t child = fork ();
  if (child == 0) {
    replace_command (argv, alen, program);
    snprintf (log_buf, LOG_SIZE, "calling %s %d %d %s %s\n",
              program, rpipe, wpipe, extra, extra2);
    log_print ();
    run_function (rpipe, wpipe, extra, extra2);
    child_return (program, ad, self);
  } else {  /* parent, close the child pipes */
    print_pid (fd, child);
    close (rpipe);
    close (wpipe);
    snprintf (log_buf, LOG_SIZE, "parent called %s %d %d %s %s, closed %d %d\n",
              program, rpipe, wpipe, extra, extra2, rpipe, wpipe);
    log_print ();
  }
}

static pid_t my_call_ad (char * argv, int alen, int num_pipes, int * rpipes,
                         int * wpipes, int fd)
{
  int i;
  pid_t self = getpid ();
  pid_t child = fork ();
  if (child == 0) {
    char * program = "ad";
    replace_command (argv, alen, program);
    snprintf (log_buf, LOG_SIZE, "calling %s\n", program);
    log_print ();
    /* close the pipes we don't use in the child */
    /* and compress the rest to the start of the respective arrays */
    for (i = 0; i < num_pipes / 2; i++) {
      close (rpipes [2 * i    ]);
      close (wpipes [2 * i + 1]);
      rpipes [i] = rpipes [2 * i + 1];
      wpipes [i] = wpipes [2 * i    ];  /* may be the same */
    }
/*  for (i = 0; i < num_pipes / 2; i++)
      printf ("pipes [%d] = %d/%d\n", i, rpipes [i], wpipes [i]); */
    ad_main (num_pipes / 2, rpipes, wpipes);
    child_return (program, 0, self);
  } else {  /* parent, close the child pipes */
    print_pid (fd, child);
    for (i = 0; i < num_pipes / 2; i++) {
      close (rpipes [2 * i + 1]);
      close (wpipes [2 * i    ]);
      rpipes [i] = rpipes [2 * i    ];  /* may be the same */
      wpipes [i] = wpipes [2 * i + 1];
    }
  }
  return child;
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

int main (int argc, char ** argv)
{
  int verbose = get_option ('v', &argc, argv);
  if (verbose)
    allnet_global_debugging = verbose;
  int alen = strlen (argv [0]);
  char * path;
  char * pname;
  find_path (argv [0], &path, &pname);
  /* printf ("astart path is %s\n", path); */

  init_log ("astart");  /* only do logging in astart, not in astop */
  snprintf (log_buf, LOG_SIZE, "astart called with %d arguments\n", argc);
  log_print ();
  setup_signal_handler (1);

  /* two pipes from ad to alocal and back, plus */
  /* two pipes from ad to aip and back */
#define NUM_FIXED_PIPES		4
  /* two pipes from ad to each abc and back */
#define NUM_INTERFACE_PIPES	2 
  int num_interfaces = argc - 1;
  int num_pipes = NUM_FIXED_PIPES + NUM_INTERFACE_PIPES * num_interfaces;
  /* note: two file descriptors (ints) per pipe */
  int * pipes = malloc_or_fail (num_pipes * 2 * sizeof (int), "astart pipes");
  init_pipes (pipes, num_pipes);
  int * rpipes = pipes;
  int * wpipes = pipes + num_pipes;

  int pid_fd = open (pid_file_name (),
                     O_WRONLY | O_TRUNC | O_CREAT | O_CLOEXEC, 0600);
  if (pid_fd < 0) {
    perror ("open");
    snprintf (log_buf, LOG_SIZE, "unable to write pids to %s\n",
              pid_file_name ());
    log_print ();
    return 1;
  }
  if (! verbose) {
    /* to go into the background, close all standard file descriptors.
     * use -v or comment this out if trying to debug to stdout/stderr */
    close (0);
    close (1);
    close (2);
  }

  /* start ad */
  pid_t ad_pid = my_call_ad (argv [0], alen, num_pipes, rpipes, wpipes, pid_fd);
  /* my_call_ad closed half the pipes and put them in the front of the arrays */
  num_pipes = num_pipes / 2;

  /* start all the other programs */
  my_call_alocal (argv [0], alen, rpipes [0], wpipes [0], pid_fd, ad_pid);
  my_call3 (argv [0], alen, "aip", aip_main, rpipes [1], wpipes [1],
            AIP_UNIX_SOCKET, pid_fd, ad_pid);
  int i;
  for (i = 0; i < num_interfaces; i++) {
    snprintf (log_buf, LOG_SIZE, "starting abc [%d/%d] %s\n",
              i, num_interfaces, argv [i + 1]);
    log_print ();
    my_call4 (argv [0], alen, "abc", abc_main_wrapper,
              rpipes [i + 2], wpipes [i + 2],
              argv [i + 1], NULL, pid_fd, ad_pid);
  }
  my_call1 (argv [0], alen, "adht", adht_main, pid_fd, ad_pid);
  my_call1 (argv [0], alen, "acache", acache_main, pid_fd, ad_pid);
  my_call1 (argv [0], alen, "traced", traced_main, pid_fd, ad_pid);
  my_call1 (argv [0], alen, "keyd", keyd_main, pid_fd, ad_pid);

#ifdef WAIT_FOR_CHILD_TERMINATION
  int status;
  pid_t child = wait (&status);  /* wait for one of the children to terminate */
  snprintf (log_buf, LOG_SIZE, "child %d terminated, exiting\n", child);
  log_print ();
#endif /* WAIT_FOR_CHILD_TERMINATION */
  return 1;
}
