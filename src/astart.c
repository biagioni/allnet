/* astart.c: start all the processes used by the allnet daemon */
/* takes as argument the interface(s) on which to start
 * sending and receiving broadcast packets */
/* in the future this may be automated or from config file */
/* (since the config file should tell us the bandwidth on each interface) */
/* alternately, if the single program is named astop or the single argument
 * is "stop", stops running ad, as long as the pids are in
 * /var/run/allnet-pids or /tmp/allnet-pids */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/types.h>
#include <netinet/in.h>

#include "lib/util.h"
#include "lib/log.h"
#include "lib/packet.h"


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
    if (pipe (pipes + i * 2) < 0) {
      perror ("pipe");
      printf ("error creating pipe set %d\n", i);
      snprintf (log_buf, LOG_SIZE, "error creating pipe set %d\n", i);
      log_print ();
      exit (1);
    }
    set_nonblock (pipes [i * 2]);
    set_nonblock (pipes [i * 2 + 1]);
    snprintf (log_buf, LOG_SIZE, "pipe [%d/%d] is read %d write %d\n",
              i * 2, i * 2 + 1, pipes [i * 2], pipes [i * 2 + 1]);
    log_print ();
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

static void exec_error (char * executable, pid_t ad, pid_t parent)
{
  perror ("execv");
  printf ("error executing %s\n", executable);
  static char buf [100000];
  char * pwd = getcwd (buf, sizeof (buf));
  printf ("current directory is %s\n", pwd);
  if (ad > 0)
    kill (ad, SIGTERM);
  if (parent > 0)
    kill (parent, SIGTERM);
  exit (1);
}

static void my_exec0 (char * path, char * program, int fd, pid_t ad)
{
  pid_t self = getpid ();
  pid_t child = fork ();
  if (child == 0) {
    char * args [3];
    args [0] = make_program_path (path, program);
    args [1] = NULL;
    args [2] = NULL;  /* in case we have -v */
    if (allnet_global_debugging)
      args [1] = "-v";
    snprintf (log_buf, LOG_SIZE, "calling %s %s\n", args [0],
              ((allnet_global_debugging) ? args [1] : ""));
    log_print ();
    execv (args [0], args);    /* should never return! */
    exec_error (args [0], ad, self);
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

static void my_exec_alocal (char * path, char * program, int * pipes, int fd,
                            pid_t ad)
{
  pid_t self = getpid ();
  pid_t child = fork ();
  if (child == 0) {
    char * args [5];
    args [0] = make_program_path (path, program);
    int i = 1;
    if (allnet_global_debugging)
      args [i++] = "-v";
    args [i++] = itoa (pipes [0]);
    args [i++] = itoa (pipes [3]);
    args [i++] = NULL;
    snprintf (log_buf, LOG_SIZE, "calling %s %s %s %s\n",
              args [0], args [1], args [2],
              ((allnet_global_debugging) ? args [3] : ""));
    log_print ();
    close (pipes [1]);
    close (pipes [2]);
    execv (args [0], args);    /* should never return! */
    exec_error (args [0], ad, self);
  } else {  /* parent, close the child pipes */
    print_pid (fd, child);
    snprintf (log_buf, LOG_SIZE, "parent called %s %d %d, closed %d %d\n",
              program, pipes [0], pipes [3], pipes [0], pipes [3]);
    log_print ();
    while (! connect_to_local())
      usleep (10 * 1000);
    close (pipes [0]);
    close (pipes [3]);
    pipes [0] = -1;
    pipes [3] = -1;
  }
}

static void my_exec3 (char * path, char * program, int * pipes, char * extra,
                      int fd, pid_t ad)
{
  pid_t self = getpid ();
  pid_t child = fork ();
  if (child == 0) {
    char * args [6];
    args [0] = make_program_path (path, program);
    int i = 1;
    if (allnet_global_debugging)
      args [i++] = "-v";
    args [i++] = itoa (pipes [0]);
    args [i++] = itoa (pipes [3]);
    args [i++] = extra;
    args [i++] = NULL;
    close (pipes [1]);
    close (pipes [2]);
    snprintf (log_buf, LOG_SIZE, "calling %s %s %s %s %s\n",
              args [0], args [1], args [2], args [3],
              ((allnet_global_debugging) ? args [4] : ""));
    log_print ();
    execv (args [0], args);
    exec_error (args [0], ad, self);
  } else {  /* parent, close the child pipes */
    print_pid (fd, child);
    close (pipes [0]);
    close (pipes [3]);
    snprintf (log_buf, LOG_SIZE, "parent called %s %d %d %s, closed %d %d\n",
              program, pipes [0], pipes [3], extra, pipes [0], pipes [3]);
    log_print ();
  }
}

static pid_t my_exec_ad (char * path, int * pipes, int num_pipes, int fd)
{
  int i;
  pid_t self = getpid ();
  pid_t child = fork ();
  if (child == 0) {
    /* ad takes as args the number of pipe pairs, then the actual pipe fds */
    int num_args = 2 /* program + number */ + num_pipes + 1 /* NULL */ ;
    char * * args = malloc_or_fail (num_args * sizeof (char *),
                                    "astart ad args");
    args [0] = make_program_path (path, "ad");
    int off = 0;
    if (allnet_global_debugging)
      args [++off] = "-v";
    args [1 + off] = itoa (num_pipes / 2);
    int n = snprintf (log_buf, LOG_SIZE, "calling %s %s ", args [0], args [1]);
    if (allnet_global_debugging)
      n += snprintf (log_buf, LOG_SIZE, "%s ", args [2]);
    /* the first num_pipes args are set to the read/write sides of the first
     * num_pipes */
    for (i = 0; i < num_pipes / 2; i++) {
      args [2 + i * 2     + off] = itoa (pipes [4 * i + 2]);
      args [2 + i * 2 + 1 + off] = itoa (pipes [4 * i + 1]);
      close (pipes [4 * i    ]);
      close (pipes [4 * i + 3]);
      n += snprintf (log_buf + n, LOG_SIZE - n,
                     "%s %s ", args [2 + i * 2], args [2 + i * 2 + 1]);
    }
    log_print ();
    args [num_args - 1 + off] = NULL;
    execv (args [0], args);
    exec_error (args [0], 0, self);
  } else {  /* parent, close the child pipes */
    print_pid (fd, child);
    for (i = 0; i < num_pipes / 2; i++) {
      close (pipes [4 * i + 1]);
      close (pipes [4 * i + 2]);
      pipes [4 * i + 1] = -1;
      pipes [4 * i + 2] = -1;
    }
  }
  return child;
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

static int stop_all ()
{
  char * fname = pid_file_name ();
  int fd = open (fname, O_RDONLY, 0);
  if (fd < 0) {
    printf ("unable to stop allnet daemon, missing pid file %s\n", fname);
    printf ("running pkill bin/ad\n");
    execlp ("pkill", "pkill", "-f", "bin/ad", ((char *)NULL));
    /* execl should never return */
    printf ("unable to pkill\n");
/*
    if (geteuid () == 0)
      printf ("if it is running, perhaps it was started as a user process\n");
    else
      printf ("if it is running, perhaps it was started as a root process\n");
*/
    return 1;
  }
  printf ("stopping allnet daemon\n");
  int pid;
  while ((pid = read_pid (fd)) > 0)
    kill (pid, SIGINT);
  close (fd);
  unlink (fname);
  unlink (AIP_UNIX_SOCKET);
  return 0;
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

  char * path;
  char * pname;
  find_path (argv [0], &path, &pname);
  if (strstr (pname, "stop") != NULL)
    return stop_all ();   /* just stop */
  /* printf ("astart path is %s\n", path); */

  init_log ("astart");  /* only do logging in astart, not in astop */
  snprintf (log_buf, LOG_SIZE, "astart called with %d arguments\n", argc);
  log_print ();
  /* two pipes from ad to alocal and back, plus */
  /* two pipes from ad to aip and back */
#define NUM_FIXED_PIPES		4
  /* two pipes from ad to each abc and back */
#define NUM_INTERFACE_PIPES	2 
  int num_interfaces = argc - 1;
  int num_pipes = NUM_FIXED_PIPES + NUM_INTERFACE_PIPES * num_interfaces;
  int * pipes = malloc_or_fail (num_pipes * 2 * sizeof (int), "astart pipes");
  init_pipes (pipes, num_pipes);

  int pid_fd = open (pid_file_name (),
                     O_WRONLY | O_TRUNC | O_CREAT | O_CLOEXEC, 0600);
  if (pid_fd < 0) {
    perror ("open");
    snprintf (log_buf, LOG_SIZE, "unable to write pids to %s\n",
              pid_file_name ());
    log_print ();
    return 1;
  }

  /* start ad */
  pid_t ad_pid = my_exec_ad (path, pipes, num_pipes, pid_fd);

  /* start all the other programs */
  my_exec_alocal (path, "alocal", pipes, pid_fd, ad_pid);
  my_exec3 (path, "aip", pipes + 4, AIP_UNIX_SOCKET, pid_fd, ad_pid);
  int i;
  for (i = 0; i < num_interfaces; i++) {
    snprintf (log_buf, LOG_SIZE, "starting abc [%d/%d] %s\n",
              i, num_interfaces, argv [i + 1]);
    log_print ();
    my_exec3 (path, "abc", pipes + 8 + (4 * i), argv [i + 1], pid_fd, ad_pid);
  }
  my_exec0 (path, "adht", pid_fd, ad_pid);
  my_exec0 (path, "traced", pid_fd, ad_pid);
  my_exec0 (path, "acache", pid_fd, ad_pid);
  my_exec0 (path, "keyd", pid_fd, ad_pid);
  return 0;
}
