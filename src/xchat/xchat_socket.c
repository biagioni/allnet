/* xchat_socket.c: send and receive xchat messages over a socket */

#if defined(WIN32) || defined(WIN64)
#ifndef WINDOWS_ENVIRONMENT
#define WINDOWS_ENVIRONMENT
#define WINDOWS_ENVIRONMENT
#endif /* WINDOWS_ENVIRONMENT */
#endif /* WIN32 || WIN64 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#ifdef WINDOWS_ENVIRONMENT
#include <windows.h>
#endif /* WINDOWS_ENVIRONMENT */

#include "lib/packet.h"
#include "lib/pipemsg.h"
#include "lib/util.h"
#include "lib/priority.h"
#include "lib/allnet_log.h"
#include "lib/trace_util.h"
#include "lib/configfiles.h"
#include "chat.h"
#include "cutil.h"
#include "retransmit.h"
#include "xcommon.h"
#include "message.h"

/* messages have a length, time, code, peer name, and text of the message. */
/* length (4 bytes, big-endian order) includes everything.
 * time (6 bytes, big-endian order) is the time of original transmission,
 *   in the os's local epoch
 * code is 1 byte,
 * - code value 0 identifies a data message: the peer name and the
 *   message are null-terminated
 * when sent from the GUI to this code, this code replies
 * with a message of type 5, CODE_SEQ */
/* to establish the connection, the GUI initially sends an arbitrary
 * message (really, "hello world\n") */
#define	CODE_DATA_MESSAGE	0
/* - code value 1 identifies a broadcast message: the peer name and the
 *   message are null-terminated */
#define	CODE_BROADCAST_MESSAGE	1
/* - code value 2 identifies a new contact, stored in the peer name.  In
 *   messages received by xchat_socket, this is followed by one or two
 *   null-terminated secret strings. */
#define	CODE_NEW_CONTACT	2
/* - code value 3 identifies an ahra, stored in the peer name, to which
 *   we want to subscribe or have subscribed */
#define	CODE_AHRA		3
/* - code value 4 identifies a seq.  text of the message is an 8-byte seq.
 *   sent from the GUI to xchat_socket */
#define CODE_SEQ                4
/* - code value 5 identifies an ack.  text of the message is an 8-byte ack */
#define CODE_ACK                5
/* - code value 6 is a trace request.  text is a 1-byte hop count */
#define CODE_TRACE              6
/* - code value 7 is a trace response.  text is the text of the response */
#define CODE_TRACE_RESPONSE     7

/* protocol: s (server) = xchat_socket, c (client) = ui
 * data:        s -> c: message received from peer (server replies with seq #)
 *              c -> s: message sent to peer (server returns seq to client)
 * broadcast:   s -> c: broadcast received
 *              c -> s: currently not supported (should be: send broadcast)
 * new contact: s -> c: send own key
 *              c -> s: received key from peer
 * ahra:        s -> c: confirm subscription
 *              c -> s: subscribe to ahra
 * ack:         s -> c: inbound ack received from peer
 * trace:       c -> s: trace request
 */

static pid_t xchat_socket_pid = -1;
static pid_t xchat_ui_pid = -1;
static pid_t trace_pid = -1;

static void kill_if_not_self (pid_t pid, const char * desc)
{
  if ((pid != -1) && (pid != getpid ())) {
/* printf ("process %d killing %s process %d\n", getpid (), desc, pid); */
    kill (pid, SIGKILL);
  }
}

/* exit code should be 0 for normal exit, 1 for error exit */
static void stop_chat_and_exit (int exit_code)
{
  kill_if_not_self (xchat_socket_pid, "xchat_socket");
  kill_if_not_self (xchat_ui_pid, "xchat_ui");
  kill_if_not_self (trace_pid, "trace");
  exit (exit_code);
}

static void send_message (int sock, struct sockaddr * sap, socklen_t slen,
                          int code, time_t time, const char * peer,
                          const char * message)
{
  int plen = strlen (peer) + 1;     /* include the null character */
  int mlen = 8;                     /* fixed size for SEQ and ACK */
  if ((code != CODE_SEQ) && (code != CODE_ACK))  /* null terminated */
    mlen = strlen (message) + 1;    /* include the null character */
  int length = 11 + plen + mlen;
  int n;
  char buf [ALLNET_MTU];
  if (length > ALLNET_MTU) {
    printf ("error: wanting to send 5 + %d + %d = %d, MTU is %d\n",
            plen, mlen, length, ALLNET_MTU);
    return;
  }
  writeb32 (buf, length);
  writeb48 (buf + 4, time + ALLNET_Y2K_SECONDS_IN_UNIX);
  buf [10] = code;
  memcpy (buf + 11, peer, plen);
  memcpy (buf + 11 + plen, message, mlen);
#ifndef MSG_NOSIGNAL  /* undefined on mac and windows */
#define MSG_NOSIGNAL	0    /* don't provide it if it is not supported */
#endif /* MSG_NOSIGNAL */
  n = sendto (sock, buf, length, MSG_DONTWAIT | MSG_NOSIGNAL, sap, slen);
  if ((n != length) && ((errno == EAGAIN) || (errno == EWOULDBLOCK)))
    return;  /* socket is busy -- should never be, but who knows */
  if (n != length) {
    perror ("send");
    printf ("error: tried to send %d, only sent %d bytes on socket\n",
            length, n);
    printf ("sendto (%d, %p, %d, %d, %p, %d)\n",
            sock, buf, length, MSG_DONTWAIT, sap, slen);
    stop_chat_and_exit (0);
  }
/* print_buffer (buf, length, "sent", 20, 1); */
}

static void send_seq_ack (int sock, struct sockaddr * sap, socklen_t slen,
                          int code, time_t time, const char * peer,
                          long long int seq_ack)
{
  if ((code != CODE_SEQ) && (code != CODE_ACK))  /* null terminated */
    printf ("error: illegal code %d in send_seq_ack\n", code);
  char buf [8];
  writeb64 (buf, seq_ack);
  send_message (sock, sap, slen, code, time, peer, buf);
}

/* return the message length if a message was received, and 0 otherwise */
/* both peer and message must have length ALLNET_MTU or more */
static int recv_message (int sock, int * code, time_t * time,
                         char * peer, char * message, char * extra,
                         struct sockaddr_in * expected_from,
                         socklen_t expected_len)
{
  *peer = '\0';
  *message = '\0';
  *extra = '\0';
  char buf [ALLNET_MTU * 10];
  struct sockaddr_storage from_s;
  socklen_t from_len = sizeof (from_s);
  struct sockaddr * sap = (struct sockaddr *) (&from_s);
  int n = recvfrom (sock, buf, sizeof (buf), MSG_DONTWAIT, sap, &from_len);
  if ((n < 0) && ((errno == EAGAIN) || (errno == EWOULDBLOCK)))
    return 0;
  if (n == 0) {    /* peer closed the socket -- is this possible w/ UDP? */
    printf ("xchat_socket: error, received peer shutdown, exiting\n");
    stop_chat_and_exit (0);
  }
  if (n < 9) {
    perror ("recv");
    printf ("error: received %d bytes on unix socket\n", n);
    stop_chat_and_exit (1);
  }
  if (expected_len != from_len) {
    printf ("xchat_socket recv_message expected sockaddr length %u, got %u\n",
            expected_len, from_len);
    print_buffer ((char *) (&from_s), from_len,
                  "xchat_socket recv_message received sockaddr", from_len, 1);
    print_buffer ((char *) (expected_from), expected_len,
                  "xchat_socket recv_message expected sockaddr", from_len, 1);
    return 0;
  }
  if (memcmp (&from_s, expected_from, expected_len) != 0) {
    print_buffer ((char *) (&from_s), from_len,
                  "xchat_socket recv_message received sockaddr", from_len, 1);
    print_buffer ((char *) (expected_from), expected_len,
                  "xchat_socket recv_message expected sockaddr", from_len, 1);
    return 0;
  }
  int len, plen, mlen;
  time_t sent_time;
  char * msg;
  len = readb32 (buf);
  if (len != n) {
    printf ("error: received %d bytes but length is %d\n", n, len);
    return 0;
  }
  sent_time = readb48 (buf + 4);
  *time = sent_time;
  *code = buf [10] & 0xff;
  if ((*code != CODE_DATA_MESSAGE) && (*code != CODE_NEW_CONTACT) &&
      (*code != CODE_AHRA) && (*code != CODE_TRACE)) {
    printf ("error: received code %d but only 0, 2, 3, and 6 supported\n",
            *code);
    return 0;
  }
  if (*code == CODE_TRACE) {
    int hops = buf [11];
    /* printf ("requested trace with hop count %d\n", hops); */
    return hops;
  }
  plen = strlen (buf + 11);
  if (plen >= ALLNET_MTU) {
    printf ("error: received peer length %d but only %d is supported\n",
            plen, ALLNET_MTU - 1);
    return 0;
  }
  msg = buf + 11 + plen + 1;
  mlen = strlen (msg);
  if (mlen >= ALLNET_MTU) {
    printf ("error: received message length %d but only %d is supported\n",
            mlen, ALLNET_MTU - 1);
    return 0;
  }
  snprintf (peer, ALLNET_MTU, "%s", buf + 11);
  if (mlen > 0)
    snprintf (message, ALLNET_MTU, "%s", msg);
  else
    message [0] = '\0';
  extra [0] = '\0';
  if (((*code) == CODE_NEW_CONTACT) && (n > (mlen + (msg - buf)))) {
    /* message carries two secrets, read the second secret */
    char * secret = msg + mlen + 1;
    int elen = strlen (secret);
    if ((elen < ALLNET_MTU) && (elen + (secret - buf) < n))
      snprintf (extra, ALLNET_MTU, "%s", secret);
  }
  if ((*code) == CODE_AHRA)
    mlen = strlen (peer);
/* printf ("recv_message %d, time %ld, peer '%s', message '%s', extra '%s'\n",
*code, *time, peer, message, extra); */
  return mlen;
}

static int get_socket ()
{
  int result = socket (AF_INET, SOCK_DGRAM, 17);
  if (result < 0) {
    perror ("socket");
    stop_chat_and_exit (1);
  }
  struct sockaddr_in sin;
  sin.sin_family = AF_INET;
  sin.sin_port = XCHAT_SOCKET_PORT;
  sin.sin_addr.s_addr = htonl (INADDR_ANY);
  if (bind (result, (struct sockaddr *) (&sin), sizeof (sin)) < 0) {
    perror ("bind");
    printf ("unable to run xchat, maybe already running?\n");
    stop_chat_and_exit (1);
  }
  return result;
}

static void wait_for_connection (int sock,
                                 struct sockaddr * sap, socklen_t * slen)
{
  if (*slen < sizeof (struct sockaddr_in))
    return;
  socklen_t alen;
  struct sockaddr_in * sinp = (struct sockaddr_in *) sap;
  int bytes;
  do {
    char buf [ALLNET_MTU * 2];
    alen = *slen;
    bytes = recvfrom (sock, buf, sizeof (buf), 0, sap, &alen);
    /* printf ("got initial %d bytes\n", bytes); */
  } while ((bytes > 0) && ((sinp->sin_family != AF_INET) ||
                           (sinp->sin_addr.s_addr != htonl (INADDR_LOOPBACK))));
  *slen = alen;
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

/* return 1 if the contact is visible (no file "hidden"), 0 otherwise */
static int is_visible (const char * contact)
{
#ifdef DEBUG_PRINT
  printf ("visible %s is %d\n", contact,
          (config_file_mod_time ("xchat", "hidden") == 0));
#endif /* DEBUG_PRINT */
  return (config_file_mod_time ("xchat", "hidden") == 0);
}

/* returned value is malloc'd. */
static char * make_program_path (char * path, char * program)
{
  int size = strlen (path) + 1 + strlen (program) + 1;
  char * result = malloc (size);
  if (result == NULL) {
    printf ("error: unable to allocate %d bytes for %s/%s, aborting\n",
            size, path, program);
    stop_chat_and_exit (1);
  }
  snprintf (result, size, "%s/%s", path, program);
  return result;
}

static char * find_java_path ()
{
  static char * result = NULL;
  if (result != NULL)   /* found it before */
    return result;
  char * path = strcpy_malloc (getenv ("PATH"), "find_java_path 1");
  char * free_path = path;   /* for calls to free, free the original */
  char * colon = strchr (path, ':');
  do {
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
   We would like to rewrite it to "C:\...", replacing all / with \ */
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
                           "C:\\windows\\system32\\java",
                           "C:\\Program Files\\Java\\jdk1.8.0_40\\bin\\java" };
  unsigned int i;
  for (i = 0; i < sizeof (candidates) / sizeof (char *); i++) {
    /* printf ("trying %s\n", candidates [i]); */
    if (access (candidates [i], X_OK) == 0)
      return candidates [i];
  }
  printf ("no java runtime found, unable to run xchat\n");
  return NULL;
}

#define LOG_FILE_NAME	"xchat-java-log.txt"
#define TMP_DIR_INITIALIZER	"/tmp"
static char * tmp_dir = TMP_DIR_INITIALIZER;

static pid_t exec_java_ui (char * arg)
{
#define JAR_FILE_NAME	"AllNetUI.jar"
  char * path;
  char * pname;
/* printf ("exec_java_ui: arg is %s\n", arg); */
  find_path (arg, &path, &pname);
/* printf ("exec_java_ui: path is %s\n", path); */
  char * jarfile = make_program_path (path, JAR_FILE_NAME);
/* printf ("exec_java_ui: jarfile is %s\n", jarfile); */
  if (access (jarfile, R_OK) != 0) {
    int plen = strlen (path);
    if ((plen > 1) && (path [plen - 1] == '/'))
      path [--plen] = '\0';   /* eliminate any trailing slash */
    if ((plen > 6) && (strcmp (path + plen - 6, "/.libs") == 0)) {
      /* try without .libs */
      path [plen - 6] = '\0';
/*     printf ("exec_java_ui: new path is %s\n", path); */
      jarfile = make_program_path (path, JAR_FILE_NAME);
/*     printf ("exec_java_ui: new jarfile is %s\n", jarfile); */
    }
  }
  if (access (jarfile, R_OK) != 0) {
    perror ("access");
    printf ("unable to start Java gui %s\n", jarfile);
    stop_chat_and_exit (1);
  }
  pid_t pid = fork ();
  if (pid < 0) {
    perror ("fork");
    stop_chat_and_exit (1);
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
#ifdef DEBUG_PRINT
#ifndef PATH_MAX
#define PATH_MAX	4096
#endif /* PATH_MAX */
    char debug [PATH_MAX + 1];
    getcwd (debug, sizeof (debug));
    printf ("exec_java_ui: final jarfile is %s, current dir %s\n",
            jarfile, debug);
#endif /* DEBUG_PRINT */

/* unfortunately, we get lots of messages such as the following:
        ** (java:14856): CRITICAL **: murrine_scrollbar_get_junction: assertion 'GTK_IS_RANGE (widget)' failed
        ** (java:14856): CRITICAL **: murrine_scrollbar_visible_steppers: assertion 'GTK_IS_RANGE (widget)' failed
        (java:14856): Gtk-WARNING **: /build/gtk+2.0-KsZKkB/gtk+2.0-2.24.30/gtk/gtkwidget.c:10000: widget class `GtkSpinButton' has no property named `stepper-size'
        ** (java:14856): CRITICAL **: murrine_scrollbar_get_stepper: assertion 'GTK_IS_RANGE (widget)' failed
        (java:14856): Gtk-WARNING **: /build/gtk+2.0-KsZKkB/gtk+2.0-2.24.30/gtk/gtkwidget.c:10000: widget class `GtkSpinButton' has no property named `stepper-size'
    to avoid these messages, which don't seem to be signaling anything
    actually important, we redirect the stdout and stderr to a file in /tmp,
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
    if (log_fd >= 0) {
      dup2 (STDOUT_FILENO, log_fd);  /* write stdout to the log file */
      dup2 (STDERR_FILENO, log_fd);  /* write stderr to the log file */
      close (log_fd);  /* no longer needed as a separate fd */
    } else {
#ifdef DEBUG_PRINT
      perror ("xchat_socket unable to create or write temp file\n");
#endif /* DEBUG_PRINT */
    }
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
    stop_chat_and_exit (0);
    return 0;  /* should never return */
  } else {
    free (jarfile);
  }
  return pid;
}

static void * child_wait_thread (void * arg)
{
  int status;
  if (xchat_ui_pid != -1)
    waitpid (xchat_ui_pid, &status, 0);
  /* child has terminated, exit the entire program */
/* printf ("child_wait_thread shutting down\n"); */
  stop_chat_and_exit (0);
  return NULL;
}

struct unacked {
  long long int seq;
  int contact_index;
};

static struct unacked * unacked_seqs = NULL;
static int unacked_size = 0;
static int unacked_count = 0;

static void add_to_unacked (long long int seq, char * contact)
{
  char ** contacts = NULL;
  int ncontacts = all_contacts (&contacts);
  int contact_index = -1;
  int i;
  for (i = 0; i < ncontacts; i++)
    if (strcmp (contact, contacts [i]) == 0)
      contact_index = i;
  if ((ncontacts > 0) && (contacts != NULL))
    free (contacts);
  if (contact_index < 0) {
    printf ("xchat_socket: contact %s not found\n", contact);
    return;
  }
  for (i = 0; i < unacked_count; i++)
    if ((unacked_seqs [i].seq == seq) &&
        (unacked_seqs [i].contact_index == contact_index))
      return;
  if (unacked_count == unacked_size) {  /* reallocate */
    unacked_size += unacked_size + 2;
    int size = unacked_size * sizeof (struct unacked);
    if (unacked_seqs != NULL)
      unacked_seqs = realloc (unacked_seqs, size);
    else
      unacked_seqs = malloc (size);
    if (unacked_seqs == NULL) {
      perror ("realloc");
      printf ("error: unable to allocate %d bytes for unacked array\n", size);
      printf ("       acknowledgements will be unreliable\n");
    }
  }
  unacked_seqs [unacked_count].seq = seq;
  unacked_seqs [unacked_count].contact_index = contact_index;
  unacked_count++;
}

static void thread_for_child_completion ()
{
  pthread_t thread;
  int result = pthread_create (&thread, NULL, child_wait_thread, NULL);
  if (result != 0)
    perror ("pthread_create");
}

struct trace_thread_arg {
  int pipefd;
  int forwarding_socket;
  struct sockaddr * fwd_addr;
  socklen_t slen;
};

static void * trace_thread (void * a)
{
  struct trace_thread_arg * arg = (struct trace_thread_arg *) a;
  pid_t initial_trace_pid = trace_pid;
  char buffer [10000];
  int n;
  while ((n = read (arg->pipefd, buffer, sizeof (buffer) - 1)) > 0) {
    buffer [n] = '\0';
/* printf ("partial result of trace was '%s'\n", buffer); */
    send_message (arg->forwarding_socket, arg->fwd_addr, arg->slen,
                  CODE_TRACE_RESPONSE, 0, "trace", buffer);
  }  /* weak synchronization, but better than nothing */
  if (trace_pid == initial_trace_pid)
    trace_pid = -1;
  close (arg->pipefd);
  free (a);
  return NULL;
}

static void do_trace (int time, int hops,
                      int forwarding_socket,
                      struct sockaddr * fwd_addr, socklen_t slen)
{ 
  if (trace_pid >= 0) {
    kill (trace_pid, SIGINT);
    trace_pid = -1;
    usleep (10000);  /* wait for the process to really die */
  }
  waitpid (-1, NULL, WNOHANG);  /* harvest any pending children */
  int pipefd [2];  /* 0 is the read (parent) end, 1 is the child end */
  if ((pipe (pipefd) == 0) && ((trace_pid = fork ()) != -1)) {
    if (trace_pid == 0) {  /* child, run the trace process until killed */
      close (pipefd [0]);
      trace_pipe (pipefd [1], NULL, -1, NULL, hops, 1, 0, 0);
      close (pipefd [1]);  /* unneeded because we will exit, but logical */
printf ("trace child exiting\n");
      exit (0);
    } /* else parent, return the results to xchat */
    close (pipefd [1]);
    struct trace_thread_arg * a =
      malloc_or_fail (sizeof (struct trace_thread_arg), "trace_thread_arg");
    a->pipefd = pipefd [0];  /* closed by thread */
    a->forwarding_socket = forwarding_socket;
    a->fwd_addr = fwd_addr;
    a->slen = slen;
    pthread_attr_t attributes;
    pthread_attr_init (&attributes);
    pthread_attr_setdetachstate (&attributes, PTHREAD_CREATE_DETACHED);
    pthread_t thread;
    pthread_create (&thread, &attributes, trace_thread, (void *) a);
  } else {  /* no pipes or no fork, use trace_string */
    char * result = trace_string (tmp_dir, time, NULL, hops, 1, 0, 1);
/* printf ("result of trace was '%s'\n", result); */
    send_message (forwarding_socket, fwd_addr, slen,
                  CODE_TRACE_RESPONSE, 0, "trace", result);
    free (result);
  }
}

int main (int argc, char ** argv)
{
int ni = incomplete_key_exchanges (NULL, NULL, NULL);
if (ni > 0) {
  printf ("%d incomplete key exchange(s)\n", ni);
  int ii;
  char ** contacts = NULL;
  keyset * keys = NULL;
  int * status = NULL;
  ni = incomplete_key_exchanges (&contacts, &keys, &status);
  for (ii = 0; ii < ni; ii++)
    printf ("  %d: %s (%d, %x)\n", ii, contacts [ii], keys [ii], status [ii]);
  free (contacts);
  free (keys);
  free (status);
}
  log_to_output (get_option ('v', &argc, argv));
#ifdef WINDOWS_ENVIRONMENT
  HWND hwNd = GetConsoleWindow ();
  ShowWindow (hwNd, SW_HIDE);
#endif /* WINDOWS_ENVIRONMENT */
  xchat_socket_pid = getpid ();  /* should never change */

/*
  if (argc < 2) {
    printf ("%s should have one socket arg, and never be called directly!\n",
            argv [0]);
    return 0;
  }
  int forwarding_socket = atoi (argv [1]);
*/

  struct allnet_log * log = init_log ("xchat_socket");
  pd p = init_pipe_descriptor (log);
  int sock = xchat_init (argv [0], p);
  if (sock < 0)
    return 1;

  struct sockaddr_in fwd_addr;
  socklen_t fwd_addr_size = sizeof (fwd_addr);

  /* open the socket first, so it is ready when the UI begins execution */
  int forwarding_socket = get_socket ();
  xchat_ui_pid = exec_java_ui (argv [0]);
  wait_for_connection (forwarding_socket, (struct sockaddr *) (&fwd_addr),
                       &fwd_addr_size);
  thread_for_child_completion ();

  int timeout = 100;      /* sleep up to 1/10 second */
  char * old_contact = NULL;
  keyset old_kset = -1;
  char * key_contact = NULL;
  char * key_secret = NULL;
  char * key_secret2 = NULL;
  char kbuf1 [ALLNET_MTU];  /* key buffer to hold the contact name */
  char kbuf2 [ALLNET_MTU];  /* key buffer to hold the first secret */
  char kbuf3 [ALLNET_MTU];  /* key buffer to hold the second secret, if any */
  unsigned char kaddr [ADDRESS_SIZE];
  unsigned int kabits;
  int check_for_key = 0;
  unsigned int num_hops = 0;
  char * subscription = NULL;
  char sbuf [ALLNET_MTU];   /* subscribe buffer */
  unsigned char saddr [ADDRESS_SIZE];
  unsigned int sbits = 0;
  while (1) {
/* use temp (loop local) buffers, then copy them to kbuf* if code is 2 */
    char to_send [ALLNET_MTU];
    char peer [ALLNET_MTU];
    char extra [ALLNET_MTU];
    int code;
    time_t rtime;
    int len = recv_message (forwarding_socket, &code, &rtime, peer, to_send,
                            extra, &fwd_addr, fwd_addr_size);
    if (len > 0) {
      if (code == CODE_DATA_MESSAGE) {
        long long int seq =
          send_data_message (sock, peer, to_send, strlen (to_send));
        add_to_unacked (seq, peer);
        send_seq_ack (forwarding_socket,
                      (struct sockaddr *) (&fwd_addr), fwd_addr_size,
                      CODE_SEQ, time (NULL), peer, seq);
      } else if (code == CODE_NEW_CONTACT) {
        snprintf (kbuf1, sizeof (kbuf1), "%s", peer);
        snprintf (kbuf2, sizeof (kbuf2), "%s", to_send);
        key_contact = kbuf1;
        key_secret = kbuf2;
        normalize_secret (key_secret);
        if (strlen (extra) > 0) {
          snprintf (kbuf3, sizeof (kbuf3), "%s", extra);
          key_secret2 = kbuf3;
          normalize_secret (key_secret2);
        }
        num_hops = rtime;
printf ("sending key to peer %s/%s, secret %s/%s/%s, %d hops\n",
peer, key_contact, to_send, key_secret, key_secret2, num_hops);
        create_contact_send_key (sock, key_contact, key_secret, key_secret2,
                                 kaddr, &kabits, num_hops);
        check_for_key = 1;
      } else if (code == CODE_AHRA) { /* subscribe -- peer is only field */
        snprintf (sbuf, sizeof (sbuf), "%s", peer);
printf ("sending subscription to %s/%s\n", peer, sbuf);
        if (subscribe_broadcast (sock, sbuf, saddr, &sbits))
          subscription = sbuf;
      } else if (code == CODE_TRACE) {
        do_trace (30, 5, forwarding_socket, (struct sockaddr *) (&fwd_addr),
                  fwd_addr_size);
      } else {
        printf ("received message with code %d\n", code);
      }
    }
    char * packet;
    int pipe;
    unsigned int pri;
    int found_key = 0;
    if (check_for_key)  /* was a key received earlier? */
      found_key = key_received (sock, key_contact, key_secret, key_secret2,
                                kaddr, kabits, num_hops); 
    int found = 0;
    if (! found_key)
      found = receive_pipe_message_any (p, timeout, &packet, &pipe, &pri);
    if (found < 0) {
      printf ("xchat_socket pipe closed, exiting\n");
      stop_chat_and_exit (0);
    }
    if ((found == 0) && (! found_key)) { 
      if (old_contact != NULL) { /* timed out, request/resend any missing */
        request_and_resend (sock, old_contact, old_kset, 0);
        old_contact = NULL;
        old_kset = -1;
      }
    } else {    /* found > 0, got a packet, or found_key, got a key */
      int verified, duplicate, broadcast;
      char * peer;
      keyset kset;
      char * desc;
      char * message;
      struct allnet_ack_info acks;
      acks.num_acks = 0;  /* in case we don't call handle_packet */
      time_t mtime = 0;
      int mlen = -1;  /* found a key, or the result of handle_packet */
      if (! found_key)
        mlen = handle_packet (sock, packet, found, pri, &peer, &kset, &acks,
                              &message, &desc, &verified, &mtime, &duplicate,
                              &broadcast, key_contact, key_secret, 
                              key_secret2, kaddr, kabits, num_hops,
                              subscription, saddr, sbits);
      if ((mlen > 0) && (verified)) {
        int mtype = CODE_DATA_MESSAGE; /* data */
        if (broadcast)
          mtype = CODE_BROADCAST_MESSAGE;  /* broadcast */
        if (! duplicate) {
          struct sockaddr * sap = (struct sockaddr *) (&fwd_addr);
          if (is_visible (peer))
            send_message (forwarding_socket, sap, fwd_addr_size,
                          mtype, mtime, peer, message);
          char ** groups = NULL;
          int ngroups = member_of_groups_recursive (peer, &groups);
          if (ngroups > 0) {
            int ig;
            for (ig = 0; ig < ngroups; ig++) {
              if (is_visible (groups [ig]))
                send_message (forwarding_socket, sap, fwd_addr_size,
                              mtype, mtime, groups [ig], message);
            }
          }
          if (groups != NULL)
            free (groups);
        }
        if ((! broadcast) &&
            ((old_contact == NULL) ||
             (strcmp (old_contact, peer) != 0) || (old_kset != kset))) {
          request_and_resend (sock, peer, kset, 1);
          old_contact = peer;
          old_kset = kset;
        } else { /* same peer, do nothing */
          free (peer);
        }
        free (message);
        if (! broadcast)
          free (desc);
      } else if (mlen == -1) {   /* confirm successful key exchange */
        mtime = time (NULL);
        send_message (forwarding_socket,
                      (struct sockaddr *) (&fwd_addr), fwd_addr_size,
                       CODE_NEW_CONTACT, mtime, key_contact, "");
        key_contact = NULL;
        key_secret = NULL;
        key_secret2 = NULL;
        num_hops = 0;
        check_for_key = 0;
      } else if (mlen == -2) {   /* confirm successful subscription */
printf ("got subscription but subscription is null\n");
        if (subscription != NULL) {
printf ("got subscription\n");
          send_message (forwarding_socket,
                        (struct sockaddr *) (&fwd_addr), fwd_addr_size,
                         CODE_AHRA, 0, subscription, "");
          subscription = NULL;
        }
      }
      /* handle_packet may have changed what has and has not been acked */
      int i;
      for (i = 0; i < acks.num_acks; i++) {
        send_seq_ack (forwarding_socket, (struct sockaddr *) (&fwd_addr),
                      fwd_addr_size, CODE_ACK, time (NULL),
                      acks.peers [i], acks.acks [i]);
        free (acks.peers [i]);
      }
    }
  }
}
