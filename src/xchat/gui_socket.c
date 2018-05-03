/* gui_socket.c: implement functions needed by the GUI and send and receive
 * information across a socket */

#if defined(WIN32) || defined(WIN64)
#ifndef WINDOWS_ENVIRONMENT
#define WINDOWS_ENVIRONMENT
#define WINDOWS_ENVIRONMENT
#endif /* WINDOWS_ENVIRONMENT */
#endif /* WIN32 || WIN64 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <pthread.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/ip.h>

#ifdef WINDOWS_ENVIRONMENT
#include <windows.h>
#endif /* WINDOWS_ENVIRONMENT */

#include "lib/util.h"
#include "xcommon.h"
#include "gui_socket.h"

static pid_t xchat_socket_pid = -1;
static pid_t xchat_ui_pid = -1;

static void kill_if_not_self (pid_t pid, const char * desc)
{
  if ((pid != -1) && (pid != getpid ())) {
/* printf ("process %d killing %s process %d\n", getpid (), desc, pid); */
    kill (pid, SIGKILL);
  }
}

/* exit code should be 0 for normal exit, 1 for error exit */
void stop_chat_and_exit (int exit_code)
{
  kill_if_not_self (xchat_socket_pid, "xchat_socket");
  kill_if_not_self (xchat_ui_pid, "xchat_ui");
  exit (exit_code);
}

static int create_allnet_sock (const char * program_name, const char * path)
{
  int sock = xchat_init (program_name, path);
  return sock;
}

static int create_listen_socket ()
{
  int result = socket (AF_INET, SOCK_STREAM, 0);
  if (result < 0) {
    perror ("socket");
    return -1;
  }
  struct sockaddr_in sin;
  sin.sin_family = AF_INET;
  sin.sin_port = XCHAT_SOCKET_PORT;
  sin.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
  if (bind (result, (struct sockaddr *) (&sin), sizeof (sin)) < 0) {
    perror ("bind");
    printf ("unable to run xchat, maybe already running?\n");
    close (result);
    return -1;
  }
  if (listen (result, 1) < 0) {
    perror ("listen");
    printf ("unable to run xchat, listen failed\n");
  }
  return result;
}

static int accept_incoming (int listen_sock)
{
  struct sockaddr_in sin;
  socklen_t alen = sizeof (sin);
  int result = accept (listen_sock, (struct sockaddr *) (&sin), &alen);
  if (result < 0)
    perror ("accept");
#ifdef DEBUG_PRINT
  else
    printf ("got connection from %d.%d.%d.%d port %d\n", 
            ((unsigned char *)(&(sin.sin_addr.s_addr))) [0],
            ((unsigned char *)(&(sin.sin_addr.s_addr))) [1],
            ((unsigned char *)(&(sin.sin_addr.s_addr))) [2],
            ((unsigned char *)(&(sin.sin_addr.s_addr))) [3],
            (((unsigned char *)(&(sin.sin_port))) [0] * 256 +
             ((unsigned char *)(&(sin.sin_port))) [1]));
#endif /* DEBUG_PRINT */
  return result;
}

/* create the process to run the gui, return the socket (or -1 for errors) */
static int create_gui_sock (const char * arg)
{
  int listen_sock = create_listen_socket ();
  if (listen_sock < 0)
    return listen_sock;
  xchat_ui_pid = start_java (arg);
  if (xchat_ui_pid < 0) {
    close (listen_sock);
    return -1;
  }
  return accept_incoming (listen_sock);
}

int main (int argc, char ** argv)
{
  /* general initialization */
  xchat_socket_pid = getpid ();  /* needed to properly kill other procs */
  log_to_output (get_option ('v', &argc, argv));
#ifdef WINDOWS_ENVIRONMENT
  HWND hwNd = GetConsoleWindow ();
  ShowWindow (hwNd, SW_HIDE);
#endif /* WINDOWS_ENVIRONMENT */

  /* create the allnet socket and the GUI socket */
  /* argv [1] is normally NULL, unless someone specified a config directory */
  int allnet_sock = create_allnet_sock (argv [0], argv [1]);
  if (allnet_sock < 0)
    return 1;
  int gui_sock = create_gui_sock (argv [0]);
  if (gui_sock < 0)
    return 1;

  /* create the thread to handle messages from the GUI */
  void * args = malloc_or_fail (sizeof (int) * 2, "gui_socket main");
  ((int *) args) [0] = gui_sock;
  ((int *) args) [1] = allnet_sock;
  pthread_t t;
  pthread_create (&t, NULL, gui_respond_thread, args);

  gui_socket_main_loop (gui_sock, allnet_sock);  /* run until exit */

  stop_chat_and_exit (0);
  return 0;   /* should never be called */
}
