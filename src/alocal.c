/* alocal.c: forward allnet messages to and from local clients */
/* two threads:
 * - one listens for connections on localhost port 0xa11e (ALLnEt)
 * - one listens for messages from ad or from clients, and forwards them
 *   to clients and ad
 * alocal takes two arguments, the fd of a pipe from AD and of a pipe to AD
 */
/* there are actually two listen threads, one for IPv4 and one for IPv6 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "lib/packet.h"
#include "lib/pipemsg.h"
#include "lib/util.h"
#include "listen.h"
#include "lib/log.h"

static void main_loop (int rpipe, int wpipe, struct listen_info * info)
{
  while (1) {
    int fd;
    int priority;
    char * message;
/* the sleep time is arbitrarily set to 50ms.  The major thing that may
 * happen while we sleep is a new socket being added.  We don't listen to
 * it until the next time we call receive_pipe_message_any.  To give good
 * responsiveness, that time should be 50ms or less.   I tried setting it
 * to 1ms, but then alocal took a little more CPU time than I liked.
 * If this value is changed, should change the corresponding value in
 * app_util.c */
    int result = receive_pipe_message_any (50, &message, &fd, &priority);
#define DEBUG_PRINT
#ifdef DEBUG_PRINT
    if (result != 0) {
      snprintf (log_buf, LOG_SIZE, "receive_pipe_message_any returns %d\n",
                result);
      log_print ();
    }
#endif /* DEBUG_PRINT */
#undef DEBUG_PRINT
    if (result < 0) {
      if (fd == rpipe) {
        snprintf (log_buf, LOG_SIZE, "ad pipe %d closed\n", rpipe);
        log_print ();
        break;
      }
      snprintf (log_buf, LOG_SIZE,
                "error on file descriptor %d, closing\n", fd);
      log_print ();
      listen_remove_fd (info, fd);
      close (fd);       /* remove from kernel */
    } else if (result > 0) {
      snprintf (log_buf, LOG_SIZE,
                "got %d bytes from %s (fd %d, priority %d)\n", result,
                (fd == rpipe) ? "ad" : "client", fd, priority);
      log_print ();
      int i;
      pthread_mutex_lock (&(info->mutex));
      if (fd != rpipe)
        listen_record_usage (info, fd);  /* make it most recently used */
      for (i = 0; i < info->num_fds; i++) {
        int xfd = info->fds [i];
        int same = (fd == xfd);
        if (xfd == rpipe)
          xfd = wpipe;
        same = (same || (fd == xfd));
        if (! same) {
          if (! send_pipe_message (xfd, message, result, priority)) {
            snprintf (log_buf, LOG_SIZE,
                      "error sending to info pipe %d/%d at %d\n",
                      info->fds [i], xfd, i);
            log_print ();
            /* listen_remove_fd (info, info->fds [i]);  now only on recv err */
          } else {
#ifdef DEBUG_PRINT
            snprintf (log_buf, LOG_SIZE,
                      "sent to fd %d/%d at %d %d bytes, prio %08x\n",
                      info->fds [i], xfd, i, result, priority);
            log_print ();
#endif /* DEBUG_PRINT */
          }
        } else {  /* else same pipe, do not send back */
#ifdef DEBUG_PRINT
          snprintf (log_buf, LOG_SIZE,
                    "not sending on same info pipe %d/%d at %d\n",
                    info->fds [i], xfd, i);
          log_print ();
#endif /* DEBUG_PRINT */
        }
      }
      pthread_mutex_unlock (&(info->mutex));
      free (message);
    }   /* else result is zero, timed out, try again */
  }
}

void alocal_main (int rpipe, int wpipe)
{
  init_log ("alocal");
  snprintf (log_buf, LOG_SIZE, "in main\n");
  log_print ();
/*
  printf ("in alocal, args are ");
  printf ("'%d %d'\n", rpipe, wpipe);
*/
  /* printf ("read pipe is fd %d, write pipe is fd %d\n", rpipe, wpipe); */
  struct listen_info info;
  snprintf (log_buf, LOG_SIZE, "calling listen_init_info\n");
  log_print ();
  listen_init_info (&info, 256, "alocal", ALLNET_LOCAL_PORT, 1, 1, 1, NULL);
  snprintf (log_buf, LOG_SIZE, "calling listen_add_fd\n");
  log_print ();
  listen_add_fd (&info, rpipe, NULL);
  snprintf (log_buf, LOG_SIZE, "calling main loop\n");
  log_print ();

  main_loop (rpipe, wpipe, &info);
  pthread_cancel (info.thread4);
  pthread_cancel (info.thread6);
  snprintf (log_buf, LOG_SIZE, "end of alocal main thread\n");
  log_print ();
}

#ifndef NO_MAIN_FUNCTION
/* global debugging variable -- if 1, expect more debugging output */
/* set in main */
int allnet_global_debugging = 0;

int main (int argc, char ** argv)
{
  int verbose = get_option ('v', &argc, argv);
  if (verbose)
    allnet_global_debugging = verbose;

  if (argc != 3) {
    printf ("arguments must be a read and a write pipe\n");
    print_usage (argc, argv, 0, 1);
    return -1;
  }
/*
  printf ("in alocal, args are ");
  printf ("'%s %s %s'\n", argv [0], argv [1], argv [2]);
*/
  int rpipe = atoi (argv [1]);
  int wpipe = atoi (argv [2]);
  /* printf ("read pipe is fd %d, write pipe is fd %d\n", rpipe, wpipe); */
  alocal_main (rpipe, wpipe);
  return 1;
}
#endif /* NO_MAIN_FUNCTION */
