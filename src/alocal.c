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
#include <pthread.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "lib/packet.h"
#include "lib/pipemsg.h"
#include "listen.h"
#include "lib/log.h"

void * main_loop (int rpipe, int wpipe, struct listen_info * info)
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
if (result != 0) {
snprintf (log_buf, LOG_SIZE, "receive_pipe_message_any returns %d\n", result);
log_print (); }
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
      if (fd == rpipe) {    /* message from ad, send to all clients */
        int i;    /* start with i = 1, no sending to ad read pipe */
        pthread_mutex_lock (&(info->mutex));
        for (i = 1; i < info->num_fds; i++) {
          if (! send_pipe_message (info->fds [i], message, result, priority)) {
            snprintf (log_buf, LOG_SIZE, "error sending to info pipe %d at %d\n",
                      info->fds [i], i);
            /* listen_remove_fd (info, info->fds [i]); */
          } else {
            snprintf (log_buf, LOG_SIZE,
                      "sent to client %d at %d %d bytes, prio %08x\n",
                      info->fds [i], i, result, priority);
          }
          log_print ();
        }
        pthread_mutex_unlock (&(info->mutex));
      } else {              /* message from a client, send to ad */
        listen_record_usage (info, fd);  /* make it most recently used */
        if (! send_pipe_message (wpipe, message, result, priority)) {
          snprintf (log_buf, LOG_SIZE, "error sending to ad pipe %d\n", wpipe);
          log_print ();
          break;
        }
        snprintf (log_buf, LOG_SIZE, "sent %d bytes to ad pipe %d\n",
                  result, wpipe);
        log_print ();
      }
      free (message);
    }   /* else result is zero, timed out, try again */
  }
}

int main (int argc, char ** argv)
{
  init_log ("alocal");
  snprintf (log_buf, LOG_SIZE, "in main\n");
  log_print ();
  if (argc != 3) {
    printf ("arguments must be a read and a write pipe\n");
    return -1;
  }
/*
  printf ("in alocal, args are ");
  printf ("'%s %s %s'\n", argv [0], argv [1], argv [2]);
*/
  int rpipe = atoi (argv [1]);
  int wpipe = atoi (argv [2]);
  /* printf ("read pipe is fd %d, write pipe is fd %d\n", rpipe, wpipe); */
  struct listen_info info;
  snprintf (log_buf, LOG_SIZE, "calling listen_init_info\n");
  log_print ();
  listen_init_info (&info, 256, "alocal", ALLNET_LOCAL_PORT, 1, 1);
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
