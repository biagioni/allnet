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
#include "lib/allnet_log.h"

static struct allnet_log * alog = NULL;

static void main_loop (pd p, int rpipe, int wpipe, struct listen_info * info,
                       int num_pipes, int * wpipes)
{
  while (1) {
    int fd;
    unsigned int priority;
    char * message;
/* the sleep time is arbitrarily set to 50ms.  The major thing that may
 * happen while we sleep is a new socket being added.  We don't listen to
 * it until the next time we call receive_pipe_message_any.  To give good
 * responsiveness, that time should be 50ms or less.   I tried setting it
 * to 1ms, but then alocal took a little more CPU time than I liked.
 * If this value is changed, should change the corresponding value in
 * app_util.c */
/*
int debug;
for (debug = 0; debug < num_pipes; debug++)
printf ("before recv: alocal wpipes [%d] is %d\n", debug, wpipes [debug]);
 */
    int result = receive_pipe_message_any (p, 50, &message, &fd, &priority);
/*
for (debug = 0; debug < num_pipes; debug++)
printf ("after recv: alocal wpipes [%d] is %d\n", debug, wpipes [debug]);
*/
#ifdef LOG_PACKETS
    if (result != 0) {
      snprintf (alog->b, alog->s, "receive_pipe_message_any returns %d\n",
                result);
      log_print (alog);
    }
#endif /* LOG_PACKETS */
    if (result < 0) {
      if (fd == rpipe) {
        snprintf (alog->b, alog->s, "ad pipe %d closed\n", rpipe);
        log_print (alog);
        break;
      }
      snprintf (alog->b, alog->s,
                "error on file descriptor %d, closing\n", fd);
      log_print (alog);
      listen_remove_fd (info, fd);
      close (fd);       /* remove from kernel */
    } else if (result > 0) {
#ifdef LOG_PACKETS
      snprintf (alog->b, alog->s,
                "got %d bytes from %s (fd %d, priority %d)\n", result,
                (fd == rpipe) ? "ad" : "client", fd, priority);
      log_print (alog);
#endif /* LOG_PACKETS */
      int i;
      pthread_mutex_lock (&(info->mutex));
/*
printf ("%d pipes: ", num_pipes);
print_packet (message, result, "alocal forwarding", 1);
for (i = 0; i < num_pipes; i++)
printf ("alocal wpipes [%d] is %d\n", i, wpipes [i]);
 */
      if ((fd > 0) && (fd != rpipe))
        listen_record_usage (info, fd);  /* make it most recently used */
      for (i = 0; i < info->num_fds + num_pipes; i++) {
        int xfd = (i < info->num_fds) ? info->fds [i]
                                      : wpipes [i - info->num_fds];
if ((xfd > 1000) || (xfd < -1000)) { printf ("bad xfd %d\n", xfd);
i = 0; xfd = xfd / i; break; }  /* die if bad xfd */
        int same = (fd == xfd);
        if (xfd == rpipe)
          xfd = wpipe;
        same = (same || (fd == xfd));
/* printf ("fds %d %d %d %d, same = %d\n", fd, xfd, rpipe, wpipe, same); */
        if (! same) {
          if (! send_pipe_message (xfd, message, result, priority, alog)) {
            snprintf (alog->b, alog->s,
                      "error sending to info pipe %d/%d at %d\n",
                      info->fds [i], xfd, i);
            log_print (alog);
            /* listen_remove_fd (info, info->fds [i]);  now only on recv err */
          } else {
#ifdef DEBUG_PRINT
            snprintf (alog->b, alog->s,
                      "sent to fd %d/%d at %d %d bytes, prio %08x\n",
                      info->fds [i], xfd, i, result, priority);
            log_print (alog);
#endif /* DEBUG_PRINT */
          }
        } else {  /* else same pipe, do not send back */
#ifdef DEBUG_PRINT
          snprintf (alog->b, alog->s,
                    "not sending on same info pipe %d/%d at %d\n",
                    info->fds [i], xfd, i);
          log_print (alog);
#endif /* DEBUG_PRINT */
        }
      }
      pthread_mutex_unlock (&(info->mutex));
      free (message);
    }   /* else result is zero, timed out, try again */
  }
}

void alocal_main (int rpipe, int wpipe,
                  int npipes, int * rpipes, int * wpipes)
{
  alog = init_log ("alocal");
  snprintf (alog->b, alog->s, "in main\n");
  log_print (alog);
/*
  printf ("in alocal, args are ");
  printf ("'%d %d'\n", rpipe, wpipe);
*/
  /* printf ("read pipe is fd %d, write pipe is fd %d\n", rpipe, wpipe); */
  pd p = init_pipe_descriptor (alog);
  if ((npipes > 0) && (rpipes != NULL)) {
      
    int i;
    for (i = 0; i < npipes; i++) {
      char pipe_number [] = "alocal_main pipe 1234567890";
      snprintf (pipe_number, sizeof (pipe_number), "alocal_main pipe %d", i);
      add_pipe (p, rpipes [i], pipe_number);
    }
for (i = 0; i < npipes; i++) printf ("alocal: now added pipe %d (%d total)\n", rpipes [i], npipes);
  }
  static struct listen_info info;
  snprintf (alog->b, alog->s, "calling listen_init_info\n");
  log_print (alog);
  listen_init_info (&info, 256, "alocal", ALLNET_LOCAL_PORT, 1, 1, 1, NULL, p);
  snprintf (alog->b, alog->s, "calling listen_add_fd\n");
  log_print (alog);
  if (! listen_add_fd (&info, rpipe, NULL, 0, "alocal_main"))
    /* should always succeed */
    printf ("alocal_main: listen_add_fd failed\n");
  snprintf (alog->b, alog->s, "calling main loop\n");
  log_print (alog);

/* int i; for (i = 0; i < npipes; i++)
   printf ("wpipes [%d] is %d\n", i, wpipes [i]); */
  main_loop (p, rpipe, wpipe, &info, npipes, wpipes);

  listen_shutdown (&info);
  snprintf (alog->b, alog->s, "end of alocal main thread\n");
  log_print (alog);
}

#ifdef DAEMON_MAIN_FUNCTION
int main (int argc, char ** argv)
{
  log_to_output (get_option ('v', &argc, argv));
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
#endif /* DAEMON_MAIN_FUNCTION */
