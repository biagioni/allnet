/* xchat_socket.c: send and receive xchat messages over a socket */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/ip.h>

#include "lib/packet.h"
#include "lib/pipemsg.h"
#include "lib/util.h"
#include "lib/priority.h"
#include "lib/log.h"
#include "chat.h"
#include "cutil.h"
#include "retransmit.h"
#include "xcommon.h"

/* messages have a length, time, code, peer name, and text of the message. */
/* length (4 bytes, big-endian order) includes everything.
 * time (6 bytes, big-endian order) is the time of original transmission,
 *   in the os's local epoch
 * code is 1 byte,
 * - code value 0 identifies a data message: the peer name and the
 *   message are null-terminated
 * - code value 1 identifies a broadcast message: the peer name and the
 *   message are null-terminated
 * - code value 2 identifies a new contact, stored in the peer name.  In
 *   messages received by xchat_socket, this is followed by one or two
 *   null-terminated secret strings.
 * - code value 3 identifies an ahra, stored in the peer name, to which
 *   we want to subscribe or have subscribed
 */

static void send_message (int sock, struct sockaddr * sap, socklen_t slen,
                          int code, time_t time, const char * peer,
                          const char * message)
{
  int plen = strlen (peer) + 1;     /* include the null character */
  int mlen = strlen (message) + 1;  /* include the null character */
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
  strcpy (buf + 11, peer);
  strcpy (buf + 11 + plen, message);
  n = sendto (sock, buf, length, MSG_DONTWAIT, sap, slen);
  if ((n != length) && ((errno == EAGAIN) || (errno == EWOULDBLOCK)))
    return;  /* socket is busy -- should never be, but who knows */
  if (n != length) {
    perror ("send");
    printf ("error: tried to send %d, only sent %d bytes on socket\n",
            length, n);
    printf ("sendto (%d, %p, %d, %d, %p, %d)\n",
            sock, buf, length, MSG_DONTWAIT, sap, slen);
    exit (1);   /* terminate the program */
  }
/* print_buffer (buf, length, "sent", 20, 1); */
}

/* return the message length if a message was received, and 0 otherwise */
/* both peer and message must have length ALLNET_MTU or more */
static int recv_message (int sock, int * code, time_t * time,
                         char * peer, char * message, char * extra)
{
  *peer = '\0';
  *message = '\0';
  *extra = '\0';
  char buf [ALLNET_MTU * 10];
  int n = recv (sock, buf, sizeof (buf), MSG_DONTWAIT);
  int len, plen, mlen;
  time_t sent_time;
  char * msg;
  if ((n < 0) && ((errno == EAGAIN) || (errno == EWOULDBLOCK)))
    return 0;
  if (n == 0) {    /* peer closed the socket */
    /* printf ("xchat_socket: received peer shutdown, exiting\n"); */
    exit (0);
  }
  if (n < 9) {
    perror ("recv");
    printf ("error: received %d bytes on unix socket\n", n);
    exit (0);
  }
  len = readb32 (buf);
  if (len != n) {
    printf ("error: received %d bytes but length is %d\n", n, len);
    return 0;
  }
  sent_time = readb48 (buf + 4);
  *time = sent_time;
  *code = buf [10] & 0xff;
  if ((*code != 0) && (*code != 2) && (*code != 3)) {
    printf ("error: received code %d but only 0, 2, and 3 supported\n", *code);
    return 0;
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
  strcpy (peer, buf + 11);
  if (mlen > 0)
    strcpy (message, msg);
  else
    message [0] = '\0';
  extra [0] = '\0';
  if (((*code) == 2) && (n > (mlen + (msg - buf)))) {   /* second secret */
    char * secret = msg + mlen + 1;
    int elen = strlen (secret);
    if ((elen < ALLNET_MTU) && (elen + (secret - buf) < n))
      strcpy (extra, secret);
  }
  if ((*code) == 3)
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
    exit (1);
  }
  struct sockaddr_in sin;
  sin.sin_family = AF_INET;
  sin.sin_port = XCHAT_SOCKET_PORT;
  sin.sin_addr.s_addr = htonl (INADDR_ANY);
  if (bind (result, (struct sockaddr *) (&sin), sizeof (sin)) < 0) {
    perror ("bind");
    exit (1);
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

/* returned value is malloc'd. */
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

static pid_t exec_java_ui (char * arg)
{
  char * path;
  char * pname;
  find_path (arg, &path, &pname);
  char * jarfile = make_program_path (path, "AllNetUI.jar");
  if (access (jarfile, R_OK) != 0) {
    perror ("access");
    printf ("unable to start Java gui %s\n", jarfile);
    exit (1);
  }
  pid_t pid = fork ();
  if (pid < 0) {
    perror ("fork");
    exit (1);
  }
  if (pid == 0) {   /* child process */
    char * args [5];
    args [0] = "/usr/bin/java";
    args [1] = "-jar";
    args [2] = jarfile;
    args [3] = "nodebug";
    args [4] = NULL;
/* printf ("calling %s %s %s %s\n", args [0], args [1], args [2], args [3]); */
    execv (args [0], args);    /* should never return! */
    perror ("execv returned");
    exit (1);
    return 0;  /* should never return */
  } else {
    free (jarfile);
  }
  return pid;
}

static void * child_wait_thread (void * arg)
{
  pid_t pid = * ((int *) arg);
  int status;
  waitpid (pid, &status, 0);
  /* child has terminated, exit the entire program */
  /* printf ("shutting down\n"); */
  exit (0);
  return NULL;
}

static void thread_for_child_completion (pid_t pid)
{
  static pid_t static_pid;
  static_pid = pid;
  pthread_t thread;
  int result = pthread_create (&thread, NULL, child_wait_thread,
                               ((void *) (&static_pid)));
  if (result != 0)
    perror ("pthread_create");
}

/* global debugging variable -- if 1, expect more debugging output */
/* set in main */
int allnet_global_debugging = 0;

int main (int argc, char ** argv)
{
  int verbose = get_option ('v', &argc, argv);
  if (verbose)
    allnet_global_debugging = verbose;

/*
  if (argc < 2) {
    printf ("%s should have one socket arg, and never be called directly!\n",
            argv [0]);
    return 0;
  }
  int forwarding_socket = atoi (argv [1]);
*/

  int sock = xchat_init (argv [0]);
  if (sock < 0)
    return 1;

  struct sockaddr_in fwd_addr;
  socklen_t fwd_addr_size = sizeof (fwd_addr);

  /* open the socket first, so it is ready when the UI begins execution */
  int forwarding_socket = get_socket ();
  pid_t child_pid = exec_java_ui (argv [0]);
  wait_for_connection (forwarding_socket, (struct sockaddr *) (&fwd_addr),
                       &fwd_addr_size);
  thread_for_child_completion (child_pid);

  int timeout = 100;      /* sleep up to 1/10 second */
  char * old_contact = NULL;
  keyset old_kset = -1;
  char * key_contact = NULL;
  char * key_secret = NULL;
  char * key_secret2 = NULL;
  char kbuf1 [ALLNET_MTU];  /* key buffer to hold the contact name */
  char kbuf2 [ALLNET_MTU];  /* key buffer to hold the first secret */
  char kbuf3 [ALLNET_MTU];  /* key buffer to hold the second secret, if any */
  int num_hops = 0;
  char * subscription = NULL;
  char sbuf [ALLNET_MTU];   /* subscribe buffer */
  unsigned char saddr [ADDRESS_SIZE];
  int sbits = 0;
  while (1) {
/* use temp (loop local) buffers, then copy them to kbuf* if code is 2 */
    char to_send [ALLNET_MTU];
    char peer [ALLNET_MTU];
    char extra [ALLNET_MTU];
    int code;
    time_t rtime;
    int len = recv_message (forwarding_socket, &code, &rtime, peer, to_send,
                            extra);
    if (len > 0) {
      if (code == 0)
        send_data_message (sock, peer, to_send, strlen (to_send));
      else if (code == 2) {
        strcpy (kbuf1, peer);
        strcpy (kbuf2, to_send);
        key_contact = kbuf1;
        key_secret = kbuf2;
        normalize_secret (key_secret);
        if (strlen (extra) > 0) {
          strcpy (kbuf3, extra);
          key_secret2 = kbuf3;
          normalize_secret (key_secret2);
        }
        num_hops = rtime;
printf ("sending key to peer %s/%s, secret %s/%s/%s, %d hops\n",
peer, key_contact, to_send, key_secret, key_secret2, num_hops);
        create_contact_send_key (sock, key_contact, key_secret, key_secret2,
                                 num_hops);
      } else if (code == 3) {   /* subscribe message -- peer is only field */
        strcpy (sbuf, peer);
printf ("sending subscription to %s/%s\n", peer, sbuf);
        if (subscribe_broadcast (sock, sbuf, saddr, &sbits))
          subscription = sbuf;
      } else
        printf ("received message with code %d\n", code);
    }
    char * packet;
    int pipe, pri;
    int found = receive_pipe_message_any (timeout, &packet, &pipe, &pri);
    if (found < 0) {
      printf ("xchat_socket pipe closed, exiting\n");
      kill (child_pid, SIGKILL);
      exit (1);
    }
    if (found == 0) {  /* timed out, request/resend any missing */
      if (old_contact != NULL) {
        request_and_resend (sock, old_contact, old_kset);
        old_contact = NULL;
        old_kset = -1;
      }
    } else {    /* found > 0, got a packet */
      int verified, duplicate, broadcast;
      char * peer;
      keyset kset;
      char * desc;
      char * message;
      time_t mtime = 0;
      int mlen = handle_packet (sock, packet, found, &peer, &kset, &message,
                                &desc, &verified, &mtime, &duplicate,
                                &broadcast, key_contact, key_secret, 
                                key_secret2, num_hops,
                                subscription, saddr, sbits);
      if ((mlen > 0) && (verified)) {
        int mtype = 0; /* data */
        if (broadcast) {
          mtype = 1;  /* broadcast */
        }
        if (broadcast || (! duplicate))
          send_message (forwarding_socket,
                        (struct sockaddr *) (&fwd_addr), fwd_addr_size,
                        mtype, mtime, peer, message);
        if ((! broadcast) &&
            ((old_contact == NULL) ||
             (strcmp (old_contact, peer) != 0) || (old_kset != kset))) {
          request_and_resend (sock, peer, kset);
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
                       2, mtime, key_contact, "");
        key_contact = NULL;
        key_secret = NULL;
        key_secret2 = NULL;
        num_hops = 0;
      } else if (mlen == -2) {   /* confirm successful subscription */
        if (subscription != NULL) {
          send_message (forwarding_socket,
                        (struct sockaddr *) (&fwd_addr), fwd_addr_size,
                         3, 0, subscription, "");
          subscription = NULL;
        }
      }
    }
  }
}
