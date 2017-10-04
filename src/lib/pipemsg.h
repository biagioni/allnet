/* pipemsg.h: transmit messages over pipes */

#ifndef PIPEMSG_H
#define PIPEMSG_H

#include <sys/types.h>
#include <sys/socket.h>

#include "allnet_log.h"

/* pipedesc is defined in pipemsg.c, and only used for receiving */
/* should be initialized to NULL before the first call */
typedef struct pipedesc * pd;

extern pd init_pipe_descriptor(struct allnet_log * log);

/* convenience function to get the log from the pd */
extern struct allnet_log * pipemsg_log (pd p);

/* the send functions return 1 in case of success and 0 in case of failure.
 * if 0 is returned, it means the pipe is no longer valid.
 * the receive functions return the number of bytes received, 0
 * in case of timeout, and -1 in case of error, including the pipe
 * no longer being usable. */
/* pipe numbers n < 0 give index = -n - 1 in allnet_queues */

extern int send_pipe_message (int pipe,
                              const char * message, unsigned int mlen,
                              unsigned int priority, struct allnet_log * log);

/* same as send_pipe_message, but frees the memory referred to by message */
extern int send_pipe_message_free (int pipe, char * message, unsigned int mlen,
                                   unsigned int priority,
                                   struct allnet_log * log);

/* send multiple messages at once, again to avoid the mysterious system
 * delay when sending multiple times in close succession on a socket.
 * messages are not freed */
extern int send_pipe_multiple (int pipe, unsigned int num_messages,
                               const char ** messages,
                               const unsigned int * mlens,
                               const unsigned int * priorities,
                               struct allnet_log * log);
/* same, but messages are freed */
extern int send_pipe_multiple_free (int pipe, unsigned int num_messages,
                                    char ** messages,
                                    const unsigned int * mlens,
                                    const unsigned int * priorities,
                                    struct allnet_log * log);

/* receives the message into a buffer it allocates for the purpose. */
/* the caller is responsible for freeing the message buffer. */
extern int receive_pipe_message (pd p, int pipe,
                                 char ** message, unsigned int * priority);

/* keeps track of which pipes are needed for receive_pipe_message_any,
 * which buffers partial messages received on a socket. */
extern void add_pipe (pd p, int pipe, const char * description);
/* return 1 if removed, 0 otherwise */
extern int remove_pipe (pd p, int pipe);

#define PIPE_MESSAGE_WAIT_FOREVER	-1
#define PIPE_MESSAGE_NO_WAIT		0

/* receive on the first ready pipe, returning the size and message
 * for the first one received, and returning 0 in case of timeout
 * and -1 in case of error, including a closed pipe.
 * timeout is specified in ms.
 * the message (if any) is malloc'd, and must be free'd
 * The pipe from which the message is received (or which has an error)
 * is returned in *from_pipe if not NULL.
 */
extern int receive_pipe_message_any (pd p, int timeout, char ** message,
                                     int * from_pipe, unsigned int * priority);

/* same as receive_pipe_message_any, but listens to the given socket as
 * well as the pipes added previously,  The socket is assumed to be a
 * UDP or raw socket.  If the first message is received on this socket,
 * the message is read with recvfrom, assuming the size of the message
 * to be ALLNET_MTU or less (any more will be in the return value of
 * receive_pipe_message_fd, but not in the message)
 * sa and salen are passed directly as the last parameters to recvfrom.
 *
 * in case some other socket is ready first, or if fd is -1,
 * this call is the same as receive_pipe_message_any
 */
extern int receive_pipe_message_fd (pd p, int timeout, char ** message, int fd,
                                    struct sockaddr * sa, socklen_t * salen,
                                    int * from_pipe, unsigned int * priority);

/* splits an incoming data into n = zero or more allnet messages, returning
 * the number of messages.
 * if the number of messages is greater than zero, malloc's arrays
 * for messages, lengths, and priorities (for each, if not NULL).  If malloc'd,
 * these arrays must be free'd when no longer needed.
 * the pointers in messages[0..n-1] point into data (or *buffer, see below),
 * and should not be free'd.
 *
 * incoming data may hold partial messages at the beginning and the end.
 * buffer is used to store such partial messages from one call to another
 * of split_messages.  The management of buffer is hidden from the caller,
 * except when a socket is closed, the corresponding buffer should be free'd.
 * The space in buffer is limited, and pointers into buffer may no
 * longer be available on a subsequent call.
 * buffers should generally be declared as static or global, and should be
 * NULL on the first call to split_messages for a given socket.
 *
 * example:
    char data [...] = ...;    // usually data received from network
    unsigned int dlen = ...;  // the number of bytes from network
    char ** messages;
    int * lengths;
    int * priorities;
    static void * buffer = NULL;   // see comments for buffer handling
    int n = split_messages (data, dlen, &messages, &lengths, &priorities,
                            &buffer);
    int i;
    for (i = 0; i < n; i++)
      process_message (messages [i], lengths [i], priorities [i]);
    if (n > 0) {
      free (messages);
      free (lengths);
      free (priorities);
    }
 */
extern int split_messages (char * data, unsigned int dlen, char *** messages,
                           unsigned int ** lengths, unsigned int ** priorities,
                           void ** buffer);

/* #define DEBUG_EBADF */
#ifdef DEBUG_EBADF
/* temporary (I hope), for debugging of EBADF */
#define EBADBUFS	10000
extern char ebadbuf [EBADBUFS];
extern void record_message (pd p);  /* call after snprintf to ebadfbuf */
#endif /* DEBUG_EBADF */

#endif /* PIPEMSG_H */
