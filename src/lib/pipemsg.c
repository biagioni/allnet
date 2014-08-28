/* pipemsg.c: transmit messages over pipes */

/* all but the receive functions return 1 in case of success and 0
 * in case of failure.
 * if 0 is returned, it means the pipe is no longer valid.
 * the receive functions return the number of bytes received, which
 * for receive_pipe_message_buffer may be greater than mlen.
 * in case of failure, the receive functions return -1 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <assert.h>
#include <sys/select.h>

#include "packet.h"
#include "priority.h"
#include "pipemsg.h"
#include "util.h"
#include "log.h"

#define MAGIC_STRING	"MAGICPIE"  /* magic pipe, squeezed into 8 chars */

/* MAGIC_SIZE does not include null character at the end */
#define MAGIC_SIZE	(sizeof (MAGIC_STRING) - 1)
#define PRIORITY_SIZE	4
#define LENGTH_SIZE	4
#define HEADER_SIZE	(MAGIC_SIZE + PRIORITY_SIZE + LENGTH_SIZE)

static int num_pipes = 0;

struct pipe_info {
  int pipe_fd;	   /* file descriptor for input */
  int in_header;
  char header [HEADER_SIZE];
  char * buffer;   /* may be null */
  int filled;      /* how many bytes does the buffer or header already have */
  int bsize;       /* how many bytes do we receive before we are done? */
};

static struct pipe_info * buffers = NULL;

static int do_not_print = 1;
static void print_pipes (const char * desc, int pipe)
{
  if (do_not_print)
    return;
  if (pipe != -1)
    snprintf (log_buf, LOG_SIZE, "%s pipe %d, total %d:\n",
              desc, pipe, num_pipes);
  else
    snprintf (log_buf, LOG_SIZE, "%s %d pipes:\n", desc, num_pipes);
  log_print ();
  int i;
  for (i = 0; i < num_pipes; i++) {
    snprintf (log_buf, LOG_SIZE,
              "  [%d]: pipe %d, %shdr, h %p b %p, filled %d bsize %d\n", i,
              buffers [i].pipe_fd, ((buffers [i].in_header) ? "" : "not "),
              buffers [i].header, buffers [i].buffer,
              buffers [i].filled, buffers [i].bsize);
   log_print ();
  }
}

/* returns the pipe index if present, -1 otherwise */
static int pipe_index (int pipe)
{
  int i;
  for (i = 0; i < num_pipes; i++)
    if (buffers [i].pipe_fd == pipe)
      return i;
  return -1;
}

void add_pipe (int pipe)
{
  if (pipe_index (pipe) != -1) {
    snprintf (log_buf, LOG_SIZE,
              "adding pipe %d already in data structure [%d]\n",
              pipe, pipe_index (pipe));
    log_print ();
    return;
  }
  int total = num_pipes + 1;
  size_t size = total * sizeof (struct pipe_info);
  struct pipe_info * new_buffer = (struct pipe_info *) malloc (size);
  if (new_buffer == NULL) {
    snprintf (log_buf, LOG_SIZE,
              "unable to allocate %zd bytes for %d slots\n", size, total);
    log_print ();
    return;
  }
  int i;
  for (i = 0; i < num_pipes; i++) {
    new_buffer [i] = buffers [i];
    if (new_buffer [i].in_header)  /* update the pointer */
      new_buffer [i].buffer = new_buffer [i].header;
  }
  new_buffer [num_pipes].pipe_fd = pipe;
  new_buffer [num_pipes].in_header = 1;/* always start by reading the header */
  new_buffer [num_pipes].buffer = new_buffer [num_pipes].header;
  new_buffer [num_pipes].bsize = HEADER_SIZE;
  new_buffer [num_pipes].filled = 0;

  if (buffers != NULL)
    free (buffers);
  buffers = new_buffer;
  num_pipes = total;
  print_pipes ("added", pipe);
}

void remove_pipe (int pipe)
{
  int index = pipe_index (pipe);
  if (index == -1)  /* nothing to delete */
    return;
  snprintf (log_buf, LOG_SIZE,
            "removing pipe %d from data structure [%d]\n", pipe, index);
  log_print ();
  if ((! buffers [index].in_header) && (buffers [index].buffer != NULL))
    free (buffers [index].buffer);
  if (index + 1 < num_pipes) {
    buffers [index] = buffers [num_pipes - 1];
    if (buffers [index].in_header)  /* update the pointer */
      buffers [index].buffer = buffers [index].header;
  }
  num_pipes--;
  print_pipes ("removed", pipe);
}

static inline void write_big_endian32 (char * array, int value)
{
  array [0] = (value >> 24) & 0xff;
  array [1] = (value >> 16) & 0xff;
  array [2] = (value >>  8) & 0xff;
  array [3] =  value        & 0xff;
}

static inline int read_big_endian32 (char * array)
{
  return ((array [0] & 0xff) << 24 | (array [1] & 0xff) << 16 |
          (array [2] & 0xff) <<  8 | (array [3] & 0xff));
}

static int send_pipe_message_orig (int pipe, char * message, int mlen,
                                   int priority)
{
  snprintf (log_buf, LOG_SIZE, "warning: send_pipe_message_orig\n");
  log_print ();  /* normally should not happen */
  char header [HEADER_SIZE];
  memcpy (header, MAGIC_STRING, MAGIC_SIZE);
  write_big_endian32 (header + MAGIC_SIZE, priority);
  write_big_endian32 (header + MAGIC_SIZE + 4, mlen);

  int w = write (pipe, header, HEADER_SIZE); 
  if (w != HEADER_SIZE) {
    perror ("send_pipe_msg(1) write");
    snprintf (log_buf, LOG_SIZE, "(1) pipe number %d, result %d\n", pipe, w);
    log_print ();
    return 0;
  }

  w = write (pipe, message, mlen); 
  if (w != mlen) {
    perror ("send_pipe_msg(2) write");
    snprintf (log_buf, LOG_SIZE,
              "(2) pipe number %d, wrote %d instead of %d\n", pipe, w, mlen);
    log_print ();
    return 0;
  }
  return 1;
}

static int send_buffer (int pipe, char * buffer, int blen, int do_free)
{
  int result = 1;
  int w = send (pipe, buffer, blen, MSG_DONTWAIT); 
  int save_errno = errno;
  int is_send = 1;
/* If it was a partial send, we just want to discard the packet,
 * no need to try again with write. */
  int is_partial_send =
    ((w > 0) && (w < blen) &&
#if 0
     ((errno == EAGAIN) || (errno == EWOULDBLOCK)));
#else   /* I am not sure why we get enotsock on partial sends, but we do */
     ((errno == EAGAIN) || (errno == EWOULDBLOCK) || (errno == ENOTSOCK)));
#endif /* 0 */
  if ((w < 0) && ((errno == EAGAIN) || (errno == EWOULDBLOCK)))
    is_partial_send = 1;
  if (is_partial_send) {
    static int partial_printed = -1;
    if (partial_printed != pipe) {
      snprintf (log_buf, LOG_SIZE,
                "pipe %d, result %d, wanted %d, original errno %d\n",
                pipe, w, blen, save_errno);
      log_error ("send_pipe_msg partial send");
      partial_printed = pipe;
    }
    result = 0;
  } else {
    /* try to send with write -- I don't think this has ever been used */
    if ((w < 0) && (errno == ENOTSOCK)) {
static int notsock_printed = -1;
if (notsock_printed != pipe) {
snprintf (log_buf, LOG_SIZE, "trying write instead of send on fd %d\n", pipe);
log_print ();
notsock_printed = pipe;
}
      w = write (pipe, buffer, blen); 
      is_send = 0;
    }
    if (w != blen) {
      static int badwrite_printed = -1;
      if (badwrite_printed != pipe) {
        badwrite_printed = pipe;
        char * name = "send_pipe_msg write";
        if (is_send)
          name = "send_pipe_msg send";
        if ((errno != EAGAIN) && (errno != EWOULDBLOCK))
          perror (name);
        snprintf (log_buf, LOG_SIZE,
                  "pipe %d, result %d, wanted %d, original errno %d\n",
                  pipe, w, blen, save_errno);
        log_error (name);
      }
/* 2014/08/11 not sure if this is correct: should return 0 even if pipe is
 * busy, because we did not write.  But if we do this, daemons think their
 * pipe to ad has been closed, and terminate.  */
      if ((errno != EAGAIN) && (errno != EWOULDBLOCK))
        result = 0;
    }
  }
#ifdef DEBUG_PRINT
  snprintf (log_buf, LOG_SIZE, "send_buffer sent %d/%d bytes on %s %d\n",
            blen, w, ((is_send) ? "socket" : "pipe"), pipe);
  log_print ();
#endif /* DEBUG_PRINT */
  if (do_free)
    free (buffer);
  return result;
}

static int send_header_data (int pipe, char * message, int mlen, int priority)
{
  char stack_packet [HEADER_SIZE + ALLNET_MTU];
  char * packet = stack_packet;
  if (mlen > ALLNET_MTU) {
/* I think this should never happen.   If it does, print it to log and screen */
    snprintf (log_buf, LOG_SIZE,
              "send_header_data warning: mlen %d > ALLNET_MTU %d\n",
              mlen, ALLNET_MTU);
    printf ("%s", log_buf);
    log_print ();
/* and malloc the packet (free'd below) */
    packet = malloc (HEADER_SIZE + mlen);
  }
/* send_pipe_message_orig is simpler, but sometimes stalls for ~35ms-40ms
 * on the second send, so it is faster if we only call write once */
  if (packet == NULL)   /* unable to malloc, use the slow strategy */
    return send_pipe_message_orig (pipe, message, mlen, priority);

  char * header = packet;
  memcpy (header, MAGIC_STRING, MAGIC_SIZE);
  write_big_endian32 (header + MAGIC_SIZE, priority);
  write_big_endian32 (header + MAGIC_SIZE + 4, mlen);
  memcpy (header + HEADER_SIZE, message, mlen);

  if (packet != stack_packet)
    return send_buffer (pipe, packet, HEADER_SIZE + mlen, 1);
  return send_buffer (pipe, packet, HEADER_SIZE + mlen, 0);
}

int send_pipe_message (int pipe, char * message, int mlen, int priority)
{
  /* avoid SIGPIPE signals when writing to a closed pipe */
  struct sigaction sa;
  sa.sa_handler = SIG_IGN;
  sa.sa_flags = 0;
  sigemptyset (&(sa.sa_mask));
  struct sigaction old_sa;
  sigaction (SIGPIPE, &sa, &old_sa);

  int result = send_header_data (pipe, message, mlen, priority);

  sigaction (SIGPIPE, &old_sa, NULL);
  return result;
}

/* send multiple messages at once, again to avoid the mysterious system
 * delay when sending multiple times in close succession on a socket.
 * (Nagle's delay?).  Each message gets its own header */
static int send_multiple_packets (int pipe, int num_messages,
                                  char ** messages, int * mlens,
                                  int * priorities)
{
  if (num_messages <= 0)
    return 0;
  int i;
  int total = 0;
  for (i = 0; i < num_messages; i++)
    total += HEADER_SIZE + mlens [i];
  int result = 1;

  char * packet = malloc (total);
  if (packet == NULL) {  /* unable to malloc, use the slow strategy */
    snprintf (log_buf, LOG_SIZE,
              "unable to malloc %d bytes for %d packets, falling back\n",
              total, num_messages);
    log_print ();
    for (i = 0; i < num_messages; i++) {
      if (! send_pipe_message (pipe, messages [i], mlens [i], priorities [i]))
        result = 0;
    }
    return result;
  }
  char * header = packet;
  for (i = 0; i < num_messages; i++) {
    memcpy (header, MAGIC_STRING, MAGIC_SIZE);
    write_big_endian32 (header + MAGIC_SIZE, priorities [i]);
    write_big_endian32 (header + MAGIC_SIZE + 4, mlens [i]);
    memcpy (header + HEADER_SIZE, messages [i], mlens [i]);
    header += HEADER_SIZE + mlens [i];
  }

  return send_buffer (pipe, packet, total, 1);
}

/* send multiple messages at once, again to avoid the mysterious system
 * delay when sending multiple times in close succession on a socket.
 * messages are not freed */
int send_pipe_multiple (int pipe, int num_messages,
                        char ** messages, int * mlens, int * priorities)
{
  /* avoid SIGPIPE signals when writing to a closed pipe */
  struct sigaction sa;
  sa.sa_handler = SIG_IGN;
  sa.sa_flags = 0;
  sigemptyset (&(sa.sa_mask));
  struct sigaction old_sa;
  sigaction (SIGPIPE, &sa, &old_sa);

  int result = send_multiple_packets (pipe, num_messages, messages, mlens,
                                      priorities);

  sigaction (SIGPIPE, &old_sa, NULL);
  return result;
}

/* same, but messages are freed */
int send_pipe_multiple_free (int pipe, int num_messages,
                             char ** messages, int * mlens, int * priorities)
{
  int r = send_pipe_multiple (pipe, num_messages, messages, mlens, priorities);
  int i;
  for (i = 0; i < num_messages; i++)
    free (messages [i]);
  return r;
}

/* same as send_pipe_message, but frees the memory referred to by message */
int send_pipe_message_free (int pipe, char * message, int mlen, int priority)
{
  int result = send_pipe_message (pipe, message, mlen, priority);
/* snprintf (log_buf, LOG_SIZE, "send_pipe_message_free freeing %p (%d)\n",
            message, mlen);
  log_print (); */
  free (message);
  return result;
}

static void add_fd_to_bitset (fd_set * set, int fd, int * max)
{
  FD_SET (fd, set);
  if (fd > *max)
    *max = fd;
#ifdef DEBUG_PRINT
  snprintf (log_buf, LOG_SIZE, "selecting pipe %d, max %d\n", fd, *max);
  log_print ();
#endif /* DEBUG_PRINT */
}

static struct timeval * set_timeout (int timeout, struct timeval * tvp)
{
  if (timeout == PIPE_MESSAGE_WAIT_FOREVER) {
#ifdef DEBUG_PRINT
    snprintf (log_buf, LOG_SIZE, "set_timeout returning NULL\n");
    log_print ();
#endif /* DEBUG_PRINT */
    return NULL; /* no timeout to select */
  }
 /* PIPE_MESSAGE_NO_WAIT would be 0, which works fine in this computation */
  tvp->tv_sec = timeout / 1000;
  tvp->tv_usec = (timeout % 1000) * 1000;
#ifdef DEBUG_PRINT
  int x = snprintf (log_buf, LOG_SIZE, "set_timeout returning %p", tvp);
  x += snprintf (log_buf + x, LOG_SIZE - x, " = %d.%06d\n",
                 (int) tvp->tv_sec, (int) tvp->tv_usec);
  log_print ();
#endif /* DEBUG_PRINT */
  return tvp;
}

/* returns exactly one fd, choosing extra first, and then fds appearing
 * earlier in the buffers array.  The order is probably not a big deal */
/* returns -1 (and prints some messages) if nothing found */
static int find_fd (fd_set * set, int extra, int select_result, int max_pipe)
{
  if ((extra != -1) && (FD_ISSET (extra, set)))
    return extra;
  int i;
  for (i = 0; i < num_pipes; i++)
    if (FD_ISSET (buffers [i].pipe_fd, set))
      return buffers [i].pipe_fd;
  /* we hope not to hit the rest of this code -- mostly debugging */
  int x = snprintf (log_buf, LOG_SIZE,
                    "find_fd: strange, s is %d but no pipes found\n",
                    select_result);
  for (i = 0; i < num_pipes; i++) {
    if (FD_ISSET (buffers [i].pipe_fd, set))
      x += snprintf (log_buf + x, LOG_SIZE - x, " +%d", buffers [i].pipe_fd);
    else
      x += snprintf (log_buf + x, LOG_SIZE - x, " -%d", buffers [i].pipe_fd);
  }
  snprintf (log_buf + x, LOG_SIZE - x, "\n");
  log_print ();
  int found_set = -1;
  for (i = 0; i < max_pipe + 1; i++) {
    if (FD_ISSET (i, set)) {
      found_set = i;
      snprintf (log_buf, LOG_SIZE, "found fd %d\n", found_set);
      log_print ();
    }
  }
  print_pipes ("not found", found_set);
  return -1;
}

/* returns the first available file descriptor, or -1 in case of timeout */
/* timeout is in milliseconds, or one of PIPE_MESSAGE_WAIT_FOREVER or
 * PIPE_MESSAGE_NO_WAIT */
static int next_available (int extra, int timeout)
{
#ifdef DEBUG_PRINT
  snprintf (log_buf, LOG_SIZE, "next_available (%d, %d)\n", extra, timeout);
  log_print ();
#endif /* DEBUG_PRINT */
  /* set up the readfd bitset */
  int i;
  int max_pipe = 0;
  fd_set receiving;
  FD_ZERO (&receiving);
  for (i = 0; i < num_pipes; i++)
    add_fd_to_bitset (&receiving, buffers [i].pipe_fd, &max_pipe);
  if (extra != -1)
    add_fd_to_bitset (&receiving, extra, &max_pipe);

  /* set up the timeout, if any */
  struct timeval tv;
  struct timeval * tvp = set_timeout (timeout, &tv);

  /* call select */
  int s = select (max_pipe + 1, &receiving, NULL, NULL, tvp);
#ifdef DEBUG_PRINT
  snprintf (log_buf, LOG_SIZE, "select done, pipe %d/%d\n", s, num_pipes);
  log_print ();
#endif /* DEBUG_PRINT */
  if (s < 0) {
    perror ("next_available/select");
    print_pipes ("current", max_pipe);
    snprintf (log_buf, LOG_SIZE, "some error in select, aborting\n");
    log_print ();
    exit (1);
  }
  if (s == 0)
    return -1;
  /* s > 0 */
  int found = find_fd (&receiving, extra, s, max_pipe);
#ifdef DEBUG_PRINT
  snprintf (log_buf, LOG_SIZE, "next_available returning %d\n", found);
  log_print ();
#endif /* DEBUG_PRINT */
  return found;
}

/* returns 1 if the fd is ready to receive, 0 otherwise (including
 * in case of errors) */
static int fd_can_recv (int fd, int wait_forever)
{
  fd_set receiving;
  FD_ZERO (&receiving);
  FD_SET (fd, &receiving);
  struct timeval tv = {0, 0};   /* do not wait, just check the fd */
  struct timeval * tvp = &tv;
  if (wait_forever)
    tvp = NULL;
  int s = select (fd + 1, &receiving, NULL, NULL, tvp);
  if (s > 0)
    return 1;
  if (s < 0) { 
    perror ("fd_can_recv/select");
    snprintf (log_buf, LOG_SIZE,
              "fd_can_recv (%d): select returned %d\n", fd, s);
    log_print ();
  }
  return 0;
}

/* returns the number of characters received, or -1 in case of error */
/* if may_block is false, only returns -1 or blen. */
/* if may_block is true, may return any value between -1 and blen */
static int receive_bytes (int pipe, char * buffer, int blen, int may_block)
{
  int recvd = 0;
  while (recvd < blen) {
    if ((! may_block) && (! fd_can_recv (pipe, 0)))
      return recvd;   /* not ready to receive, and should not block */
    /* if we did not call fd_can_recv, the call to read may block */
    int new_recvd = read (pipe, buffer + recvd, blen - recvd);
    if (new_recvd <= 0) {
      if (new_recvd == 0) {
        snprintf (log_buf, LOG_SIZE, "receive_bytes: pipe %d is closed\n", pipe);
        log_print ();
      } else
        perror ("pipemsg.c receive_bytes read");
#ifdef DEBUG_PRINT
#endif /* DEBUG_PRINT */
      snprintf (log_buf, LOG_SIZE,
                "receive_bytes: %d/%d bytes on pipe %d, expected %d/%d\n",
                new_recvd, recvd, pipe, blen - recvd, blen);
      log_print ();
      return recvd > 0 ? recvd : -1 /* error */;
    }
    recvd += new_recvd;
  }
  return blen;
}

/* returns -1 if the header is not valid, and the data size otherwise */
/* note: does not work for buffers of size 2^32 - 1 -- but any buffer
 * larger than 2^31 - 1 is likely to cause problems due to signed ints anyway */
static int parse_header (char * header, int pipe, int * priority)
{
  static int printed = 0;
  if (memcmp (header, MAGIC_STRING, MAGIC_SIZE) != 0) {
    if (printed == 0) {
      snprintf (log_buf, LOG_SIZE, "error: unsynchronized pipe %d\n", pipe);
      log_print ();
      buffer_to_string (header, HEADER_SIZE, " header:", 20, 1,
                        log_buf, LOG_SIZE);
      log_print ();
    }
    printed++;
    return -1;
  }
  if (printed != 0) {
    snprintf (log_buf, LOG_SIZE, "  (%dx)\n", printed);
    log_print ();
  }
  printed = 0;
  if (priority != NULL)
    *priority = read_big_endian32 (header + MAGIC_SIZE);
  return        read_big_endian32 (header + MAGIC_SIZE + PRIORITY_SIZE);
}

/* shift the header left by one position, to make room for one more char */
static void shift_header (char * header)
{
  int i;
  for (i = 0; i + 1 < HEADER_SIZE; i++)
    header [i] = header [i + 1];
}

/* similar to receive_pipe_message but may return 0 if no message
 * is immediately ready to return.  returns -1 in case of error */
static int receive_pipe_message_poll (int pipe, char ** message, int * priority)
{
  *message = NULL;
  int index = pipe_index (pipe);
  if (index < 0) {
    do_not_print = 0;
    print_pipes ("not found", pipe);
    snprintf (log_buf, LOG_SIZE,
              "pipe %d not found, aborting and dumping core\n", pipe);
    log_print ();
    assert (0);  /* cause a core dump so we can debug this */
    /* if NDEBUG is set, assert will not end the program, so return -1 */
    return -1;
  }
  struct pipe_info * bp = buffers + index;

  int offset = bp->filled;
  int read = receive_bytes (pipe, bp->buffer + offset, bp->bsize - offset, 0);
  if (read <= 0) {
    return -1;
  }
  offset += read;
  if (offset == bp->bsize) {
   /* received all we were looking for, either allocate new buffer or return */
    if (bp->in_header) {
      int received_len = parse_header (bp->header, pipe, priority);
      if (received_len != -1) {  /* successfully read a header */
        bp->buffer = malloc (received_len);
        if (bp->buffer == NULL) {
          snprintf (log_buf, LOG_SIZE,
                    "failed to allocate %d for receive_pipe_message_poll\n",
                    received_len);
          log_print ();
          return -1;
        }
        bp->bsize = received_len;
        bp->in_header = 0;
        bp->filled = 0;
      } else {  /* failed to parse, i.e. no magic_string at start of header */
        shift_header (bp->header);            /* shift header and try again */
        if (bp->filled > 0)
          bp->filled = bp->filled - 1;
      }
      /* we stopped because the header was filled.  Try again, for either
         the next attempt to match, or the actual data */
/* printf ("recursive call rpmp (%d, %p, %d)\n", pipe, *message, *priority); */
      return receive_pipe_message_poll (pipe, message, priority);
    } else {    /* not reading header and buffer is full, so we are done. */
      *message = bp->buffer;
      int result = bp->bsize;
      bp->in_header = 1;  /* next time read a new header */
      bp->buffer = bp->header;
      bp->bsize = HEADER_SIZE;
      bp->filled = 0;
      return result;
    }
  } /* else buffer is not filled, just return to caller */
  return 0;
}

/* receives the message into a buffer it allocates for the purpose. */
/* the caller is responsible for freeing the buffer. */
int receive_pipe_message (int pipe, char ** message, int * priority)
{
  char header [HEADER_SIZE];

  int wanted = HEADER_SIZE;
  int received_len = 0;
  while (1) {
    /* read the header */
    int r = receive_bytes (pipe, header + (HEADER_SIZE - wanted), wanted, 1);
    if (r < 0)
      return -1;
    if (r == 0)
      return 0;
    /* first part of header should be MAGIC_STRING.  If not, it is an error,
       report it and keep looking */
    received_len = parse_header (header, pipe, priority);
    if (received_len != -1)   /* successfully received the header */
      break;
    shift_header (header);    /* no match, shift the header and try again */
    wanted = 1;
  }

  /* allocate the result buffer */
  char * buffer = malloc (received_len);
  if (buffer == NULL) {
    snprintf (log_buf, LOG_SIZE,
              "unable to allocate %d bytes for receive_pipe_message buffer\n",
              received_len);
    log_print ();
    return -1;
  }
  /* printf ("receive_pipe_message allocated buffer %p\n", buffer); */

  if (receive_bytes (pipe, buffer, received_len, 1) < 0) {
    free (buffer);
    return -1;
  }

  /* return the buffer and length to the caller */
  *message = buffer;
  return received_len;
}

static int tv_compare (struct timeval * t1, struct timeval * t2)
{
/*
  printf ("comparing %ld.%06ld to %ld.%06ld\n",
          t1->tv_sec, t1->tv_usec, t2->tv_sec, t2->tv_usec);
*/
  if (t1->tv_sec < t2->tv_sec)
    return -1;
  if (t1->tv_sec > t2->tv_sec)
    return 1;
  if (t1->tv_usec < t2->tv_usec)
    return -1;
  if (t1->tv_usec > t2->tv_usec)
    return 1;
  return 0;
}

static int receive_dgram (int fd, char ** message, 
                          struct sockaddr * sa, socklen_t * salen)
{
  *message = malloc (ALLNET_MTU);
  if (*message == NULL) {
    snprintf (log_buf, LOG_SIZE,
              "unable to allocate %d bytes for receive_dgram", ALLNET_MTU);
    log_print ();
    return -1;
  }
#ifdef DEBUG_PRINT
  snprintf (log_buf, LOG_SIZE, "ready to receive datagram on fd %d\n", fd);
  log_print ();
#endif /* DEBUG_PRINT */
  int result = recvfrom (fd, *message, ALLNET_MTU, MSG_DONTWAIT, sa, salen);
  if (result < 0) {
    if ((errno != EAGAIN) && (errno != EWOULDBLOCK))
      perror ("recvfrom");
    free (*message);
    *message = NULL;
    if ((errno != EAGAIN) && (errno != EWOULDBLOCK))
      return -1;
    return 0;   /* EAGAIN or EWOULDBLOCK, no message ready at this time */
  }
  return result;
}

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
int receive_pipe_message_fd (int timeout, char ** message, int fd,
                             struct sockaddr * sa, socklen_t * salen,
                             int * from_pipe, int * priority)
{
  struct timeval now, finish;
  gettimeofday (&now, NULL);
  finish = now;
  if (timeout != PIPE_MESSAGE_WAIT_FOREVER)
    add_us (&finish, timeout * 1000LL);

  if (from_pipe != NULL) *from_pipe = -1;
  if (priority != NULL) *priority = ALLNET_PRIORITY_EPSILON;
  while ((timeout == PIPE_MESSAGE_WAIT_FOREVER) ||
         (tv_compare (&now, &finish) <= 0)) {
    int pipe;
    pipe = next_available (fd, timeout);
    if (pipe >= 0) { /* can read pipe */
      if (from_pipe != NULL) *from_pipe = pipe;
      int r;
      if (pipe != fd) { /* it is a pipe, not a datagram socket */
        r = receive_pipe_message_poll (pipe, message, priority);
/* if (r < 0) printf ("receive_pipe_message_poll returned %d\n", r); */
        if ((sa != NULL) && (salen != NULL) && (*salen > 0))
          bzero (sa, *salen);
        if (salen != NULL)
          *salen = 0;
      } else {         /* UDP or raw socket */
        r = receive_dgram (pipe, message, sa, salen);
/* if (r < 0) printf ("receive_dgram returned %d\n", r); */
      }
      if (r < 0)
        return -1;
      if (r > 0)
        return r;
      /* else read a partial or no buffer, repeat until timeout */
      if (from_pipe != NULL) *from_pipe = -1;
    }
    gettimeofday (&now, NULL);
  }
  return 0;    /* timed out */
}

/* receive on the first ready pipe, returning the size and message
 * for the first one received, and returning 0 in case of timeout
 * and -1 in case of error, including a closed pipe.
 * timeout is specified in ms.
 * The pipe from which the message is received (or which has an error)
 * is returned in *from_pipe.
 * if udp_fd is not -1, also listens to the UDP fd, returning the
 * corresponding *from_pipe and returning 0, but not actually reading the fd
 */
int receive_pipe_message_any (int timeout, char ** message,
                              int * from_pipe, int * priority)
{
  return receive_pipe_message_fd (timeout, message, -1, NULL, NULL,
                                  from_pipe, priority);
}
