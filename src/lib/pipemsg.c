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
#include <time.h>
#include <pthread.h>
#include <sys/select.h>

#include "packet.h"
#include "priority.h"
#include "pipemsg.h"
#include "util.h"
#include "allnet_log.h"
#include "allnet_queue.h"

#define MAGIC_STRING	"MAGICPIE"  /* magic pipe, squeezed into 8 chars */

/* MAGIC_SIZE does not include null character at the end */
#define MAGIC_SIZE	(sizeof (MAGIC_STRING) - 1)
#define PRIORITY_SIZE	4
#define LENGTH_SIZE	4
#define HEADER_SIZE	(MAGIC_SIZE + PRIORITY_SIZE + LENGTH_SIZE)

#define KILL_SOCKET_AFTER	100   /* after data pending for 100 seconds */

struct allnet_pipe_info {
  int pipe_fd;	   /* file descriptor for input */
  int in_header;
  char header [HEADER_SIZE];
  char * buffer;   /* may be null */
  unsigned int filled; /* how many bytes already in the buffer or header? */
  unsigned int bsize;  /* how many bytes do we receive before we are done? */
  char description [100];
};

#define MAX_PIPES	100
struct pipedesc {
  int num_pipes;
  struct allnet_pipe_info buffers [MAX_PIPES];
  int num_queues;
  int queues [MAX_PIPES];  /* negative integers -x, at index x - 1 */
  struct allnet_log * log;
  pthread_mutex_t receive_mutex;
#ifdef DEBUG_EBADF
#define NUM_EBADBUFS	20
char ebadbufs [NUM_EBADBUFS] [EBADBUFS];
int ebadbufindex;  /* index of first, i.e. earliest, message */
int ebadbufcount;
#endif /* DEBUG_EBADF */
};

pd init_pipe_descriptor (struct allnet_log * log)
{
  pd result = malloc_or_fail (sizeof (struct pipedesc), "init pipe descriptor");
  memset (result, 0, sizeof (*result));  /* makes debugging easier */
  result->num_pipes = 0;
  result->num_queues = 0;
  result->log = log;
  pthread_mutex_init (&(result->receive_mutex), NULL);
#ifdef DEBUG_EBADF
  memset (&(result->ebadbufs [0] [0]), 0, sizeof (result->ebadbufs));
  result->ebadbufindex = 0;
  result->ebadbufcount = 0;
#endif /* DEBUG_EBADF */
  return result;
}

struct allnet_log * pipemsg_log (pd p)
{
  return p->log;
}

static char last_received_message [LOG_SIZE] = "";
static struct allnet_log * last_received_log = NULL;

void pipemsg_debug_last_received (const char * message)
{
  if (strlen (last_received_message) > 0) {
    printf ("%s\n%s", message, last_received_message);
    if (last_received_log != NULL) {
      snprintf (last_received_log->b, last_received_log->s,
                "%s", last_received_message);
      log_print (last_received_log);
    }
  }
  last_received_message [0] = '\0';   /* delete the message */
}

static void save_received_message (pd p, int pipe,
                                   char * msg, unsigned int mlen)
{
  if (mlen <= 24)
    return;
  /* 99 57 is a known sender of bad packets, ignore for now (2017/04) */
  if (((msg [8] & 0xff) == 0x99) && ((msg [16] & 0xff) == 0x99) &&
      ((msg [9] & 0xff) == 0x57) && ((msg [17] & 0xff) == 0x57)) {
    last_received_message [0] = '\0';   /* delete the message, don't print */
    return;
  }
  int off = snprintf (last_received_message, LOG_SIZE,
                      "%s packet received from fd %d, ",
                      p->log->debug_info, pipe);
  if (off < LOG_SIZE) {
    off += buffer_to_string (msg, mlen, NULL, 150, 0, 
                             last_received_message + off, LOG_SIZE - off);
    if ((off < LOG_SIZE) && (mlen > 150)) {  /* also print the last 4 bytes */
      off += buffer_to_string (msg + mlen - 4, 4, "last", 4, 1, 
                               last_received_message + off, LOG_SIZE - off);
    }
  } else {
    snprintf (last_received_message, LOG_SIZE,
              "%s packet received from fd %d, %u bytes\n",
              p->log->debug_info, pipe, mlen);
  }
  last_received_log = p->log;
}

static void die (const char * msg)
{
  int x = 0;
  printf ("%s\n", msg);
  int y = 10 / x;
  x = y;
}

static int do_not_print = 1;
static void print_pipes (pd p, const char * desc, int pipe)
{
  if (do_not_print)
    return;
  char * is_locked = "";
  if (pthread_mutex_trylock (&(p->receive_mutex)) == 0) {
    pthread_mutex_unlock (&(p->receive_mutex));
  } else {
    is_locked = " (locked)";
  }
  if (pipe != -1)
    snprintf (p->log->b, p->log->s, "%s pipe %d, total %d/%d%s\n",
              desc, pipe, p->num_pipes, p->num_queues, is_locked);
  else
    snprintf (p->log->b, p->log->s, "%s %d/%d pipes%s\n",
              desc, p->num_pipes, p->num_queues, is_locked);
  printf ("%s", p->log->b);
  log_print (p->log);
if ((pipe > 1000) || (pipe < -1000)) die ("illegal pipe number");
  int i;
  for (i = 0; i < p->num_pipes; i++) {
    char * inhdr = ((p->buffers [i].in_header) ? "" : "not ");
    snprintf (p->log->b, p->log->s,
              "  [%d: %s]: pipe %d, %shdr, h %p b %p, filled %u bsize %u\n", i,
              p->buffers [i].description,
              p->buffers [i].pipe_fd, inhdr,
              p->buffers [i].header, p->buffers [i].buffer,
              p->buffers [i].filled, p->buffers [i].bsize);
    printf ("%s", p->log->b);
    log_print (p->log);
    buffer_to_string (p->buffers [i].header, HEADER_SIZE, "header",
                      HEADER_SIZE, 1, p->log->b, p->log->s);
    printf ("%s", p->log->b);
    log_print (p->log);
  }
  for (i = 0; i < p->num_queues; i++) {
    int index = (- (p->queues [i])) - 1;
    if (allnet_queues != NULL) {
      struct allnet_queue * q = allnet_queues [index];
      snprintf (p->log->b, p->log->s, "  [%d/%d]: queue '%s', %d packets\n",
                i, index, allnet_queue_info (q), allnet_queue_size (q)); 
      printf ("%s", p->log->b);
      log_print (p->log);
    }
  }
}

/* returns the pipe index if present, -1 otherwise */
static int pipe_index (pd p, int pipe)
{
  int i;
  for (i = 0; i < p->num_pipes; i++)
    if (p->buffers [i].pipe_fd == pipe)
      return i;
  return -1;
}

/* returns the queue index if present, -1 otherwise */
static int queue_index (pd p, int queue)
{
  int i;
  for (i = 0; i < p->num_queues; i++)
    if (p->queues [i] == queue)
      return i;
  return -1;
}

void add_pipe (pd p, int pipe, const char * description)
{
  if (pipe >= 0) {
    if (pipe_index (p, pipe) != -1) {
      snprintf (p->log->b, p->log->s,
                "adding pipe %d already in data structure [%d]\n",
                pipe, pipe_index (p, pipe));
      log_print (p->log);
      return;
    }
    if (p->num_pipes >= MAX_PIPES) {
      snprintf (p->log->b, p->log->s,
                "too many (%d) pipes, not adding %d\n", p->num_pipes, pipe);
      log_print (p->log);
      return;
    }
    struct allnet_pipe_info * api = p->buffers + p->num_pipes;
    p->num_pipes = p->num_pipes + 1;
    api->pipe_fd = pipe;
    api->in_header = 1;  /* always start by reading the header */
    api->buffer = api->header;
    api->bsize = HEADER_SIZE;
    api->filled = 0;
    snprintf (api->description, sizeof (api->description), "%s", description);
  } else {  /* negative, so it's a queue */
    if (queue_index (p, pipe) != -1) {
      snprintf (p->log->b, p->log->s,
                "adding queue %d already in data structure [%d]\n",
                pipe, queue_index (p, pipe));
      log_print (p->log);
      return;
    }
    if (p->num_queues >= MAX_PIPES) {
      snprintf (p->log->b, p->log->s,
                "too many (%d) queues, not adding %d\n", p->num_queues, pipe);
      log_print (p->log);
      return;
    }
    p->queues [p->num_queues] = pipe;
    p->num_queues = p->num_queues + 1;
  }
  print_pipes (p, "added", pipe);
}

/* return 1 if removed, 0 otherwise */
int remove_pipe (pd p, int pipe)
{
  /* acquire the lock, so we only remove when we are not receiving */
  pthread_mutex_lock (&(p->receive_mutex));
  int is_pipe = (pipe >= 0);
  int index = (is_pipe) ? (pipe_index (p, pipe)) : (queue_index (p, pipe));
  if (index == -1) { /* nothing to delete */
    pthread_mutex_unlock (&(p->receive_mutex));
    return 0;
  }
  snprintf (p->log->b, p->log->s,
            "removing %s %d from data structure [%d]\n",
            (is_pipe) ? "pipe" : "queue", pipe, index);
  log_print (p->log);
  if (is_pipe) {
    struct allnet_pipe_info * api = p->buffers + index;
    if ((! api->in_header) && (api->buffer != NULL))
      free (api->buffer);
    if (index + 1 < p->num_pipes) {
      p->buffers [index] = p->buffers [p->num_pipes - 1];
      if (p->buffers [index].in_header)  /* update the pointer */
        p->buffers [index].buffer = p->buffers [index].header;
    }
    p->num_pipes = p->num_pipes - 1;
  } else {
    if (index + 1 < p->num_queues)
      p->queues [index] = p->queues [p->num_queues - 1];
    p->num_queues = p->num_queues - 1;
  }
  pthread_mutex_unlock (&(p->receive_mutex));
  print_pipes (p, "removed", pipe);
  return 1;
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

#if 0  /* dead code, but might be useful in the future */
static int send_pipe_message_orig (int pipe, const char * message, int mlen,
                                   int priority, struct allnet_log * log)
{
  snprintf (log->b, log->s, "warning: send_pipe_message_orig\n");
  log_print ();  /* normally should not happen */
  char header [HEADER_SIZE];
  memcpy (header, MAGIC_STRING, MAGIC_SIZE);
  write_big_endian32 (header + MAGIC_SIZE, priority);
  write_big_endian32 (header + MAGIC_SIZE + 4, mlen);

  int w = write (pipe, header, HEADER_SIZE); 
  if (w != HEADER_SIZE) {
    perror ("send_pipe_msg(1) write");
    snprintf (log->b, log->s, "(1) pipe number %d, result %d\n", pipe, w);
    log_print ();
    return 0;
  }

  w = write (pipe, message, mlen); 
  if (w != mlen) {
    perror ("send_pipe_msg(2) write");
    snprintf (log->b, log->s,
              "(2) pipe number %d, wrote %d instead of %d\n", pipe, w, mlen);
    log_print ();
    return 0;
  }
  return 1;
}
#endif /* 0 */

struct saved_bytes_for_send {
  int pipe;
  int num_saved_bytes;
  unsigned long long first_created;
  char * buffer;
};
static struct saved_bytes_for_send * saved_records = NULL;
static int num_saved_records = 0;

/* if there are saved bytes for this pipe, replace buffer with those bytes
 * concatenating the two if the result is short enough (arbitrarily, we
 * set the limit to ALLNET_MTU) */
/* invariant: after the call, this pipe is not in saved_records. */
/* fc records the time at which this record was first created (0 for none) */
static void saved_bytes_for_pipe (int pipe, char ** buffer, int * blen,
                                  unsigned long long int * fc,
                                  int * do_free, struct allnet_log * log)
{
  *fc = 0;
  int found = 0;  /* if true, found a match, replaced buffer */
  int i;
  for (i = 0; i < num_saved_records; i++) {
    if (found) {
      if (i <= 0) {   /* sanity check, if found, i should always be > 0 */
        snprintf (log->b, log->s,
                  "saved_bytes_for_pipe: found %d, i %d\n", found, i);
        log_print (log);
      } else {        /* i > 0, copy this record to previous location */
        saved_records [i - 1] = saved_records [i];
      }
    } else if (saved_records [i].pipe == pipe) { /* match, replace buffer */
      found = 1;   /* from here on up, copy records instead of searching */
      /* save the new buffer with the old unless the result is large */
      *fc = saved_records [i].first_created;
      int combined_size = *blen + saved_records [i].num_saved_bytes;
      if (combined_size <= ALLNET_MTU) {  /* combine them */
        char * new_buffer = memcat_malloc (saved_records [i].buffer,
                                           saved_records [i].num_saved_bytes,
                                           *buffer, *blen,
                                           "saved_bytes_for_pipe combine");
        free (saved_records [i].buffer);  /* no longer needed */
        saved_records [i].buffer = new_buffer; 
        saved_records [i].num_saved_bytes = combined_size;
      }   /* else, just use the saved buffer without combining */
      /* now, replace the caller's buffer with the new one */
      if (*do_free)
        free (*buffer);
      *do_free = 1;  /* always free the returned buffer */
      *buffer = saved_records [i].buffer;  /* will be free'd by caller */
      *blen = saved_records [i].num_saved_bytes;
    }
  }
  /* finished loop.  If not found, we are done.  If found, reallocate
   * saved_records to be one smaller, and decrement num_saved_records */
  if (found) {   /* deleted something */
    /* invariant: num_saved_records > 0 (otherwise found would be 0) */
    num_saved_records--;
    if (num_saved_records < 0) {   /* sanity check */
      snprintf (log->b, log->s, "saved_bytes_for_pipe: %d saved records\n",
                num_saved_records);
      log_print (log);
      num_saved_records = 0;
    }
    size_t size = num_saved_records * sizeof (struct saved_bytes_for_send);
    if (size > 0) {
      saved_records = realloc (saved_records, size);
      if (saved_records == NULL)   /* realloc failed, should be rare */
        num_saved_records = 0;
    } else {
      free (saved_records);
      saved_records = NULL;
    }
  }
}

/* adds the record to the end of saved_records */
/* invariant (must hold before the call): this pipe is not in saved_records.
 * if save_remaining_bytes is called after saved_bytes_for_pipe,
   the invariant should hold */
static void save_remaining_bytes (int pipe, char * buffer, int blen,
                                  unsigned long long int first_created) 
{
  if (blen <= 0)
    return;
  if ((saved_records == NULL) || (num_saved_records <= 0)) {
    saved_records = malloc (sizeof (struct saved_bytes_for_send));
    num_saved_records = 1;
  } else {
    num_saved_records++;
    saved_records = realloc (saved_records,
                             sizeof (struct saved_bytes_for_send) *
                             num_saved_records);
  }
  if ((saved_records == NULL) ||  /* allocation error, abort */
      (num_saved_records <= 0)) { /* sanity check */
    num_saved_records = 0;
    return;
  }
  /* invariants: num_saved_records > 0, saved_records != NULL */
  int index = num_saved_records - 1;
  saved_records [index].pipe = pipe;
  saved_records [index].num_saved_bytes = blen;
  saved_records [index].first_created = first_created;
  saved_records [index].buffer = memcpy_malloc (buffer, blen,
                                                "save_remaining_bytes");
}

/* returns 1 if the send was "successful", i.e. the pipe is not dead --
 * if the socket was busy, the packet may not actually have been sent,
 * but still return 1.  Return 0 in case of actual errors */
static int send_buffer (int pipe, char * buffer, int blen, int do_free,
                        struct allnet_log * log)
{
  static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
  pthread_mutex_lock (&mutex);
  /* otherwise different threads might send at the same time, and
   * their packets might overlap */
  /* INVARIANT: this code always runs through to the unlock statement
   * at the end.  Maintainers: please maintain this invariant */
  /* if we need to send the remainder of an earlier packet,
   * discard this packet and replace it with those bytes,
   * or (if the combined size is small enough) concatenate the two */
  unsigned long long int created;
  saved_bytes_for_pipe (pipe, &buffer, &blen, &created, &do_free, log);
  int result = 1;
  ssize_t w = send (pipe, buffer, blen, MSG_DONTWAIT); 
  int save_errno = errno;
  ssize_t save_w = w;
  /* invariant: w shows the amount of data sent, or is -1 for error */
  /* error may include EAGAIN, if the socket was full */
  /* note on some systems EAGAIN and EWOULDBLOCK are the same */
  if (w < blen) {   /* incomplete write or outright error */
    result = 0;  /* it's an error */
    if ((w >= 0) ||    /* partial send */
        ((errno == EAGAIN) || (errno == EWOULDBLOCK))) { /* socket busy */
      result = 1;  /* report as success, since the socket is not dead */
      if (created == 0)   /* first time */
        created = allnet_time ();
      else if (created + KILL_SOCKET_AFTER < allnet_time ())
        result = 0;  /* socket idle more than 100sec, close it */
      snprintf (log->b, log->s,
                "pipe %d, partial %zd/%zd/%d/%d, "
                "time %llu/%llu, errno %d/%d, %d records\n",
                pipe, w, save_w, blen, result, created, allnet_time (),
                save_errno, errno, num_saved_records);
      log_error (log, "send_pipe_msg partial send");
      ssize_t save = w;  /* now save the unsent bytes */
      if (save < 0)      /* send them next time we are called for this pipe */
        save = 0;
      /* if (w == 0), this code is just an optimization.
       * if (w > 0) , this code is required to avoid creating hybrid packets */
      if (result != 0)
        save_remaining_bytes (pipe, buffer + save, blen - (int)save, created); 
    } else {  /* w < 0, this is an error */
      if (errno == EPIPE) {
        snprintf (log->b, log->s,
                  "sigpipe/epipe %d/%d on pipe %d\n",
                  errno, save_errno, pipe);
        log_error (log, "send_pipe_msg send");
        /* it is normal for aip and alocal to have sigpipes, do not report */
        if ((strcmp (log->debug_info, "aip") != 0) &&
            (strcmp (log->debug_info, "alocal") != 0))
          printf ("%s: sigpipe on fd %d\n", log->debug_info, pipe);
      } else if (errno == ENOTSOCK) {
        snprintf (log->b, log->s,
                  "result %zd, errno %d, notsock, maybe try write on fd %d?\n",
                  w, save_errno, pipe);
        log_error (log, "send_pipe_msg send, not socket");
      } else {
        snprintf (log->b, log->s, "result of send is %zd, errno %d, fd %d\n",
                  w, save_errno, pipe);
        log_error (log, "send_pipe_msg send");
      }
    }
  }
#ifdef DEBUG_PRINT
  snprintf (log->b, log->s, "send_buffer sent %d/%zd bytes on socket %d\n",
            blen, w, pipe);
  log_print (log);
#endif /* DEBUG_PRINT */
  if (do_free)
    free (buffer);
  pthread_mutex_unlock (&mutex);
  return result;
}

static int send_header_data (int pipe, const char * message, int mlen,
                             int priority, struct allnet_log * log)
{
  char packet [HEADER_SIZE + ALLNET_MTU];
  if (mlen > ALLNET_MTU) {
/* I think this should never happen.  If it does, print it to log and screen */
    snprintf (log->b, log->s,
              "send_header_data warning: mlen %d > ALLNET_MTU %d\n",
              mlen, ALLNET_MTU);
    printf ("%s", log->b);
    log_print (log);
    buffer_to_string (message, mlen, "message is", 64, 1, log->b, log->s);
    printf ("%s", log->b);
    log_print (log);
    packet_to_string (message, mlen, NULL, 1, log->b, log->s);
    printf ("%s", log->b);
    log_print (log);
    return 0; /* and return as an error */
  }
#ifdef PACKET_DECLARED_AS_POINTER_IN_SEND_HEADER_DATA  /* never NULL */
/* send_pipe_message_orig is simpler, but sometimes stalls for ~35ms-40ms
 * on the second send, so it is faster if we only call write once */
  if (packet == NULL)   /* unable to malloc, use the slow strategy */
    return send_pipe_message_orig (pipe, message, mlen, priority);
#endif /* PACKET_DECLARED_AS_POINTER_IN_SEND_HEADER_DATA */

  char * header = packet;
  memcpy (header, MAGIC_STRING, MAGIC_SIZE);
  write_big_endian32 (header + MAGIC_SIZE, priority);
  write_big_endian32 (header + MAGIC_SIZE + 4, mlen);
  memcpy (header + HEADER_SIZE, message, mlen);

  int result = send_buffer (pipe, packet, HEADER_SIZE + mlen, 0, log);
/* room for debugging code, when needed */
  return result;
}

int send_pipe_message (int pipe, const char * message, unsigned int mlen,
                       unsigned int priority,
                       struct allnet_log * log)
{
  if (pipe < 0) {
    if (allnet_queues != NULL)
      return allnet_enqueue (allnet_queues [-pipe - 1],
                             (const unsigned char *) message,
                             (unsigned int) mlen, (unsigned int) priority);
    else
      return 0;
  }
  /* avoid SIGPIPE signals when writing to a closed pipe */
  struct sigaction sa;
  sa.sa_handler = SIG_IGN;
  sa.sa_flags = 0;
  sigemptyset (&(sa.sa_mask));
  struct sigaction old_sa;
  sigaction (SIGPIPE, &sa, &old_sa);

  int result = send_header_data (pipe, message, mlen, priority, log);

  sigaction (SIGPIPE, &old_sa, NULL);
  return result;
}

/* send multiple messages at once, again to avoid the mysterious system
 * delay when sending multiple times in close succession on a socket.
 * (Nagle's delay?).  Each message gets its own header */
static int send_multiple_packets (int pipe, unsigned int num_messages,
                                  const char ** messages,
                                  const unsigned int * mlens,
                                  const unsigned int * priorities,
                                  struct allnet_log * log)
{
  if (num_messages <= 0)
    return 0;
  unsigned int i;
  int total = 0;
  for (i = 0; i < num_messages; i++)
    total += HEADER_SIZE + mlens [i];
  int result = 1;

  char * packet = malloc (total);
  if (packet == NULL) {  /* unable to malloc, use the slow strategy */
    snprintf (log->b, log->s,
              "unable to malloc %d bytes for %d packets, falling back\n",
              total, num_messages);
    log_print (log);
    for (i = 0; i < num_messages; i++) {
      if (! send_pipe_message (pipe, messages [i], mlens [i],
                               priorities [i], log))
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

  return send_buffer (pipe, packet, total, 1, log);
}

/* send multiple messages at once, again to avoid the mysterious system
 * delay when sending multiple times in close succession on a socket.
 * messages are not freed */
int send_pipe_multiple (int pipe, unsigned int num_messages,
                        const char ** messages, const unsigned int * mlens,
                        const unsigned int * priorities,
                        struct allnet_log * log)
{
  if (pipe < 0) {
    if (allnet_queues != NULL) {
      unsigned int i;
      int success = 1;
      for (i = 0; i < num_messages; i++) {
        success = success &&
                  allnet_enqueue (allnet_queues [-pipe - 1],
                                  (const unsigned char *) (messages [i]),
                                  (unsigned int) (mlens [i]),
                                  (unsigned int) (priorities [i]));
printf ("enqueued message of size %d on pipe %d, success %d (%d/%d)\n",
mlens [i], pipe, success, i, num_messages);
      }
      return success;
    } else
      return 0;
  }
  /* avoid SIGPIPE signals when writing to a closed pipe */
  struct sigaction sa;
  sa.sa_handler = SIG_IGN;
  sa.sa_flags = 0;
  sigemptyset (&(sa.sa_mask));
  struct sigaction old_sa;
  sigaction (SIGPIPE, &sa, &old_sa);

  int result = send_multiple_packets (pipe, num_messages, messages, mlens,
                                      priorities, log);

  sigaction (SIGPIPE, &old_sa, NULL);
  return result;
}

/* same, but messages are freed */
int send_pipe_multiple_free (int pipe, unsigned int num_messages,
                             char ** messages, const unsigned int * mlens,
                             const unsigned int * priorities,
                             struct allnet_log * log)
{
  int r = send_pipe_multiple (pipe, num_messages, (const char **)messages,
                              mlens, priorities, log);
  unsigned int i;
  for (i = 0; i < num_messages; i++)
    free (messages [i]);
  return r;
}

/* same as send_pipe_message, but frees the memory referred to by message */
int send_pipe_message_free (int pipe, char * message, unsigned int mlen,
                            unsigned int priority,
                            struct allnet_log * log)
{
  int result = send_pipe_message (pipe, message, mlen, priority, log);
/* snprintf (log->b, log->s, "send_pipe_message_free freeing %p (%d)\n",
            message, mlen);
  log_print (); */
  free (message);
  return result;
}

static void add_fd_to_bitset (fd_set * set, int fd, int * max,
                              struct allnet_log * log)
{
  FD_SET (fd, set);
  if (fd > *max)
    *max = fd;
#ifdef DEBUG_PRINT
  snprintf (log->b, log->s, "selecting pipe %d, max %d\n", fd, *max);
  log_print (log);
#endif /* DEBUG_PRINT */
}

/* returns NULL for a wait-forever timeout, or
 *         tvp, with *tvp updated to the correct timeout */
static struct timeval * set_timeout (int timeout, struct timeval * tvp,
                                     struct allnet_log * log)
{
  if (timeout == PIPE_MESSAGE_WAIT_FOREVER) {
#ifdef DEBUG_PRINT
    snprintf (log->b, log->s, "set_timeout returning NULL\n");
    log_print (log);
#endif /* DEBUG_PRINT */
    return NULL; /* no timeout to select */
  }
  if (timeout < 0) {
    printf ("set_timeout (%d) error: bad timeout\n", timeout);
    snprintf (log->b, log->s, "set_timeout (%d) error: bad timeout\n", timeout);
    log_print (log);
  }
  if (timeout > (86400 * 1000)) {  /* one day */
    printf ("set_timeout (%d): large timeout\n", timeout);
    snprintf (log->b, log->s, "set_timeout (%d): large timeout\n", timeout);
    log_print (log);
  }
 /* PIPE_MESSAGE_NO_WAIT would be 0, which works fine in this computation */
  tvp->tv_sec = timeout / 1000;
  tvp->tv_usec = (timeout % 1000) * 1000;
#ifdef DEBUG_PRINT
  int x = snprintf (log->b, log->s, "set_timeout returning %p", tvp);
  x += snprintf (log->b + x, log->s - x, " = %d.%06d\n",
                 (int) tvp->tv_sec, (int) tvp->tv_usec);
  log_print (log);
#endif /* DEBUG_PRINT */
  return tvp;
}

/* returns exactly one fd, choosing extra first, and then fds appearing
 * earlier in the buffers array.  The order is probably not a big deal */
/* returns -1 (and prints some messages) if nothing found */
static int find_fd (pd p, fd_set * set, int extra,
                    int select_result, int max_pipe)
{
  if ((extra != -1) && (FD_ISSET (extra, set)))
    return extra;
  int i;
  for (i = 0; i < p->num_pipes; i++)
    if (FD_ISSET (p->buffers [i].pipe_fd, set))
      return p->buffers [i].pipe_fd;
  /* we hope not to hit the rest of this code -- mostly debugging */
  int x = snprintf (p->log->b, p->log->s,
                    "find_fd: strange, s is %d but no pipes found\n",
                    select_result);
  for (i = 0; i < p->num_pipes; i++) {
    if (FD_ISSET (p->buffers [i].pipe_fd, set))
      x += snprintf (p->log->b + x, p->log->s - x, " +%d",
                     p->buffers [i].pipe_fd);
    else
      x += snprintf (p->log->b + x, p->log->s - x, " -%d",
                     p->buffers [i].pipe_fd);
  }
  snprintf (p->log->b + x, p->log->s - x, "\n");
  log_print (p->log);
  int found_set = -1;
  for (i = 0; i < max_pipe + 1; i++) {
    if (FD_ISSET (i, set)) {
      found_set = i;
      snprintf (p->log->b, p->log->s, "found fd %d\n", found_set);
      log_print (p->log);
    }
  }
  print_pipes (p, "not found", found_set);
  return -1;
}

static int make_fdset (pd p, int extra, fd_set * set, struct allnet_log * log)
{
  int i;
/* for (i = 0; i < p->num_pipes; i++)
if ((p->buffers [i].pipe_fd > 1000) || (p->buffers [i].pipe_fd < -1000))
printf ("next_available err: fd %d at index %d\n", p->buffers [i].pipe_fd, i);*/
  int max_pipe = 0;
  FD_ZERO (set);
  for (i = 0; i < p->num_pipes; i++)
    add_fd_to_bitset (set, p->buffers [i].pipe_fd, &max_pipe, log);
  if (extra != -1)
    add_fd_to_bitset (set, extra, &max_pipe, log);
  return max_pipe;
}

/* we've been called with ebadf.  find out which fd caused the problem */
/* copies some code from make_fdset */
static void debug_ebadf (pd p, int extra)
{
  int i;
#ifdef DEBUG_EBADF
  printf ("ebadbufcount is %d, index %d\n", p->ebadbufcount, p->ebadbufindex);
  for (i = 0; i < p->ebadbufcount; i++)
    printf ("[%d]: %s", i, p->ebadbufs [(i + p->ebadbufindex) % NUM_EBADBUFS]);
#endif /* DEBUG_EBADF */
  printf ("debug_ebadf, %d pipes, extra %d\n", p->num_pipes, extra);
  int old_do_not_print = do_not_print;
  do_not_print = 0;
  print_pipes (p, "debug_ebadf", -1);
  do_not_print = old_do_not_print;
  for (i = 0; i < p->num_pipes + 1; i++) {
    /* like make_fdset, but only FD i */
    fd_set receiving;
    FD_ZERO (&receiving);
    int max_pipe = 0;
    int fd = ((i < p->num_pipes) ? (p->buffers [i].pipe_fd) : (extra));
    if (fd >= 0) {
      add_fd_to_bitset (&receiving, fd, &max_pipe, p->log);
      struct timeval tv;
      struct timeval * tvp = set_timeout (0, &tv, p->log);
      int s = select (fd + 1, &receiving, NULL, NULL, tvp);
      if ((s < 0) && (errno == EBADF)) {
        snprintf (p->log->b, p->log->s,
                  "EBADF: bad fd [%d/%d: %s] = %d\n", i, p->num_pipes,
                  p->buffers [i].description, fd);
        printf ("%s", p->log->b);
        log_print (p->log);
      }
    } else if (i < p->num_pipes) {  /* it's OK if extra is -1 */
      snprintf (p->log->b, p->log->s,
                "EBADF: negative bad fd [%d/%d] = %d\n", i, p->num_pipes, fd);
      printf ("%s", p->log->b);
      log_print (p->log);
    }
  }
}

#ifdef DEBUG_PIPEMSG_SELECT
static fd_set debug_fdset1;
static fd_set debug_fdset2;
static fd_set debug_fdset3;
static fd_set debug_fdset4;
static unsigned long long int debug_fdtime = 0;
#endif /* DEBUG_PIPEMSG_SELECT */

/* returns the first available file descriptor, or -1 in case of timeout */
/* timeout is in milliseconds, or one of PIPE_MESSAGE_WAIT_FOREVER or
 * PIPE_MESSAGE_NO_WAIT */
static int next_available (pd p, int extra, int timeout)
{
#ifdef DEBUG_PRINT
  snprintf (p->log->b, p->log->s, "next_available (%d, %d)\n",
            extra, timeout);
  log_print (p->log);
#endif /* DEBUG_PRINT */
  /* set up the fdset for receiving */
  fd_set receiving;
  int max_pipe = make_fdset (p, extra, &receiving, p->log);
  /* set up the timeout, if any */
  struct timeval tv;
  struct timeval * tvp = set_timeout (timeout, &tv, p->log);
  if ((timeout > 0) && (timeout != PIPE_MESSAGE_WAIT_FOREVER) &&
      (p->num_pipes == 0) && (extra == -1) && (p->num_queues > 0))
    /* since we have queues and no pipes, set timeout so we check
     * the queues after a 10ms timeout */
    tvp = set_timeout (10, &tv, p->log);
  struct timeval orig_tv = tv;

  /* call select */
#ifdef DEBUG_PIPEMSG_SELECT
  debug_fdset1 = receiving;
#endif /* DEBUG_PIPEMSG_SELECT */
  int s = select (max_pipe + 1, &receiving, NULL, NULL, tvp);
#ifdef DEBUG_PIPEMSG_SELECT
  debug_fdset2 = receiving;
  debug_fdtime = allnet_time_us ();
#endif /* DEBUG_PIPEMSG_SELECT */
#ifdef DEBUG_PRINT
  snprintf (p->log->b, p->log->s, "select done, pipe %d/%d\n",
            s, p->num_pipes);
  log_print (p->log);
#endif /* DEBUG_PRINT */
  if (s < 0) {
    /* we are going to exit (unless EBADF), so print everything, unless
     * killed on purpose (EINTR) */
    do_not_print = ((errno == EINTR) || (errno == EBADF));
    char * error_string = "some error";
    char * q_string = ", shutting down";
    if (errno == EINTR)
      error_string = "interrupted (EINTR)";
    if (errno == EBADF)
      error_string = "bad file descriptor (EBADF)";
    if (do_not_print)
      q_string = "";
    if (! do_not_print)
      perror ("next_available/select");
    int off = snprintf (p->log->b, p->log->s,
                        "%s in select (errno %d extra %d, mp %d, ",
                        error_string, errno, extra, max_pipe);
    off += snprintf (p->log->b + off, p->log->s - off,
                     "t %ld.%ld/%ld.%ld/%p/%d)%s\n",
                     tv.tv_sec, (long) tv.tv_usec,
                     orig_tv.tv_sec, (long) orig_tv.tv_usec,
                     tvp, timeout, q_string);
    int exiting = 1;                 /* normally exit */
    if (errno == EBADF) /* usually, FD closed but not (yet) removed from p */
      exiting = 0;
    static time_t printed_sec = 0;
    if (exiting || (printed_sec < time (NULL))) {
      /* print EBADF at most once per second */
      printed_sec = time (NULL);
      log_print (p->log);
      print_pipes (p, "current", max_pipe);
      if (errno == EBADF)
        debug_ebadf (p, extra);
    }
    if (! exiting)   /* usually, FD closed but not (yet) removed from p */
      return -1;     /* unable to complete */
    exit (1);
  }
  if (s == 0)
    return -1;
  /* s > 0 */
  int found = find_fd (p, &receiving, extra, s, max_pipe);
#ifdef DEBUG_PRINT
  snprintf (p->log->b, p->log->s,
            "next_available returning %d\n", found);
  log_print (p->log);
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
#ifdef DEBUG_PIPEMSG_SELECT
  debug_fdset3 = receiving;
#endif /* DEBUG_PIPEMSG_SELECT */
  int s = select (fd + 1, &receiving, NULL, NULL, tvp);
#ifdef DEBUG_PIPEMSG_SELECT
  debug_fdset4 = receiving;
#endif /* DEBUG_PIPEMSG_SELECT */
  if (s > 0)
    return 1;
  if (s < 0) { 
    perror ("fd_can_recv/select");
    printf ("fd_can_recv (%d): select returned %d\n", fd, s);
  }
  return 0;
}

/* returns the number of characters received, or -1 in case of error */
/* if may_block is true, only returns -1 or blen. */
/* if may_block is false, may return any value between -1 and blen */
static int receive_bytes (int pipe, char * buffer, int blen, int may_block,
                          struct allnet_log * log)
{
  int recvd = 0;
  while (recvd < blen) {
    if ((! may_block) && (! fd_can_recv (pipe, 0))) {
      if ((recvd == 0) && (! may_block)) {
#ifdef DEBUG_PIPEMSG_SELECT
        unsigned long long int now = allnet_time_us ();
        printf ("%s: fd_can_recv (%d, %d) == %d, time %lluus, recvd %d\n",
                log->debug_info, pipe, may_block, fd_can_recv (pipe, 0),
                now - debug_fdtime, recvd);
        print_buffer ((char *)&debug_fdset1, sizeof (debug_fdset1),
                      "original fdset", 8, 1);
        print_buffer ((char *)&debug_fdset2, sizeof (debug_fdset2),
                      "returned fdset", 8, 1);
        print_buffer ((char *)&debug_fdset3, sizeof (debug_fdset3),
                      "fd_can_recv bf", 8, 1);
        print_buffer ((char *)&debug_fdset4, sizeof (debug_fdset4),
                      "fd_can_recv af", 8, 1);
#else /* DEBUG_PIPEMSG_SELECT */
        printf ("%s: fd_can_recv (%d, %d) == %d, recvd %d\n",
                log->debug_info, pipe, may_block, fd_can_recv (pipe, 0),
                recvd);
#endif /* DEBUG_PIPEMSG_SELECT */
      }
      return recvd;   /* not ready to receive, and should not block */
    }
    /* if we did not call fd_can_recv, the call to read may block */
    int new_recvd = (int)read (pipe, buffer + recvd, blen - recvd);
    if (new_recvd <= 0) {
      if (new_recvd == 0) {
        snprintf (log->b, log->s, "receive_bytes: pipe %d closed\n", pipe);
        log_print (log);
      }
#ifdef DEBUG_PRINT
      else perror ("pipemsg.c receive_bytes read");
#endif /* DEBUG_PRINT */
      snprintf (log->b, log->s,
                "receive_bytes: %d/%d bytes on pipe %d, expected %d/%d\n",
                new_recvd, recvd, pipe, blen - recvd, blen);
      log_print (log);
      return recvd > 0 ? recvd : -1 /* error */;
    }
    recvd += new_recvd;
  }
  return blen;
}

/* returns -1 if the header is not valid, and the data size otherwise */
/* note: does not work for buffers of size 2^32 - 1 -- but any buffer
 * larger than 2^31 - 1 is likely to cause problems due to signed ints anyway */
static int parse_header (char * header, int pipe, unsigned int * priority,
                         struct allnet_log * log)
{
  static int printed = 0;
  if (memcmp (header, MAGIC_STRING, MAGIC_SIZE) != 0) {
    if (printed == 0) {
      if (log != NULL) {
        snprintf (log->b, log->s, "error: unsynchronized pipe %d\n", pipe);
        log_print (log);
        buffer_to_string (header, HEADER_SIZE, " header:", 20, 1,
                          log->b, log->s);
        log_print (log);
      } else {
        printf ("error: unsynchronized pipe %d\n", pipe);
        print_buffer (header, HEADER_SIZE, " header:", 20, 1);
      }
    }
    printed++;
    return -1;
  }
  if (printed != 0) {
    if (log != NULL) {
      snprintf (log->b, log->s, "  (%dx)\n", printed);
      log_print (log);
    } else {
      printf ("  (%dx)\n", printed);
    }
  }
  printed = 0;
  if (priority != NULL) {
    *priority = read_big_endian32 (header + MAGIC_SIZE);
    if (((*priority) > ALLNET_PRIORITY_MAX) ||
        ((*priority) < ALLNET_PRIORITY_EPSILON)) /* bad priority */
      *priority = ALLNET_PRIORITY_EPSILON;       /* make it min possible */
  }
  int result  = read_big_endian32 (header + MAGIC_SIZE + PRIORITY_SIZE);
/* need to cast ALLNET_HEADER_SIZE to int because result may be -1,
 * and without the cast, the comparison is unsigned, so -1 > header size */
  if ((result < (int)ALLNET_HEADER_SIZE) || (result > ALLNET_MTU)) {
    if (log != NULL) {
      snprintf (log->b, log->s, "parse_header: illegal header size %d (%u)\n",
                result, result);
      log_print (log);
      buffer_to_string (header, HEADER_SIZE, " header:", HEADER_SIZE, 1,
                        log->b, log->s);
      log_print (log);
    } else {
      printf ("parse_header: illegal header size %d (%u)\n", result, result);
    }
  }
  return result;
}

/* shift the header left as far as needed to start the new magic string*/
static int shift_header (char * header)
{
#ifdef DEBUG_PRINT
  print_buffer (header, HEADER_SIZE, "header before shift", HEADER_SIZE, 1);
#endif /* DEBUG_PRINT */
  int i;
  for (i = 1; i < HEADER_SIZE; i++) {
    if (header [i] == MAGIC_STRING [0]) {
      memmove (header, header + i, HEADER_SIZE - i);
#ifdef DEBUG_PRINT
      char message [1000];
      snprintf (message, sizeof (message), "header after %d-byte shift", i);
      print_buffer (header, HEADER_SIZE - i, message, HEADER_SIZE, 1);
#endif /* DEBUG_PRINT */
      return (HEADER_SIZE - i);
    }
  }
  return 0;  /* no magic string, discard everything */
}

/* similar to receive_pipe_message but may return 0 if no message
 * is immediately ready to return.  returns -1 in case of error */
static int receive_pipe_message_poll (pd p, int pipe,
                                      char ** message, unsigned int * priority)
{
  *message = NULL;
  int index = pipe_index (p, pipe);
  if (index < 0) {
    do_not_print = 0;
    print_pipes (p, "not found", pipe);
    snprintf (p->log->b, p->log->s,
              "pipe %d not found, aborting and dumping core\n", pipe);
    log_print (p->log);
    assert (0);  /* cause a core dump so we can debug this */
    /* if NDEBUG is set, assert will not end the program, so return -1 */
    return -1;
  }
  struct allnet_pipe_info * bp = (p->buffers) + index;

  unsigned int offset = bp->filled;
  if (bp->bsize <= offset) {   /* serious error, can't read anything */
    printf ("%s: receive_bytes %d - %d, pipe %d\n", p->log->debug_info,
            bp->bsize, offset, pipe);
    do_not_print = 0;
    print_pipes (p, "receive_pipe_message_poll", pipe);
    die ("aip: stuck, can never make progress");
  }
  int read = receive_bytes (pipe, bp->buffer + offset, bp->bsize - offset, 0,
                            p->log);
  if (read < 0)
    return -1;
  if (read == 0)
    return 0;
  offset += (unsigned int) read;  /* read > 0 */
  if (offset == bp->bsize) {
   /* received all we were looking for, either allocate new buffer or return */
    if (bp->in_header) {
      int received_len = parse_header (bp->header, pipe, priority, p->log);
/* need to cast ALLNET_HEADER_SIZE to int because received_len may be -1,
 * and without the cast, the comparison is unsigned, so -1 > header size */
      if ((received_len >= (int)ALLNET_HEADER_SIZE) &&
          (received_len <= ALLNET_MTU)) { /* received a MAGICPIE header */
        bp->buffer = malloc (received_len);
        if (bp->buffer == NULL) {
          snprintf (p->log->b, p->log->s,
                    "failed to allocate %d for receive_pipe_message_poll\n",
                    received_len);
          log_print (p->log);
          return -1;
        }
        bp->bsize = (unsigned int) received_len;
        bp->in_header = 0;
        bp->filled = 0;
      } else {  /* failed to parse, i.e. no magic_string at start of header */
                /* or a weird received length */
        bp->filled = shift_header (bp->header); /* shift header, try again */
      }
      /* we stopped because the header was filled. Tell caller to try again. */
      return 0;
    } else {    /* not reading header and buffer is full, so we are done. */
save_received_message (p, pipe, bp->buffer, bp->bsize);
      *message = bp->buffer;
      int result = (int) (bp->bsize);
      bp->in_header = 1;  /* next time read a new header */
      bp->buffer = bp->header;
      bp->bsize = HEADER_SIZE;
      bp->filled = 0;
      return result;
    }
  } else { /* buffer is not filled, just return to caller */
    bp->filled = offset;  /* this is how many we've gotten */
  }
  return 0;
}

static int receive_queue_message (int pipe, char ** message,
                                  unsigned int * priority,
                                  struct allnet_log * log)
{
  if (allnet_queues == NULL) {  /* error */
    snprintf (log->b, log->s,
              "receive_queue_message %d, but allnet_queues == NULL\n", pipe);
    log_print (log);
    printf ("receive_queue_message %d, but allnet_queues == NULL\n", pipe);
    exit (1);
  }
  while (1) {  /* loop in case we need to try again */
    int index = -pipe - 1;
    unsigned char result [ALLNET_MTU];
    unsigned int nqueue = 1;
    unsigned int plen = sizeof (result);
    /* timeout is -1, so wait forever */
    int call = allnet_dequeue (&(allnet_queues [index]), &nqueue, result,
                               &plen, (unsigned int *)priority,
                               (unsigned int) (-1));
    if (call == 1) {
      *message = malloc_or_fail (plen, "receive_queue_message");
      memcpy (*message, result, plen);
      return plen;
    }
    if (call == -2) { /* should never happen, but inevitably will. Discard */
      printf ("receive_queue_message %d error: received %d, MTU %d, ignoring\n",
              -pipe, plen, ALLNET_MTU);
      allnet_queue_discard_first (allnet_queues [index]);
      /* and repeat */
    } else {
      if (call == 0) /* should never happen with a timeout of -1 */
        printf ("error in receive_queue_message: dequeue timed out\n");
      return 0;
    }
  }
}

/* receives the message into a buffer it allocates for the purpose. */
/* the caller is responsible for freeing the buffer. */
int receive_pipe_message (pd p, int pipe, char ** message,
                          unsigned int * priority)
{
  if (pipe < 0)
    return receive_queue_message (pipe, message, priority, p->log);
  char header [HEADER_SIZE];

  int filled = 0;
  int received_len = 0;
  while (1) {
    if (filled >= HEADER_SIZE) /* should never happen */
      die ("aip: filled >= HEADER_SIZE");
    /* read the header */
    int r = receive_bytes (pipe, header + filled, HEADER_SIZE - filled,
                           1, p->log);
    if (r < 0)
      return -1;
    /* may_block is true, so r should only be -1 or HEADER_SIZE - filled */
    received_len = parse_header (header, pipe, priority, p->log);
/* need to cast ALLNET_HEADER_SIZE to int because received_len may be -1,
 * and without the cast, the comparison is unsigned, so -1 > header size */
    if ((received_len >= (int)ALLNET_HEADER_SIZE) && /* rcvd a MAGICPIE hdr */
        (received_len <= ALLNET_MTU))           /* and a reasonable length */
      break;
    received_len = 0;
    filled = shift_header (header);             /* start over */
  }

  /* allocate the result buffer */
  char * buffer = malloc (received_len);
  if (buffer == NULL) {
    snprintf (p->log->b, p->log->s,
              "unable to allocate %d bytes for receive_pipe_message pipe %d\n",
              received_len, pipe);
    log_print (p->log);
    return -1;
  }
  /* printf ("receive_pipe_message allocated buffer %p\n", buffer); */

  if (receive_bytes (pipe, buffer, received_len, 1, p->log) < 0) {
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
                          struct sockaddr * sa, socklen_t * salen,
                          struct allnet_log * log)
{
  *message = malloc (ALLNET_MTU);
  if (*message == NULL) {
    snprintf (log->b, log->s,
              "unable to allocate %d bytes for receive_dgram", ALLNET_MTU);
    log_print (log);
    return -1;
  }
#ifdef DEBUG_PRINT
  snprintf (log->b, log->s, "ready to receive datagram on fd %d\n", fd);
  log_print (log);
#endif /* DEBUG_PRINT */
  int old_salen = -3;  /* a value unlikely to be in *salen */
  if (salen != NULL)
    old_salen = *salen;
  char old_sa [200] = "";
  char new_sa [200] = "";
  if ((sa != NULL) && (old_salen > 0))
    buffer_to_string ((char *) sa, old_salen, NULL, 10, 0,
                      old_sa, sizeof (old_sa));
  int result = (int)recvfrom (fd, *message, ALLNET_MTU, MSG_DONTWAIT,
                              sa, salen);
  if (result < 0) {
    if ((errno != EAGAIN) && (errno != EWOULDBLOCK)) {
      perror ("recvfrom");
      int new_salen = -5;  /* a value unlikely to be in *salen */
      if (salen != NULL)
        new_salen = *salen;
      if ((sa != NULL) && (new_salen > 0))
        buffer_to_string ((char *) sa, new_salen, NULL, 10, 0,
                          new_sa, sizeof (new_sa));
      printf ("%s: errno %d, fd %d, pointers %p %p %p, salen %d/%d, sa %s/%s\n",
              log->debug_info, errno, fd, *message, sa, salen,
              new_salen, old_salen, new_sa, old_sa);
    }
    free (*message);
    *message = NULL;
    if ((errno != EAGAIN) && (errno != EWOULDBLOCK))
      return -1;
    return 0;   /* EAGAIN or EWOULDBLOCK, no message ready at this time */
  }
  if ((sa->sa_family != AF_INET) && (sa->sa_family != AF_INET6)
#ifdef PF_PACKET
      && (sa->sa_family != PF_PACKET)
#endif /* PF_PACKET */
      ) { /* strange */
    snprintf (log->b, log->s, "receive_dgram got %d bytes, family %d\n",
              result, sa->sa_family);
    log_print (log);
  }
  return result;
}

/* if returning for a pipe rather than a UDP socket, clear the address */
static void clear_addr (struct sockaddr * sa, socklen_t * salen)
{
  if (salen != NULL) {
    if ((sa != NULL) && (*salen > 0)) {
      memset (sa, 0, *salen);
      sa->sa_family = -1; /* debug */
    }
    *salen = 0;
  }
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
int receive_pipe_message_fd (pd p, int timeout, char ** message, int fd,
                             struct sockaddr * sa, socklen_t * salen,
                             int * from_pipe, unsigned int * priority)
{
  struct timeval now, finish;
  gettimeofday (&now, NULL);
  finish = now;
  if (timeout != PIPE_MESSAGE_WAIT_FOREVER)
    add_us (&finish, timeout * 1000LL);  /* timeout in ms, adding us */

  if (from_pipe != NULL) *from_pipe = -1;
  if (priority != NULL) *priority = ALLNET_PRIORITY_EPSILON;
  while ((timeout == PIPE_MESSAGE_WAIT_FOREVER) ||
         (tv_compare (&now, &finish) <= 0)) {
    int pipe;
    int effective_timeout = timeout;
    if (((timeout == PIPE_MESSAGE_WAIT_FOREVER) || (timeout > 10)) &&
        (p->num_queues > 0))
      effective_timeout = 10;    /* look at the queues every 10ms */
/* receive with the lock held, since otherwise one of the file descriptors
   might be closed while we receive, in which case the behavior of select
   is undefined and apparently sometimes messed up. */ 
    pthread_mutex_lock (&(p->receive_mutex));
    if (effective_timeout > 100)
      effective_timeout = 100;    /* release the lock at least every 100ms */
    pipe = next_available (p, fd, effective_timeout);
    if (pipe >= 0) { /* can read pipe */
      if (from_pipe != NULL) *from_pipe = pipe;
      int r;
      if (pipe != fd) { /* it is a pipe, not a datagram socket */
        r = receive_pipe_message_poll (p, pipe, message, priority);
        if (r != 0) {
/* if (r < 0) printf ("receive_pipe_message_poll returned %d\n", r); */
          clear_addr (sa, salen); /* clear the address */
          pthread_mutex_unlock (&(p->receive_mutex));
          return r;
        }
      } else {         /* UDP or raw socket */
        r = receive_dgram (pipe, message, sa, salen, p->log);
/* if (r < 0) printf ("receive_dgram returned %d\n", r); */
        if (r != 0) {
          pthread_mutex_unlock (&(p->receive_mutex));
          return r;
        }
      }
      /* else read a partial or no buffer, repeat until timeout */
      if (from_pipe != NULL) *from_pipe = -1;
    }
    if ((allnet_queues != NULL) && (p->num_queues > 0)) {
/*extern int debug_print_fd;
int debug_index = ((- p->queues[0]) - 1);
struct allnet_queue * debug_q = allnet_queues [debug_index];
if (fd == debug_print_fd)
printf ("checking %d queues, first @ %d/%d is %s, has %d packets\n", p->num_queues, debug_index, p->queues[0], allnet_queue_info(debug_q), allnet_queue_size(debug_q));*/
      struct allnet_queue ** queues =
        malloc (p->num_queues * sizeof (struct allnet_queue *));
      if (queues != NULL) {
        int i;
        for (i = 0; i < p->num_queues; i++)
          queues [i] = allnet_queues [(- (p->queues [i])) - 1];
        unsigned char buffer [ALLNET_MTU];
        unsigned int nqueue = p->num_queues;
        unsigned int plen = sizeof (buffer); /* timeout 0 to just poll */
/*
unsigned int debug_alocal = 0;
if ((debug_alocal == 0) && (strncmp (p->log->debug_info, "alocal", 6) == 0))
debug_alocal = (unsigned int) pthread_self ();
if (debug_alocal == (unsigned int) pthread_self ())
printf ("receive_pipe_message_fd %3d (%s) looking at %d queues, plen %d\n",
(unsigned int)pthread_self () % 1000, p->log->debug_info, p->num_queues, plen);
if (debug_alocal == (unsigned int) pthread_self ())
for (i = 0; i < p->num_queues; i++) printf ("queue %d is %d\n", i, p->queues [i]);
*/
        int result = allnet_dequeue (queues, &nqueue, buffer, &plen,
                                     (unsigned int *) priority, 0);
/*
if (debug_alocal == (unsigned int) pthread_self ())
printf ("receive_pipe_message_fd %3d (%s) got %d/%d, %d\n",
(unsigned int)pthread_self () % 1000, p->log->debug_info, result, nqueue, plen);
*/
        if ((result == 1) && (plen > 0)) {
          if (from_pipe != NULL) {  /* find out the fd we got it on */
            for (i = 0; i < p->num_queues; i++) {
              if (queues [nqueue] == allnet_queues [(- (p->queues [i])) - 1]) {
                *from_pipe = p->queues [i];
/* printf ("receive_pipe_message_fd got %d-byte message on queue %d @ %d\n",
plen, p->queues [i], i); */
                /*if (fd == debug_print_fd)
                  printf ("set from_pipe to %d, p->queues [%d] is %d\n", *from_pipe, i, p->queues [i]);*/
                break;
              }
            }
          }
          free (queues);  /* no longer needed */
          *message = malloc_or_fail (plen, "receive_pipe_message_fd queue");
          memcpy (*message, buffer, plen);
          pthread_mutex_unlock (&(p->receive_mutex));
          return plen;
        }
        free (queues);  /* no longer needed */
        if ((result == -2) && (plen > 0))
          allnet_queue_discard_first (queues [nqueue]);
      }
    }
    /* release the lock, acquire it again at the top of the loop */
    pthread_mutex_unlock (&(p->receive_mutex));
    /* refresh the current time, used at the top of the loop */
    if (timeout != PIPE_MESSAGE_WAIT_FOREVER)
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
int receive_pipe_message_any (pd p, int timeout, char ** message,
                              int * from_pipe, unsigned int * priority)
{
  return receive_pipe_message_fd (p, timeout, message, -1, NULL, NULL,
                                  from_pipe, priority);
}

#ifndef DEBUG_PRINT
#define DEBUG_PRINT
#endif /* DEBUG_PRINT */
static void print_split_message_error (int code, int n1, int n2,
                                       unsigned int n3)
{
  printf ("split_messages %d: error %d %d %u\n", code, n1, n2, n3);
}

static void extend_results (char * data, unsigned int len, unsigned int prio,
                            unsigned int * index,/* incremented by this call */
                            char *** mbuf, unsigned int ** lbuf,
                            unsigned int ** pbuf)
{
  int num_entries = (*index) + 1;
  size_t csize = num_entries * sizeof (char *);
  size_t isize = num_entries * sizeof (int);
  *mbuf = realloc (*mbuf, csize);
  *lbuf = realloc (*lbuf, isize);
  *pbuf = realloc (*pbuf, isize);
  if ((*mbuf == NULL) || (*lbuf == NULL) || (*pbuf == NULL)) {
    printf ("pipemsg.c extend_results: ptrs %p %p %p, i %d, sizes %zu %zu\n",
            *mbuf, *lbuf, *pbuf, *index, csize, isize);
    exit (1);
  }
  (*mbuf) [*index] = data;
  (*lbuf) [*index] = len;
  (*pbuf) [*index] = prio;
  *index = num_entries;
}

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
    char data [...] = ...;  // usually data received from network
    int dlen = ...;         // the number of bytes from network
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
int split_messages (char * data, unsigned int dlen,
                    char *** messages, unsigned int ** lengths,
                    unsigned int ** priorities, void ** buffer)
{
  struct buffer_info {
    unsigned int filled;    /* number of bytes in data */
    char data [HEADER_SIZE + ALLNET_MTU];   /* bytes not yet processed */
    char prior [ALLNET_MTU];                /* message returned in prior call */
  };
  struct buffer_info * bp = (struct buffer_info *) (*buffer);
  if (bp == NULL) {
    int asize = sizeof (struct buffer_info);
    bp = (struct buffer_info *)
            (malloc_or_fail (asize, "pipemsg.c split_messages"));
    bp->filled = 0;
    *buffer = bp;
  }
  unsigned int mi = 0;           /* message index (and the return value) */
  /* clear *messages, *lengths, *priorities in case of error return */
  if (messages != NULL)   *messages   = NULL;
  if (lengths != NULL)    *lengths    = NULL;
  if (priorities != NULL) *priorities = NULL;
  char ** mbuf = NULL;
  unsigned int *lbuf = NULL;
  unsigned int *pbuf = NULL;
  unsigned int priority;
  while (bp->filled > 0) {  /* there is still data to process */
    while ((bp->filled < HEADER_SIZE) && (dlen > 0)) {
      bp->data [bp->filled] = *data;
      bp->filled++;
      data++;
      dlen--;
    }
    if (bp->filled < HEADER_SIZE)   /* dlen is zero, incomplete header */
      return 0;   /* finished */
    int parse_result = parse_header (bp->data, -1, &priority, NULL);
    if ((parse_result < 0) || (parse_result > ALLNET_MTU)) {
      if (parse_result > ALLNET_MTU)
        print_split_message_error (1, parse_result, ALLNET_MTU, bp->filled);
      /* bad header, try again with next char */
      bp->filled -= 1;
      memmove (bp->data, bp->data + 1, bp->filled);
    } else if (bp->filled + dlen >= parse_result + HEADER_SIZE) {
      unsigned int msize = parse_result;
      /* valid msize, and we have the data */
      int from_data = msize;
      if (bp->filled > HEADER_SIZE) {   /* copy message to prior */
        int from_bp = bp->filled - HEADER_SIZE;
        from_data = msize - from_bp; /* may be zero or less */
        if (from_data < 0)
          from_data = 0;
        if (from_bp > 0)
          memcpy (bp->prior, bp->data + HEADER_SIZE, from_bp);
        if (from_data > 0)
          memcpy (bp->prior + from_bp, data, from_data);
        extend_results (bp->prior, msize, priority, &mi, &mbuf, &lbuf, &pbuf);
      } else {     /* point to the message in data */
        extend_results (bp->data, msize, priority, &mi, &mbuf, &lbuf, &pbuf);
      }
      bp->filled = 0;     /* at most one message in bp->data, so end loop */
      data += from_data;
      dlen -= from_data;
    } else { /* not enough data for the message */
             /* add partial data to bp->data, return */
  /* assertion should hold because bp->filled + dlen < msize + HEADER_SIZE
   * and msize <= ALLNET_MTU */
      assert (bp->filled + dlen < sizeof (bp->data));
      if (dlen > 0) {
        memcpy (bp->data + bp->filled, data, dlen);
        bp->filled += dlen;
      }
      return 0;
    }
  }
  /* should be zero because that is the only way to leave the while loop */
  assert (bp->filled == 0);

  while (dlen >= HEADER_SIZE) {
    unsigned int my_priority;
    int my_msize = parse_header (data, -1, &my_priority, NULL);
    if ((my_msize < 0) || (my_msize > ALLNET_MTU)) {
      /* bad header, try again with next char */
      if (my_msize > ALLNET_MTU)
        print_split_message_error (2, my_msize, ALLNET_MTU, dlen);
      data++;
      dlen--;
    } else if (dlen >= HEADER_SIZE + my_msize) {
      extend_results (data + HEADER_SIZE, my_msize, my_priority,
                      &mi, &mbuf, &lbuf, &pbuf);
      data += HEADER_SIZE + my_msize;
      dlen -= HEADER_SIZE + my_msize;
    } else {      /* dlen < my_msize, end loop, save in bp->data */
      break;
    }
  }
  if ((dlen > 0) && (dlen <= sizeof (bp->data))) {      /* save in bp->data */
    memcpy (bp->data, data, dlen);
    bp->filled = dlen;
    data += dlen;
    dlen -= dlen;   /* not needed, but good for consistency */
  } else if (dlen > 0) {   /* dlen > sizeof (bp->data), some error */
    print_split_message_error (6, dlen, sizeof (bp->data), 0);
    exit (1);
  }
  if (mi > 0) {
    if (messages != NULL)   *messages   = mbuf; else free (mbuf);
    if (lengths != NULL)    *lengths    = lbuf; else free (lbuf);
    if (priorities != NULL) *priorities = pbuf; else free (pbuf);
  }
  return mi;
}

#ifdef DEBUG_EBADF
/* temporary (I hope), for debugging of EBADF */
/* #define EBADBUFS       10000 */
char ebadbuf [EBADBUFS];
void record_message (pd p)  /* call after snprintf to ebadfbuf */
{
  int idx = (p->ebadbufindex + p->ebadbufcount) % NUM_EBADBUFS;
  if (p->ebadbufcount >= NUM_EBADBUFS) {
    p->ebadbufindex = (p->ebadbufindex + 1) % NUM_EBADBUFS;
  } else {
    p->ebadbufcount = p->ebadbufcount + 1; 
  }
  time_t now = time (NULL);
  char ctime_buf [100];
  ctime_r (&now, ctime_buf);
  char * nl = strchr (ctime_buf, '\n');
  if (nl != NULL)
    *nl = '\0';  /* no newlines */
  snprintf (p->ebadbufs [idx], EBADBUFS, "%s %s", ctime_buf, ebadbuf);
}

#endif /* DEBUG_EBADF */


