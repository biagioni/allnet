/* log.c: log allnet interactions for easier debugging */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <pthread.h>
#include <errno.h>

#include "../packet.h"
#include "log.h"
#include "util.h"

char log_buf [LOG_SIZE];    /* global */

#define LOG_DIR		"log"

static char * module_name = "unknown module -- have main call init_log()";
static char log_file_name [100] = "";

static int make_string ()
{
  int i;
  int eol = -1;
  for (i = 0; i < LOG_SIZE; i++) {
    if (log_buf [i] == '\n')
      eol = i;
    if (log_buf [i] == '\0') {
      if ((eol >= 0) && (eol + 1 == i))  /* terminated and newline, done */
        return i;
      if (i + 1 >= LOG_SIZE)
        i = i - 1;
      log_buf [i] = '\n';   /* add a newline if needed */
      log_buf [i + 1] = '\0';     /* and restore the null character */
      return i + 1;
    }
  }
  log_buf [LOG_SIZE - 2] = '\n';
  log_buf [LOG_SIZE - 1] = '\0';
  return LOG_SIZE - 1;
}

static int file_name (time_t seconds, int must_exist)
{
  struct tm n;
  localtime_r (&seconds, &n);
  snprintf (log_file_name, sizeof (log_file_name),
            "%s/%04d%02d%02d-%02d%02d%02d", LOG_DIR,
            n.tm_year + 1900, n.tm_mon + 1, n.tm_mday,
            n.tm_hour, n.tm_min, n.tm_sec);
  if (must_exist) {
    if (access (log_file_name, W_OK) != 0) {
/* no need to print this, or it will always print when first starting
      perror ("access");
      printf ("%s: unable to access '%s' for reading and writing\n", module_name,
              log_file_name); */
      /* clear the name */
      log_file_name [0] = '\0';
      return 0;
    }  /* else, all is well */
  } else {
    int fd = open (log_file_name, O_WRONLY | O_APPEND | O_CREAT | O_EXCL, 0644);
    if (fd < 0) {
      perror ("creat");
      printf ("%s: unable to create '%s'\n", module_name, log_file_name);
      /* clear the name */
      log_file_name [0] = '\0';
      return 0;
    }
    close (fd);   /* file has been created, should now exist */
    /* printf ("%s: created file %s\n", module_name, log_file_name); */
  }
  return 1;
}

void init_log (char * name)
{
  module_name = name;
  mkdir (LOG_DIR, 0700);  /* if it fails because it already exists, it's OK */
  time_t now = time (NULL);
  int count = 0;
  while ((count < 5) && (! file_name (now - count, 1)))
    count++;
  if (count >= 5)        /* create a new file */
    file_name (now, 0);
}

static void log_print_buffer (char * buffer, int blen)
{
  static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
  pthread_mutex_lock (&mutex);
  int fd = open (log_file_name, O_WRONLY | O_APPEND);
  if (fd < 0) {
    printf ("%s", buffer);
    pthread_mutex_unlock (&mutex);
    return;
  }
  struct flock lock;
  lock.l_type = F_WRLCK;
  lock.l_whence = SEEK_END;
  lock.l_start = 0;
  lock.l_len = blen;
  if (fcntl (fd, F_SETLKW, &lock) < 0) {
    perror ("unable to lock log file\n");
    printf ("%s", buffer);
    close (fd);
    pthread_mutex_unlock (&mutex);
    return;
  }
  int w = write (fd, buffer, blen);
  if (w < blen) {
    perror ("write to log file");
    if (w >= 0)
      printf ("tried to write %d bytes to %s, wrote %d bytes", blen,
              log_file_name, w);
    printf ("%s", buffer);
  }
  lock.l_type = F_UNLCK;
  if (fcntl (fd, F_SETLKW, &lock) < 0)   /* essentially, ignore this error */
    perror ("unable to unlock log file\n");
  close (fd);
  pthread_mutex_unlock (&mutex);
}

void log_print_str (char * string)
{
  char time_str [100];
  static char buffer [LOG_SIZE + LOG_SIZE];
  time_t now = time (NULL);
  struct tm n;
  if (localtime_r (&now, &n) == NULL)
    snprintf (time_str, sizeof (time_str), "bad time %ld", now);
  else
    snprintf (time_str, sizeof (time_str), "%02d/%02d %02d:%02d:%02d",
              n.tm_mon + 1, n.tm_mday, n.tm_hour, n.tm_min, n.tm_sec);
  int len = snprintf (buffer, sizeof (buffer), "%s %s: %s",
                      time_str, module_name, string);
  /* add a newline if it is not already at the end of the string */
  if ((len + 1 < sizeof (buffer)) && (len > 0) && (buffer [len - 1] != '\n')) {
    buffer [len++] = '\n';
    buffer [len] = '\0';
  }
  log_print_buffer (buffer, len);
}

void log_print ()
{
  make_string ();   /* make sure it is terminated */
  log_print_str (log_buf);
  bzero (log_buf, sizeof (log_buf));
}

static int addr_to_str (int nbits, char * addr,
                        int rsize, char * result)
{
  if (nbits == 0)
    return snprintf (result, rsize, "(none)");
  int i;
  int offset = 0;
  for (i = 0; i < (nbits + 7 / 8); i++) {
    if (i > 0)
      offset += snprintf (result + offset, rsize - offset, ":");
    offset += snprintf (result + offset, rsize - offset, "%02x",
                        addr [i] & 0xff);
  }
  return offset;
}

static int addrs_to_str (int src_nbits, char * source,
                         int dst_nbits, char * destination,
                         int rsize, char * result)
{
  int offset = addr_to_str (src_nbits, source, rsize, result);
  offset += snprintf (result + offset, rsize - offset, "->");
  offset += addr_to_str (dst_nbits, destination, rsize, result);
  return offset;
}

static char * pck_str (char * packet, int plen)
{
  static char buffer [LOG_SIZE];
  if (plen < ALLNET_HEADER_SIZE) {
    snprintf (buffer, LOG_SIZE, "log_packet: header size %d < min %zd\n",
              plen, ALLNET_HEADER_SIZE);
    return buffer;
  }
  char pname [100];
  struct allnet_header * hp = (struct allnet_header *) packet;
  switch (hp->message_type) {
    case (ALLNET_TYPE_DATA):
      snprintf (pname, LOG_SIZE, "data"); break;
    case (ALLNET_TYPE_ACK):
      snprintf (pname, LOG_SIZE, "ack"); break;
    case (ALLNET_TYPE_DATA_REQ):
      snprintf (pname, LOG_SIZE, "data request"); break;
    case (ALLNET_TYPE_KEY_XCHG):
      snprintf (pname, LOG_SIZE, "key xchg"); break;
    case (ALLNET_TYPE_KEY_REQ):
      snprintf (pname, LOG_SIZE, "key req"); break;
    case (ALLNET_TYPE_CLEAR):
      snprintf (pname, LOG_SIZE, "clear"); break;
    case (ALLNET_TYPE_MGMT):
      snprintf (pname, LOG_SIZE, "mgmt"); break;
    default:
      snprintf (pname, LOG_SIZE, "unknown packet type %d", hp->message_type);
      break;
  }
  char addresses [100];
  addrs_to_str (hp->src_nbits, hp->source, hp->dst_nbits, hp->destination,
                sizeof (addresses), addresses);
  int offset = snprintf (buffer, LOG_SIZE, "%d %s %s, %d/%d ",
                         hp->version, pname, addresses, hp->hops, hp->max_hops);
  char * stream_id = ALLNET_STREAM_ID(hp, hp->transport, plen);
  if (stream_id != NULL)
    offset += snprintf (buffer + offset, LOG_SIZE - offset,
                        " s %02x%02x%02x%02x%02x%02x",
                        stream_id [0], stream_id [1], stream_id [2],
                        stream_id [3], stream_id [4], stream_id [5]);
  char * message_id = ALLNET_MESSAGE_ID(hp, hp->transport, plen);
  if (message_id != NULL)
    offset += snprintf (buffer + offset, LOG_SIZE - offset,
                        " m %02x%02x%02x%02x%02x%02x",
                        message_id [0], message_id [1], message_id [2],
                        message_id [3], message_id [4], message_id [5]);
  char * packet_id = ALLNET_PACKET_ID(hp, hp->transport, plen);
  char * npackets = ALLNET_NPACKETS(hp, hp->transport, plen);
  char * sequence = ALLNET_SEQUENCE(hp, hp->transport, plen);
  /* only printing the low-order 8 bytes of sequence and npackets, since
   * - C (as far as I know) does not have built-in 128-bit ints
   * - it will likely be a long time before any message is sent that
   *   is larger than 2^64 packets */
  if ((packet_id != NULL) && (npackets != NULL) && (sequence != NULL))
    offset += snprintf (buffer + offset, LOG_SIZE - offset,
                        " p %02x%02x%02x%02x%02x%02x %lld of %lld",
                        packet_id [0], packet_id [1], packet_id [2],
                        packet_id [3], packet_id [4], packet_id [5],
                        readb64 (sequence + 8), readb64 (npackets + 8));
  char * expiration = ALLNET_EXPIRATION(hp, hp->transport, plen);
  if (expiration != NULL)
    offset += snprintf (buffer + offset, LOG_SIZE - offset,
                        " e in %llds", readb64 (expiration) - time (NULL)
                                       - Y2K_SECONDS_IN_UNIX);
  return buffer;
}

/* log desc followed by a description of the packet (packet type, ID, etc) */
void log_packet (char * desc, char * packet, int plen)
{
  static char local_buf [LOG_SIZE];
  snprintf (local_buf, sizeof (local_buf), "%s %s",
            desc, pck_str (packet, plen));
  log_print_str (local_buf);
}

/* log the error number for the given system call, followed by whatever
   is in the buffer */
void log_error (char * syscall)
{
  static char local_buf [LOG_SIZE + LOG_SIZE];
  if (errno < sys_nerr) {
    snprintf (local_buf, sizeof (local_buf), "%s: %s\n    %s",
              syscall, sys_errlist [errno], log_buf);
  } else {
    snprintf (local_buf, sizeof (local_buf), "%s: unknown error %d\n    %s",
              syscall, errno, log_buf);
  }
  log_print_str (local_buf);
}

