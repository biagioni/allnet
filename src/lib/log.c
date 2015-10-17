/* log.c: log allnet interactions for easier debugging */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <pthread.h>
#include <errno.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "packet.h"
#include "log.h"
#include "util.h"
#include "configfiles.h"

#include <pthread.h>

#ifndef __IPHONE_OS_VERSION_MIN_REQUIRED 
#define LOG_TO_FILE
/* ios doesn't give the user any reasonable way to read or
 * manage log files, so no use printing to file under iOS */
#endif /* __IPHONE_OS_VERSION_MIN_REQUIRED */

char log_buf [LOG_SIZE];    /* global */

#ifndef PATH_MAX	/* defined in a different place in some OS's */
#include <sys/syslimits.h>
#ifndef PATH_MAX	/* give up, just define it */
#define PATH_MAX	4096
#endif /* PATH_MAX */
#endif /* PATH_MAX */

#ifdef LOG_TO_FILE 
#define LOG_DIR		"log"

static char log_dir [PATH_MAX] = LOG_DIR;

static char log_file_name [PATH_MAX] = "";
#endif /* LOG_TO_FILE */

struct thread_info {
  char * name;
  pthread_t id;
};
#define MAX_THREAD_INFO		100
static struct thread_info ti [MAX_THREAD_INFO];
static int num_threads = 0;
static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;
static pid_t process_id = 0;

static void log_thread_id (const char * name)
{
  pthread_mutex_lock (&log_mutex);
  pthread_t id = pthread_self ();
  pid_t pid = getpid ();
  if ((process_id == 0) || (process_id != pid)) {
  /* if process_id != pid, we have been called after a fork.  The only
   * sensible thing to do is to overwrite any existing entries */
    process_id = pid;
    num_threads = 0;
  }
  if (num_threads < MAX_THREAD_INFO) {
    ti [num_threads].name = strcpy_malloc (name, "log_thread_id");
    ti [num_threads].id = id;
#ifdef DEBUG_PRINT
    printf ("ti [%d] (%04x) = {%p (%s), %04x}\n", num_threads,
            ((unsigned int) pid) & 0xffff, ti [num_threads].name, name,
            ((unsigned int) id) & 0xffff);
#endif /* DEBUG_PRINT */
    num_threads++;
  } else {
    printf ("reached MAX_THREAD_INFO %d\n", MAX_THREAD_INFO);
  }
  pthread_mutex_unlock (&log_mutex);
}

static void unlog_thread_id ()
{
  pthread_mutex_lock (&log_mutex);
  pthread_t id = pthread_self ();
  int i = 0;
  while (i < num_threads) {
    if (id == ti [i].id) {
#ifdef DEBUG_PRINT
      printf ("freeing name [%d] (%d) = { %p", i, getpid (), ti [i].name);
      printf (" (%s), ", ti [i].name);
      printf ("%04x}\n", ((unsigned int) ti [i].id) & 0xffff);
#endif /* DEBUG_PRINT */
      free (ti [i].name);
      ti [i].name = NULL;
      ti [i] = ti [num_threads - 1];
      num_threads--;
    } else {
      i++;
    }
  }
  pthread_mutex_unlock (&log_mutex);
}

const char * module_name ()
{
  if (num_threads <= 0)
    return "unknown module -- have main call init_log ()";
  pthread_t id = pthread_self ();
  int i;
  for (i = 0; i < num_threads; i++) {
    if (ti [i].id == id)
      return ti [i].name;
  }
/* printf ("unknown thread ID %u\n", me); */
  return "allnet";
}

static int allnet_global_debugging = 0;

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

#ifdef LOG_TO_FILE 
/* returns 1 if the file exists by the end of the call, and 0 otherwise. */
static int create_if_needed ()
{
  char original [PATH_MAX];  /* for debugging */
  strncpy (original, log_file_name, sizeof (original));
  int fd = open (log_file_name, O_WRONLY | O_APPEND | O_CREAT, 0644);
  if (fd < 0) {
    perror ("creat");
    printf ("%s: unable to create %s(%zd)/%s(%zd)\n", module_name (),
            log_file_name, strlen (log_file_name), original, strlen (original));
    /* clear the name */
    log_file_name [0] = '\0';
    return 0;
  }
  close (fd);   /* file has been created, should now exist */
  /* printf ("%s: created file %s\n", module_name, log_file_name); */
  return 1;
}

/* fills in log_file_name with a name corresponding to the time.
 * creates the file if necessary.
 * returns 1 if the file exists by the end of the call, and 0 otherwise. */
static int file_name (time_t seconds)
{
  struct tm n;
  localtime_r (&seconds, &n);
  snprintf (log_file_name, sizeof (log_file_name),
            "%s/%04d%02d%02d-%02d%02d%02d", log_dir,
            n.tm_year + 1900, n.tm_mon + 1, n.tm_mday,
            n.tm_hour, n.tm_min, n.tm_sec);
  return create_if_needed ();
}

/* put the latest log file name in log_file_name */
static void latest_file (time_t seconds)
{
  DIR * dir = opendir (log_dir);
  if (dir == NULL) {
    perror ("opendir");
    printf ("unable to open log directory %s\n", log_dir);
    return;
  }
  char * latest = NULL;
  struct dirent * dent;
  while ((dent = readdir (dir)) != NULL) {
/* printf ("log.c: looking at %s/%s\n", log_dir, dent->d_name); */
    if ((dent->d_name [0] != '.') &&
        ((latest == NULL) || (strcmp (dent->d_name, latest) > 0))) {
/* printf ("log.c:    using %s/%s\n", log_dir, dent->d_name); */
      if (latest != NULL)
        free (latest);
      latest = strcpy_malloc (dent->d_name, "log.c latest_file()");
    }
  }
  closedir (dir);
  int file_exists = 0;
  if (latest != NULL) {
    snprintf (log_file_name, sizeof (log_file_name),
              "%s/%s", log_dir, latest);
    free (latest);
    file_exists = create_if_needed ();
/* printf ("log.c: checked %s, result is %d\n", log_file_name, file_exists); */
  }
  if (! file_exists)
    file_name (seconds);  /* create new log file */
}
#endif /* LOG_TO_FILE */

void init_log (char * name)
{
  log_thread_id (name);  /* acquires log_mutex, so call before acquiring */
#ifdef LOG_TO_FILE   /* create a log file */
  pthread_mutex_lock (&log_mutex);
  snprintf (log_dir, sizeof (log_dir), "/tmp/.allnet-log/");
  char * home = getenv (HOME_ENV);
  if (home != NULL)
    snprintf (log_dir, sizeof (log_dir), "%s/.allnet/%s", home, LOG_DIR);
  else if (geteuid () == 0)  /* root user, keep the log in /var/log/allnet/ */
    snprintf (log_dir, sizeof (log_dir), "/var/log/allnet");

  if (! create_dir (log_dir))
    printf ("%s: unable to create directory %s\n", name, log_dir);
  time_t now = time (NULL);
  /* only open a new log file if this is the astart or allnet module */
  if ((strcasecmp (name, "astart") == 0) || (strcasecmp (name, "allnet") == 0))
    file_name (now); /* create a new file */
  else /* use the latest available file, only create new if none are present */
    latest_file (now);
  pthread_mutex_unlock (&log_mutex);
#endif /* LOG_TO_FILE */
}

/* call at the very end of a thread or a process, if possible */
/* argument is ignored, used to make usable with pthread_cleanup_push */
void close_log (void * ignored)
{
  unlog_thread_id ();
}

static void log_print_buffer (char * buffer, int blen)
{
#ifdef LOG_TO_FILE 
  int fd = open (log_file_name, O_WRONLY | O_APPEND);
  if (fd < 0) {
    printf ("%s", buffer);
    return;
  }
  struct flock lock;  /* lock the file, to keep others out while we print */
  lock.l_type = F_WRLCK;
  lock.l_whence = SEEK_END;
  lock.l_start = 0;
  lock.l_len = blen;
  if (fcntl (fd, F_SETLKW, &lock) < 0) {
    perror ("unable to lock log file");
    printf ("(%d) %s", blen, buffer);
    close (fd);
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
    perror ("unable to unlock log file");
  close (fd);
#endif /* LOG_TO_FILE  */
  if (allnet_global_debugging)
    printf ("%s", buffer);
}

void log_print_str_locked (char * string)
{
  char time_str [100];
  char buffer [LOG_SIZE + LOG_SIZE];
  struct timeval now;
  gettimeofday (&now, NULL);
  struct tm n;
  if (localtime_r (&now.tv_sec, &n) == NULL)
    snprintf (time_str, sizeof (time_str), "bad time %ld", now.tv_sec);
  else
    snprintf (time_str, sizeof (time_str), "%02d/%02d %02d:%02d:%02d.%06ld",
              n.tm_mon + 1, n.tm_mday, n.tm_hour, n.tm_min, n.tm_sec,
              (long int) (now.tv_usec));
  int len = snprintf (buffer, sizeof (buffer), "%s %s: %s",
                      time_str, module_name (), string);
  /* add a newline if it is not already at the end of the string */
  if ((len + 1 < sizeof (buffer)) && (len > 0) && (buffer [len - 1] != '\n')) {
    buffer [len++] = '\n';
    buffer [len] = '\0';
  }
  log_print_buffer (buffer, len);
}


void log_print_str (char * string)
{
  pthread_mutex_lock (&log_mutex);
  log_print_str_locked (string);
  pthread_mutex_unlock (&log_mutex);
}

void log_print ()
{
  pthread_mutex_lock (&log_mutex);
  make_string ();   /* make sure it is terminated with newline and \0 */
  log_print_str_locked (log_buf);
  bzero (log_buf, sizeof (log_buf));
  pthread_mutex_unlock (&log_mutex);
}

#ifdef ADDRS_TO_STR_USED
static int addr_to_str (int nbits, char * addr,
                        int rsize, char * result)
{
  if (nbits == 0)
    return snprintf (result, rsize, "(none)");
  int i;
  int offset = 0;
  for (i = 0; i < (nbits + 7 / 8); i++) {
    if (i > 0)
      offset += snprintf (result + offset, minz (rsize, offset), ":");
    offset += snprintf (result + offset, minz (rsize, offset), "%02x",
                        addr [i] & 0xff);
  }
  return offset;
}

static int addrs_to_str (int src_nbits, char * source,
                         int dst_nbits, char * destination,
                         int rsize, char * result)
{
  int offset = addr_to_str (src_nbits, source, rsize, result);
  offset += snprintf (result + offset, minz (rsize, offset), "->");
  offset += addr_to_str (dst_nbits, destination, rsize, result);
  return offset;
}
#endif /* ADDRS_TO_STR_USED */

static char * pck_str (char * packet, int plen)
{
  static char buffer [LOG_SIZE];
  packet_to_string (packet, plen, NULL, 1, buffer, LOG_SIZE);
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
  snprintf (local_buf, sizeof (local_buf), "%s: %s\n    ",
            syscall, strerror (errno));
  log_print_str (local_buf);
  log_print_str (log_buf);
}

/* output everything to stdout as well as the log file if on != 0.
 * if on == 0, only output to the log file. */
void log_to_output (int on)
{
  allnet_global_debugging = on;
}


