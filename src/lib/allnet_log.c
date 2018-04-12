/* log.c: log allnet interactions for easier debugging */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <pwd.h>
#include <fcntl.h>
#include <pthread.h>
#include <errno.h>
#include <dirent.h>
#include <syslog.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "packet.h"
#include "allnet_log.h"
#include "util.h"
#include "configfiles.h"

#include <pthread.h>

/* the default is to NOT create log files.  On development systems,
 * compile with -DLOG_TO_FILE, or just look in the system logs */
/* #define LOG_TO_FILE */

#ifdef LOG_TO_FILE 
#define LOG_DIR		"log"

static char log_dir [PATH_MAX] = "";

static char log_file_name [PATH_MAX] = "";
#endif /* LOG_TO_FILE */

static int allnet_global_debugging = 0;

#ifdef CHECK_USERNAME  /* not currently in use */
static int username_matches (const char * user)
{
  static pthread_mutex_t one_at_a_time = PTHREAD_MUTEX_INITIALIZER;
  pthread_mutex_lock (&one_at_a_time);
  int result = 0;     /* uid not found or not matching */
  uid_t my_id = getuid ();
  struct passwd * p;
  setpwent ();   /* start at the beginning */
  while ((p = getpwent ()) != NULL) {
    if (p->pw_uid == my_id) {  /* uid found */
      if (strcmp (user, p->pw_name) == 0)
        result = 1;  /* uid found and matching */
      break;         /* uid found, whether or not matching */
    }
  }
  pthread_mutex_unlock (&one_at_a_time);
  return result;
}
#endif /* CHECK_USERNAME */

#ifdef LOG_TO_FILE 
/* returns 1 if the file exists by the end of the call, and 0 otherwise. */
static int create_if_needed (const char * name)
{
  char original [PATH_MAX];  /* for debugging */
  strncpy (original, log_file_name, sizeof (original));
  int fd = open (log_file_name, O_WRONLY | O_APPEND | O_CREAT, 0644);
  if (fd < 0) {
    perror ("creat");
    printf ("%s: unable to create %s(%zd)/%s(%zd)\n", name,
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
static int file_name (const char * name, time_t seconds)
{
  struct tm n;
  localtime_r (&seconds, &n);
  snprintf (log_file_name, sizeof (log_file_name),
            "%s/%04d%02d%02d-%02d%02d%02d", log_dir,
            n.tm_year + 1900, n.tm_mon + 1, n.tm_mday,
            n.tm_hour, n.tm_min, n.tm_sec);
  return create_if_needed (name);
}

/* put the latest log file name in log_file_name */
static void latest_file (const char * name, time_t seconds)
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
    file_exists = create_if_needed (name);
/* printf ("log.c: checked %s, result is %d\n", log_file_name, file_exists); */
  }
  if (! file_exists)
    file_name (name, seconds);  /* create new log file */
}
#endif /* LOG_TO_FILE */

struct allnet_log * init_log (const char * name)
{
#ifdef LOG_TO_FILE   /* create a log file */
  // pthread_mutex_lock (&log_mutex);
  if (log_dir [0] == '\0') {   /* log_dir uninitialized, initialize it */
    snprintf (log_dir, sizeof (log_dir), "/tmp/.allnet-log/");
    char * home = getenv (HOME_ENV);
    if (home != NULL)
      snprintf (log_dir, sizeof (log_dir), "%s/.allnet/%s", home, LOG_DIR);
    else if (geteuid () == 0)  /* root user, keep log in /var/log/allnet/ */
      snprintf (log_dir, sizeof (log_dir), "/var/log/allnet");
  }

  if (! create_dir (log_dir))
    printf ("%s: unable to create directory %s\n", name, log_dir);
  time_t now = time (NULL);
  /* only open a new log file if this is the astart or allnet module */
  if ((strcasecmp (name, "astart") == 0) || (strcasecmp (name, "allnet") == 0))
    file_name (name, now); /* create a new file */
  else /* use the latest available file, only create new if none are present */
    latest_file (name, now);
  // pthread_mutex_unlock (&log_mutex);
#endif /* LOG_TO_FILE */
  
  size_t count = sizeof (struct allnet_log) + strlen (name) + 1;
  struct allnet_log * result = malloc_or_fail (count, "init_log");
  result->debug_info = ((char *) result) + sizeof (struct allnet_log);
  strcpy (result->debug_info, name);
  result->b [0] = '\0';  /* clear the buffer */
  result->s = LOG_SIZE;
  result->log_to_output = 0;
  return result;
}

/* call at the very end of a thread or a process, if possible */
/* argument is ignored, used to make usable with pthread_cleanup_push */
void close_log (struct allnet_log * log)
{
  free (log);
}

static void log_print_buffer (char * buffer, int blen, int out)
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
  int syslog_option = LOG_DAEMON | LOG_WARNING;
  /* use buffer + 12 to skip over most of the date (04/14 03:13:) */
  syslog (syslog_option, "%s", buffer + 12);
  if ((allnet_global_debugging) || (out))
    printf ("%s", buffer);
}

void log_print_str (struct allnet_log * log, const char * string)
{
  char header [100];
  char buffer [LOG_SIZE + LOG_SIZE];
  struct timeval now;
  gettimeofday (&now, NULL);
  struct tm n;
  int process = (getpid ()) % 100000;
  int thread = ((long int)(pthread_self ())) % 100000;
  if (localtime_r (&now.tv_sec, &n) == NULL)
    snprintf (header, sizeof (header), "bad time %ld p%05d t%05d",
              now.tv_sec, process, thread);
  else
    snprintf (header, sizeof (header),
              "%02d/%02d %02d:%02d:%02d.%06ld p%05d t%05d",
              n.tm_mon + 1, n.tm_mday, n.tm_hour, n.tm_min, n.tm_sec,
              (long int) (now.tv_usec), process, thread);
  /* add a newline if it is not already at the end of the string */
  char * last_nl = strrchr (string, '\n');
  char * add_nl = "\n";
  if ((last_nl != NULL) && (last_nl - string + 1 == ((int) strlen (string))))
    add_nl = "";   /* already present */
  int len = snprintf (buffer, sizeof (buffer), "%s %s: %s%s",
                      header, log->debug_info, string, add_nl);
  log_print_buffer (buffer, len, log->log_to_output);
}

void log_print (struct allnet_log * log)
{
/* if (log == NULL) printf ("start of NULL log_print\n");
else printf ("start of log_print %s\n", log->debug_info); */
  log_print_str (log, log->b);
/* printf ("end of log_print %s\n", log->debug_info); */
  log->b [0] = '\0';
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

static char * pck_str (const char * packet, int plen)
{
  static char buffer [LOG_SIZE];
  packet_to_string (packet, plen, NULL, 1, buffer, LOG_SIZE);
  return buffer;
}

/* log desc followed by a description of the packet (packet type, ID, etc) */
void log_packet (struct allnet_log * log, const char * desc,
                 const char * packet, int plen)
{
  static char local_buf [LOG_SIZE];
  snprintf (local_buf, sizeof (local_buf), "%s %s",
            desc, pck_str (packet, plen));
  log_print_str (log, local_buf);
}

/* log the error number for the given system call, followed by whatever
   is in the buffer */
void log_error (struct allnet_log * log, const char * syscall)
{
  int saved_errno = errno; 
  char ebuf [1000];
  strerror_r (errno, ebuf, sizeof (ebuf));
  char local_buf [LOG_SIZE + LOG_SIZE];
  if (strlen (log->b) > 0)
    snprintf (local_buf, sizeof (local_buf), "%s: %s (errno %d)\n  %s",
              syscall, ebuf, saved_errno, log->b);
  else
    snprintf (local_buf, sizeof (local_buf), "%s: %s (errno %d)",
              syscall, ebuf, saved_errno);
  log_print_str (log, local_buf);
}

/* output everything to stdout as well as the log file if on != 0.
 * if on == 0, only output to the log file. */
void log_to_output (int on)
{
  allnet_global_debugging = on;
}


