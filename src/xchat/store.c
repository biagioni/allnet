/* store.c: provide access to chat messages stored in ~/.allnet/xchat/ */
/* messages are stored in a directory specific to a contact+keyset pair,
 * in a file that is updated every day.  So a typical message might be
 * stored in ~/.allnet/xchat/20140301044819/20140307, where the first
 * part matches the keyset (found in ~/.allnet/contacts/20140301044819/),
 * and the second part is the date (in UTC) that the chats were stored. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <inttypes.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/file.h>
#include <sys/stat.h>

#include "lib/packet.h"
#include "lib/util.h"
#include "lib/keys.h"
#include "lib/configfiles.h"
#include "lib/sha.h"
#include "store.h"
#include "message.h"  /* is_acked */

/* start_iter and prev_message define an iterator over messages.
 * the iterator proceeds backwards, setting type to MSG_TYPE_DONE
 * after the last message has been read. */
/* the iterator should be deallocated with free_iter after it is used */
/* for a single record, use most_recent record. */

#define DATE_LEN 		8	/* strlen ("20130327") */

struct msg_iter {
  char * contact;         /* dynamically allocated */
  keyset k;
  char * dirname;         /* dynamically allocated */
  char * current_fname;   /* dynamically allocated */
  char * current_file;    /* dynamically allocated */
  uint64_t current_size;
  int64_t current_pos;
};

struct msg_iter * start_iter (const char * contact, keyset k)
{
  if ((contact == NULL) || (k < 0))
    return NULL;
  char * directory = key_dir (k);
  if (directory== NULL)
    return NULL;
  struct msg_iter * result = malloc_or_fail (sizeof (struct msg_iter),
                                             "start_iter struct");
  result->contact = strcpy_malloc (contact, "start_iter contact");
  result->k = k;
  result->dirname = string_replace_once (directory, "contacts", "xchat", 1);
  result->current_fname = NULL;
  result->current_file = NULL;
  result->current_size = 0;
  result->current_pos = 0;
  return result;
}

static int is_data_file (char * fname)
{
  struct stat st;
  if (stat (fname, &st) < 0) {
printf ("unable to stat %s\n", fname);  /* debug msg, remove later */
    return 0;    /* not a valid file name at all, hence not a data file */
  }
  if (S_ISREG (st.st_mode))
    return 1;
  return 0;
}

/* if it is the kind of name we want, it should end in a string of n digits */
/* if ext is not NULL, it indicates a possible extension, e.g. ".txt" */
static int end_ndigits (char * path, int ndigits, char * ext)
{
  char * slash = strrchr (path, '/');
  char * name = path;
  if (slash != NULL)
    name = slash + 1;
  size_t elen = 0;
  if (ext != NULL)
    elen = strlen (ext);
  if ((strlen (name) != ndigits) && (strlen (name) != ndigits + elen)) {
  /* printf ("end_ndigits (%s, %d, %s) => 0 (length %zd != %d [ + %zd])\n",
            path, ndigits, ext, strlen (name), ndigits, strlen (ext)); */
    return 0;
  }
  int i;
  for (i = 0; i < ndigits; i++) {
    if ((name [i] < '0') || (name [i] > '9')) {
/*    printf ("end_ndigits (%s, %d) => 0 ([%d] is %c)\n", path, ndigits,
              i, name [i]); */
      return 0;
    }
  }
/* printf ("end_ndigits (%s, %d) => 1\n", path, ndigits); */
  if (strlen (name) == ndigits)
    return 1;
/*  strlen (name) == ndigits + elen, from a previous if */
  return (strcmp (name + ndigits, ext) == 0);
}

/* returns 1 for success, 0 for failure */
/* if successful, reads the file contents into memory and updates iter
 */
static int find_prev_file (struct msg_iter * iter)
{
  create_dir (iter->dirname);
  DIR * dir = opendir (iter->dirname);
  if (dir == NULL) {  /* eventually probably don't need to print */
int debug = 0;
    perror ("find_prev_file");
    printf ("unable to open directory %s\n", iter->dirname);
printf ("debug time: %d\n", 5 / debug);  /* crash */
    return 0;
  }
  char * greatest_less_than_current = NULL;
  struct dirent * dep;
  while ((dep = readdir (dir)) != NULL) {
    char * path =
      strcat3_malloc (iter->dirname, "/", dep->d_name, "find_prev_file");
    /* we update greatest_less_than_current (gltc) if we have found a name
     * greater than gltc but less than the current.  The comparison always
     * succeeds in case gltc or current are NULL */
    char * current_tail = iter->current_fname;
    if ((current_tail != NULL) && (strrchr (current_tail, '/') != NULL))
      current_tail = strrchr (current_tail, '/') + 1;
    char * gltc_tail = greatest_less_than_current;
    if ((gltc_tail != NULL) && (strrchr (gltc_tail, '/') != NULL))
      gltc_tail = strrchr (gltc_tail, '/') + 1;
/* printf ("examining %s, %s + %s\n", dep->d_name, current_tail, gltc_tail); */
    if ((end_ndigits (dep->d_name, DATE_LEN, ".txt")) &&
        ((current_tail == NULL) || (strcmp (dep->d_name, current_tail) < 0)) &&
        ((gltc_tail == NULL)    || (strcmp (dep->d_name, gltc_tail) > 0)) &&
        (is_data_file (path))) {
      if (greatest_less_than_current != NULL)
        free (greatest_less_than_current);
      greatest_less_than_current = path;
    } else {
      free (path);
    }
  }
  closedir (dir);
  if (greatest_less_than_current == NULL) {
    iter->k = -1;   /* at end, invalidate the iterator */
    return 0;
  }
  if (iter->current_fname != NULL)
    free (iter->current_fname);
  if (iter->current_file != NULL)
    free (iter->current_file);
  iter->current_fname = greatest_less_than_current;
  iter->current_size = read_file_malloc (greatest_less_than_current,
                                         &(iter->current_file), 1);
  iter->current_pos = iter->current_size;  /* decremented before use */
/*
printf ("loaded file %s, size %ju, pos %ju\n",
        iter->current_fname, (uintmax_t)(iter->current_size),
        (uintmax_t)(iter->current_pos));
*/
  return 1;
}

static int found_at_line_start (char * p, uint64_t pos, char * pattern)
{
  if ((strncmp (p, pattern, strlen (pattern)) == 0) &&
      ((pos == 0) || (*(p - 1) == '\n')))
    return 1;
  return 0;
}

/* return 1 if the current position matches the start of a record,
 * 0 otherwise */
/* a record begins with "got ack", "sent id", or "rcvd id". */
#define PATTERN_SENT    "sent id: "
#define PATTERN_RCVD    "rcvd id: "
#define PATTERN_ACK     "got ack: "
static int match_record_start (struct msg_iter * iter)
{
  if (iter->current_pos < 0)
    return 0;
  uint64_t length = iter->current_size - iter->current_pos;
  if (length < strlen (PATTERN_SENT))
    return 0;
  char * p = iter->current_file + iter->current_pos;
  if (found_at_line_start (p, iter->current_pos, PATTERN_SENT)) return 1;
  if (found_at_line_start (p, iter->current_pos, PATTERN_RCVD)) return 1;
  if (found_at_line_start (p, iter->current_pos, PATTERN_ACK )) return 1;
  return 0;
}

static int parse_hex (char * dest, char * string, int dest_len)
{
  int i;
  for (i = 0; i < dest_len; i++) {
    int b;
    if (sscanf (string + i * 2, "%2x", &b) != 1)
      return 0;
    dest [i] = b;
  }
  return 1;
}

static int parse_seq_time (char * string, uint64_t * seq, uint64_t * time,
                           int * tz, uint64_t * rcvd_time)
{
#define SEQUENCE_STR     "sequence "
  char * parse_string = strstr (string, SEQUENCE_STR);
  if (parse_string == NULL) {
    printf ("sequence string missing from '%s'\n", string);
    return 0;
  }
  parse_string += strlen (SEQUENCE_STR);
  char * end;
  uint64_t n = strtoll (parse_string, &end, 10);
  if (end == parse_string) {
    printf ("sequence value missing from '%s'\n", string);
    return 0;
  }
  if (seq != NULL)
    *seq = n;
  char * paren = strchr (parse_string, '(');
  if (paren == NULL) {
    printf ("paren missing from '%s'\n", string);
    return 0;
  }
  n = strtoll (paren + 1, &end, 10);
  if (end == paren + 1) {
    printf ("time missing from '%s'\n", paren);
    return 0;
  }
  if (time != NULL)
    *time = n;
  if (rcvd_time != NULL)   /* in case we don't set it later */
    *rcvd_time = n;
/* if (time != NULL)
printf ("parsed time %llu from string %s\n", *time, paren + 1); */
  char * blank = end;
  n = strtol (blank + 1, &end, 10);
  if (end == blank + 1)
    printf ("timezone missing from '%s', not a problem\n", blank);
  else if (tz != NULL)
    *tz = (int)n;
/* if (tz != NULL)
printf ("parsed tz %d from string %s\n", *tz, blank + 1); */
  char * slash = strchr (parse_string, '/');
  if (slash != NULL) {  /* receive time only included since 2015/08/07 */
    n = strtoll (slash + 1, &end, 10);
    if ((end != slash + 1) && (rcvd_time != NULL))
      *rcvd_time = n;
  }
  return 1;
} 

/* returns the record type, if any */
/* a sent/rcvd record has 3 or more lines: the ack/id line, the
 * sequence/time line, and the message line(s).  Each message line
 * is indented by a blank */
/* an ack record only has one line. */
static int parse_record (char * record, uint64_t * seq, uint64_t * time,
                         int * tz, uint64_t * rcvd_time, char * message_ack,
                         char ** message, int * msize)
{
  if (seq != NULL)
    *seq = 0;
  if (time != NULL)
    *time = 0;
  if (tz != NULL)
    *tz = 0;
  if (message_ack != NULL)
    bzero (message_ack, MESSAGE_ID_SIZE);
  if (message != NULL)
    *message = NULL;
  if (msize != NULL)
    *msize = 0;
  int type = MSG_TYPE_DONE;
  if (found_at_line_start (record, 0, PATTERN_SENT)) type = MSG_TYPE_SENT;
  if (found_at_line_start (record, 0, PATTERN_RCVD)) type = MSG_TYPE_RCVD;
  if (found_at_line_start (record, 0, PATTERN_ACK )) type = MSG_TYPE_ACK;
  if (type == MSG_TYPE_DONE) {
    return type;
  }
  char * second_line = strchr (record, '\n');
  if (second_line == NULL) {
    return MSG_TYPE_DONE;
  }
  second_line++;

  char * mp = record + strlen (PATTERN_SENT);
  if ((message_ack != NULL) &&
      (! parse_hex (message_ack, mp, MESSAGE_ID_SIZE))) {
    bzero (message_ack, MESSAGE_ID_SIZE);
    return MSG_TYPE_DONE;
  }
  if (type == MSG_TYPE_ACK) /* should all be on the first line */
    return type;
  /* note that even though an ack is all on one line, the computation
   * of second_line should still have worked */

  if (! parse_seq_time (second_line, seq, time, tz, rcvd_time)) {
    bzero (message_ack, MESSAGE_ID_SIZE);
    if (seq != NULL)  *seq = 0;
    if (time != NULL) *time = 0;
    return MSG_TYPE_DONE;
  }

  char * user_data = strchr (second_line, '\n');
  if (user_data == NULL) {
    bzero (message_ack, MESSAGE_ID_SIZE);
    if (seq != NULL)  *seq = 0;
    if (time != NULL) *time = 0;
    return MSG_TYPE_DONE;
  }
  user_data++;
  if (*user_data != ' ') {
    bzero (message_ack, MESSAGE_ID_SIZE);
    if (seq != NULL)  *seq = 0;
    if (time != NULL) *time = 0;
    return MSG_TYPE_DONE;
  }
  user_data++;

  /* copy the user data to the beginning, so it is easier to free */
  memmove (record, user_data, strlen (user_data) + 1);
  int i;
  /* remove the blanks at the beginning of lines in the user data */
  /* in this loop, strlen decreases whenever a non-terminal newline is found */
  for (i = 0; i < strlen (record); i++) {
    if ((record [i] == '\n') && (i + 1 < strlen (record)) &&
        (record [i + 1] == ' ')) {
      char * blank = record + i + 1;
      memmove (blank, blank + 1, strlen (blank)); /* copies the \0 also */
    } else if ((record [i] == '\n') && (i + 1 == strlen (record))) {
      record [i] = '\0';
    }
  }
  if (msize != NULL)
    *msize = (int)strlen (record);
  if (message != NULL)
    *message = record;
  return type;
}

static char * find_prev_record (struct msg_iter * iter)
{
  while (1) {
    if (iter->k < 0)  /* invalid iterator */
      return NULL;
    if (((iter->current_file == NULL) ||  /* at start */
         (iter->current_pos <= 0)) &&       /* update file */
        (! find_prev_file (iter)))
      return NULL;
    uint64_t record_end_pos = iter->current_pos;
    /* a record begins with "got ack", "sent id", or "rcvd id". */
    do {
      (iter->current_pos)--;
    } while ((iter->current_pos >= 0) && (! match_record_start (iter)));
    if ((iter->current_pos >= 0) && (match_record_start (iter))) {
      int size = (int) (record_end_pos - iter->current_pos);
      char * result = malloc_or_fail (size + 1, "find_prev_record");
      memcpy (result, (iter->current_file) + (iter->current_pos), size);
      result [size] = '\0';
      return result;
    }
    printf ("unable to find any records in file %s\n", iter->current_fname);
  }
}

/* returns the message type, or MSG_TYPE_DONE if we've reached the end */
/* in case of SENT or RCVD, sets *seq, message_ack (which must have
 * MESSAGE_ID_SIZE bytes), and sets *message to point to newly 
 * allocated memory containing the message (caller must free this).
 * for ACK, sets message_ack only, sets *seq to 0 and *message to NULL
 * for DONE, sets *seq to 0, clears message_ack, and sets *message to NULL */
int prev_message (struct msg_iter * iter, uint64_t * seq, uint64_t * time,
                  int * tz_min, uint64_t * rcvd_time, char * message_ack,
                  char ** message, int * msize)
{
  if (iter->k < 0)  /* invalid */
    return MSG_TYPE_DONE;
  char * record = find_prev_record (iter);
  if (record == NULL)  /* finished */
    return MSG_TYPE_DONE;
  int result = parse_record (record, seq, time, tz_min, rcvd_time,
                             message_ack, message, msize);
  if ((message == NULL) || (*message != record))
    free (record);
  return result;
}

void free_iter (struct msg_iter * iter)
{
  if (iter->k < 0)
    return;
  if (iter->contact != NULL)
    free (iter->contact);
  if (iter->dirname != NULL)
    free (iter->dirname);
  if (iter->current_fname != NULL)
    free (iter->current_fname);
  if (iter->current_file != NULL)
    free (iter->current_file);
  iter->contact = NULL;
  iter->k = -1;            /* invalidate */
  iter->dirname = NULL;
  iter->current_fname = NULL;
  iter->current_file = NULL;
  iter->current_size = 0;
  iter->current_pos = 0;
}

/* returns the message type, or MSG_TYPE_DONE if none are available.
 * most recent refers to the most recently saved in the file.  This may
 * not be very useful, highest_seq_record may be more useful */ 
int most_recent_record (const char * contact, keyset k, int type_wanted,
                        uint64_t * seq, uint64_t * time, int * tz_min,
                        uint64_t * rcvd_time,
                        char * message_ack, char ** message, int * msize)
{
  /* easy implementation, just calling the iterator.  Later perhaps optimize */
  struct msg_iter * iter = start_iter (contact, k);
  if (iter == NULL)
    return MSG_TYPE_DONE;
  int type;
  do {
    type = prev_message (iter, seq, time, tz_min, rcvd_time,
                         message_ack, message, msize);
  } while ((type != MSG_TYPE_DONE) &&
           (type_wanted != MSG_TYPE_ANY) && (type != type_wanted));
  free_iter (iter);
  return type;
}

/* returns the message type, or MSG_TYPE_DONE if none are available */
int highest_seq_record (const char * contact, keyset k, int type_wanted,
                        uint64_t * seq, uint64_t * time, int * tz_min,
                        uint64_t * rcvd_time,
                        char * message_ack, char ** message, int * msize)
{
  struct msg_iter * iter = start_iter (contact, k);
  if (iter == NULL)
    return MSG_TYPE_DONE;
  int type;
  int max_type = MSG_TYPE_DONE;  /* in case we have no matches */
  uint64_t max_seq = 0;
  uint64_t max_time = 0;
  uint64_t max_rcvd_time = 0;
  int max_tz = 0;
  char max_ack [MESSAGE_ID_SIZE];
  char * max_message = NULL;
  int max_msize = 0;
  while (1) {
    uint64_t this_seq = 0;
    uint64_t this_time = 0;
    uint64_t this_rcvd_time = 0;
    int this_tz = 0;
    char this_ack [MESSAGE_ID_SIZE];
    char * this_message = NULL;
    int this_msize = 0;
    if (message != NULL) {
      type = prev_message (iter, &this_seq, &this_time, &this_tz,
                           &this_rcvd_time, this_ack,
                           &this_message, &this_msize);
    } else {
      type = prev_message (iter, &this_seq, &this_time, &this_tz,
                           &this_rcvd_time, this_ack, NULL, NULL);
    }
    if (type == MSG_TYPE_DONE)  /* no (more) messages */
      break;
    if (((type_wanted == MSG_TYPE_ANY) || (type == type_wanted)) &&
        ((this_seq > max_seq) ||
         ((this_seq == max_seq) && (this_time > max_time)))) {
      max_type = type;
      max_seq = this_seq;
      max_time = this_time;
      max_tz = this_tz;
      max_rcvd_time = this_rcvd_time;
      memcpy (max_ack, this_ack, MESSAGE_ID_SIZE);
      if (message != NULL) {
        max_message = this_message;
        max_msize = this_msize;
      }
    } else if (message != NULL) {  /* free the newly allocated message */
      free (this_message);
    }
  }
  free_iter (iter);
  if (max_seq > 0) {
    if (seq != NULL)
      *seq = max_seq;
    if (time != NULL)
      *time = max_time;
    if (tz_min != NULL)
      *tz_min = max_tz;
    if (rcvd_time != NULL)
      *rcvd_time = max_rcvd_time;
    if (message_ack != NULL)
      memcpy (message_ack, max_ack, MESSAGE_ID_SIZE);
    if (message != NULL)
      *message = max_message;
    if (msize != NULL)
      *msize = max_msize;
  }
  return max_type;
}


static void store_save_string_len (int fd, char * string, int mlen)
{
  if (write (fd, string, mlen) != mlen) {
    perror ("write/len");
    printf ("unable to write '%s' to file (%d)\n", string, mlen);
    exit (1);
  }
}

static void store_save_string (int fd, char * string)
{
  if (write (fd, string, strlen (string)) != strlen (string)) {
    perror ("write");
    printf ("unable to write '%s' to file\n", string);
    exit (1);
  }
}

static void store_save_64 (int fd, uint64_t value)
{
  /* 2^64 < 10^20, so 30 bytes are more than needed for the digits */
  char buffer [30];
  snprintf (buffer, sizeof (buffer), "%ju", (uintmax_t)value);
  store_save_string (fd, buffer);
}

static void store_save_message (int fd, const char * message, int mlen)
{
  int num_indents = 1;  /* have to insert a blank before the message */
  int i;
  for (i = 0; i + 1 < mlen; i++)
    if (message [i] == '\n')
      num_indents++;
  char * buffer = malloc_or_fail (mlen + num_indents + 2, "store_save_message");
  int from;
  buffer [0] = ' ';
  int to = 1;
  for (from = 0; from < mlen; from++) {
    if ((from + 1 < mlen) || (message [from] != '\n')) {
    /* the if is so we don't copy the last \n, if any */
      buffer [to++] = message [from];
      if (message [from] == '\n')
        buffer [to++] = ' ';
    }
  }
  buffer [to++] = '\n';
  buffer [to] = '\0';
  store_save_string_len (fd, buffer, to);
  free (buffer);
}

static void store_save_message_type (int fd, int type)
{
  switch (type) {
  case MSG_TYPE_RCVD:
    store_save_string (fd, "rcvd id:");
    break;
  case MSG_TYPE_SENT:
    store_save_string (fd, "sent id:");
    break;
  case MSG_TYPE_ACK:
    store_save_string (fd, "got ack:");
    break;
  default:
    printf ("unknown message type %d\n", type);
    exit (1);
  }
}

static void store_save_message_id (int fd, const char * id)
{
  store_save_string (fd, " ");
  char buffer [MESSAGE_ID_SIZE * 2 + 1];
  int i;
  for (i = 0; i < MESSAGE_ID_SIZE; i++)
    snprintf (buffer + 2 * i, sizeof (buffer) - 2 * i, "%02x", (id [i]) & 0xff);
  store_save_string (fd, buffer);
}

static void store_save_message_seq_time (int fd, uint64_t seq,
                                         uint64_t time, int tz, uint64_t rcvd)
{
  store_save_string (fd, "sequence ");
  store_save_64 (fd, seq);
  store_save_string (fd, ", time ");
  char time_buf [ALLNET_TIME_STRING_SIZE];
  allnet_time_string (time, time_buf);
  store_save_string (fd, time_buf);
  store_save_string (fd, " (");
  store_save_64 (fd, time);
  if (tz < 0) {
    store_save_string (fd, " -");
    tz = -tz;
  } else {
    store_save_string (fd, " +");
  }
  store_save_64 (fd, tz);
  store_save_string (fd, ")/");
  store_save_64 (fd, rcvd);
  store_save_string (fd, "\n");
}

void save_record (const char * contact, keyset k, int type, uint64_t seq,
                  uint64_t t, int tz_min, uint64_t rcvd_time,
                  const char * message_ack, const char * message, int msize)
{
  if ((type != MSG_TYPE_RCVD) && (type != MSG_TYPE_SENT) &&
      (type != MSG_TYPE_ACK))
    return;
  struct msg_iter * iter = start_iter (contact, k);
  if (iter == NULL)
    return;
  time_t now;
  time (&now);
  struct tm * tm = gmtime (&now);
#define EXTENSION		".txt"
#define EXTENSION_LENGTH	4  /* number of characters in ".txt" */
  char fname [DATE_LEN + EXTENSION_LENGTH + 1];
  snprintf (fname, sizeof (fname), "%04d%02d%02d%s", tm->tm_year + 1900,
            tm->tm_mon + 1, tm->tm_mday, EXTENSION);
  char * path = strcat3_malloc (iter->dirname, "/", fname, "save_record");
  int fd = open (path, O_WRONLY | O_APPEND | O_CREAT, 0600);
  if (fd < 0) {
    perror ("open");
    printf ("unable to open file %s\n", path);
    free (path);
    return;
  }
 
  flock (fd, LOCK_EX);  /* exclusive write, otherwise multiple writers
                         * make a mess of the file */
  store_save_message_type (fd, type);
  store_save_message_id (fd, message_ack);
  char id [MESSAGE_ID_SIZE];
  sha512_bytes (message_ack, MESSAGE_ID_SIZE, id, MESSAGE_ID_SIZE);
  store_save_message_id (fd, id);
  store_save_string (fd, "\n");

  if (type != MSG_TYPE_ACK) {
    store_save_message_seq_time (fd, seq, t, tz_min, rcvd_time);
    store_save_message (fd, message, msize);
  }
  flock (fd, LOCK_UN);  /* remove the file lock */

  close (fd);
  free (path);
}

/* add an individual message, modifying msgs, num_alloc or num_used as needed
 * 0 <= position <= *num_used
 * normally call after calling save_record (or internally)
 * return 1 if successful, 0 if not */
int add_message (struct message_store_info ** msgs, int * num_alloc,
                 int * num_used, int position,
                 int type, uint64_t seq, uint64_t missing,
                 uint64_t time, int tz_min, uint64_t rcvd_time, int acked,
                 const char * message, int msize)
{
  if ((num_used == NULL) || (num_alloc == NULL) ||
      (position < 0) || (position > (*num_used) + 1))
    return 0;
  if (*num_used < 0)
    *num_used = 0;
  if ((msgs == NULL) || (*num_used >= *num_alloc)) {
    int count = *num_alloc;
    if (count <= 0)
      count = 100;
    /* increase by a factor of 10, to do this as infrequently as possible */
    int needed_count = count * 10;
    size_t needed = needed_count * sizeof (struct message_store_info);
    void * allocated = realloc (*msgs, needed);
    if (allocated == NULL) {
      perror ("realloc");
      printf ("add_message error trying to allocate %zd bytes\n", needed);
      return 0;
    }
    *num_alloc = needed_count;
    *msgs = allocated;
  }
  int index = *num_used;
  struct message_store_info * p = (*msgs) + index;
  while (index > position) {
    index--;
    p--;
    *(p + 1) = *p;
  }
  *num_used = (*num_used) + 1;
  p->msg_type = type;
  p->seq = seq;
  p->prev_missing = missing;
  p->time = time;
  p->tz_min = tz_min;
  p->rcvd_time = rcvd_time;
  p->message_has_been_acked = acked;
  p->message = message;
  p->msize = msize;
  return 1;
}

#define ACK_CACHE_ENTRIES	8	/* should be small */
static char ack_cache [ACK_CACHE_ENTRIES] [MESSAGE_ID_SIZE];
static int cache_start_pos = 0;

static int ack_is_cached (const char * ack)
{
  int i;
  for (i = 0; i < ACK_CACHE_ENTRIES; i++)
    if (memcmp (ack, ack_cache [i], MESSAGE_ID_SIZE) == 0) {
      cache_start_pos = i;  /* probably no need to reuse this ack */
      return 1;
    }
  return 0;
}

static void cache_ack (const char * ack)
{
  memcpy (ack_cache [cache_start_pos], ack, MESSAGE_ID_SIZE);
  cache_start_pos = (cache_start_pos + 1) % ACK_CACHE_ENTRIES;
}

#ifdef DEBUG_PRINT
static void print_message_ack (int next, const char * ack)
{
  char * name = "no name";
  if (next == MSG_TYPE_ACK)
    name = "found ack ";
  else if (next == MSG_TYPE_RCVD)
    name = "found rcvd";
  else if (next == MSG_TYPE_SENT)
    name = "found sent";
  print_buffer (ack, MESSAGE_ID_SIZE, name, MESSAGE_ID_SIZE, 1);
}
#endif /* DEBUG_PRINT */

/* *msgs must be NULL or pointing to num_alloc (malloc'd or realloc'd) records
 * of type struct message_store_info.  list_all_messages may realloc this if
 * more space is needed.  Initially, *num_used must be 0.  After returning,
 * *num_used <= *num_alloc (both numbers may have changed)
 * if msgs was previously used, its messages should have been freed
 * by calling free_all_messages.
 * return 1 if successful, 0 if not */
int list_all_messages (const char * contact,
                       struct message_store_info ** msgs,
                       int * num_alloc, int * num_used)
{
  *num_used = 0;
  keyset * k = NULL;
  int nk = all_keys (contact, &k);
  if (nk <= 0)  /* no such contact, or this contact has no keys */
    return 0;
  int ik;
  for (ik = 0; ik < nk; ik++) {
    struct msg_iter * iter = start_iter (contact, k [ik]);
    if (iter == NULL) {
      free (k);
      return 0;
    }
    uint64_t seq;
    uint64_t time = 0;
    uint64_t rcvd_time = 0;
    int tz_min;
    char ack [MESSAGE_ID_SIZE];
    char * message = NULL;
    int msize;
    int next = prev_message (iter, &seq, &time, &tz_min, &rcvd_time,
                             ack, &message, &msize);
    while (next != MSG_TYPE_DONE) {
      int inserted = 0;
#ifdef DEBUG_PRINT
      print_message_ack (next, ack);
#endif /* DEBUG_PRINT */
      if (((next == MSG_TYPE_RCVD) || (next == MSG_TYPE_SENT)) &&
          (message != NULL)) {
        int has_ack = ((next == MSG_TYPE_SENT) &&
                       (ack_is_cached (ack) || is_acked (contact, seq)));
/* if messages are mostly ordered, most of the time this loop will be short */
        int i = (*num_used) - 1;
        for ( ; ((i >= 0) && (! inserted)); i--) {
          if (time <= (*msgs) [i].time) {   /* insert here */
/* for now, set missing always to zero.  Fixed in the loop below. */
            add_message (msgs, num_alloc, num_used, i + 1,
                         next, seq, 0, time, tz_min, rcvd_time, has_ack,
                         message, msize);
            inserted = 1;
          }
        }
        if (! inserted) {
          add_message (msgs, num_alloc, num_used, 0,
                       next, seq, 0, time, tz_min, rcvd_time, has_ack,
                       message, msize);
          inserted = 1;
        }
      } else if (next == MSG_TYPE_ACK) {
        cache_ack (ack);
      }
      if ((! inserted) && (message != NULL))
        free (message);
      message = NULL;
      next = prev_message (iter, &seq, &time, &tz_min, &rcvd_time,
                           ack, &message, &msize);
    }
    free_iter (iter);
  }
  free (k);
  /* now fix prev_missing */
  int index = *num_used; /* first valid index is *num_used - 1 */
  struct message_store_info * msg = (*msgs);
  uint64_t prev_seq = 0; /* the first sequence number (if any) should be 1 */
  while (--index >= 0) { /* in the loop, index always points to a valid entry */
    if (msg [index].msg_type == MSG_TYPE_RCVD) {
      if (msg [index].seq > prev_seq + 1)
        msg [index].prev_missing = (msg [index].seq - (prev_seq + 1));
      prev_seq = msg [index].seq;
    }
  }
  return 1;
}

/* frees the message storage pointed to by each message entry */
void free_all_messages (struct message_store_info * msgs, int num_used)
{
  int i;
  for (i = 0; i < num_used; i++) {
    if (((msgs [i].msg_type == MSG_TYPE_RCVD) ||
         (msgs [i].msg_type == MSG_TYPE_SENT)) &&
        (msgs [i].message != NULL) &&
        (msgs [i].msize > 0))
      free ((void *)(msgs [i].message));
  }
}


#ifdef TEST_STORE
/* compile with:
   gcc -DTEST_STORE -g -o tstore store.c -I.. ../lib/ *.c -lcrypto
   (without the space before *.c)
 */
int main (int argc, char ** argv)
{
  keyset * keys = NULL;
  int n = 0;
  if (argc >= 2) {
    n = all_keys (argv [1], &keys);
    printf ("found %d keys\n", n);
  }
  if (argc != 3) {
    printf ("call with contact name and keyset number\n");
    if (argc == 2) {
      printf ("for contact %s, %d keysets and directories are:\n", argv [1], n);
      int i;
      for (i = 0; i < n; i++)
        printf ("%d: %d, %s\n", i, keys [i], key_dir (keys [i]));
    }
    return 0;
  }
  int k = atoi (argv [2]);
  uint64_t seq;
  uint64_t time;
  uint64_t rcvd_time;
  int tz = -1;
  char ack [MESSAGE_ID_SIZE];
  char * msg;
  int type = most_recent_record (argv [1], keys [k], MSG_TYPE_ANY,
                                 &seq, &time, &tz, ack, &msg);
  printf ("latest message type %d %s, seq %ju, time %ju%+d\n",
          type, msg, (uintmax_t)seq, (uintmax_t)time, tz);
  print_buffer (ack, MESSAGE_ID_SIZE, "  ack", MESSAGE_ID_SIZE, 1);
  type = most_recent_record (argv [1], keys [k], MSG_TYPE_SENT,
                             &seq, &time, &tz, ack, &msg);
  printf ("latest sent type %d %s, seq %ju, time %ju%+d\n",
          type, msg, (uintmax_t)seq, (uintmax_t)time, tz);
  print_buffer (ack, MESSAGE_ID_SIZE, "  ack", MESSAGE_ID_SIZE, 1);
  type = most_recent_record (argv [1], keys [k], MSG_TYPE_RCVD,
                             &seq, &time, &tz, ack, &msg);
  printf ("latest rcvd type %d %s, seq %ju, time %ju%+d\n",
          type, msg, (uintmax_t)seq, (uintmax_t)time, tz);
  print_buffer (ack, MESSAGE_ID_SIZE, "  ack", MESSAGE_ID_SIZE, 1);
  type = most_recent_record (argv [1], keys [k], MSG_TYPE_ACK,
                             &seq, &time, &tz, ack, &msg);
  printf ("latest ack type %d %s, seq %ju, time %ju%+d\n",
          type, msg, (uintmax_t)seq, (uintmax_t)time, tz);
  print_buffer (ack, MESSAGE_ID_SIZE, "  ack", MESSAGE_ID_SIZE, 1);
  printf ("\n");

  struct msg_iter * iter = start_iter (argv [1], keys [k]);
  if (n > 0)
    free (keys);
  if (iter == NULL) {
    printf ("null iterator, quitting\n");
    return 0;
  }
  int i = 0;
  int msize;
  while ((type = prev_message (iter, &seq, &time, &tz, &rcvd_time,
                               ack, &msg, &msize)) != MSG_TYPE_DONE) {
    printf ("message %i, %d bytes type %d, %s, seq %ju, time %ju%+d/%ju\n",
            ++i, msize, type, msg, (uintmax_t)seq, (uintmax_t)time, tz,
            (uintmax_t)rcvd_time);
    print_buffer (ack, MESSAGE_ID_SIZE, "  ack", MESSAGE_ID_SIZE, 1);
  }
  free_iter (iter);
  return 0;
}
#endif /* TEST_STORE */
