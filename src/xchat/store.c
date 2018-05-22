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
#include <pthread.h>
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

/* start_iter and prev_message define an iterator over messages.
 * the iterator proceeds backwards, setting type to MSG_TYPE_DONE
 * after the last message has been read. */
/* the iterator should be deallocated with free_iter after it is used */
/* a stack-based iterator with free_unallocated_iter */
/* for a single record, use most_recent record. */

#define DATE_LEN 		8	/* strlen ("20130327") */

struct msg_iter {
  char * contact;         /* dynamically allocated */
  keyset k;
  int is_in_memory;
  /* used in case the data is not already in memory */
  char * dirname;         /* dynamically allocated */
  char * current_fname;   /* dynamically allocated */
  char * current_file;    /* dynamically allocated */
  uint64_t current_size;
  int64_t current_pos;
  /* used only if the data is already in memory */
  int message_cache_index;
  int last_message_index;
  int ack_returned;       /* for sent messages, whether we've already
                           * returned the corresponding ack */
};

struct message_cache_record {
  char * contact;  /* dynamically allocated, but never freed */
  struct message_store_info * msgs;
  int num_alloc;
  int num_used;
};

#define MESSAGE_CACHE_NUM_CONTACTS	10000
static struct message_cache_record message_cache [MESSAGE_CACHE_NUM_CONTACTS];
static int message_cache_count = 0;
/* this mutex should be acquired each time before accessing message_cache
 * or message_cache_count, and released at the end of any related set
 * of accesses */
static pthread_mutex_t message_cache_mutex = PTHREAD_MUTEX_INITIALIZER;

/* returns -1 if not found */
/* must be called with the mutex held */
static int find_message_cache_record (const char * contact)
{
  int i;
  for (i = 0; i < message_cache_count; i++)
    if (strcmp (contact, message_cache [i].contact) == 0)
      return i;
  return -1;
}

/* returns -1 if unable to add, the record index otherwise */
/* must be called with the mutex held */
static int add_message_cache_record (const char * contact,
                                     struct message_store_info * msgs,
                                     int num_alloc,
                                     int num_used)
{
  if (message_cache_count >= MESSAGE_CACHE_NUM_CONTACTS) {
    printf ("unable to add to message cache record for %s\n", contact);
    return -1;
  }
  int index = find_message_cache_record (contact);
  if (index == -1) {   /* not found, add new */
    index = message_cache_count;
    message_cache_count++;
    message_cache [index].contact =
      strcpy_malloc (contact, "add_message_cache_record");
  } else if (message_cache [index].msgs != NULL) {
    free (message_cache [index].msgs);
  }
  message_cache [index].msgs = msgs;
  message_cache [index].num_alloc = num_alloc;
  message_cache [index].num_used = num_used;
  return index;
}

/* returns 1 for success, 0 otherwise */
static int start_iter_from_file (const char * contact, keyset k,
                                 struct msg_iter * result)
{
  char * directory = key_dir (k);
  if (directory == NULL)
    return 0;
  result->contact = strcpy_malloc (contact, "start_iter contact");
  result->k = k;
  result->is_in_memory = 0;
  result->dirname = string_replace_once (directory, "contacts", "xchat", 1);
  result->current_fname = NULL;
  result->current_file = NULL;
  result->current_size = 0;
  result->current_pos = 0;
  free (directory);
  return 1;
}

struct msg_iter * start_iter (const char * contact, keyset k)
{
  if ((contact == NULL) || (k < 0))
    return NULL;
  pthread_mutex_lock (&message_cache_mutex);
  int index = find_message_cache_record (contact);
  struct msg_iter file_iter;
  if ((index < 0) &&  /* not already cached, get data from files */
      (message_cache_count < MESSAGE_CACHE_NUM_CONTACTS)) {
    struct message_store_info * msgs = NULL;
    int num_used = 0;
    int num_alloc = 0;
    int success = list_all_messages (contact, &msgs, &num_alloc, &num_used);
    if (success) {
      index = add_message_cache_record (contact, msgs, num_alloc, num_used);
      if (index < 0) { /* unable to cache */
        if ((msgs != NULL) && (num_used > 0))
          free_all_messages (msgs, num_used);
        if (! start_iter_from_file (contact, k, &file_iter)) {
          pthread_mutex_unlock (&message_cache_mutex);
          return NULL;   /* unable to cache, unable to find file */
        }
      }
    } else {   /* unable to list messages, probably unable to find file */
      pthread_mutex_unlock (&message_cache_mutex);
      return NULL;
    }
  }
  /* this code handles messages in cache, whether found or added */
  struct msg_iter * result = malloc_or_fail (sizeof (struct msg_iter),
                                             "start_iter struct");
  result->contact = strcpy_malloc (contact, "start_iter contact");
  result->k = k;
  if (index >= 0) {
    result->is_in_memory = 1;
    result->message_cache_index = index;
    result->last_message_index = message_cache [index].num_used;
    result->ack_returned = 0;
    /* set the other values to reasonable defaults */
    result->dirname = NULL;
    result->current_fname = NULL;
    result->current_file = NULL;
    result->current_size = 0;
    result->current_pos = 0;
  } else { /* unable to cache, use file */
    /* *result = file_iter -- file_iter is only initialized if
          (message_cache_count < MESSAGE_CACHE_NUM_CONTACTS) */
    start_iter_from_file(contact, k, result);
  }
  pthread_mutex_unlock (&message_cache_mutex);
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
static int end_ndigits (char * path, unsigned int ndigits, char * ext)
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
  unsigned int i;
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
  if (iter->current_size <= 0)
    iter->current_size = 0;
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
    memset (message_ack, 0, MESSAGE_ID_SIZE);
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
    memset (message_ack, 0, MESSAGE_ID_SIZE);
    return MSG_TYPE_DONE;
  }
  if (type == MSG_TYPE_ACK) /* should all be on the first line */
    return type;
  /* note that even though an ack is all on one line, the computation
   * of second_line should still have worked */

  if (! parse_seq_time (second_line, seq, time, tz, rcvd_time)) {
    memset (message_ack, 0, MESSAGE_ID_SIZE);
    if (seq != NULL)  *seq = 0;
    if (time != NULL) *time = 0;
    return MSG_TYPE_DONE;
  }

  char * user_data = strchr (second_line, '\n');
  if (user_data == NULL) {
    memset (message_ack, 0, MESSAGE_ID_SIZE);
    if (seq != NULL)  *seq = 0;
    if (time != NULL) *time = 0;
    return MSG_TYPE_DONE;
  }
  user_data++;
  if (*user_data != ' ') {
    memset (message_ack, 0, MESSAGE_ID_SIZE);
    if (seq != NULL)  *seq = 0;
    if (time != NULL) *time = 0;
    return MSG_TYPE_DONE;
  }
  user_data++;

  /* copy the user data to the beginning, so it is easier to free */
  memmove (record, user_data, strlen (user_data) + 1);
  unsigned int i;
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

static void set_result (
   uint64_t * seqp, uint64_t seq, uint64_t * timep, uint64_t time,
   int * tz_minp, int tz_min, uint64_t * rcvd_timep, uint64_t rcvd_time,
   char * message_ackp, const char * ack_value,
   char ** messagep, const char * message, int * msizep, size_t msize)
{
  if (seqp != NULL) *seqp = seq;
  if (timep != NULL) *timep = time;
  if (tz_minp != NULL) *tz_minp = tz_min;
  if (rcvd_timep != NULL) *rcvd_timep = rcvd_time;
  if (message_ackp != NULL)
    memcpy (message_ackp, ack_value, MESSAGE_ID_SIZE);
  if (messagep != NULL) {
    *messagep = NULL;
    if ((message != NULL) && (msize > 0)) {
      char * m = malloc_or_fail (msize + 1, "store.c set_result");
      m [msize] = '\0';  /* so we can print as text, for debugging */
      memcpy (m, message, msize);
      *messagep = m;
    }
  }
  if (msizep != NULL) *msizep = (int)msize;
}

/* must be called with the mutex held */
static int prev_message_in_memory
  (struct msg_iter * iter, uint64_t * seq, uint64_t * time,
   int * tz_min, uint64_t * rcvd_time, char * message_ack,
   char ** message, int * msize)
{
  int index = iter->message_cache_index;
  int pos = iter->last_message_index;
  if ((index < 0) || (index >= message_cache_count)) /* invalid iterator */
    return MSG_TYPE_DONE;
  if (pos < 0)                      /* iterator completed */
    return MSG_TYPE_DONE;
  struct message_store_info * msgs = message_cache [index].msgs;
  /* pos is the last message that was returned, and may refer to
   * an invalid message if no messages were returned yet. 
   * if iter->ack_returned, pos refers to the message to be returned now */
#ifdef DEBUG_PRINT
  if (strcmp (iter->contact, "edo-on-celine") == 0) {
    int i = ((iter->ack_returned) ? pos : (pos - 1));
    printf ("iter has k %d, i %d, m %d (%d), ret %d, index %d, ",
            iter->k, iter->message_cache_index, iter->last_message_index, pos,
            iter->ack_returned, i);
    if (i >= 0)
      printf ("'%s' (%zd), seq %ju ", msgs [i].message, msgs [i].msize,
              (uintmax_t) msgs [i].seq);
    print_buffer (msgs [i].ack, MESSAGE_ID_SIZE, "ack", 6, 1);
  }
#endif /* DEBUG_PRINT */
  if (iter->ack_returned) {  /* msg_type should be MSG_TYPE_SENT */
    set_result (seq, msgs [pos].seq, time, msgs [pos].time,
                tz_min, msgs [pos].tz_min, rcvd_time, msgs [pos].rcvd_ackd_time,
                message_ack, msgs [pos].ack,
                message, msgs [pos].message, msize, msgs [pos].msize);
    /* do not change last_message_index, just clear ack_returned */
    iter->ack_returned = 0;
    return MSG_TYPE_SENT;
  }
  /* find the preceding message with this keyset */
  while (--pos >= 0) {
    if (msgs [pos].keyset == iter->k) {
      break;
    }
  }
  iter->last_message_index = pos;
  if (pos < 0)                      /* iterator completed */
    return MSG_TYPE_DONE;
  /* pos >= 0, msgs [pos].keyset == iter->k -- we will return this message */
  if ((msgs [pos].msg_type == MSG_TYPE_SENT) &&
      (msgs [pos].message_has_been_acked)) {  /* return the ack */
    set_result (seq, 0, time, 0, tz_min, 0, rcvd_time, 0,
                message_ack, msgs [pos].ack, message, NULL, msize, 0);
    iter->ack_returned = 1; /* and on the next call, return this message */
    return MSG_TYPE_ACK;
  }   /* else, return this message */
  set_result (seq, msgs [pos].seq, time, msgs [pos].time,
              tz_min, msgs [pos].tz_min, rcvd_time, msgs [pos].rcvd_ackd_time,
              message_ack, msgs [pos].ack,
              message, msgs [pos].message, msize, msgs [pos].msize);
  return msgs [pos].msg_type;
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
  if (iter->is_in_memory) {
    pthread_mutex_lock (&message_cache_mutex);
    int r = prev_message_in_memory (iter, seq, time, tz_min, rcvd_time,
                                    message_ack, message, msize);
    pthread_mutex_unlock (&message_cache_mutex);
    return r;
  }
  char * record = find_prev_record (iter);
  if (record == NULL)  /* finished */
    return MSG_TYPE_DONE;
  int result = parse_record (record, seq, time, tz_min, rcvd_time,
                             message_ack, message, msize);
  if ((message == NULL) || (*message != record))
    free (record);
  return result;
}

void free_unallocated_iter (struct msg_iter * iter)
{
  if (iter->k < 0)
    return;
  if (iter->contact != NULL)
    free (iter->contact);
  if (! iter->is_in_memory) {
    if (iter->dirname != NULL)
      free (iter->dirname);
    if (iter->current_fname != NULL)
      free (iter->current_fname);
    if (iter->current_file != NULL)
      free (iter->current_file);
  }
  iter->contact = NULL;
  iter->k = -1;            /* invalidate */
  iter->is_in_memory = 0;
  iter->dirname = NULL;
  iter->current_fname = NULL;
  iter->current_file = NULL;
  iter->current_size = 0;
  iter->current_pos = 0;
  iter->message_cache_index = 0;
  iter->last_message_index = 0;
  iter->ack_returned = 0;
}

void free_iter (struct msg_iter * iter)
{
  free_unallocated_iter (iter);
  free (iter);
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
        if (max_message != NULL)
          free (max_message);
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

static char * get_xchat_dir (keyset k)
{
  char * contact_dir = key_dir (k);
  if (contact_dir == NULL)
    return NULL;
  char * xchat_dir = string_replace_once (contact_dir, "contacts", "xchat", 1);
  free (contact_dir);
  return xchat_dir;
}

static char * get_xchat_path (keyset k, const char * fname)
{
  char * xchat_dir = get_xchat_dir (k);  /* must be free'd */
  if (xchat_dir == NULL)
    return NULL;
  char * path = strcat3_malloc (xchat_dir, "/", fname, "find_prev_file");
  free (xchat_dir);
  return path;
}

static uint64_t read_int_from_file (const char * contact, keyset k,
                                    const char * fname)
{
  char * path = get_xchat_path (k, fname);  /* must be free'd */
  if (path == NULL)
    return 0;
  char * contents = NULL;                   /* must be free'd */
  int csize = read_file_malloc (path, &contents, 0);
  free (path);
  if ((csize <= 0) || (contents == NULL))
    return 0;
  uint64_t result = 0;
  sscanf (contents, "%" PRIu64, &result);
  free (contents);
  return result;
}

static void save_int_to_file (const char * contact, keyset k,
                              const char * fname, uint64_t value)
{
  char * path = get_xchat_path (k, fname);  /* must be free'd */
  if (path == NULL)
    return;
  char buffer [] = "18446744073709551616\n";  /* 2^64 */
  snprintf (buffer, sizeof (buffer), "%" PRIu64 "\n", value);
  write_file (path, buffer, (int)strlen (buffer), 1);
  free (path);
}

#ifdef IMPLEMENTING_SEQ_CACHING
struct cached_seq_value {
  uint64_t seq;
  uint64_t time;
};

struct cached_seq_pair {
  keyset k;
  struct cached_seq_value sent;
  struct cached_seq_value rcvd;
};

#define NUM_CACHE_ENTRIES	1000
static struct cached_seq_pair cached_seq [NUM_CACHE_ENTRIES];
static int cached_seq_index = 0;

/* returns -1 if not found */
static int get_cached (keyset k)
{
  int i;
  for (i = 0; i < cached_seq_index; i++) {
    if (cached_seq [i].k == k)
      return i;
  }
  return -1;
}

static void cache_seq (keyset k, uint64_t seq, uint64_t time, int sent)
{
  int i = 0;
  int index = cached_seq_index;
  int need_new = 1;
  for (i = 0; i < cached_seq_index; i++) {
    if (cached_seq [i].k == k) {
      need_new = 0;
      index = i;
      break;
    }
  }
  if (need_new && (index >= NUM_CACHE_ENTRIES))
    return;  /* no room, don't cache */
  if (need_new) {  /* initialize the new entry to default values */
    cached_seq [index].k = k;
    cached_seq [index].sent.seq = 0;
    cached_seq [index].sent.time = 0;
    cached_seq [index].rcvd.seq = 0;
    cached_seq [index].rcvd.time = 0;
    cached_seq_index++;
  }
  if (sent) {
    cached_seq [index].sent.seq = seq;
    cached_seq [index].sent.time = time;
  } else {
    cached_seq [index].rcvd.seq = seq;
    cached_seq [index].rcvd.time = time;
  }
}
#endif /* IMPLEMENTING_SEQ_CACHING */

/* returns the sequence number, or 0 if none are available */
/* type_wanted must be MSG_TYPE_ANY, MSG_TYPE_RCVD, or MSG_TYPE_SENT,
 * otherwise returns 0 */
uint64_t highest_seq_value (const char * contact, keyset k, int type_wanted)
{
  if ((type_wanted != MSG_TYPE_SENT) && (type_wanted != MSG_TYPE_RCVD) &&
      (type_wanted != MSG_TYPE_ANY)) {
    printf ("coding error: highest_seq_value takes %d or %d or %d, got %d\n",
            MSG_TYPE_SENT, MSG_TYPE_RCVD, MSG_TYPE_ANY, type_wanted);
    return 0;
  }
  uint64_t seq = 0;
  if ((type_wanted == MSG_TYPE_SENT) || (type_wanted == MSG_TYPE_ANY)) {
    seq = read_int_from_file (contact, k, "last_sent");
  }
  if ((type_wanted == MSG_TYPE_RCVD) || (type_wanted == MSG_TYPE_ANY)) {
    uint64_t seq_r = read_int_from_file (contact, k, "last_received");
    if (seq_r > seq)  /* always true if MSG_TYPE_RCVD and sane file exists */
      seq = seq_r;
  }
  if (seq > 0)
    return seq;
  /* no such message found, iterate through all messages to find it. */
  struct msg_iter * iter = start_iter (contact, k);
  if (iter == NULL)
    return 0;
#ifdef IMPLEMENTING_SEQ_CACHING
  uint64_t saved_seq = 0;
  uint64_t saved_time = 0;
  int cache_index = get_cached (k);
  if (cache_index >= 0) {
    int save_sent = (type_wanted == MSG_TYPE_SENT);
    if ((type_wanted == MSG_TYPE_ANY) &&
        (cached_seq [cache_index].sent.seq > cached_seq [cache_index].rcvd.seq))
      save_sent = 1;
    if (save_sent) {
      saved_seq  = cached_seq [cache_index].sent.seq;
      saved_time = cached_seq [cache_index].sent.time;
    } else {
      saved_seq  = cached_seq [cache_index].rcvd.seq;
      saved_time = cached_seq [cache_index].rcvd.time;
    }
  }
#endif /* IMPLEMENTING_SEQ_CACHING */
  int max_type = MSG_TYPE_DONE;
  uint64_t max_seq = 0;
  uint64_t max_time = 0;
  while (1) {
    uint64_t this_seq = 0;
    uint64_t this_time = 0;
    int type = prev_message (iter, &this_seq, &this_time,
                             NULL, NULL, NULL, NULL, NULL);
    if (type == MSG_TYPE_DONE)  /* no (more) messages */
      break;
    if (((type == MSG_TYPE_SENT) || (type == MSG_TYPE_RCVD)) && /* no acks */
        ((type_wanted == MSG_TYPE_ANY) || (type == type_wanted))) { /* match */
      if ((this_seq > max_seq) ||
          ((this_seq == max_seq) && (this_time > max_time))) {
        max_type = type;
        max_seq = this_seq;
        max_time = this_time;
      }
#ifdef IMPLEMENTING_SEQ_CACHING
      if ((cache_index >= 0) &&
          (this_seq == saved_seq) && (this_time == saved_time))
        break; /* reached the cached value, no point going further */
#endif /* IMPLEMENTING_SEQ_CACHING */
    }
  }
  free_iter (iter);
  if (max_seq > 0) {   /* save the result of all this hard work */
    if (max_type == MSG_TYPE_SENT) {
#ifdef IMPLEMENTING_SEQ_CACHING
      cache_seq (k, max_seq, max_time, 1);
#endif /* IMPLEMENTING_SEQ_CACHING */
      save_int_to_file (contact, k, "last_sent", max_seq);
    } else if (max_type == MSG_TYPE_RCVD) {
#ifdef IMPLEMENTING_SEQ_CACHING
      cache_seq (k, max_seq, max_time, 0);
#endif /* IMPLEMENTING_SEQ_CACHING */
      save_int_to_file (contact, k, "last_received", max_seq);
    }
  }
  return max_seq;
}

/* returns the sequence number, or 0 if none are available */
/* type_wanted must be MSG_TYPE_ANY, MSG_TYPE_RCVD, or MSG_TYPE_SENT,
 * otherwise returns 0 */
uint64_t highest_seq_any_key (const char * contact, int type_wanted)
{
  uint64_t result = 0;
  int i;
  keyset * ks = NULL;
  int nks = all_keys (contact, &ks);
  for (i = 0; i < nks; i++) {
    uint64_t found = highest_seq_value (contact, ks [i], type_wanted);
    if (found > result)
      result = found;
  }
  if (ks != NULL)
    free (ks);
  return result;
}

/* fix the prev_missing of each received message.  quadratic loop */
static void set_missing (struct message_store_info * msgs, int num_used,
                         keyset k)
{
  int i;
  for (i = 0; i < num_used; i++) {
    if ((msgs [i].keyset == k) && (msgs [i].msg_type == MSG_TYPE_RCVD)) {
      uint64_t seq = msgs [i].seq;
      uint64_t prev_seq = 0; /* the first sequence number should be 1 */
      int index;
      for (index = 0; index < num_used; index++) {
        if ((msgs [index].keyset == k) &&
            (msgs [index].msg_type == MSG_TYPE_RCVD) &&
            (msgs [index].seq < seq) &&
            (msgs [index].seq > prev_seq))
          prev_seq = msgs [index].seq;
      }
      msgs [i].prev_missing = 0;
      if (prev_seq >= msgs [i].seq)
        printf ("error: prev_seq %" PRIu64 " >= seq [%d] %" PRIu64 "\n",
                prev_seq, i, msgs [i].seq);
      else /* prev_seq < msgs [i].seq) */
        msgs [i].prev_missing = (msgs [i].seq - (prev_seq + 1));
    }
  }
}

/* set the message_has_been_acked of each sent message acked by this message */
static void ack_one_message (struct message_store_info * msgs, int num_used,
                             const char * ack, uint64_t ack_time)
{
  int i;
  for (i = 0; i < num_used; i++) {
    /* acknowledge any sent messages acked by this ack message */
    if ((msgs [i].msg_type == MSG_TYPE_SENT) &&
        (! msgs [i].message_has_been_acked) &&
        (memcmp (msgs [i].ack, ack, MESSAGE_ID_SIZE) == 0)) {
      msgs [i].rcvd_ackd_time = ack_time;
      msgs [i].message_has_been_acked = 1;
    }
  }
}

/* set the message_has_been_acked of each acked sent message.  quadratic loop */
static void ack_all_messages (struct message_store_info * msgs, int num_used,
                              const char * contact, keyset k)
{
  if (contact == NULL) {
    printf ("ack_all_messages error: NULL contact\n");
    return;
  }
  if ((msgs == NULL) || (num_used <= 0)) {
    /* no messages to ack, nothing to do */
    return;
  }
  struct msg_iter iter;
  if (! start_iter_from_file (contact, k, &iter)) {
    printf ("error: ack_all_messages unable to create iter for %s/%d\n",
            contact, k);
    return;
  }
  char ack [MESSAGE_ID_SIZE];
  uint64_t ack_time;
  int next = prev_message (&iter, NULL, &ack_time, NULL, NULL, ack, NULL, NULL);
  while (next != MSG_TYPE_DONE) {
    if (next == MSG_TYPE_ACK)
      ack_one_message (msgs, num_used, ack, ack_time);
    next = prev_message (&iter, NULL, NULL, NULL, NULL, ack, NULL, NULL);
  }
  free_unallocated_iter (&iter);
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
  if (write (fd, string, strlen (string)) != (int) (strlen (string))) {
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
  struct msg_iter iter;
  if (! start_iter_from_file (contact, k, &iter))
    return;
  time_t now;
  time (&now);
  struct tm * tm = gmtime (&now);
#define EXTENSION		".txt"
#define EXTENSION_LENGTH	4  /* number of characters in ".txt" */
  char fname [DATE_LEN + EXTENSION_LENGTH + 1];
  snprintf (fname, sizeof (fname), "%04d%02d%02d%s", tm->tm_year + 1900,
            tm->tm_mon + 1, tm->tm_mday, EXTENSION);
  char * path = strcat3_malloc (iter.dirname, "/", fname, "save_record");
  free_unallocated_iter (&iter);
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
  /* now save it internally, if we are caching this contact's data */
  pthread_mutex_lock (&message_cache_mutex);
  int index = find_message_cache_record (contact);
  if (index >= 0) {
    if ((type == MSG_TYPE_SENT) || (type == MSG_TYPE_RCVD)) {
      add_message (&(message_cache [index].msgs),
                   &(message_cache [index].num_alloc),
                   &(message_cache [index].num_used),
                   message_cache [index].num_used,  /* add at the end */
                   k, type, seq, 0,  /* none missing */
                   t, tz_min, rcvd_time, 0, /* no ack */
                   message_ack, message, msize);
      if (type == MSG_TYPE_RCVD) /* may change prev_missing */
        set_missing (message_cache [index].msgs,
                     message_cache [index].num_used, k);
      if (type == MSG_TYPE_SENT) /* may change message_has_been_acked */
        ack_all_messages (message_cache [index].msgs,
                          message_cache [index].num_used, contact, k);
    } else if (type == MSG_TYPE_ACK) {
      ack_one_message (message_cache [index].msgs,
                       message_cache [index].num_used, message_ack, rcvd_time);
    }
  }
  /* save the sequence number if it is a new maximum */
  if (type == MSG_TYPE_SENT) {
    uint64_t max_seq = read_int_from_file (contact, k, "last_sent");
    if (max_seq < seq)
      save_int_to_file (contact, k, "last_sent", seq);
  } else if (type == MSG_TYPE_RCVD) {
    uint64_t max_seq = read_int_from_file (contact, k, "last_received");
    if (max_seq < seq)
      save_int_to_file (contact, k, "last_received", seq);
  }
  pthread_mutex_unlock (&message_cache_mutex);
}

/* add an individual message, modifying msgs, num_alloc or num_used as needed
 * 0 <= position <= *num_used
 * normally call after calling save_record (or internally)
 * return 1 if successful, 0 if not */
int add_message (struct message_store_info ** msgs, int * num_alloc,
                 int * num_used, int position, keyset keyset,
                 int type, uint64_t seq, uint64_t missing,
                 uint64_t time, int tz_min, uint64_t rcvd_ackd_time,
                 int acked, const char * ack,
                 const char * message, int msize)
{
  if ((num_used == NULL) || (num_alloc == NULL) || (msgs == NULL) ||
      (position < 0) || (position > (*num_used) + 1))
    return 0;
  if (*num_used < 0)
    *num_used = 0;
  if ((*msgs == NULL) || (*num_used >= *num_alloc)) {
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
  p->keyset = keyset;
  p->msg_type = type;
  p->seq = seq;
  p->prev_missing = missing;
  p->time = time;
  p->tz_min = tz_min;
  p->rcvd_ackd_time = rcvd_ackd_time;
  p->message_has_been_acked = acked;
  if (ack != NULL)
    memcpy (p->ack, ack, MESSAGE_ID_SIZE);
  else
    memset (p->ack, 0, MESSAGE_ID_SIZE);
  p->message = strcpy_malloc (message, "add_message");
  p->msize = msize;
  return 1;
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

static void add_all_messages (struct message_store_info ** msgs,
                              int * num_alloc, int * num_used,
                              const char * contact, keyset k)
{
  struct msg_iter iter;
  if (! start_iter_from_file (contact, k, &iter)) {
    printf ("error: add_all_messages unable to create iter for %s/%d\n",
            contact, k);
    return;
  }
  uint64_t seq;
  uint64_t time = 0;
  uint64_t rcvd_time = 0;
  int tz_min;
  char ack [MESSAGE_ID_SIZE];
  char * message = NULL;
  int msize;
  int next = prev_message (&iter, &seq, &time, &tz_min, &rcvd_time,
                           ack, &message, &msize);
  while (next != MSG_TYPE_DONE) {
    int inserted = 0;
#ifdef DEBUG_PRINT
    print_message_ack (next, ack);
#endif /* DEBUG_PRINT */
    if (((next == MSG_TYPE_RCVD) || (next == MSG_TYPE_SENT)) &&
        (message != NULL)) {
/* if messages are mostly ordered, most of the time this loop will be short */
      int i = (*num_used) - 1;
      for ( ; ((i >= 0) && (! inserted)); i--) {
        if (time <= (*msgs) [i].time) {   /* insert here */
/* for now, let missing and acked both be zero.
 * missing is fixed by set_missing, acked by ack_all_messages */
          add_message (msgs, num_alloc, num_used, i + 1, k,
                       next, seq, 0, time, tz_min, rcvd_time, 0, ack,
                       message, msize);
          inserted = 1;
        }
      }
      if (! inserted) {
        add_message (msgs, num_alloc, num_used, 0, k,
                     next, seq, 0, time, tz_min, rcvd_time, 0, ack,
                     message, msize);
        inserted = 1;
      }
    }
    if ((! inserted) && (message != NULL))
      free (message);
    message = NULL;
    next = prev_message (&iter, &seq, &time, &tz_min, &rcvd_time,
                         ack, &message, &msize);
  }
  free_unallocated_iter (&iter);
}

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
  if ((contact == NULL) || (msgs == NULL) ||
      (num_alloc == NULL) || (num_used == NULL))
    return 0;
  *num_used = 0;
  keyset * k = NULL;
  int nk = all_keys (contact, &k);
  if (nk <= 0)  /* no such contact, or this contact has no keys */
    return 0;
  int ik;
  for (ik = 0; ik < nk; ik++) {
    add_all_messages (msgs, num_alloc, num_used, contact, k [ik]);
    ack_all_messages (*msgs, *num_used, contact, k [ik]);
    set_missing (*msgs, *num_used, k [ik]);
  }
  free (k);
#ifdef DEBUG_PRINT
  /* test code -- let's see if everything is set correctly */
  if (strcmp (contact, "edo-on-maru") == 0) {
    int i;
    for (i = 0; i < *num_used; i++) {
      struct message_store_info * msg = (*msgs) + i;
      printf ("%s [%d] is ", contact, i);
      printf ("%zd B @%p, ", msg->msize, msg->message);
      printf ("k %d, type %d, ", msg->keyset, msg->msg_type);
      printf ("seq %" PRIu64 "", msg->seq);
      if (msg->message_has_been_acked)
        printf (" (acked)");
      if (msg->prev_missing != 0)
        printf (" (%" PRIu64 " missing)", msg->prev_missing);
      printf ("\n     times %" PRIu64 " %d %" PRIu64 "\n",
              msg->time, msg->tz_min, msg->rcvd_time);
      print_buffer (msg->ack, MESSAGE_ID_SIZE, "     ack", 6, 1);
    }
  }
#endif /* DEBUG_PRINT */
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

static int64_t file_storage_size (const char * fname)
{
  struct stat st;
  int result = stat (fname, &st);
  if (result != 0) {
    perror ("file_size stat");
    printf ("store.c file_size unable to stat '%s'\n", fname);
    return -1;
  }
  size_t len = strlen (fname);
  if ((len > 3) && (strcmp ("/..", fname + (len - 3)) == 0))
    return 0;  /* do not count parent directory */
  return st.st_blocks * 512;
}

/* returns a system time that can be compared,
 * or 0 in case of non-files (e.g. directories) or errors */
static uint64_t file_mod_time (const char * fname, int print_errors)
{
  struct stat st;
  int result = stat (fname, &st);
  if (result != 0) {
    if (print_errors) {
      perror ("file_mod_time stat");
      printf ("store.c file_mod_time unable to stat '%s'\n", fname);
    }
    return 0;
  }
  if (! S_ISREG (st.st_mode)) {
printf ("store.c file_mod_time: '%s' is not a regular file\n", fname);
    return 0;
  }
  return st.st_mtime;
}

/* returns an estimate of the number of bytes used to save the
 * conversation information for this contact
 * returns -1 if the contact does not exist or for other errors */
int64_t conversation_size (const char * contact)
{
  keyset * k = NULL;
  int n = all_keys (contact, &k);
  if (n < 0)
    return -1;
  if (n == 0) {
    if (k != NULL)
      free (k);
    return 0;
  }
  int success = 0;
  int i;
  int64_t result = 0;
  for (i = 0; i < n; i++) {
    char * contacts_dir = key_dir (k [i]);
    if (contacts_dir == NULL) {
      printf ("no key_dir for contact %s, key [%d] %d\n", contact, i, k [i]);
      continue;              /* try the next key */
    }
    char * xchat_dir =
      string_replace_once (contacts_dir, "contacts", "xchat", 1);
    free (contacts_dir);
    DIR * dir = opendir (xchat_dir);
    if (dir == NULL) {
#ifdef DEBUG_PRINT
      perror ("conversation_size opendir");
      printf ("unable to open directory %s\n", xchat_dir);
#endif /* DEBUG_PRINT */
      free (xchat_dir);
      continue;              /* try the next key */
    }
    struct dirent * dep;
    while ((dep = readdir (dir)) != NULL) {
      char * path =
        strcat3_malloc (xchat_dir, "/", dep->d_name, "conversation_size");
      int64_t new_result = file_storage_size (path);
      free (path);
      if (new_result > 0)
        result += new_result;
      if (new_result >= 0)   /* found something, count it */
        success = 1;
    }
    closedir (dir);
    free (xchat_dir);
  }
  if (k != NULL)
    free (k);
  if (success)
    return result;
  return -1;
}

static char * oldest_nonempty_file (const char * contact)
{
  keyset * k = NULL;
  int n = all_keys (contact, &k);
  int i;
  char * oldest_fname = NULL;
  uint64_t oldest_time = 0;
  for (i = 0; i < n; i++) {
    char * xchat_dir = get_xchat_dir (k [i]);
    if (xchat_dir == NULL)
      continue;
    DIR * dir = opendir (xchat_dir);
    if (dir != NULL) {
      struct dirent * de;
      while ((de = readdir (dir)) != NULL)
      {
        char * fname = strcat3_malloc (xchat_dir, "/", de->d_name,
                                       "oldest_nonemtpy_file");
        
        uint64_t ftime = file_mod_time (fname, 1);
        if ((ftime != 0) && ((oldest_time == 0) || (oldest_time > ftime))) {
          oldest_time = ftime;
          if (oldest_fname != NULL)  /* malloc'd, must be free'd */
            free (oldest_fname);
          oldest_fname = fname;
        } else {
          free (fname);
        }
      }
    }
    free (xchat_dir);
  }
  return oldest_fname;
}

/* remove older files one by one until the remaining conversation size
 * is less than or equal to max_size
 * returns 1 for success, 0 for failure. */
int reduce_conversation (const char * contact, uint64_t max_size_u)
{
  int64_t max_size = (int64_t) max_size_u;
  if (contact == NULL)
    return 0;
  while (conversation_size (contact) > max_size) {
    char * fname = oldest_nonempty_file (contact);
    if (fname == NULL) {
    /* could be an error, but more likely, no files left and
       max_size > size of the empty dir */
      printf ("oldest_nonempty is NULL, %" PRId64 " remain\n",
              conversation_size (contact));
      return 1;      /* success of some kind or other */
    }
    if (unlink (fname) != 0) {
      perror ("unlink");
      printf ("unable to remove %s\n", fname);
      return 0;   /* if we continue, we are in an infinite loop */
    }
    free (fname);
  }
  return 1;  /* success */
}

/* returns 1 for success, 0 for failure. */
int delete_conversation (const char * contact)
{
  if (contact == NULL)
    return 0;
  keyset * k = NULL;
  int n = all_keys (contact, &k);
  if (n <= 0)
    return 0;
  int i;
  for (i = 0; i < n; i++) {
    char * xchat_dir = get_xchat_dir (k [i]);
    rmdir_and_all_files (xchat_dir);
    free (xchat_dir);
  }
  return 1;
}

/* returns 1 for success, 0 for failure. */
int clear_conversation (const char * contact)
{
  if (contact == NULL)
    return 0;
  keyset * k = NULL;
  int n = all_keys (contact, &k);
  if (n <= 0)
    return 0;
  int i;
  for (i = 0; i < n; i++) {
    char * xchat_dir = get_xchat_dir (k [i]);
    rmdir_matching (xchat_dir, ".txt");
    free (xchat_dir);
  }
  return 1;
}

/* return -1 if the file does not exist, the size otherwise.
 * if content is not NULL, malloc's enough space to hold the
 * content (with null termination), and returns it */
int xchat_file_get (const char * contact, keyset k,
                    const char * fname, char ** content)
{
  char * path = get_xchat_path (k, fname);  /* must be free'd */
  if (path == NULL)
    return -1;
  char * local_content = NULL;                   /* must be free'd */
  int csize = read_file_malloc (path, &local_content, 0);
  free (path);
  if ((csize <= 0) || (local_content == NULL))
    return 0;
  if (content != NULL) {
    *content = local_content;
  } else {
    free (local_content);
  }
  return csize;
}

/* write the content to the file, returning 0 in case of error, 1 otherwise */
int xchat_file_write (const char * contact, keyset k,
                      const char * fname, char * content, int clength)
{
  char * path = get_xchat_path (k, fname);  /* must be free'd */
  if (path == NULL)
    return 0;
  write_file (path, content, clength, 0);
  free (path);
  return 1;
}

/* useful to find out when the file was last written
 * time returned is allnet microseconds (see lib/util.h), or 0 for errors */
/* because nano/microsecond resolution is not supported on older systems,
 * for simplicity just return the seconds multiplied by 1,000,000 */
long long int xchat_file_time (const char * contact, keyset k,
                               const char * fname, int print_errors)
{
  char * path = get_xchat_path (k, fname);  /* must be free'd */
  if (path == NULL)
    return 0;
  uint64_t file_time = file_mod_time (path, print_errors);
  free (path);
  if (file_time > ALLNET_Y2K_SECONDS_IN_UNIX)
    return (file_time - ALLNET_Y2K_SECONDS_IN_UNIX) * 1000LL * 1000LL;
  return 0;
}

/* return 1 if the file was deleted, 0 otherwise */
int xchat_file_delete (const char * contact, keyset k,
                       const char * fname)
{
  char * path = get_xchat_path (k, fname);  /* must be free'd */
  if (path == NULL)
    return 0;
  int result = (unlink (path) == 0);
  free (path);
  return result;
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
