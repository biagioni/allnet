/* store.c: provide non-volatile storage of chat names, messages, and keys */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

#include "util.h"
#include "config.h"
#include "priority.h"
#include "cutil.h"
#include "store.h"

/* return the length of a public key, based on the key type stored in the
 * first byte of the key.  The length includes the first byte */
int public_key_length (char * pubkey)
{
  if (*pubkey == KEY_RSA4096_E65537)
    return (4096 / 8) + 1;
  printf ("public_key_length: unknown key type %d\n", (*pubkey) & 0xff);
  return 0;
}

struct missing_info {
  long long int first;   /* first sequence number known to be missing */
  long long int last;    /* last  sequence number -- may be same */
};

struct unacked_info {
  long long int seq;   /* sequence number not yet acked */
  long long int time;  /* sent at time -- we do not retransmit earlier
                          versions of the same sequence number) */
  unsigned char packet_id [PACKET_ID_SIZE];
};

#define SEQ_STORAGE	100
struct contact_info {
  char * name;
  char * contact_key;      /* my contact's public key */
  int contact_ksize;
  char * my_key;           /* my private and public key */
  int my_ksize;
  unsigned long long int num_messages;
  char * dirname;
  long long int last_received;
  struct missing_info missing [SEQ_STORAGE];
  int nmissing;                            /* # missing, <= SEQ_STORAGE */
  struct unacked_info unacked [SEQ_STORAGE];
  int nunack;                              /* # unacked, <= SEQ_STORAGE */
};

#define COUNTER_NAME_LEN	20	/* 2^64, 18,446,744,073,709,551,616 */
#define COUNTERS_PER_FILE	1	/* 10^4 */
#define COUNTER_FNAME_DIGITS	(COUNTER_NAME_LEN)    /* 20 */
#define DATE_TIME_LEN 		14	/* strlen("20130101120102") */
#define DATE_LEN 		8	/* strlen("20130327") */

#define MAX_CONTACTS	1000
static int actual_contacts = 0;
static struct contact_info contacts [MAX_CONTACTS];

/* like strcasestr, but keeps going past null characters in the haystack,
 * untile it reaches the end.  Needle must be a string (but easy to change
 * if needed -- just add nsize as a parameter)
 */
static char * strncasestr (char * haystack, int hsize, char * needle)
{
  int nsize = strlen (needle);
  while (hsize >= nsize) {
    int i;
    for (i = 0; i < nsize; i++)
      if (tolower (haystack [i]) != tolower (needle [i]))
        break;
    if (i == nsize)       /* complete match */
      return haystack;
    haystack++;
    hsize--;
  }
  return NULL;
}

/* if it is the kind of name we want, it should end in a string of n digits */
static int start_ndigits (char * path, int ndigits)
{
  char * slash = rindex (path, '/');
  char * name = path;
  if (slash != NULL)
    name = slash + 1;
  if (strlen (name) < ndigits) {
/* printf ("start_ndigits (%s, %d) => 0 (length %zd is less than %d)\n",
            path, ndigits, strlen (name), ndigits); */
    return 0;
  }
  int i;
  for (i = 0; i < ndigits; i++) {
    if ((name [i] < '0') || (name [i] > '9')) {
/*    printf ("start_ndigits (%s, %d) => 0 ([%d] is %c)\n", path, ndigits,
              i, name [i]); */
      return 0;
    }
  }
/* printf ("start_ndigits (%s, %d) => 1\n", path, ndigits); */
  return 1;
}

static int read_file_contents (char * dirname, char * fname, int delete_eol,
                               char ** result)
{
  *result = NULL;
  int length = strlen (dirname) + 1 + strlen (fname) + 1;
  char * path = malloc_or_fail (length, "read_file_contents");
  snprintf (path, length, "%s/%s", dirname, fname);
  struct stat st;
  if (stat (path, &st) != 0) {
    perror ("stat/read_file_contents");
    printf ("unable to stat file %s\n", fname);
    return 0;
  }
  if ((st.st_mode & S_IFMT) != S_IFREG) {
    /* printf ("%s is not a regular file, ignoring\n", fname); */
    return 0;
  }
#ifdef DEBUG_PRINT
  printf ("reading %s (size %zd)\n", path, st.st_size);
#endif /* DEBUG_PRINT */
  int fd = open (path, O_RDONLY);
  free (path);
  if (fd < 0) {
    perror ("read_file_contents/open");
    printf ("unable to read file %s\n", fname);
    return 0;
  }
  char * buffer = malloc_or_fail (st.st_size + 1,  /* + 1 for '\0' at end */
                                  "read_file_contents contents");
  int r = read (fd, buffer, st.st_size);
  if (r != st.st_size) {
    perror ("read_file_contents/read");
    printf ("unable to read %d bytes from file %s, only read %d\n",
            (int) (st.st_size), path, r);
    close (fd);
    free (buffer);
    return 0;
  }
  close (fd);
  buffer [r] = '\0';   /* usually text, so null terminate */
  if (delete_eol && (buffer [r - 1] == '\n'))
    buffer [r - 1] = '\0';
  *result = buffer;
  return r;
}

static int ascii_hex (char * data, int * error)
{
  if (*error)
    return 0;
  int c = *data;
  if ((c >= '0') && (c <= '9'))
    return (c - '0');
  if ((c >= 'A') && (c <= 'F'))
    return (10 + c - 'A');
  if ((c >= 'a') && (c <= 'f'))
    return (10 + c - 'a');
  *error = 1;
  printf ("character '%c' is not hex!\n", c);
  return 0;
}

/* data is in hex, packet_id in binary */
/* returns 1 for match, 0 for not match */
static int matching_packet_id (char * data, int dsize, char * packet_id)
{
  if (dsize < PACKET_ID_SIZE * 2 /* 32 */ )
    return 0;
  int i;
  for (i = 0; i < PACKET_ID_SIZE; i++) {
    int failed = 0;
    int new_byte = ascii_hex (data + 2 * i, &failed) * 16 +
                   ascii_hex (data + 2 * i + 1, &failed);
    if ((failed) || (new_byte & 0xff) != (packet_id [i] & 0xff))
      return 0;  /* not matching */
  }
  return 1;      /* everything matches */
}

/* data is in hex, packet_id in binary */
static void read_packet_id (char * data, int dsize, char * packet_id)
{
  if (dsize < PACKET_ID_SIZE * 2 /* 32 */ ) {
    printf ("read_packet_id called with dsize %d, min is %d\n",
            dsize, PACKET_ID_SIZE * 2);
    exit (1);
  }
  int i;
  for (i = 0; i < PACKET_ID_SIZE; i++) {
    int failed = 0;
    int new_byte = ascii_hex (data + 2 * i, &failed) * 16 +
                   ascii_hex (data + 2 * i + 1, &failed);
    if (failed) {
      char copy [PACKET_ID_SIZE * 2 + 1];
      memcpy (copy, data, PACKET_ID_SIZE * 2);
      copy [PACKET_ID_SIZE * 2] = '\0';
      printf ("unable to read packet id from %s, chars %d or %d\n", copy,
              2 * i, 2 * i + 1);
    }
    packet_id [i] = new_byte;
  }
}

/* remove the record at the position from */
static void remove_ack (struct unacked_info * unacked, int * nunack, int from)
{
  int i;
  for (i = from; i + 1 < *nunack; i++)
    unacked [i] = unacked [i + 1];
  *nunack = *nunack - 1;
}

/* find and return a time value of the form (seconds, +- minutes offset) */
static long long int parse_time_in_parens (char * data, int dsize)
{
  int i;
  for (i = 0; i + 1 < dsize; i++) {
    if (data [i] == '(') {
      char * start = data + i + 1;
      char * finish;
      long long int time = strtoll (start, &finish, 10);
      if (start == finish) {
        char copy [100];
        snprintf (copy, sizeof (copy), "%s", start);
        printf ("some error parsing time in %s\n", copy);
        return -1;
      }
      start = finish;
      long long int offset = strtol (start, &finish, 10);
      if (start == finish) {
        char copy [100];
        snprintf (copy, sizeof (copy), "%s", data + i + 1);
        printf ("some error parsing timezone offset in %s\n", copy);
        return -1;
      }
      return ((time << 16) | (offset & 0xffff));
    }
  }
  return -1;
}

/* unacked is an array of SEQ_STORAGE unacked_info structs.  nunack is
 * the number of those structs that are currently filled. */
/* nunack is updated as entries are removed (because acks are found) or
 * added (because you new sent entries are found) */
/* if the array overflows, the earliest entry is deleted */
static void last_unacked (char * data, int dsize,
                          struct unacked_info * unacked, int * nunack)
{
  int i;
  for (i = 0; i < dsize; i++) {
    /* only check at the beginning of a line */
    if ((i == 0) || (data [i - 1] == '\n')) {
#ifdef DEBUG_PRINT
      static char copy [61];
      memcpy (copy, data + i, 60);
      copy [60] = '\0';
      printf ("last_unacked: %s\n", copy);
#endif /* DEBUG_PRINT */

#define ACK_STR		"got ack: "
#define ACK_LEN		strlen (ACK_STR)
#define SENT_ID_STR		"sent id: "
#define SENT_ID_LEN		strlen (SENT_ID_STR)
#define SENT_SEQ_STR		"sent sequence "
#define SENT_SEQ_LEN		strlen (SENT_SEQ_STR)
      if (strncmp (data + i, ACK_STR, ACK_LEN) == 0) {  /* found an ack */
        int j;
        for (j = 0; j < *nunack; j++) {   /* compare it to the unacked seqs */
          if (matching_packet_id (data + i + ACK_LEN, dsize - i - ACK_LEN,
                                  unacked [j].packet_id)) {
#ifdef DEBUG_PRINT
            printf ("last_unacked matched ");
            print_buffer (unacked [j].packet_id, PACKET_ID_SIZE, "packet ID",
                          PACKET_ID_SIZE, 0);
#endif /* DEBUG_PRINT */
            remove_ack (unacked, nunack, j);
#ifdef DEBUG_PRINT
            printf (", nunack now %d\n", *nunack);
#endif /* DEBUG_PRINT */
          }
        }
      } else if (strncmp (data + i, SENT_ID_STR, SENT_ID_LEN) == 0) {
        if (*nunack >= SEQ_STORAGE)   /* make room for the new record*/
          remove_ack (unacked, nunack, 0);
        /* now we have room for this record */
        unacked [*nunack].seq = 0;   /* sequence and time not yet known */
        unacked [*nunack].time = 0;
        read_packet_id (data + i + SENT_ID_LEN, dsize - i - SENT_ID_LEN,
                        unacked [*nunack].packet_id);
#ifdef DEBUG_PRINT
        printf ("last_unacked found ");
        print_buffer (unacked [*nunack].packet_id, PACKET_ID_SIZE,
                      "sent packet ID", PACKET_ID_SIZE, 1);
#endif /* DEBUG_PRINT */
      } else if (strncmp (data + i, SENT_SEQ_STR, SENT_SEQ_LEN) == 0) {
        if ((*nunack < SEQ_STORAGE) && (unacked [*nunack].seq == 0)) {
          /* fill in the sequence number and time for this hash */
          char * start = data + i + SENT_SEQ_LEN;
          char * finish;
          long long int seq = strtoll (start, &finish, 10);
          long long int time =
            parse_time_in_parens (finish, dsize - (finish - data));
          if ((finish != start) && (time != -1)) {
            unacked [*nunack].seq = seq;
            unacked [*nunack].time = time;
            *nunack = *nunack + 1;
#ifdef DEBUG_PRINT
            printf ("last_unacked found seq %lld time %lld, nunack now %d\n",
                    seq, time, *nunack);
#endif /* DEBUG_PRINT */
          } else {
            static char copy [1000];
            int debug_count = (dsize - (start - data));
            if (debug_count >= sizeof (copy))
              debug_count = sizeof (copy) - 1;
            memcpy (copy, start, debug_count);
            copy [debug_count] = '\0';
            if (start == finish)
              printf ("unable to read sequence number from %s\n", copy);
            if (time == -1)
              printf ("unable to read time from %s\n", copy);
          }
        } else
          printf ("last_unacked: bad nunack %d (max %d) or known seq %lld\n",
                  *nunack, SEQ_STORAGE,
                  ((*nunack < SEQ_STORAGE) ? (unacked [*nunack].seq) : 0));
      }
    }
  }
}

static void remove_missing (struct missing_info * missing, int * nmissing,
                            unsigned long long int seq)
{
  int i, j;
  for (i = 0; i < *nmissing; i++) {
    if ((seq == missing [i].first) && (seq == missing [i].last)) { /* remove */
      for (j = i; j + 1 < *nmissing; j++)
        missing [j] = missing [j + 1];
      *nmissing = *nmissing - 1;
    } else if (seq == missing [i].first) { /* shrink up */
      missing [i].first = seq + 1; 
    } else if (seq == missing [i].last) { /* shrink down */
      missing [i].last = seq - 1; 
    } else if ((seq > missing [i].first) && (seq < missing [i].last)) {
        /* split*/
      int do_split = 1;
      int new_low = i;
      int first = missing [i].first;
      int last = missing [i].last;
      if (*nmissing >= SEQ_STORAGE) {  /* make room */
        if (i == 0) {     /* just get rid of the first interval */
          missing [i].first = seq + 1;
          do_split = 0;
        } else {
          for (j = 0; j + 1 < i; j++)
            missing [j] = missing [j + 1];
          new_low = i - 1;
        }
      } else {    /* copy everything, including i, up by one */
        for (j = *nmissing; j > i; j--)
          missing [j] = missing [j - 1];
        *nmissing = *nmissing + 1;
      }
      if (do_split) {  /* add new at i */
        missing [new_low].first = first;
        missing [new_low].last = seq - 1;
        missing [new_low + 1].first = seq + 1;
        missing [new_low + 1].last = last;
      }
    }   /* else ignore, no overlap */
  }
}

static void add_missing (struct missing_info * missing, int * nmissing,
                         unsigned long long int from,
                         unsigned long long int to)
{
  if (from > to) {
    printf ("error: add_missing (%lld, %lld)\n", from, to);
    return;
  }
  if (*nmissing >= SEQ_STORAGE) {
    printf ("add_missing out of space, deleting %lld to %lld\n",
            missing [0].first, missing [0].last);
    *nmissing = *nmissing - 1;
    int i;
    for (i = 0; i < *nmissing; i++)
      missing [i] = missing [i + 1];
  }
  missing [*nmissing].first = from;
  missing [*nmissing].last = to;
  *nmissing = *nmissing + 1;
}

/* missing is an array of SEQ_STORAGE long long ints.  nmissing is
 * the number of those structs that are currently filled. */
/* nmissing is updated as entries are removed (because seqs are found) or
 * added (because a new, later entry is found) */
/* if the array overflows, the earliest entry is deleted */
static void last_missing (char * data, int dsize,
                          struct missing_info * missing, int * nmissing,
                          unsigned long long int * latest)
{
  int i;
  for (i = 0; i < dsize; i++) {
    /* only check at the beginning of a line */
    if ((i == 0) || (data [i - 1] == '\n')) {
#define RCVD_SEQ_STR		"rcvd sequence "
#define RCVD_SEQ_LEN		strlen (RCVD_SEQ_STR)
      if (strncmp (data + i, RCVD_SEQ_STR, RCVD_SEQ_LEN) == 0) {
        char * start = data + i + RCVD_SEQ_LEN;
        char * finish;
        long long int seq = strtoll (start, &finish, 10);
        if (finish != start) {    /* valid seq number */
          if (seq < *latest)       /* received packet, remove from missing */
            remove_missing (missing, nmissing, seq);
          if (seq > *latest + 1)   /* all the intermediate ones are missing */
            add_missing (missing, nmissing, *latest + 1, seq - 1);
          if (seq > *latest)
            *latest = seq;
#ifdef DEBUG_PRINT
          printf ("last_missing found seq %lld, latest now %lld\n",
                  seq, *latest);
          int i;
          for (i = 0; i < *nmissing; i++)
            printf ("[%d]: %lld to %lld\n", i, missing [i].first,
                    missing [i].last);
#endif /* DEBUG_PRINT */
        }
      }
    }
  }
}


/* returns the largest sequence matching sr, which should be "sent" or "rcvd"
 */
static long long int largest_sequence (char * sr, char * data, int size)
{
  long long int result = 0;
  char * search = data;
  if ((size > 0) && (data != NULL)) {
    char * found;
    while ((found = strstr (search, sr)) != NULL) {
      /* printf ("largest_sequence found %s\n", sr); */
      search = found + strlen (sr);
      const char * seq = " sequence ";
      if (strncmp (search, seq, strlen (seq)) == 0) {
        /* printf ("largest_sequence then found %s\n", seq); */
        search += strlen (seq);
        char * next_search;
        long long int new = strtoll (search, &next_search, 10);
        if ((next_search != search) && (new > result)) {
          result = new;
          search = next_search;
        } /* else no sequence number found */
      } /* else string "sequence" not found */
    }
  }
  return result;
}

static int get_msg_info (char * dirname, char * fname,
                         unsigned long long int * max_sent,
                         unsigned long long int * max_received,
                         struct missing_info * missing, int * nmissing,
                         struct unacked_info * unacked, int * nunack)
{
  char * data = NULL;
  int size = read_file_contents (dirname, fname, 1, &data);
  int new_sent = largest_sequence ("sent", data, size);
  if (new_sent > *max_sent)
    *max_sent = new_sent;
  last_missing (data, size, missing, nmissing, max_received);
  last_unacked (data, size, unacked, nunack);
  if (data != NULL)
    free (data);
  return 1;
}

static void init_contact (char * dirname)
{
#ifdef DEBUG_PRINT
  printf ("init_contact called for %s\n", dirname);
#endif /* DEBUG_PRINT */
  if (actual_contacts >= MAX_CONTACTS) {
    printf ("too many contacts!  Only %d supported\n", MAX_CONTACTS);
    return;
  }
  DIR * dir = opendir (dirname);
  if (dir == NULL) {  /* eventually probably don't need to print */
    perror ("opendir/2");
    printf ("unable to open directory %s\n", dirname);
    return;
  }
  struct dirent * dep;
  unsigned long long int max_sequence = 0;
  unsigned long long int max_received = 0;
  char * name = NULL;
  int name_size = 0;
  char * contact_key = NULL;      /* my contact's public key */
  int contact_ksize = 0;
  char * my_key = NULL;           /* my private and public key */
  int my_ksize = 0;
/* printf ("init_contact, going through %s\n", dirname); */
  struct missing_info missing [SEQ_STORAGE];
  int nmissing = 0;
  struct unacked_info unacked [SEQ_STORAGE];
  int nunack = 0;
  while ((dep = readdir (dir)) != NULL) {
    if (start_ndigits (dep->d_name, DATE_LEN)) /* message file */
      get_msg_info (dirname, dep->d_name, &max_sequence, &max_received,
                    missing, &nmissing, unacked, &nunack);
    else if (strcmp (dep->d_name, "name") == 0)
      name_size     = read_file_contents (dirname, dep->d_name, 1, &name);
    else if (strcmp (dep->d_name, "contact_public_key") == 0)
      contact_ksize = read_file_contents (dirname, dep->d_name, 0,
                                          &contact_key);
    else if (strcmp (dep->d_name, "my_key") == 0)
      my_ksize      = read_file_contents (dirname, dep->d_name, 0, &my_key);
    /* printf ("file %s, c %lld, max %lld\n", dep->d_name, c, max_sequence); */
  }
  if ((name != NULL) && (name_size > 0) &&
      (contact_key != NULL) && (contact_ksize > 0) &&
      (my_key      != NULL) && (my_ksize      > 0)) {  /* success! */
    struct contact_info * cip = contacts + actual_contacts;
    cip->name = name;
    cip->contact_key = contact_key;
    cip->contact_ksize = contact_ksize;
    cip->my_key = my_key;
    cip->my_ksize = my_ksize;
    cip->num_messages = max_sequence;
    cip->dirname = strcpy_malloc (dirname, "init_contact dirname");
    cip->last_received = max_received;
    cip->nmissing = nmissing;
    memcpy (cip->missing, missing, sizeof (missing));
    cip->nunack = nunack;
    memcpy (cip->unacked, unacked, sizeof (unacked));
#ifdef DEBUG_PRINT
    printf ("[%d], '%s', '%s', %lld\n", actual_contacts, cip->dirname, name,
            max_sequence);
    printf ("added contact [%d], name '%s'\n", actual_contacts, name);
#endif /* DEBUG_PRINT */
#ifdef DEBUG_PRINT
    printf ("contact %s has %d missing\n", cip->name, cip->nmissing);
    int dbg;
    for (dbg = 0; dbg < cip->nmissing; dbg++)
    printf ("missing %d is %lld to %lld\n", dbg,
            cip->missing [dbg].first, cip->missing [dbg].last);
    printf ("contact %s has %d unacked\n", cip->name, cip->nunack);
    for (dbg = 0; dbg < cip->nunack; dbg++)
    printf ("unacked %d is %lld at time %lld\n", dbg,
            cip->unacked [dbg].seq, cip->unacked [dbg].time);
#endif /* DEBUG_PRINT */
    actual_contacts++;
  } else {
    if (name != NULL)
      free (name);
    if (contact_key != NULL)
      free (contact_key);
    if (my_key != NULL)
      free (my_key);
  }
}

static void init_contacts ()
{
  static int initialized = 0;
  if (initialized)
    return;
  int i;
  for (i = 0; i < MAX_CONTACTS; i++) {
    contacts [i].name = NULL;
    contacts [i].contact_key = NULL;
    contacts [i].contact_ksize = 0;
    contacts [i].my_key = NULL;
    contacts [i].my_ksize = 0;
    contacts [i].num_messages = 0;
  }
  initialized = 1;
  char * dirname;
  int dirnamesize = config_file_name ("xchat", "contacts", &dirname);
#ifdef DEBUG_PRINT
  printf ("directory name is %s (%d)\n", dirname, dirnamesize);
#endif /* DEBUG_PRINT */
  if (! create_dir (dirname)) {
    printf ("directory %s does not exist, and unable to create it\n", dirname);
    free (dirname);
    return;
  }
  DIR * dir = opendir (dirname);
  if (dir == NULL) {
    perror ("opendir");
    printf ("unable to open directory %s\n", dirname);
  }
  struct dirent * dep;
  while ((dep = readdir (dir)) != NULL) {
    int length = strlen (dirname) + 1 + strlen (dep->d_name) + 1;
    char * contact_dirname = malloc_or_fail (length, "init_contacts");
    snprintf (contact_dirname, length, "%s/%s", dirname, dep->d_name);
/*  printf ("looking at file %s (%s)\n", dep->d_name, contact_dirname); */
    if (start_ndigits (contact_dirname, DATE_TIME_LEN))
      init_contact (contact_dirname);
    free (contact_dirname);
  }
  free (dirname);
  closedir (dir);
}

/* allocates and returns an array of pointers to null-terminated
 * contact names.  Call free_contacts to release. */
int all_contacts (char *** res)
{
  init_contacts ();
/*  printf ("in all_contacts, actual_contacts is %d\n", actual_contacts); */
  *res = NULL;
  if (actual_contacts <= 0)
    return 0;
  /* first part of result is the array of pointers */
  int pointers_bytes = actual_contacts * sizeof (char *);
  int size = pointers_bytes;
  int i;
  /* rest of result is storage area for the strings */
  for (i = 0; i < actual_contacts; i++)
    size += strlen (contacts [i].name) + 1;
  char * * result = malloc_or_fail (size, "all_contacts");
  /* point to the first byte not in the array of pointers */
  char * p = ((char *)result) + (actual_contacts * sizeof (char *));
  for (i = 0; i < actual_contacts; i++) {
    strcpy (p, contacts [i].name);
    result [i] = p;
    p += strlen (contacts [i].name) + 1;
  }
  if (res != NULL)
    *res = result;
  return actual_contacts;
}

void free_contacts (char ** contacts)
{
  init_contacts ();
  free (contacts);
}

static char * new_contact_fname ()
{
  char * dirname;
  int dirnamesize = config_file_name ("xchat", "contacts", &dirname);
/* printf ("directory name for new_contact_fname is %s (%d)\n",
          dirname, dirnamesize); */
  int length = dirnamesize + 1 + strlen ("20130215093612") + 1;
  char * path = malloc_or_fail (length, "new_contact_fname");
  struct tm t;
  time_t now = time (NULL);
  if (localtime_r (&now, &t) == NULL) {
    printf ("unable to get local time\n");
    free (dirname);
    exit (1);
  }
  snprintf (path, length, "%s/%04d%02d%02d%02d%02d%02d", dirname,
            t.tm_year + 1900, t.tm_mon + 1, t.tm_mday,
            t.tm_hour, t.tm_min, t.tm_sec);
  free (dirname);
  DIR * dir = opendir (path);
  if (dir != NULL) {
    closedir (dir);
    printf ("new contact directory %s already exists!\n", path);
    exit (1);
    free (path);
    return NULL;
  }
  return path;
}

static int save_contact_info (char * dirname, char * fname,
                              char * data, int dsize)
{
  if (! create_dir (dirname)) {
    printf ("directory %s does not exist, and unable to create it\n", dirname);
    return 0;
  }
  int length = strlen (dirname) + 1 + strlen (fname) + 1;
  char * path = malloc_or_fail (length, "save_contact_info");
  snprintf (path, length, "%s/%s", dirname, fname);
  /* printf ("saving to contact file %s (%s)\n", fname, path); */
  int fd = open (path, O_WRONLY | O_CREAT, 0600);
  free (path);
  if (fd < 0) {
    perror ("save_contact_info/open");
    printf ("unable to open/create file %s\n", fname);
    return 0;
  }
  int w = write (fd, data, dsize);
  if (w != dsize) {
    perror ("save_contact_info/write");
    printf ("unable to write %d bytes to file %s, only wrote %d\n",
            dsize, path, w);
    close (fd);
    return 0;
  }
  close (fd);
  return w;
}

static int find_contact_again (const char * contact, int start_index)
{
  if (contact == NULL)
    return -1;
  int i;
  for (i = start_index; i < actual_contacts; i++) {
/*    printf ("comparing '%s' to '%s'\n", contact, contacts [i].name); */
    if (strcmp (contact, contacts [i].name) == 0)
      return i;
  }
  return -1;
}

static int find_contact (const char * contact)
{
  return find_contact_again (contact, 0);
}

static int find_single_contact (const char * contact)
{
  if (contact == NULL)
    return -1;
  int index = find_contact (contact);
  if (index < 0) {
    printf ("contact %s not found\n", contact);
    return -1;
  }
  if (find_contact_again (contact, index + 1) >= 0) {
    printf ("contact %s found more than once\n", contact);
    return -2;
  }
  return index;
}

static void callback (int type, int count, void * arg)
{
  if (type == 0)
    printf (".");
  else if (type == 1)
    printf (",");
  else if (type == 2)
    printf ("!");
  else if (type == 3)
    printf (":");
  else
    printf ("?");
  fflush (stdout);
}

static int externalize_public_key (char * pem, int len, char ** res)
{
  BIO * mbio = BIO_new_mem_buf (pem, len);
  RSA * rsa = PEM_read_bio_RSAPublicKey (mbio, NULL, NULL, NULL);
  BIO_free (mbio);

  int bn_size = BN_num_bytes (rsa->n);
  if (res != NULL) {
    *res = malloc_or_fail (bn_size + 1, "externalize_public_key");
    BN_bn2bin (rsa->n, (*res) + 1);
    **res = KEY_RSA4096_E65537;  /* only kind supported so far */
    /* print_buffer (*res, bn_size + 1, "externalize", 16, 1); */
  }
  RSA_free (rsa);
  return bn_size + 1;
}

/* automatically generates a public/private key pair */
/* if successful returns the public key size and sets *pubkey to point to
 * a static buffer containing the key (do not free or modify the key). */
/* returns 0 in case of error */
/* the keys are stored in memory, and only saved to disk by calling
 * save_contact_pubkey */
int new_contact (char * contact, char ** pubkey)
{
  init_contacts ();
  if (actual_contacts >= MAX_CONTACTS) {
    printf ("too many contacts %d (max %d)\n", actual_contacts, MAX_CONTACTS);
    return 0;
  }
  int index = find_contact (contact);
  if (index >= 0) {
    printf ("contact '%s' is already known\n", contact);
    return 0;
  }
  /* create the keys */
  int bits = 4096;
  printf ("generating %d-bit private key", bits);
  RSA * key = RSA_generate_key (bits, RSA_E65537_VALUE, callback, NULL);
  printf ("\n");

  struct contact_info * new_info = contacts + actual_contacts;
  new_info->name = strcpy_malloc (contact, "new_contact name");
  new_info->contact_key = NULL;  /* not known yet */
  new_info->contact_ksize = 0;   /* not known yet */
  new_info->num_messages = 0;
  new_info->dirname = new_contact_fname ();

  BIO * mbio = BIO_new (BIO_s_mem ());
  PEM_write_bio_RSAPrivateKey (mbio, key, NULL, NULL, 0, NULL, NULL);
  printf ("private key takes %zd bytes\n", BIO_ctrl_pending (mbio));
  PEM_write_bio_RSAPublicKey (mbio, key);
  char * keystore;
  long ksize = BIO_get_mem_data (mbio, &keystore);
  new_info->my_ksize = ksize;
  new_info->my_key = memcpy_malloc (keystore, ksize, "new_contact key");
  BIO_free (mbio);
  printf ("private + public key take %ld bytes\n", ksize);

  RSA_free (key);  /* saved in new_info->my_key, so no longer needed here */

  actual_contacts++;

  return externalize_public_key (new_info->my_key, new_info->my_ksize, pubkey);
}

/* called after receiving the public key of the contact.  If the contact
 * is unknown (i.e. new_contact was not called before), generates our
 * own public/private key pair.
 * Either way, fills in *key with our public key and returns its size.
 * saves all the contact information to disk.
 * returns 0 in case of error */
unsigned int save_contact_pubkey (char * contact, char * contact_pubkey,
                                  int contact_pubkey_size, char ** my_key)
{
/* print_buffer (contact_pubkey, contact_pubkey_size, "save_pubkey", 16, 1); */
  init_contacts ();
  int index = find_contact (contact);
  /* if index == -1, it is a new contact, generate the keys */
  if (index == -1) {
    if (new_contact (contact, NULL) <= 0)
      return 0;
    index = find_single_contact (contact);  /* should be there this time */
  }
  if (index < 0) {
    printf ("unable to generate key for contact %s\n", contact);
    return 0;
  }
  if (*contact_pubkey != KEY_RSA4096_E65537) {
    printf ("save_contact_pubkey: unknown public key type %d, ignoring\n",
            (*contact_pubkey) & 0xff);
    return 0;
  }
  struct contact_info * info = contacts + index;
  if ((info->contact_key != NULL) ||
      (info->contact_ksize != 0)) {
    printf ("save_contact_pubkey called, but contact pubkey already exists!\n");
    return 0;
  }

  RSA * contact_pubkey_rsa = RSA_new ();
  contact_pubkey_rsa->n =
     BN_bin2bn (contact_pubkey + 1, contact_pubkey_size - 1, NULL);
  contact_pubkey_rsa->e = NULL;
  BN_dec2bn (&(contact_pubkey_rsa->e), RSA_E65537_STRING);

  BIO * mbio = BIO_new (BIO_s_mem ());
  PEM_write_bio_RSAPublicKey (mbio, contact_pubkey_rsa);
  char * keystore;
  long ksize = BIO_get_mem_data (mbio, &keystore);
  info->contact_ksize = ksize;
  info->contact_key = memcpy_malloc (keystore, ksize, "save_contact_pubkey");
  BIO_free (mbio);
  RSA_free (contact_pubkey_rsa);
  /* printf ("public key takes %ld bytes\n", ksize); */

  /* info->fname, info->name, my_key, my_keysize, etc have been set
   * by a previous call to new_contact, perhaps above in this same
   * function, but perhaps a a separate call. */
  save_contact_info (info->dirname, "name", info->name, strlen (info->name));
  save_contact_info (info->dirname, "contact_public_key",
                     info->contact_key, info->contact_ksize);
  save_contact_info (info->dirname, "my_key", info->my_key, info->my_ksize);

  return externalize_public_key (info->my_key, info->my_ksize, my_key);
}

/* returns 0 if the contact cannot be found or matches more than one contact */
unsigned long long int get_counter (const char * contact)
{
  init_contacts ();
  int index = find_single_contact (contact);
  if (index < 0)
    return 0;
#ifdef DEBUG_PRINT
  printf ("get_counter: index is %d, num is %lld for contact %s\n",
          index, contacts [index].num_messages, contact);
#endif /* DEBUG_PRINT */
  return contacts [index].num_messages + 1;
}

/* returns 0 if the contact cannot be found or matches more than one contact
 * or none received yet */
unsigned long long int get_last_received (char * contact)
{
  init_contacts ();
  int index = find_single_contact (contact);
  if (index < 0)
    return 0;
#ifdef DEBUG_PRINT
  printf ("get_counter: index is %d, num is %lld for contact %s\n",
          index, contacts [index].num_messages, contact);
#endif /* DEBUG_PRINT */
  return contacts [index].last_received;
}

/* return the key length if successful, and set key to point to the
 * internal storage of the key (should not be free'd) */
/* return 0 if the contact cannot be found or matches more than one contact */
unsigned int get_contact_pubkey (char * contact, char ** key)
{
  init_contacts ();
  int index = find_single_contact (contact);
  if (index < 0)
    return 0;
  return externalize_public_key (contacts [index].contact_key,
                                 contacts [index].contact_ksize, key);
}

unsigned int get_my_pubkey (char * contact, char ** key)
{
  init_contacts ();
  int index = find_single_contact (contact);
  if (index < 0)
    return 0;
  return externalize_public_key (contacts [index].my_key,
                                 contacts [index].my_ksize, key);
}

unsigned int get_my_privkey (char * contact, char ** key)
{
  init_contacts ();
  int index = find_single_contact (contact);
  if (index < 0)
    return 0;
  *key = memcpy_malloc (contacts [index].my_key,
                        contacts [index].my_ksize, "get_my_privkey");
  return contacts [index].my_ksize;
}

static char * copy_with_indent (char * text, int tsize, char * indent)
{
  int newlines = 1;
  int i;
  for (i = 0; i < tsize; i++)
    if (text [i] == '\n')
      newlines++;
  int extra_space = 1 + newlines * strlen (indent);
  int total = tsize + extra_space;
  char * result = malloc_or_fail (total, "copy_with_indent");
  char * to = result;
  strcpy (to, indent);   /* indent at the beginning, too */
  to += strlen (indent);
  for (i = 0; i < tsize; i++) {
    *to = text [i];
    to++;
    if (text [i] == '\n') {
      strcpy (to, indent);
      to += strlen (indent);
    }
  }
  *to = '\0';
  return result;
}

static char * packet_ids_to_string (char * packet_id, char * p1, char * p2)
{
  char hashed [PACKET_ID_SIZE];
  sha512_bytes (packet_id, PACKET_ID_SIZE, hashed, PACKET_ID_SIZE);
  int i;
  /* size has n1+n2+3 for p1+p2, 64 for 32B in hex, 1 each for ' ' '\n' '\0' */
  int size = strlen (p1) + strlen (p2) + 3 + PACKET_ID_SIZE * 4 + 1 + 1 + 1;
  char * result = malloc_or_fail (size, "packet_ids_to_string");
  char * p = result;
  int written = 0;   /* how many bytes written overall */
  int w;             /* how many bytes written in the latest operation */
  w = snprintf (p, size - written, "%s %s: ", p1, p2);
  p += w; written += w;
  for (i = 0; i < PACKET_ID_SIZE; i++) {
    w = snprintf (p, size - written, "%02x", packet_id [i] & 0xff);
    p += w; written += w;
  }
  w = snprintf (p, size - written, " ");
  p += w; written += w;
  for (i = 0; i < PACKET_ID_SIZE; i++) {
    w = snprintf (p, size - written, "%02x", hashed [i] & 0xff);
    p += w; written += w;
  }
  w = snprintf (p, size - written, "\n");
  p += w; written += w;
  /* maybe delete this if statement after feeling confident of computation */
  if (written + 1 != size) {
    printf ("packet_ids_to_string, error in computing how much to allocate\n");
    printf ("size %d, written %d, packet ID size %d, result %p, p %p\n",
            size, written, PACKET_ID_SIZE, result, p);
    exit (1);
  }
  return result;
}

static void save_unacked (int index, struct chat_descriptor * cp)
{
  unsigned long long int seq = read_big_endian64 (cp->counter);
  unsigned long long int send_time = read_big_endian48 (cp->timestamp);
  struct contact_info * cip = contacts + index;
  int i;
  for (i = 0; i < cip->nunack; i++) {
    if (cip->unacked [i].seq == seq) {
      if (cip->unacked [i].time < send_time)
        cip->unacked [i].time = send_time;
      return;
    }
  }
  while (cip->nunack >= SEQ_STORAGE) {   /* make room for this one */
    int j;
    for (j = 1; j < SEQ_STORAGE; j++)
      cip->unacked [j - 1] = cip->unacked [j];
    cip->nunack = cip->nunack - 1;
  }
  cip->unacked [cip->nunack].seq = seq;
  cip->unacked [cip->nunack].time = send_time;
  cip->nunack = cip->nunack + 1;
}

/* write a C string to the file, closing cleanly in case of error */
#define write_or_ret(fd, str, name, w, p)	\
  w = write (fd, str, strlen (str));		\
  if (w < strlen (str)) {			\
    perror ("save_message/write");		\
    printf ("wrote %d instead of %zd bytes to %s\n", w, strlen (str), name); \
    free (name);				\
    if (p != NULL) free (p);			\
    close (fd);					\
    return;					\
  }

static void save_message (char * dirname, char * prefix,
                          struct chat_descriptor * cp, char * text, int tsize)
{
  unsigned long long int counter = read_big_endian64 (cp->counter);
  unsigned long long int send_time = read_big_endian48 (cp->timestamp);
  short int tz_off = read_big_endian16 (cp->timestamp + 6);
  int namelen = strlen (dirname) + 1 + DATE_LEN + 1;
  char * name = malloc_or_fail (namelen, "save_message file name");
  /* snprintf (name, namelen, "%s/%020lld%s", dirname, counter, postfix); */
  time_t now;
  time (&now);
  struct tm * tm = localtime (&now);
  snprintf (name, namelen, "%s/%d%02d%02d", dirname,
            tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday);
  int fd = open (name, O_RDWR | O_CREAT | O_APPEND, 0600);
  if (fd < 0) {
    perror ("save_message/open-create");
    printf ("unable to open message file %s\n", name);
    free (name);
    return;
  }
  int w;
  /* write the packet ID to the file */
  char * pids_str = packet_ids_to_string (cp->packet_id, prefix, "id");
  write_or_ret (fd, pids_str, name, w, pids_str);
  free (pids_str);
  /* print the readable descriptor to the file */
  char * desc = chat_descriptor_to_string (cp, 0, 1);
  write_or_ret (fd, prefix, name, w, NULL);
  write_or_ret (fd, " ", name, w, NULL);
  write_or_ret (fd, desc, name, w, NULL);
  /* follow that with the time and the timezone */
  char timestamp_str [16];
  snprintf (timestamp_str, sizeof (timestamp_str), "%lld", send_time);
  write_or_ret (fd, " (", name, w, NULL);
  write_or_ret (fd, timestamp_str, name, w, NULL);
  write_or_ret (fd, " ", name, w, NULL);
  snprintf (timestamp_str, sizeof (timestamp_str), "%+d", tz_off);
  write_or_ret (fd, timestamp_str, name, w, NULL);
  write_or_ret (fd, ")", name, w, NULL);
  /* on the next line, with an indent of one space, put the message */
  write_or_ret (fd, "\n", name, w, NULL);
  char * text_copy = copy_with_indent (text, tsize, " ");
  write_or_ret (fd, text_copy, name, w, text_copy);
  free (text_copy);
  write_or_ret (fd, "\n", name, w, NULL);
  free (name);
  close (fd);
}

/* save an outgoing message */
void save_outgoing (char * contact, struct chat_descriptor * cp,
                    char * text, int tsize)
{
  init_contacts ();
  int index = find_single_contact (contact);
  if (index < 0) {
    printf ("unable to send message to %s, not known", contact);
    return;
  }
  long long int counter = read_big_endian64 (cp->counter);
  if (counter < 0) {
    printf ("num messages [%d] was %lld, ", index,
            contacts [index].num_messages);
    printf ("set to %lld\n", counter);
  }
  contacts [index].num_messages = counter;
  char * dirname = contacts [index].dirname;
  save_message (dirname, "sent", cp, text, tsize);
  save_unacked (index, cp);
}

static char * find_backwards (char * start, char * end, char * pattern)
{
#ifdef DOUBLE_DEBUG_PRINT
  char debug [1000];
  int size = sizeof (debug) - 1;
  if (size > end - start + 1) size = end - start + 1; 
  memcpy (debug, start, size);
  debug [size] = '\0';
  printf ("searching for '%s' in:\n%s\n", pattern, debug);
#endif /* DOUBLE_DEBUG_PRINT */
  int plen = strlen (pattern);
  if (plen <= 0)
    return end;   /* found */
  end -= (plen - 1);
  while ((end >= start) && (strncmp (end, pattern, plen) != 0))
    end--;
  if (end < start)
    return NULL;
  return end;
}

static char * get_message (char * data, int dsize, int * rsize)
{
  int size = 0;
  int lines = 1;
  while (size < dsize) {
    if ((data [size] == '\n') &&
        ((size + 1 == dsize) || (data [size + 1] != ' ')))
      /* found end of message -- the newline is not part of the message */
      break;
    size++;
    if ((size > 0) && (data [size] == ' ') && (data [size - 1] == '\n'))
      lines++;
  }
  int alloc = size - lines;  /* one blank per line is not in the message */
  char * result = malloc (alloc + 1);
  if (result == NULL) {
    printf ("get_message unable to allocate %d bytes for message\n", alloc);
    return NULL;
  }
  int dindex = 1;
  int rindex = 0;
  while (rindex < alloc) {
    if ((rindex == 0) || (data [dindex] != ' ') || (data [dindex - 1] != '\n'))
      result [rindex++] = data [dindex];
    dindex++;
  }
  result [alloc] = '\0';
  *rsize = alloc;
  return result;
}

static char * find_latest (char * dirname, char * fname,
                           unsigned long long int seq,
                           /* results: */
                           int * size, unsigned long long int * time,
                           char * packet_id)
{
  *size = 0;
  *time = 0;
  char * result = NULL;
  char * data;
  int dsize = read_file_contents (dirname, fname, 1, &data);
  char * p = data + dsize - 1;
  char find [100];
  snprintf (find, sizeof (find), "sent sequence %lld, ", seq);
  char * found = find_backwards (data, p, find);
  if (found == NULL) {  /* sequence number not found in this file */
    free (data);
    return NULL;
  }
  char * id = find_backwards (data, found, "sent id: ");
  if (id == NULL) {  /* sequence number not found in this file */
    free (data);
    return NULL;
  }
  char * id_string = id + strlen ("sent id: ");
  read_packet_id (id_string, dsize - (id_string - data), packet_id);
  char * time_string = index (found, '(');
  *time = parse_time_in_parens (found, dsize - (found - data));
  char * message_start = index (found, '\n');
  if (message_start != NULL) {
    message_start++;
    if (*message_start == ' ')  /* indented */
      result = get_message (message_start, dsize - (message_start - data),
                            size);
    else
      printf ("error: no blank in message with sequence %lld, time %lld\n",
              seq, *time);
  } else {
    printf ("error: no message with sequence %lld, time %lld\n", seq, *time);
  }
  free (data);
  return result;
}

/* return the (malloc'd) outgoing message with the given sequence number,
 * or NULL if there is no such message.
 * if there is more than one such message, returns the latest.
 * Also fills in the size, time and packet_id -- packet_id must have
 * at least PACKET_ID_SIZE bytes */
char * get_outgoing (char * contact, unsigned long long int seq,
                     int * size, unsigned long long int * time,
                     char * packet_id)
{
  init_contacts ();
  char * result = NULL;
  *size = 0;
  *time = 0;
  int index = find_single_contact (contact);
  if (index < 0) {
    printf ("unable to retransmit messages to %s, not known", contact);
    return NULL;
  }
  DIR * dir = opendir (contacts [index].dirname);
  if (dir == NULL) {
    perror ("opendir/3");
    printf ("unable to open directory %s\n", contacts [index].dirname);
  }
  struct dirent * dep;
  while ((dep = readdir (dir)) != NULL) {
    char * this_result = NULL;
    int this_size;
    unsigned long long int this_time;
    char this_packet_id [PACKET_ID_SIZE];
    if (start_ndigits (dep->d_name, DATE_LEN)) /* message file */
      this_result = find_latest (contacts [index].dirname, dep->d_name, seq,
                                 &this_size, &this_time, this_packet_id);
    if ((this_result != NULL) && ((result == NULL) || (this_time > *time))) {
      if (result != NULL)
        free (result);
      result = this_result;
      *time = this_time;
      *size = this_size;
      memcpy (packet_id, this_packet_id, PACKET_ID_SIZE);
    } else if (this_result != NULL) {
      free (this_result);
    }
  }
  closedir (dir);
  return result;
}

/* save a received message */
void save_incoming (char * contact, struct chat_descriptor * cp,
                    char * text, int tsize)
{
  init_contacts ();
  int index = find_single_contact (contact);
  if (index < 0) {
    printf ("unable to save incoming message from %s, not known", contact);
    return;
  }
  char * dirname = contacts [index].dirname;
  save_message (dirname, "rcvd", cp, text, tsize);
  unsigned long long int seq = read_big_endian64 (cp->counter);
  if (seq != COUNTER_FLAG) {
    struct contact_info * cip = contacts + index;
    if (seq < cip->last_received) /* received packet, remove from missing */
      remove_missing (cip->missing, &(cip->nmissing), seq);
    if (seq > cip->last_received + 1) /* intermediate ones are missing */
      add_missing (cip->missing, &(cip->nmissing),
                   cip->last_received + 1, seq - 1);
    if (seq > cip->last_received)
      cip->last_received = seq;
#ifdef DEBUG_PRINT
    printf ("save_incoming found seq %lld, latest now %lld\n",
            seq, cip->last_received);
    printf ("contact %s has %d missing\n", cip->name, cip->nmissing);
    int dbg;
    for (dbg = 0; dbg < cip->nmissing; dbg++)
    printf ("missing %d is %lld to %lld\n", dbg,
            cip->missing [dbg].first, cip->missing [dbg].last);
    printf ("contact %s has %d unacked\n", cip->name, cip->nunack);
    for (dbg = 0; dbg < cip->nunack; dbg++)
    printf ("unacked %d is %lld at time %lld\n", dbg,
            cip->unacked [dbg].seq, cip->unacked [dbg].time);
#endif /* DEBUG_PRINT */
  }
}

static void free_close (void * p1, void * p2, void * p3, int fd, DIR * dir)
{
  if (p1 != NULL)
    free (p1);
  if (p2 != NULL)
    free (p2);
  if (p3 != NULL)
    free (p3);
  if (fd >= 0)
    close (fd);
  if (dir != NULL)
    closedir (dir);
}

/* return sequence number if successfully added this ack for this dir, and
 * return -1 if the packet was found, but was already acked
 * return 0 otherwise */
static long long add_ack (char * dirname, char * packet_id)
{
  DIR * dir = opendir (dirname);
  if (dir == NULL) {  /* eventually probably don't need to print */
    perror ("opendir/3");
    printf ("ack_received/add_ack unable to open directory %s\n", dirname);
    return -1;   /* unknown contact */
  }
  struct dirent * dep;
  unsigned long long int max = 0;
  while ((dep = readdir (dir)) != NULL) {
    if (start_ndigits (dep->d_name, DATE_LEN)) { /* message file */
      char * pid_str = packet_ids_to_string (packet_id, "sent", "id");
      char * pack_str = packet_ids_to_string (packet_id, "got", "ack");
      char * contents;
      int size = read_file_contents (dirname, dep->d_name, 0, &contents);
      char * p = strncasestr (contents, size, pack_str);
      if (p != NULL) {   /* found the ack */
#ifdef DEBUG_PRINT
        printf ("'%s' already found, %s/%s\n", pack_str, dirname, dep->d_name);
#endif /* DEBUG_PRINT */
        free_close (pid_str, pack_str, contents, -1, dir);
        return -1;
      }
#ifdef DEBUG_PRINT
      printf ("looking for '%s' in %s/%s\n", pid_str, dirname, dep->d_name);
#endif /* DEBUG_PRINT */
      p = strncasestr (contents, size, pid_str);
      if (p != NULL) {   /* found the id, counter is on next line */
#ifdef DEBUG_PRINT
        printf ("'%s' found in %s/%s\n", pid_str, dirname, dep->d_name);
#endif /* DEBUG_PRINT */
        char * pseq = index (p, '\n');
        char * seq_str = "sent sequence ";
        if ((pseq != NULL) &&
            (strncmp (pseq + 1, seq_str, strlen (seq_str)) == 0)) {
          char * start = pseq + 1 + strlen (seq_str);
          char * finish;
          int seq = strtoll (start, &finish, 10);
          if (start == finish) {  /* no sequence number found */
            printf ("no sequence following id %s in %s/%s\n(%s)\n",
                    pid_str, dirname, dep->d_name, contents);
            free_close (pid_str, pack_str, contents, -1, dir);
            return 0;
          }
          free (contents);
          char * fname = strcat3_malloc (dirname, "/", dep->d_name, "add_ack");
          int fd = open (fname, O_RDWR | O_APPEND | O_CREAT);
          if (fd < 0) {
            perror ("insert_into_file/open");
            printf ("unable to add at end of file %s\n", fname);
            free_close (pid_str, pack_str, fname, fd, dir);
            return 0;
          }
          int bytes = strlen (pack_str);
          int w = write (fd, pack_str, bytes);   /* append */
#ifdef DEBUG_PRINT
          if (w == bytes)
            printf ("wrote '%s' to %s/%s\n", pack_str, dirname, dep->d_name);
#endif /* DEBUG_PRINT */
          if (w != bytes)
            perror ("add_ack/write");
          free_close (pid_str, pack_str, fname, fd, dir);
          if (w != bytes) {
#ifdef DEBUG_PRINT
            printf ("wrote %zd bytes, result %d\n", bytes, w);
#endif /* DEBUG_PRINT */
            return 0;
          }
          return seq;
        }
        printf ("pseq %s\n", pseq);
        if (pseq != NULL)
          printf ("compared '%s' to '%s'\n", pseq + 1, seq_str);
        printf ("unable to find sequence following id %s in %s/%s\n(%s)\n",
                pid_str, dirname, dep->d_name, contents);
        free_close (pid_str, pack_str, contents, -1, dir);
        return 0;
      }
      free_close (pid_str, pack_str, contents, -1, NULL);
    }
  }
  free_close (NULL, NULL, NULL, -1, dir);
  return 0;
}

static void remove_unacked (struct contact_info * cip, long long int seq)
{
  int i = 0;
  while (i < cip->nunack) {
    if (cip->unacked [i].seq == seq)   /* remove this sequence number */
      remove_ack (cip->unacked, &(cip->nunack), i);
    else
      i++;
  }
}

/* mark a previously sent message as acknowledged */
/* return the sequence number > 0 if this is an ack for a known contact, */
/* return 0 ... never, hopefully */
/* return -1 if this ack is not recognized */
/* return -2 if this ack was previously received */
/* fill in *contact (to a malloc'd string -- must free) if return > 0 or -2 */
/* otherwise set *contact to NULL */
long long int ack_received (char * packet_id, char * * contact)
{
  init_contacts ();
  *contact = NULL;
  int i;
  for (i = 0; i < actual_contacts; i++) {
    long long int seq = add_ack (contacts [i].dirname, packet_id);
    if (seq > 0) {   /* found!! */
      remove_unacked (contacts + i, seq);
      *contact = strcpy_malloc (contacts [i].name, "ack_received contact");
      return seq; /* ack saved, and matches contact */
    }
    if (seq < 0) {
      *contact = strcpy_malloc (contacts [i].name, "ack_received contact/2");
      return -2;  /* ack previously received */
    }
    /* else: continue loop */
  }
#ifdef DEBUG_PRINT
  char * pid_str = packet_ids_to_string (packet_id, "received", "id");
  printf ("ack_received did not find any matching contact for %s\n", pid_str);
  free (pid_str);
#endif /* DEBUG_PRINT */
  return -1;
}

/* returns a new (malloc'd) array, or NULL in case of error (or none missing) */
/* the new array has (singles + 2 * ranges) * COUNTER_SIZE bytes. */
/* the first *singles * COUNTER_SIZE bytes are individual sequence numbers
 * that we never received.
 * the next *ranges * 2 * COUNTER_SIZE bytes are pairs of sequence numbers a, b
 * such that any seq such that we never received a <= seq <= b */
char * get_missing (char * contact, int * singles, int * ranges)
{
  init_contacts ();
  *ranges = 0;
  *singles = 0;
  int index = find_single_contact (contact);
  if (index < 0) {
    printf ("unable to get missing for %s, not known\n", contact);
    return NULL;
  }
  struct contact_info * cip = contacts + index;
  int i;
  for (i = 0; i < cip->nmissing; i++) {
    if (cip->missing [i].first == cip->missing [i].last)    /* single */
      *singles = *singles + 1;
    else
      *ranges = *ranges + 1;
  }
  if ((*ranges == 0) && (*singles == 0))
    return NULL;
  int n = *ranges * 2 + *singles;
  char * result = malloc (n * COUNTER_SIZE);
  if (result == NULL) {
    perror ("malloc in store.c/get_missing");
    printf ("unable to allocate %d bytes\n", n * COUNTER_SIZE);
    return NULL;
  }
  int outpos = 0;
  for (i = 0; i < cip->nmissing; i++) {
    if (cip->missing [i].first == cip->missing [i].last) {
      write_big_endian64 (result + outpos * COUNTER_SIZE,
                          cip->missing [i].first);
      outpos++;
    }
  }
  for (i = 0; i < cip->nmissing; i++) {
    if (cip->missing [i].first != cip->missing [i].last) {
      write_big_endian64 (result + outpos * COUNTER_SIZE,
                          cip->missing [i].first);
      outpos++;
      write_big_endian64 (result + outpos * COUNTER_SIZE,
                          cip->missing [i].last);
      outpos++;
    }
  }
  return result;
}

/* insertion sort has fast runtime when the array is already sorted */
static void sort_unacked (struct unacked_info * unacked, int nunack)
{
  int i, j;
  for (i = 1; i < nunack; i++) {
    for (j = i; (j > 0) && (unacked [j].seq < unacked [j - 1].seq); j--) {
      struct unacked_info swap = unacked [j    ];
      unacked [j    ] =          unacked [j - 1];
      unacked [j - 1] = swap;
    }
  }
}

/* returns a new (malloc'd) array, or NULL in case of error or no unacked */
/* the new array has (singles + 2 * ranges) * COUNTER_SIZE bytes. */
/* the first *singles * COUNTER_SIZE bytes are individual sequence numbers
 * that can be sent.
 * the next *ranges * 2 * COUNTER_SIZE bytes are pairs of sequence numbers a, b
 * such that any seq such that a <= seq <= b can be sent */
char * get_unacked (char * contact, int * singles, int * ranges)
{
  init_contacts ();
  *ranges = 0;
  *singles = 0;   /* in case we return due to error */
  int index = find_single_contact (contact);
  if (index < 0) {
    printf ("unable to get unacked for %s, not known\n", contact);
    return NULL;
  }
  struct contact_info * cip = contacts + index;
  if (cip->nunack == 0)
    return NULL;

  int nunack = cip->nunack;
  int size = nunack * COUNTER_SIZE;

  /* note -- this may malloc more than needed, if there are any ranges,
   * we should use fewer entries.  No matter, malloc/free can handle this */
  char * result = malloc (size);
  if (result == NULL) {
    perror ("malloc in store.c/get_unacked");
    printf ("unable to allocate %d bytes\n", size);
    return NULL;
  }

  /* sort the sequence numbers (if necessary) to detect ranges */
  sort_unacked (cip->unacked, cip->nunack);
  int i;
  int num_singles = 0;
  int num_ranges = 0;
  long long int last_seq = -1;
  int in_range = 0;
  char * singlep = result;         /* put at the front */
  char * rangep = result + size;   /* put at the end, then copy down */
  for (i = 0; i < cip->nunack; i++) {
    if ((i == 0) || (last_seq + 1 < cip->unacked [i].seq)) {   /* single */
      write_big_endian64 (singlep, cip->unacked [i].seq);
      singlep += COUNTER_SIZE;
      num_singles++;
      in_range = 0;
    } else if (in_range) {   /* extend the existing range */
      write_big_endian64 (rangep + COUNTER_SIZE, cip->unacked [i].seq);
    } else {                 /* create a new range */
      rangep -= 2 * COUNTER_SIZE;   /* make room for the new range */
      /* the start of the new range is the last single value we stored */
      singlep -= COUNTER_SIZE;
      num_singles--;
      write_big_endian64 (rangep, read_big_endian64 (singlep));
      write_big_endian64 (rangep + COUNTER_SIZE, cip->unacked [i].seq);
      num_ranges++;
      in_range = 1;
    }
    last_seq = cip->unacked [i].seq;
  }
  for (i = 0; i < num_ranges; i++) {  /* now shift the ranges down */
    write_big_endian64 (singlep, read_big_endian64 (rangep));
    rangep += COUNTER_SIZE;
    singlep += COUNTER_SIZE;
    write_big_endian64 (singlep, read_big_endian64 (rangep));
    rangep += COUNTER_SIZE;
    singlep += COUNTER_SIZE;
  }
  *singles = num_singles;
  *ranges = num_ranges;
  return result;
}

/* returns 1 if this sequence number has been acked, 0 otherwise */
int is_acked (char * contact, long long int seq)
{
  init_contacts ();
  int index = find_single_contact (contact);
  if (index < 0) {
    printf ("unable to get is_acked for %s, not known\n", contact);
    return 0;   /* not acked! */
  }
  struct contact_info * cip = contacts + index;
  if (cip->nunack == 0)
    return 1;   /* everything acked */
  int i;
  for (i = 0; i < cip->nunack; i++)
    if (cip->unacked [i].seq == seq)
      return 1;
  return 0;
}

/* returns 1 if this sequence number has been received, 0 otherwise */
int was_received (char * contact, long long int seq)
{
  init_contacts ();
  int index = find_single_contact (contact);
  if (index < 0) {
    printf ("unable to get was_received for %s, not known\n", contact);
    return 0;   /* not received */
  }
  struct contact_info * cip = contacts + index;
  if (seq > cip->last_received)
    return 0;     /* a sequence number we have never heard of */
  int i;
  for (i = 0; i < cip->nmissing; i++) {
    if ((seq >= cip->missing [i].first) && (seq <= cip->missing [i].last))
      return 0;   /* missing, not received */
  }
  return 1;       /* already received */
}

