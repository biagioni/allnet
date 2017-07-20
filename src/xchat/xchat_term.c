/* xchat_term.c: send and receive xchat messages (executable is named xt) */
/* terminal interface meant to be equivalent to xchat */
/* once started, commands are: */

#define XCHAT_TERM_HELP_MESSAGE	\
"<typing> send message to current contact (no . at start)\n\
.m        multiline message ending with .m, no .m in text\n\
.c <name> switch sending to contact 'name', or list all \n\
.c        list all contacts \n\
.q        quit \n\
.h        print this help message \n\
.l n      print the last n messages (n defaults to 10)\n\
.t        trace (hop count, . t 1, address . t 1 f0)\n\
.k name <secret> exchange a key with a new contact \n\
                 one of the two gives the other's secret\n\
"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "lib/packet.h"
#include "lib/pipemsg.h"
#include "lib/util.h"
#include "lib/priority.h"
#include "lib/allnet_log.h"
#include "lib/trace_util.h"
#include "chat.h"
#include "cutil.h"
#include "store.h"
#include "retransmit.h"
#include "xcommon.h"
#include "message.h"

static const char * prompt = XCHAT_TERM_HELP_MESSAGE "<no contact>";

static void print_to_output (const char * string)
{
  static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
  pthread_mutex_lock (&mutex);  /* only one thread at a time may print */
  int add_newline = ((string == NULL) || (strlen (string) == 0) ||
                     ((strlen (string) > 0) &&
                      (string [strlen (string) - 1] != '\n')));
  if (string != NULL)
    printf ("%s%s%s: ", string, ((add_newline) ? "\n" : ""), prompt); 
  else  /* just print the prompt */
    printf ("%s: ", prompt);
  fflush (stdout);
  pthread_mutex_unlock (&mutex);
}

#define MESSAGE_BUF_SIZE	(1000)
#define PRINT_BUF_SIZE		(ALLNET_MTU + MESSAGE_BUF_SIZE)

struct receive_thread_args {
  pd p;
  int sock;
  int print_duplicates;
};

static void * receive_thread (void * arg)
{
  struct receive_thread_args a = *((struct receive_thread_args *) arg);
  char * old_contact = NULL;
  keyset old_kset = -1;
  while (1) {
    char * packet;
    int pipe;
    unsigned int pri;
    int found = receive_pipe_message_any (a.p, PIPE_MESSAGE_WAIT_FOREVER,
                                          &packet, &pipe, &pri);
    if (found < 0) {
      printf ("xt pipe closed, thread exiting\n");
      exit (1);
    }
    /* it's good to call handle_packet even if we didn't get a packet */
    int verified, duplicate, broadcast;
    uint64_t seq;
    char * peer;
    keyset kset;
    char * desc;
    char * message;
    struct allnet_ack_info acks;
    int mlen = handle_packet (a.sock, packet, found, pri, &peer, &kset,
                              &message, &desc, &verified, &seq, NULL,
                                &duplicate, &broadcast, &acks, NULL);
    if (mlen > 0) {
      /* time_t rtime = time (NULL); */
      char * ver_mess = "";
      if (! verified)
        ver_mess = " (not verified)";
      char * dup_mess = "";
      if (duplicate)
        dup_mess = "duplicate ";
      char * bc_mess = "";
      if (broadcast) {
        bc_mess = "broacast ";
        dup_mess = "";
        desc = "";
      }
      if ((! duplicate) || (a.print_duplicates)) {
        char string [PRINT_BUF_SIZE];
        if (strcmp (prompt, peer) != 0)
          snprintf (string, sizeof (string),
                    "from '%s'%s got %s%s%s\n  %s\n",
                    peer, ver_mess, dup_mess, bc_mess, desc, message);
        else
          snprintf (string, sizeof (string),
                    "got %s%s%s\n  %s\n", dup_mess, bc_mess, desc, message);
        print_to_output (string);
      }
      if ((! broadcast) &&
          ((old_contact == NULL) ||
           (strcmp (old_contact, peer) != 0) || (old_kset != kset))) {
        request_and_resend (a.sock, peer, kset, 1);
        if (old_contact != NULL)
          free (old_contact);
        old_contact = peer;
        old_kset = kset;
      } else {  /* same peer */
        free (peer);
      }
      free (message);
      if (! broadcast)
        free (desc);
    } 
    if (acks.num_acks > 0) {
      int i;
      for (i = 0; i < acks.num_acks; i++) {
        char string [PRINT_BUF_SIZE];
        if (strcmp (prompt, acks.peers [i]) != 0)
          snprintf (string, sizeof (string),
                    "from '%s' got ack for seq %" PRIu64 "\n", acks.peers [i],
                    acks.acks [i]);
        else
          snprintf (string, sizeof (string),
                    "got ack for seq %" PRIu64 "\n", acks.acks [i]);
        print_to_output (string);
      }
    }
  }
}

/* result is malloc'd, should be free'd */
static char * most_recent_contact ()
{
  char * result = NULL;
  char ** contacts = NULL;
  int nc = all_contacts (&contacts);
  if (nc <= 1) {   /* 0 or one contact */
    if (nc > 0)    /* if there is only one contact, use that */
      result = strcpy_malloc (contacts [0], "most_recent_contact single");
    if (contacts != NULL)
      free (contacts);
    return result;
  }
  time_t latest = 0;
  int ic;
  for (ic = 0; ic < nc; ic++) {
    keyset * keysets = NULL;
    int nk = all_keys (contacts [ic], &keysets);
    int ik;
    for (ik = 0; ik < nk; ik++) {
      char * dir = key_dir (keysets [ik]);
      if (dir != NULL) {
        char * xchat_dir = string_replace_once (dir, "contacts", "xchat", 1);
        char * file = strcat_malloc (xchat_dir, "/last_sent",
                                     "most_recent_contact file name");
        struct stat st;
        if (stat (file, &st) == 0) {  /* success, file exists */
          if ((latest == 0) || (st.st_mtime > latest)) {
            if (result != NULL)
              free (result);
            result = strcpy_malloc (contacts [ic], "most_recent_contact ic");
            latest = st.st_mtime;
          }
        }
        free (file);
        free (xchat_dir);
        free (dir);
      }
    }
    if (keysets != NULL)
      free (keysets);
  }
  if (contacts != NULL)
    free (contacts);
/* check the time for last_sent in the xchat directory, pick the latest */
  return result;
}

static void print_n_messages (const char * peer, const char * arg, int def)
{ 
  int max_messages = def;
  if ((arg != NULL) && (strlen (arg) > 0)) {  /* number of messages to print */
    char * ends;
    int conversion = strtol (arg, &ends, 10);
    if ((ends == NULL) || (ends != arg))
      max_messages = conversion;
  }
  if (max_messages <= 0)
    return;
  struct message_store_info * msgs = NULL;
  int num_alloc = 0;
  int num_used = 0;
  list_all_messages (peer, &msgs, &num_alloc, &num_used);
  if (num_used <= 0) {
    free_all_messages (msgs, num_used);
    return;
  }
  /* indices into the msgs data structure of the first (earliest in time)
   * message to be printed, and last (latest in time). */
  /* note first is actually off by one as an index */
  int first_message = num_used;
  int last_message = 0;
  if (num_used > max_messages)
    first_message = max_messages;
  size_t total_size = first_message * PRINT_BUF_SIZE;
  char * string = malloc_or_fail (total_size, "xt message listing");
  size_t off = 0;
  int i;
  for (i = first_message - 1; i >= last_message; i--) {
    if (msgs [i].msg_type == MSG_TYPE_SENT) {
      off += snprintf (string + off, minz (total_size, off),
                       "s %" PRIu64 " %s %s\n", msgs [i].seq,
                       (msgs [i].message_has_been_acked ? "*" : " "),
                       msgs [i].message);
    } else {   /* received */
      if (msgs [i].prev_missing > 0)
        off += snprintf (string + off, minz (total_size, off),
                         "(%" PRIu64 " messages missing)\n",
                         msgs [i].prev_missing);
      off += snprintf (string + off, minz (total_size, off),
                       "r %" PRIu64 " %s\n", msgs [i].seq,
                       msgs [i].message);
    }
  }
  free_all_messages (msgs, num_used);
  print_to_output (string);
  free (string);
}

/* strip closing newline, if any */
static void strip_final_newline (char * string)
{
  char * nl = rindex (string, '\n');
  if ((nl != NULL) && (*(nl + 1) == '\0'))
    *nl = '\0';
}

static void append_to_message (const char * message, char ** result)
{
  if (*result == NULL) {
    *result = strcpy_malloc (message, "append_to_message new message");
  } else {
    *result = strcat3_malloc (*result, "\n", message, "append_to_message");
  }
  strip_final_newline (*result);
}

static void switch_to_contact (char * new_peer, char ** peer)
{
  strip_final_newline (new_peer);
  if ((strlen (new_peer) > 0) && (num_keysets (new_peer) > 0)) {
    if (*peer != NULL)
      free (*peer);   /* free earlier peer */
    *peer = strcpy_malloc (new_peer, "xchat_term peer");
    prompt = *peer;
  } else {                             /* no such peer */
    int print_peers = 1;               /* turn off if numeric selector */
    char ** contacts = NULL;
    int n = all_contacts (&contacts);
    if (strlen (new_peer) > 0) {
      char * endp = NULL;
      long int index = strtol (new_peer, &endp, 10);
      if ((endp != NULL) && (endp != new_peer) &&
          (index > 0) && (index <= n)) {  /* numeric selector */
        if (*peer != NULL)
          free (*peer);   /* free earlier peer */
        *peer = strcpy_malloc (contacts [index - 1], "xchat_term peer");
        prompt = *peer;
        print_peers = 0;
      } else {                     /* contact specified, but does not exist */
        char string [PRINT_BUF_SIZE];
        snprintf (string, sizeof (string),
                  "contact '%s' does not exist\n", new_peer);
        print_to_output (string);
      }
    }
    /* print available peers */
    if (print_peers && (n > 0) && (contacts != NULL)) {
      char peers [PRINT_BUF_SIZE];
      size_t size = PRINT_BUF_SIZE;
      char * p = peers;
      int i;
      for (i = 0; ((i < n) && (size > 0)); i++) {
        int off = printf ("%d: %s\n", i + 1, contacts [i]);
        /* int off = printf (p, size, "%d: %s\n", i + 1, contacts [i]); */
        if (off < 0)
          return;
        else if (off > size)    /* finished buffer */
          size = 0;
        else {
          size -= off;
          p += off;
        }
      }
    }
    if (contacts != NULL)
      free (contacts);
  }
  print_to_output (NULL);
}

/* get_nybble, get_byte, get_address are copied from trace.c, as is
 * the core of run_trace */
static int get_nybble (const char * string, int * offset)
{
  const char * p = string + *offset;
  while ((*p == ':') || (*p == ',') || (*p == '.'))
    p++;
  *offset = (int)((p + 1) - string);
  if ((*p >= '0') && (*p <= '9'))
    return *p - '0';
  if ((*p >= 'a') && (*p <= 'f'))
    return 10 + *p - 'a';
  if ((*p >= 'A') && (*p <= 'F'))
    return 10 + *p - 'A';
  *offset = (int)(p - string);   /* point to the offending character */
  return -1;
}

static int get_byte (const char * string, int * offset, unsigned char * result)
{
  int first = get_nybble (string, offset);
  if (first == -1)
    return 0;
  *result = (first << 4);
  int second = get_nybble (string, offset);
  if (second == -1)
      return 4;
  *result = (first << 4) | second;
  /* printf ("get_byte returned %x\n", (*result) & 0xff); */
  return 8;
}

static int get_address (const char * address, unsigned char * result, int rsize)
{
  int offset = 0;
  int index = 0;
  int bits = 0;
  while (index < rsize) {
    int new_bits = get_byte (address, &offset, result + index);
    if (new_bits <= 0)
      break;
    bits += new_bits;
    if (new_bits < 8)
      break;
    index++;
  }
  if (address [offset] == '/') { /* number of bits follows */
    char * end;
    long given_bits = strtol (address + offset + 1, &end, 10);
    if ((end != address + offset + 1) && (given_bits <= bits))
      bits = (int)given_bits;
  }
  return bits;
}

static void run_trace (int sock, pd p, struct allnet_log * log, char * params)
{
  strip_final_newline (params);
  int hops = 5;
  int abits = 0;
  unsigned char address [ADDRESS_SIZE];
  if (strlen (params) > 0) {
    char * finish = NULL;
    hops = strtol (params, &finish, 10);
    if (finish == params)
      hops = 5;
    params = finish;
    while (*params == ' ')
      params++;
    if (strlen (params) > 0) {
      abits = get_address (params, address, sizeof (address));
      if (abits <= 0) {
        printf ("params %s, invalid number of bits %d, should be > 0\n",
                params, abits);
        abits = 0;
      }
    }
  }
#ifdef DEBUG_PRINT
  if (abits > 0) {
    printf ("run_trace (%d, %d bits, ", hops, abits);
    print_buffer ((char *)address, ((abits + 7) / 8), NULL, ADDRESS_SIZE, 0);
    printf (")\n");
  } else if (strlen (params) > 0) {
    printf ("run_trace (%d, %s)\n", hops, params);
  } else {
    printf ("run_trace (%d)\n", hops);
  }
#endif /* DEBUG_PRINT */
  int repeat = 1;
  int sleep = 5;  /* seconds */
  int match_only = 1;
  int no_intermediates = 1;
  int wide = 1;
  int null_term = 0;
  int fd_out = STDOUT_FILENO;
  do_trace_loop (sock, p, address, abits, repeat, sleep,
                 hops, match_only, no_intermediates, wide,
                 null_term, fd_out, NULL, log);
  print_to_output (NULL);
}

static void send_message (int sock, const char * peer, const char * message)
{
  if ((peer == NULL) || (message == NULL)) {
    printf ("send_message: null peer %p or message %p\n", peer, message);
    print_to_output (XCHAT_TERM_HELP_MESSAGE);
    return;
  }
  if ((strlen (peer) <= 0) || (strlen (message) <= 0)) {
    printf ("send_message: empty peer '%s' or message '%s'\n", peer, message);
    print_to_output (XCHAT_TERM_HELP_MESSAGE);
    return;
  }
  if (num_keysets (peer) <= 0) { /* cannot send */
    print_to_output ("no valid contact to send to\n");
    return;
  }
  unsigned long long int seq =
    send_data_message (sock, peer, message, strlen (message));
  char string [PRINT_BUF_SIZE];
  snprintf (string, sizeof (string),
            "sent to '%s' sequence number %llu\n", peer, seq);
  print_to_output (string);
}

int main (int argc, char ** argv)
{
  log_to_output (get_option ('v', &argc, argv));
  struct allnet_log * log = init_log ("xt");
  pd p = init_pipe_descriptor (log);

  int sock = xchat_init (argv [0], p);
  if (sock < 0)
    return 1;

  int print_duplicates = 0;
  int i;
  for (i = 1; i < argc; i++) {
    if (strcmp (argv [i], "-a") == 0)
      print_duplicates = 1;
  }
  static struct receive_thread_args rta;
  rta.p = p;
  rta.sock = sock;
  rta.print_duplicates = print_duplicates;
  pthread_t thread;
  pthread_create (&thread, NULL, receive_thread, &rta);

  char * peer = most_recent_contact ();
  if (peer != NULL) {
    prompt = peer;
    print_to_output (XCHAT_TERM_HELP_MESSAGE);
  } else {
    print_to_output (NULL);
  }

  char * term_string = NULL;  /* string terminating the message, if any */
  char message [MESSAGE_BUF_SIZE];
  char * saved_message = NULL;
  while (fgets (message, sizeof (message), stdin) != NULL) {
    if (strlen (message) <= 0)              /* ignore */
      continue;
    /* strlen (message) > 0 */
    if (term_string != NULL) {
      char * termination = strstr (message, term_string);
      if (termination != NULL) /* end of message */
        *termination = '\0';   /* exclude termination from message */
      append_to_message (message, &saved_message);
      if (termination != NULL) {
        send_message (sock, peer, saved_message);
        free (saved_message);
        saved_message = NULL;
        term_string = NULL;
      }
      continue;    /* complete or not, start reading the next line */
    }
    if (message [0] != '.') {   /* a one-line message to send */
      strip_final_newline (message);
      send_message (sock, peer, message);
      continue;
    }
    /* message begins with '.'.  Strip leading blanks, if any */
    char * ptr = message + 1;
    while (*ptr == ' ')
      ptr++;
    char * next = ptr + 1;   /* in case there is a parameter */
    while (*next == ' ')
      next++;
    switch (tolower (*ptr)) {
      case 'm':  /* new multiline message */
        term_string = ".m";
        append_to_message (next, &saved_message);
        break;
      case 'c':  /* new contact to send to */
        switch_to_contact (next, &peer);
        break;
      case 'q':  /* quit */
        print_to_output ("quit command, exiting\n");
        exit (0);
        break;   /* not needed, but good form */
      case 'h':  /* show help message */
        print_to_output (XCHAT_TERM_HELP_MESSAGE);
        break;
      case 'l':  /* print last n messages*/
        print_n_messages (peer, next, 10);
        break;
      case 't':  /* trace */
        run_trace (sock, p, log, next);
        break;
      case 'k':  /* exchange a key with a new contact, optional secret */
        print_to_output ("key exchange not implemented (yet)\n");
        break;
      default:   /* send as a message */
        print_to_output ("unknown command\n");;
        break;
    }
  }
  print_to_output ("EOF on input, exiting\n");
  exit (0);
}

