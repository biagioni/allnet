/* xchat_term.c: send and receive xchat messages (executable is named xt) */
/* terminal interface meant to be equivalent to xchat */
/* once started, commands are: */

#define XCHAT_TERM_HELP_MESSAGE	\
"<typing> send message to current contact (no . at start)\n\
   end line with .= or .- to continue typing on next line\n\
.c    list all contacts, .c n  start sending to contact n\n\
.q    quit \n\
.h    print this help message \n\
.l n  print the last n messages (default n=10, .ll long)\n\
.t    trace (hop count .t 1, address .t 1 f0)\n\
.k    key exchanges (type .k for more information) \n\
"

#define XCHAT_TERM_KEY_SUBMENU	  \
".k usage: \n\
.k name <hops>      exchange a key with a new contact\n\
        <hops>      defaults to 1 if not specified\n\
.k name hops secret one side gives the other's secret\n\
.k                  list incomplete key exchanges \n\
.k + number or name resend a key in an exchange \n\
.k - number or name end or complete an exchange \n\
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
#include "lib/util.h"
#include "lib/priority.h"
#include "lib/allnet_log.h"
#include "lib/trace_util.h"
#include "lib/app_util.h"
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
  int sock;
  int print_duplicates;
};

/* variables to keep track of trace messages */
static char expecting_trace [MESSAGE_ID_SIZE];  /* trace we are looking for */
static int trace_count = 0;  /* changes every time we start a new trace */
static unsigned long long int trace_start_time = 0;

static void * receive_thread (void * arg)
{
  struct receive_thread_args a = *((struct receive_thread_args *) arg);
  char * old_contact = NULL;
  keyset old_kset = -1;
  while (1) {
    char * packet;
    unsigned int pri;
    int found = local_receive (1000, &packet, &pri);
    if (found < 0) {
      printf ("xt pipe closed, thread exiting\n");
      exit (1);
    }
    /* it's good to call handle_packet even if we didn't get a packet */
    int verified = 0, duplicate = -1, broadcast = -2;
    uint64_t seq = 0;
    char * peer = NULL;
    keyset kset = 0;
    char * desc = NULL;
    char * message = NULL;
    struct allnet_ack_info acks;
    acks.num_acks = 0;
    struct allnet_mgmt_trace_reply * trace = NULL;
    int mlen = handle_packet (a.sock, packet, found, pri, &peer, &kset,
                              &message, &desc, &verified, &seq, NULL,
                              &duplicate, &broadcast, &acks, &trace);
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
    } else if (mlen < 0) {
      char string [PRINT_BUF_SIZE] = "";
      if (mlen == -1)        /* confirm successful key exchange */
        snprintf (string, sizeof (string), "from '%s' got key\n", peer);
      else if (mlen == -2)   /* confirm successful subscription */
        snprintf (string, sizeof (string), "subscription %s complete\n", peer);
      else if ((mlen == -4)  /* got a trace reply */
               && (trace != NULL)
               && (memcmp (trace->trace_id, expecting_trace,
                           MESSAGE_ID_SIZE) == 0)) {
        trace_to_string (string, sizeof (string), trace,
                         trace_count, trace_start_time);
        printf ("%s", string);
        string [0] = '\0';   /* do not call print_to_output */
      }
      if (strlen (string) > 0)
        print_to_output (string);
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
  return result;
}

static void make_date (char * buffer, size_t size, const char * msg,
                       uint64_t time)
{
  char localtime [ALLNET_TIME_STRING_SIZE];
  allnet_localtime_string (time, localtime);
  snprintf (buffer, size, "%s %s", msg, localtime);
}

static void print_n_messages (const char * peer, const char * arg, int def)
{ 
  int print_long = 0;
  if ((arg != NULL) && (strlen (arg) > 0) && (arg [0] == 'l')) {  /* long */
    print_long = 1;
    arg++;
  }
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
    print_to_output ("");
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
    char print_date [1000];
    char print_rcvd_ackd [1000];
    print_date [0] = '\0';          /* off by default */
    print_rcvd_ackd [0] = '\0';     /* off by default */
    if (print_long)
      make_date (print_date, sizeof (print_date), "sent", msgs [i].time);
    if (msgs [i].msg_type == MSG_TYPE_SENT) {
      if (msgs [i].message_has_been_acked) {
        snprintf (print_rcvd_ackd, sizeof (print_rcvd_ackd), "* ");
        if (print_long) {
          char print_buf [sizeof (print_date)];
          strncpy (print_buf, print_date, sizeof (print_date));
          /* note: for now (2017/11/22) rcvd_ackd_time should
             be msgs [i].time (or 0) for any sent message.
             The code in the "if" should work correctly once
             ack times are supported, so it may be a good idea
             to keep it (but remove this comment ;) */
          if (msgs [i].rcvd_ackd_time > msgs [i].time)
            snprintf (print_date, sizeof (print_date),
                      "%s, acked %" PRIu64 " second%s later: ", print_buf,
                      msgs [i].rcvd_ackd_time - msgs [i].time,
                      (msgs [i].rcvd_ackd_time > msgs [i].time + 1) ? "s" : "");
          else
            snprintf (print_date, sizeof (print_date), "%s: ", print_buf);
        }
      } else {   /* not acked, add : to the date */
        snprintf (print_rcvd_ackd, sizeof (print_rcvd_ackd), "%s", print_date);
        if (print_long)
          snprintf (print_date, sizeof (print_date), ": ");
        else
          print_date [0] = '\0';
      }
      off += snprintf (string + off, minz (total_size, off),
                       "s %" PRIu64 " %s%s%s\n", msgs [i].seq, print_rcvd_ackd,
                       print_date, msgs [i].message);
    } else {   /* received */
      if (msgs [i].prev_missing > 0)
        off += snprintf (string + off, minz (total_size, off),
                         "(%" PRIu64 " messages missing)\n",
                         msgs [i].prev_missing);
      if ((print_long) && (msgs [i].rcvd_ackd_time > msgs [i].time)) {
        if (msgs [i].rcvd_ackd_time > msgs [i].time + 1)
          snprintf (print_rcvd_ackd, sizeof (print_rcvd_ackd),
                    ", received %" PRIu64 " seconds later: ",
                     msgs [i].rcvd_ackd_time - msgs [i].time);
        else
          snprintf (print_rcvd_ackd, sizeof (print_rcvd_ackd),
                    ", received 1 second later: ");
      } else if (print_long) {
        snprintf (print_rcvd_ackd, sizeof (print_rcvd_ackd), ": ");
      }
      off += snprintf (string + off, minz (total_size, off),
                       "r %" PRIu64 " %s%s%s\n", msgs [i].seq,
                       print_date, print_rcvd_ackd, msgs [i].message);
    }
  }
  free_all_messages (msgs, num_used);
  print_to_output (string);
  free (string);
}

/* strip closing newline, if any */
static void strip_final_newline (char * string)
{
  char * nl = strrchr (string, '\n');
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
  int pto = 1;   /* call print_to_output at the end -- unless already done */
  strip_final_newline (new_peer);
  if ((strlen (new_peer) > 0) && (num_keysets (new_peer) > 0)) {
    if (strcasecmp (new_peer, *peer) != 0) {
      if (*peer != NULL) {
        free (*peer);   /* free earlier peer */
        pto = 0;        /* print in this if */
      }
      *peer = strcpy_malloc (new_peer, "xchat_term peer");
      prompt = *peer;
      if (! pto)
        print_n_messages (prompt, NULL, 10);
    }
  } else {                             /* no such peer */
    int print_peers = 1;               /* turn off if numeric selector */
    char ** contacts = NULL;
    int n = all_contacts (&contacts);
    if (strlen (new_peer) > 0) {
      char * endp = NULL;
      long int index = strtol (new_peer, &endp, 10);
      if ((endp != NULL) && (endp != new_peer) &&
          (index > 0) && (index <= n)) {  /* numeric selector */
        if ((*peer == NULL) ||            /* there was no prior peer */
            (strcasecmp (contacts [index - 1], *peer) != 0)) {
          if (*peer != NULL) {
            free (*peer);   /* free earlier peer */
            pto = 0;        /* print in this if */
          }
          *peer = strcpy_malloc (contacts [index - 1], "xchat_term peer");
          prompt = *peer;
          if (! pto)
            print_n_messages (prompt, NULL, 10);
        }
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
  if (pto)
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

static int get_address (const char * address, unsigned char * result, int rsize,
                        int * consumed)
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
    offset = end - address;
  }
  if (consumed != NULL)
    *consumed = offset;
  return bits;
}

static void run_trace (int sock, struct allnet_log * log, char * params)
{
  strip_final_newline (params);
  int hops = 5;
  int abits = 0;
  int sleep_sec = 5;
  unsigned char address [ADDRESS_SIZE];
  if (strlen (params) > 0) {
    char * finish = NULL;
    hops = strtol (params, &finish, 10);
    if (finish == params)
      hops = 5;
    params = finish;
    while (*params == ' ')
      params++;
    int consumed = 0;
    if (strlen (params) > 0) {
      abits = get_address (params, address, sizeof (address), &consumed);
      if (abits < 0) {
        printf ("params %s, invalid number of bits %d, should be > 0\n",
                params, abits);
        abits = 0;
      }
    }
    if ((consumed > 0) && (strlen (params) > consumed)) {
      finish = NULL;
      sleep_sec = strtol (params + consumed, &finish, 10);
      if (finish == params + consumed)
        sleep_sec = 5;
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
  trace_count++;
  trace_start_time = allnet_time_ms ();
  if (! start_trace (sock, address, abits, hops, 0, expecting_trace))
    printf ("unable to start trace\n");
  sleep (sleep_sec);
  print_to_output (NULL);
}

static void xt_delete_contact (char * contact, char ** peer)
{
  strip_final_newline (contact);
  printf ("contact deletion cannot be undone.  Type Y to delete contact %s\n",
          contact);
  char response [MESSAGE_BUF_SIZE];
  if ((fgets (response, sizeof (response), stdin) != NULL) &&
      (*response == 'Y')) {
    printf ("deleting contact %s\n", contact);
    delete_conversation (contact);
    make_invisible (contact);
    delete_contact (contact);
    /* reset the prompt if necessary */
    if ((peer != NULL) && (*peer != NULL) && (strcmp (*peer, contact) == 0)) {
      /* reset the prompt */
      char * new = most_recent_contact ();
      switch_to_contact (new, peer);
      return;  /* no print_to_output required, done by switch_to_contact */
    }
  } else {
    printf ("contact %s is not deleted\n", contact);
  }
  print_to_output (NULL);
}

/* if contact is not NULL, selects that incomplete (if any)
 * otherwise, if select is > 0, selects that incomplete (if any)
 * if selects a valid contact and key/received_key is not NULL,
 *   sets *key to the keyset corresponding to the contact
 *   sets *received_key to whether the key was received
 * if a valid contact was selected, returns a malloc'd copy of the contact name
 * otherwise, if select is == 0, prints the status of all the incompletes,
 *   returns NULL */
static char * list_incompletes (const char * contact, int select,
                                keyset * key, int * received_key)
{
  char * result = NULL;
  char ** contacts = NULL;
  keyset * keys = NULL;
  int * status = NULL;
  int ni = incomplete_key_exchanges (&contacts, &keys, &status);
  if ((ni > 0) && (contacts != NULL) && (keys != NULL) && (status != NULL)) {
    if (contact != NULL) {
      int ii;
      for (ii = 0; ii < ni; ii++) {
        if (strcmp (contact, contacts [ii]) == 0) { /* found it */
          if (key != NULL)
            *key = keys [ii];
          if (received_key != NULL)
            *received_key = 
              ((status [ii] & KEYS_INCOMPLETE_NO_CONTACT_PUBKEY) == 0);
          result = strcpy_malloc (contacts [ii], "list_incompletes 1");
          break;
        }
      }
    } else if ((select < 0) || (select > ni)) {
      printf ("valid selectors are %d..%d\n", 1, ni);
    } else if (select != 0) {  /* valid select */
      result = strcpy_malloc (contacts [select - 1], "list_incompletes 2");
      if (key != NULL)
        *key = keys [select - 1];
      if (received_key != NULL)
        *received_key = 
          ((status [select - 1] & KEYS_INCOMPLETE_NO_CONTACT_PUBKEY) == 0);
    } else {                   /* select == 0, list all */
      int ii;
      for (ii = 0; ii < ni; ii++) {
        char * pr_status = NULL;
        if ((status [ii] & KEYS_INCOMPLETE_NO_CONTACT_PUBKEY) &&
            (status [ii] & KEYS_INCOMPLETE_HAS_EXCHANGE_FILE))
          pr_status = "no key received";
        else if (status [ii] & KEYS_INCOMPLETE_NO_CONTACT_PUBKEY)
          pr_status = "no key received (and no exchange file, may be an error)";
        else if (status [ii] & KEYS_INCOMPLETE_HAS_EXCHANGE_FILE)
          pr_status = "key received";
        else
          pr_status = "key exchange is complete (this may be an error)";
        char * s1 = NULL;
        char * s2 = NULL;
        int ns = key_exchange_secrets (contacts [ii], &s1, &s2);
        char secrets [ALLNET_MTU] = "";
        if (ns == 1)
          snprintf (secrets, sizeof (secrets), ", secret %s", s1);
        else if (ns == 2)
          snprintf (secrets, sizeof (secrets), ", secrets %s and %s", s1, s2);
        printf ("%d: contact  %s,   status: %s%s\n",
                ii + 1, contacts [ii], pr_status, secrets);
      }
    }
    free (contacts);
    free (keys);
    free (status);
  } else {
    if ((contact == NULL) && (select == 0))
      printf ("there are no incomplete key exchanges\n");
  }
  return result;
}

static void key_exchange (int sock, struct allnet_log * log,
                          char * params, char ** peer)
{
/*
".k name <hops>        exchange a key with a new contact\n\
         <hops> defaults to 1 if not specified\n\
.k name hops secret   one side gives the other's secret\n\
.k                    list incomplete key exchanges \n\
.k + number/name      resend a key in an exchange \n\
.k - number/name      end or complete an exchange \n\
*/
  int hops_or_selector = -1;
  char * first = strtok (params, " \t\n");
  char * second = NULL;
  if (first != NULL) {
    if ((*first == '+') && (strlen (first) > 1)) {
      second = first + 1;
      first = "+";
    } else if ((*first == '-') && (strlen (first) > 1)) {
      second = first + 1;
      first = "-";
    } else {
      second = strtok (NULL, " \t\n");
    }
  }
  if (second != NULL) {
    char * finish = NULL;
    hops_or_selector = strtol (second, &finish, 10);
    if ((finish == second) && (*first != '+') && (*first != '-')) {
      printf ("second parameter in key exchange (%s) should be hop count\n",
              second);
      printf (XCHAT_TERM_KEY_SUBMENU);
      print_to_output (NULL);
      return;
    }
  }
  char * third = NULL;
  if (second != NULL)
    third = strtok (NULL, " \t\n");
#ifdef DEBUG_PRINT
  printf ("parameters are %s/%p, %s/%p, %s/%p\n", first, first, second,
          second, third, third);
#endif /* DEBUG_PRINT */

  if (first == NULL) {          /* just list the incompletes */
    list_incompletes (NULL, 0, NULL, NULL);
    printf (XCHAT_TERM_KEY_SUBMENU);
  } else if ((second != NULL) &&
             ((strcmp ("-", first) == 0) || (strcmp ("+", first) == 0))) {
    int got_key;
    keyset k;
    char * name = list_incompletes (second, hops_or_selector, &k, &got_key);
    if (name == NULL)
      name = list_incompletes (NULL, hops_or_selector, &k, &got_key);
    if (name != NULL) {
      if (strcmp ("-", first) == 0) { /* end the key exchange */
        printf ("ending key exchange with %s/%d, %s the contact's key\n",
                name, k, got_key ? "got" : "did not get");
        if (got_key) {
          /* complete the exchange and make the contact visible */
          incomplete_exchange_file (name, k, NULL, NULL);
          if (is_invisible (name))
            make_visible (name);
        } else {       /* delete the contact */
          printf ("deleting contact %s, for which never got a key\n", name);
          xt_delete_contact (name, peer);
          free (name);
          return;
        }
      } else { /* resend the key */
        if (resend_contact_key (sock, name))
          printf ("resent key to %s\n", name);
        else
          printf ("error resending key to %s\n", name);
      }
      free (name);
    } else {
      printf ("%s does not identify an incomplete key exchange\n", second);
      printf (XCHAT_TERM_KEY_SUBMENU);
    }
  } else {             /* initiate a key exchange */
    int hops = 1;  /* default */
    if (second != NULL) {
      hops = hops_or_selector;
      if ((hops < 1) || (hops > 30)) {
        printf ("invalid hop count %s (1-30 required)\n", second);
        print_to_output (NULL);
        return;
      }
    }
    char * secret = third;
    char secret_buf [1000];
    if (secret == NULL) {   /* generate secret */
      if (hops == 1)
        random_string (secret_buf, 7);
      else
        random_string (secret_buf, 15);
      secret = secret_buf;
      normalize_secret (secret);
      printf ("generated secret %s\n", secret);
    } else {
      normalize_secret (secret);
    }
    printf ("key exchange for new contact %s, %d hops, secret %s\n",
            first, hops, secret);
    if (! create_contact_send_key (sock, first, secret, NULL, hops))
      printf ("unable to send key for new contact %s, %d hops, secret %s\n",
              first, hops, secret);
  }
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
    if (strlen (peer) <= 0)
      printf ("send_message: empty peer '%s'\n", peer);
    if (strlen (message) <= 0)
      printf ("send_message: empty message '%s'\n", message);
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

  /* not expecting any trace */
  memset (expecting_trace, 0, sizeof (expecting_trace));

  int print_duplicates = 0;
  char * path = NULL;
  int i;
  for (i = 1; i < argc; i++) {
    if (strcmp (argv [i], "-a") == 0)
      print_duplicates = 1;
    else if ((i + 1 < argc) && (strcmp (argv [i], "-d") == 0))
      path = argv [i + 1];
  }

  int sock = xchat_init (argv [0], path);
  if (sock < 0)
    return 1;

  static struct receive_thread_args rta;
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

  char message [MESSAGE_BUF_SIZE];
  char * saved_message = NULL;
  while (fgets (message, sizeof (message), stdin) != NULL) {
    size_t len = strlen (message);
    if (len <= 0)              /* ignore */
      continue;
    /* strlen (message) > 0 */
    if (message [0] != '.') {        /* not a command */
      if ((len > 3) && ((strncmp (".=", message + len - 3, 2) == 0) ||
                        (strncmp (".-", message + len - 3, 2) == 0))) {
        /* message continues on the next line */
        message [len - 3] = '\0';  /* get rid of .= or .- and the newline */
        append_to_message (message, &saved_message);
      } else if (saved_message != NULL) {   /* append new input, then send */
        append_to_message (message, &saved_message);
        send_message (sock, peer, saved_message);
        free (saved_message);
        saved_message = NULL;
      } else {   /* a one-line message to send */
        strip_final_newline (message);
        send_message (sock, peer, message);
      }
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
      case 'c':  /* new contact to send to */
        switch_to_contact (next, &peer);
        break;
      case 'q':  /* quit */
        printf ("quit command, exiting\n");
        exit (0);
        break;   /* not needed, but good form */
      case 'h':  /* show help message */
        print_to_output (XCHAT_TERM_HELP_MESSAGE);
        break;
      case 'l':  /* print last n messages*/
        print_n_messages (peer, next, 10);
        break;
      case 't':  /* trace */
        run_trace (sock, log, next);
        break;
      case 'd':  /* delete contact, not listed in menu */
        xt_delete_contact (next, &peer);
        break;
      case 'k':  /* exchange a key with a new contact, optional secret */
        key_exchange (sock, log, next, &peer);
        break;
      default:   /* send as a message */
        print_to_output ("unknown command\n");;
        break;
    }
  }
  print_to_output ("EOF on input, exiting\n");
  exit (0);
}

