/* gui_respond.c: respond to requests from the GUI */

#if defined(WIN32) || defined(WIN64)
#ifndef WINDOWS_ENVIRONMENT
#define WINDOWS_ENVIRONMENT
#define WINDOWS_ENVIRONMENT
#endif /* WINDOWS_ENVIRONMENT */
#endif /* WIN32 || WIN64 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <inttypes.h>
#include <pthread.h>
#include <fcntl.h>
#include <errno.h>

#ifdef WINDOWS_ENVIRONMENT
#include <windows.h>
#endif /* WINDOWS_ENVIRONMENT */

#include "lib/packet.h"
#include "lib/util.h"
#include "lib/keys.h"
#include "lib/mgmt.h"
#include "lib/trace_util.h"
#include "xcommon.h"
#include "store.h"
#include "cutil.h"
#include "gui_socket.h"

static int send_bytes (int sock, char *buffer, int64_t length)
{
  while (length > 0) {   /* inefficient implementation for now */
    if (write (sock, buffer, 1) != 1) {
      perror ("gui.c send_bytes");
      return 0;
    }
    buffer++;
    length--;
  }
  return 1;              /* success */
}

static int receive_bytes (int sock, char *buffer, int64_t length)
{
  while (length > 0) {
    /* get one byte at a time -- for now, inefficient implementation */
    if (read (sock, buffer, 1) != 1) {
      if ((errno != ENOENT) &&      /* ENOENT when the socket is closed */
          (errno != ECONNRESET)) {  /* or ECONNRESET */
        perror ("gui_respond.c receive_bytes");
        printf ("errno %d on connection %d\n", errno, sock);
      }
      return 0;
    }
    buffer++;
    length--;
  }
  return 1;              /* success */
}

/* returns 1 for success or 0 for failure */
/* also called from gui_callback.c, so the mutex is global */
int gui_send_buffer (int sock, char *buffer, int64_t length)
{
  if (length < 1)
    return 0;
  char length_buf [8];
  writeb64 (length_buf, length);
  int result = 0;
  /* use a mutex to ensure only one message is sent at a time */
  static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
  pthread_mutex_lock (&mutex);
  if ((send_bytes (sock, length_buf, 8)) &&
      (send_bytes (sock, buffer, length)))
    result = 1;
  pthread_mutex_unlock (&mutex);
  return result;
}

static int64_t receive_buffer (int sock, char **buffer)
{
  char length_buf [8];
  if (! receive_bytes (sock, length_buf, 8))
    return 0;
  int64_t length = readb64 (length_buf);
  if (length < 1)
    return 0;
  *buffer = malloc_or_fail (length, "gui.c receive_buffer");
  if (! receive_bytes (sock, *buffer, length))
    return 0;
  return length;
}

static size_t size_of_string_array (char ** array, int count)
{
  size_t result = 0;
  int i;
  for (i = 0; i < count; i++)
    result += (strlen (array [i]) + 1);
  return result;
}

static int copy_string_array (char * dest, size_t dsize,
                              char ** array, int count)
{
  if ((dsize < 1) || (count <= 0))
    return 0;
  if (dsize < size_of_string_array (array, count)) /* inefficient but sane */
    return 0;
  int i;
  for (i = 0; i < count; i++) {
    strcpy (dest, array [i]);
    dest += strlen (array [i]) + 1;
  }
  return 1;
}

/* if extra is not null, adds esize bytes to the header */
static void gui_send_string_array (int code, char ** array,
                                   int count, char * extra, int esize,
                                   int sock, const char * caller)
{
/* format: code, 64-bit number of strings, extra, null-terminated strings */
#define STRING_ARRAY_HEADER_SIZE	9
  if (extra == NULL)
    esize = 0;
  size_t string_alloc = size_of_string_array (array, count);
  size_t alloc = STRING_ARRAY_HEADER_SIZE + string_alloc + esize;
  char * reply = malloc_or_fail (alloc, caller);
  reply [0] = code;
  writeb64 (reply + 1, count);
  if (extra != NULL)
    memcpy (reply + STRING_ARRAY_HEADER_SIZE, extra, esize);
  int offset = STRING_ARRAY_HEADER_SIZE	+ esize;
  if ((count > 0) && (string_alloc > 0))
    copy_string_array (reply + offset, string_alloc, array, count);
  gui_send_buffer (sock, reply, alloc);
  free (reply);
#undef STRING_ARRAY_HEADER_SIZE
}

/* returns new count */
static int add_unique (char * match, char ** result, int count)
{
  int i;
  for (i = 0; i < count; i++) {
    if (strcmp (result [i], match) == 0)
      return count;
  }
  result [count] = match;
  return count + 1;
}

/* send all the contacts to the gui, null-separated */
static void gui_contacts (int sock)
{
/* format: code, 64-bit number of contacts,
 *               1-byte bitset for each contact,
 *               null-terminated list of all contacts
 * the bitset contains one bit each for visible (1), notify (2),
 * save (4), is_group (8) */
  char ** contacts = NULL;
  int nc = all_contacts (&contacts);
  char ** invisibles = NULL;
  int ninv = invisible_contacts (&invisibles);
  char ** incompletes = NULL;
  int ni = incomplete_key_exchanges (&incompletes, NULL, NULL);
  char ** all = malloc_or_fail (sizeof(char*) * (nc + ni + ninv),
                                "gui_contacts 1");
  int na = 0; /* total number of contacts */
  int i;
  for (i = 0; i < nc; i++)
    na = add_unique (contacts [i], all, na);
  for (i = 0; i < ninv; i++)
    na = add_unique (invisibles [i], all, na);
  for (i = 0; i < ni; i++)
    na = add_unique (incompletes [i], all, na);
  /* na has the count of names in the "all" array */
  char * extra = NULL;
  if (na > 0) {
    extra = malloc_or_fail (na, "gui_contacts 2");
    for (i = 0; i < na; i++) {
      int byte = 0;
      if (is_visible (all [i]))
        byte |= 1;
      if (contact_file_get (all [i], "no_notify", NULL) < 0)
        byte |= 2;
      if (contact_file_get (all [i], "no_saving", NULL) < 0)
        byte |= 4;
      if (is_group (all [i]))
        byte |= 8;
      extra [i] = byte;
    }
  }
  gui_send_string_array (GUI_CONTACTS, all, na, extra, na,
                         sock, "gui_contacts");
  if (contacts != NULL)
    free (contacts);
  if (invisibles != NULL)
    free (invisibles);
  if (incompletes != NULL)
    free (incompletes);
  if (all != NULL)
    free (all);
  if (extra != NULL)
    free (extra);
}

/* send all the subscriptions to the gui, null-separated */
static void gui_subscriptions (int sock)
{
/* format: code, 64-bit number of senders, null-terminated contacts */
  struct bc_key_info * bki = NULL;
  int nb = get_other_keys (&bki);
  char ** senders = malloc_or_fail (nb * sizeof (char *), "gui_subscriptions");
  int i;
  for (i = 0; i < nb; i++)
    senders [i] = bki [i].identifier;
  gui_send_string_array (GUI_SUBSCRIPTIONS, senders, nb, NULL, 0,
                         sock, "gui_subscriptions");
  free (senders);
}

/* dynamically allocates contact, must be freed */
static char * contact_name_from_buffer (char * message, int64_t length)
{
  if (length > 0) {
    char * contact = malloc_or_fail (length + 1, "contact_name_from_buffer");
    memcpy (contact, message, length);
    contact [length] = '\0';   /* null terminate if necessary */
    return contact;
  }
  return NULL;
}

/* send a 1 if a contact exists, or a 0 otherwise */
static void gui_contact_exists (char * message, int64_t length, int sock)
{
/* message format: contact name (not null terminated) */
/* reply format: 1-byte code, 1-byte response */
  char reply [2];
  reply [0] = GUI_CONTACT_EXISTS;
  reply [1] = 0;   /* does not exist */
  if (length > 0) {
    char * contact = contact_name_from_buffer (message, length);
    if (num_keysets (contact) > 0)
      reply [1] = 1;   /* success */
    free (contact);
  }
  gui_send_buffer (sock, reply, sizeof (reply));
}

/* send a 1 if a contact exists and is a group, or a 0 otherwise */
static void gui_contact_is_group (char * message, int64_t length, int sock)
{
/* message format: contact name (not null terminated) */
/* reply format: 1-byte code, 1-byte response */
  char reply [2];
  reply [0] = GUI_CONTACT_IS_GROUP;
  reply [1] = 0;   /* does not exist */
  if (length > 0) {
    char * contact = contact_name_from_buffer (message, length);
    if ((num_keysets (contact) > 0) && (is_group (contact)))
      reply [1] = 1;   /* success */
    free (contact);
  }
  gui_send_buffer (sock, reply, sizeof (reply));
}

/* send a 1 if a contact exists and has a peer key, or a 0 otherwise */
static void gui_contact_has_peer_key (char * message, int64_t length, int sock)
{
/* message format: contact name (not null terminated) */
/* reply format: 1-byte code, 1-byte response */
  char reply [2];
  reply [0] = GUI_HAS_PEER_KEY;
  reply [1] = 0;   /* by default, no peer key */
  if (length > 0) {
    char * contact = contact_name_from_buffer (message, length);
    if (has_symmetric_key (contact, NULL, 0)) {
      reply [1] = 1;   /* has key */
    } else {
      keyset * keys = NULL;
      int nk = all_keys (contact, &keys);
      int ik;
      for (ik = 0; ik < nk; ik++) {
        allnet_rsa_pubkey k;  /* do not free */
        if (get_contact_pubkey (keys [ik], &k) > 0)
          reply [1] = 1;   /* has key */
      }
      if (keys != NULL)
        free (keys);
    }
    free (contact);
  }
  gui_send_buffer (sock, reply, sizeof (reply));
}

/* create a group, sending a 1 or a 0 as response */
static void gui_create_group (char * message, int64_t length, int sock)
{
/* message format: group name (not null terminated) */
/* reply format: 1-byte code, 1-byte response */
  char reply [2];
  reply [0] = GUI_CREATE_GROUP;
  reply [1] = 0;   /* failure */
  if (length > 0) {
    char * contact = contact_name_from_buffer (message, length);
    if (create_group (contact))
      reply [1] = 1;   /* success */
    free (contact);
  }
  gui_send_buffer (sock, reply, sizeof (reply));
}

static void gui_members (unsigned int code, char * message, int64_t length,
                         int gui_sock, int recursive)
{
/* message format: group name (not null terminated) */
/* format: code, 64-bit number of members, null-terminated member names */
  if (length > 0) {
    char * contact = contact_name_from_buffer (message, length);
    char ** members = NULL;
    int count = (recursive ? group_membership_recursive (contact, &members)
                           : group_membership (contact, &members));
    gui_send_string_array (code, members, count, NULL, 0,
                           gui_sock, "gui_members");
    free (contact);
    if (members != NULL)
      free (members);
  } else {
    char reply [9];
    reply [0] = code;
    writeb64 (reply + 1, 0);
    gui_send_buffer (gui_sock, reply, sizeof (reply));
  }
}

static void gui_member_of (unsigned int code, char * message, int64_t length,
                           int gui_sock, int recursive)
{
/* message format: contact name (not null terminated) */
/* format: code, 64-bit number of groups, null-terminated group names */
  if (length > 0) {
    char * contact = contact_name_from_buffer (message, length);
    char ** members = NULL;
    int count = (recursive ? member_of_groups_recursive (contact, &members)
                           : member_of_groups (contact, &members));
    gui_send_string_array (code, members, count, NULL, 0,
                           gui_sock, "gui_member_of");
    free (contact);
    if (members != NULL)
      free (members);
  } else {
    char reply [9];
    reply [0] = code;
    writeb64 (reply + 1, 0);
    gui_send_buffer (gui_sock, reply, sizeof (reply));
  }
}

static void gui_rename_contact (char * message, int64_t length, int gui_sock)
{
/* message format: old contact name, new contact name both null terminated */
/* reply format: 1-byte code, 1-byte response */
  char reply [2];
  reply [0] = GUI_RENAME_CONTACT;
  reply [1] = 0;   /* failure */
  if (length >= 4) {   /* shortest is two single-character names, null-term */
    char * old = message;
    size_t offset = strlen (message) + 1;  /* should be index of new name */
    if (offset + 1 < length) { /* room for new name, plus null termination */
      char * new = message + offset;
      if ((strlen (old) > 0) && (strlen (new) > 0) &&
          (rename_contact (old, new)))
        reply [1] = 1;    /* success */
      else
        printf ("gui_rename_contact error: failed to rename %s to %s\n",
                old, new);
    }
  }
  gui_send_buffer (gui_sock, reply, sizeof (reply));
}

static void gui_clear_conversation (char * message, int64_t length,
                                    int gui_sock)
{
/* message format: contact name (not null terminated) */
/* reply format: 1-byte code, 1-byte response */
  char reply [2];
  reply [0] = GUI_CLEAR_CONVERSATION;
  reply [1] = 0;   /* failure */
  if (length > 1) {   /* shortest is a single-character name */
    char * contact = contact_name_from_buffer (message, length);
    reply [1] = clear_conversation (contact);
    free (contact);
  }
  gui_send_buffer (gui_sock, reply, sizeof (reply));
}

static void gui_delete_contact (char * message, int64_t length, int gui_sock)
{
/* message format: contact name (not null terminated) */
/* reply format: 1-byte code, 1-byte response */
  char reply [2];
  reply [0] = GUI_DELETE_CONTACT;
  reply [1] = 0;   /* failure */
  if (length > 1) {   /* shortest is a single-character name */
    char * contact = contact_name_from_buffer (message, length);
    delete_conversation (contact);  /* ignore the result, not relevant */
    reply [1] = delete_contact (contact);  /* this is the one we report */
    free (contact);
  }
  gui_send_buffer (gui_sock, reply, sizeof (reply));
}

static void gui_variable (char * message, int64_t length, int op, int gui_sock)
{
/* message format: variable code, contact name (not null terminated) */
/* reply format: 1-byte code, 1-byte response */
  char reply [2] = {0, 0};
  if (op == -1)
    reply [0] = GUI_QUERY_VARIABLE;
  else if (op == 0)
    reply [0] = GUI_UNSET_VARIABLE;
  else if (op == 1)
    reply [0] = GUI_SET_VARIABLE;
  else
    printf ("gui_variable: unknown op %d\n", op);
  reply [1] = 0;   /* not set, or failure */
  if ((op >= -1) && (op <= 1) && (length > 1)) {
    int code = message [0];
    char * contact = contact_name_from_buffer (message + 1, length - 1);
    if (num_keysets (contact) > 0) {  /* contact exists */
      switch (code) {
      case GUI_VARIABLE_VISIBLE:
        if (op == -1)       /* query */
          reply [1] = is_visible (contact);
        else if (op == 0)   /* make invisible */
          reply [1] = make_invisible (contact);
        else if (op == 1)   /* make visible */
          reply [1] = make_visible (contact);
        break;
      case GUI_VARIABLE_NOTIFY:
        if (op == -1)       /* query */
          reply [1] = (contact_file_get (contact, "no_notify", NULL) < 0);
        else if (op == 0)   /* cancel notifications by creating no_notify */
          reply [1] = (contact_file_write (contact, "no_notify", "", 0) == 1);
        else if (op == 1) { /* make notifiable by deleting "no_notify" if any */
          contact_file_delete (contact, "no_notify");
          reply [1] = 1;
        }
        break;
      case GUI_VARIABLE_SAVING_MESSAGES:
        if (op == -1)       /* query */
          reply [1] = (contact_file_get (contact, "no_saving", NULL) < 0);
        else if (op == 0)   /* cancel message saving by creating no_saving */
          reply [1] = (contact_file_write (contact, "no_saving", "", 0) == 1);
        else if (op == 1) { /* save by deleting "no_saving" if any */
          contact_file_delete (contact, "no_saving");
          reply [1] = 1;
        }
        break;
      case GUI_VARIABLE_COMPLETE:
        if (op == -1) {     /* query */
          reply [1] = (contact_file_get (contact, "exchange", NULL) < 0);
        } else if (op == 1) { /* delete exchange file if any */
          contact_file_delete (contact, "exchange");
          if (is_invisible (contact))
            make_visible (contact);
          reply [1] = 1;
        } else {
          printf ("gui_variable_complete: unsupported %d/%d, %s\n",
                  op, code, contact);
        }
        break;
      case GUI_VARIABLE_READ_TIME:
        if (op == 1) {      /* set */
          set_last_read_time (contact);
        } else {
          printf ("gui_variable_read_time: unsupported %d/%d, %s\n",
                  op, code, contact);
        }
        break;
      case GUI_VARIABLE_HOP_COUNT:
      case GUI_VARIABLE_SECRET:
        if (op == -1) {      /* query */
          int hops = 0;
          char * s1 = NULL;
          char * s2 = NULL;
          if (parse_exchange_file (contact, &hops, &s1, &s2)) {
            if (code == GUI_VARIABLE_HOP_COUNT) {
              if (s1 != NULL)
                free (s1);
              if (s2 != NULL)
                free (s2);
              reply [1] = hops;
            } else {  /* code == GUI_VARIABLE_SECRET */
              if ((s1 != NULL) || (s2 != NULL)) {
                char * secret = s1;
                if (s2 != NULL)
                  secret = s2;
                int size = 2 + strlen (secret) + 1;
                char * my_reply = malloc_or_fail (size, "gui_variable_secret");
                my_reply [0] = GUI_QUERY_VARIABLE;
                my_reply [1] = 1;
                snprintf (my_reply + 2, size - 2, "%s", secret);
                gui_send_buffer (gui_sock, my_reply, size);
                if (s1 != NULL)
                  free (s1);
                if (s2 != NULL)
                  free (s2);
                /* do not send the reply, i.e. do not run the code at
                   the end of the function */
                return;
              }
            }
          } else {
            printf ("gui_variable_hop_count/secret: "
                    "unable to parse file for contact %s\n", contact);
          }
        } else {
          printf ("gui_variable_hop_count/secret: unsupported %d/%d, %s\n",
                  op, code, contact);
        }
        break;
      default:
        printf ("gui_variable: unsupported %d/%d, %s\n", op, code, contact);
        break;
      }
    } else if (strchr (contact, '@') != NULL) {  /* broadcast contact */
      if (op == -1) {     /* query -- the only supported operation for now */
        switch (code) {
        case GUI_VARIABLE_VISIBLE:
        case GUI_VARIABLE_COMPLETE:
        case GUI_VARIABLE_NOTIFY:
        case GUI_VARIABLE_READ_TIME:
          reply [1] = (get_other_bc_key (contact) != NULL);
          break;
        case GUI_VARIABLE_SAVING_MESSAGES:
        case GUI_VARIABLE_HOP_COUNT:
        case GUI_VARIABLE_SECRET:
          reply [1] = 0;   /* same for everyone */
          break;
        default:
          printf ("gui_variable: unsupported %d/%d, %s\n", op, code, contact);
        }
      } else if (op == 1) {
        switch (code) {
        case GUI_VARIABLE_VISIBLE:
        case GUI_VARIABLE_COMPLETE:
        case GUI_VARIABLE_READ_TIME:
          /* ok to set complete, visible, or read time for subscription */
          reply [1] = 1;
          break;
        default:
          printf ("gui_variable: unsupported %d for %d for broadcast %s\n",
                  op, code, contact);
        }
      } else {
        printf ("gui_variable: unsupported %d/%d for broadcast %s\n",
                op, code, contact);
      }
    }
    free (contact);
  }
  gui_send_buffer (gui_sock, reply, sizeof (reply));
}

static void gui_send_result_messages (int code,
                                      struct message_store_info * msgs,
                                      int count, int sock,
                                      unsigned long long int lr)
{
/* format: code, 64-bit number of messages, then the messages
   each message has type, sequence, number of missing prior sequence
   numbers, time sent, timezone sent, time received, and
   null-terminated message contents.
   type                1 byte     byte  0      1 sent, 2 sent+acked, 3 received
   sequence            8 bytes    bytes 1..8
   missing             8 bytes    bytes 9..16  0 for sent messages
   time_sent           8 bytes    bytes 17..24
   timezone            2 bytes    bytes 25..26
   time_received       8 bytes    bytes 27..34
   is_new              1 byte     byte  35
   message             n+1 bytes  bytes 36...
 */
#define MESSAGE_ARRAY_HEADER_SIZE	9
#define MESSAGE_HEADER_SIZE		36
  size_t message_alloc = 0;
  int i;
  for (i = 0; i < count; i++)
    message_alloc += (MESSAGE_HEADER_SIZE + strlen (msgs [i].message) + 1);
  size_t alloc = MESSAGE_ARRAY_HEADER_SIZE + message_alloc;
/* printf ("gui_send_result_messages (%d, %p, %d, %d, %llu) allocating %zd(%zd)\n", code, msgs, count, sock, lr, alloc, message_alloc); */
  char * reply = malloc_or_fail (alloc, "gui_send_messages");
  memset (reply, 0, alloc);  /* clear everything */
  reply [0] = code;
  writeb64 (reply + 1, count);
  char * dest = reply + MESSAGE_ARRAY_HEADER_SIZE;
  for (i = 0; i < count; i++) {
    if (msgs [i].msg_type == MSG_TYPE_RCVD)
      dest [0] = 3;
    else if (msgs [i].message_has_been_acked)
      dest [0] = 2;
    else
      dest [0] = 1;
    writeb64 (dest + 1, msgs [i].seq);
    writeb64 (dest + 9, 0);
    if (msgs [i].msg_type == MSG_TYPE_RCVD)
      writeb64 (dest + 9, msgs [i].prev_missing);
    writeb64 (dest + 17, msgs [i].time);
    writeb16 (dest + 25, msgs [i].tz_min);
    writeb64 (dest + 27, msgs [i].rcvd_ackd_time);
    dest [35] = (lr < msgs [i].rcvd_ackd_time);
    strcpy (dest + MESSAGE_HEADER_SIZE, msgs [i].message);
/* if (i + 10 > count) {
int len = MESSAGE_HEADER_SIZE + strlen (msgs [i].message) + 1;
char s [1000];
snprintf (s, sizeof (s), "%d/%d: bytes %zd..%zd of %zd",
i, count, (dest - reply), ((dest + len - 1) - reply), alloc);
print_buffer (dest, len, s, 40, 1);
} */
    dest += MESSAGE_HEADER_SIZE + strlen (msgs [i].message) + 1;
  }
  gui_send_buffer (sock, reply, alloc);
  free (reply);
#undef MESSAGE_HEADER_SIZE
#undef MESSAGE_ARRAY_HEADER_SIZE
}

static void gui_get_messages (char * message, int64_t length, int gui_sock)
{
/* message format: 64-bit max, contact name (not null terminated) */
/* max is zero to request all messages */
/* reply format: 1-byte code, 64-bit number of messages, messages each
 * in the format shown under gui_send_result_messages */
  char reply_header [9];
  reply_header [0] = GUI_GET_MESSAGES;
  writeb64 (reply_header + 1, 0);   /* in case of failure */
  if (length >= 9) {
    int64_t max = readb64 (message);
    message += 8;
    length -= 8;
    char * contact = contact_name_from_buffer (message, length);
    unsigned long long int latest = last_read_time (contact);
    if (num_keysets (contact) > 0) { /* contact exists */
      /* for now, use list_all_messages.  Later, modify list_all_messages
       * to accept a maximum number of messages */
      struct message_store_info * msgs = NULL;
      int num_alloc = 0;
      int num_used = 0;
      if (list_all_messages (contact, &msgs, &num_alloc, &num_used)) {
        unsigned long long int debug_time = allnet_time ();
        for (int dbg = 0; dbg < num_used; dbg++) {
          if ((msgs [dbg].time > debug_time) ||
              (msgs [dbg].rcvd_ackd_time > debug_time)) {
            printf ("gui_get_messages for contact %s message %d: "
                    "times %" PRIu64 " or %" PRIu64 " > %llu\n",
                    contact, dbg, msgs [dbg].time,
                    msgs [dbg].rcvd_ackd_time, debug_time);
          }
        }
        int nresult = num_used;
        if ((max > 0) && (nresult > max))
          nresult = max;
        gui_send_result_messages (GUI_GET_MESSAGES, msgs, nresult,
                                  gui_sock, latest);
        free_all_messages (msgs, num_used);
        free (contact);
        return;
      }
    }
    free (contact);
  }
  /* if we didn't reply above, something went wrong.  Send 0 messages */
  gui_send_buffer (gui_sock, reply_header, sizeof (reply_header));
}

struct send_args_struct {
  int sock;
  char * contact;
  char * message;
  uint64_t expected_seq;
};

static void * send_message_thread (void * arg) {
  struct send_args_struct * a = (struct send_args_struct *) arg;
  uint64_t result = send_data_message (a->sock, a->contact,
                                       a->message, strlen (a->message));
  if (result != a->expected_seq)
    printf ("error: sent message '%s' to '%s' with sequence %" PRIu64
            ", expected %" PRIu64 "\n", a->message, a->contact, result,
            a->expected_seq);
  free (a->contact);
  free (a->message);
  free (a);
  return NULL;
}

static void gui_send_message (char * message, int64_t length, int broadcast,
                             int gui_sock, int allnet_sock)
{
/* message format: contact name and message, both null terminated */
/* reply format: 1-byte code, 64-bit sequence number (0 in case of error) */
  char reply_header [9];
  reply_header [0] = GUI_SEND_MESSAGE;
  writeb64 (reply_header + 1, 0);
  if (length >= 4) {
    char * contact = message;
    size_t offset = strlen (message) + 1;  /* should be index of message */
    if (offset + 1 < length) { /* room for message, plus null termination */
      char * to_send = message + offset;
      if ((strlen (to_send) > 0) && (strlen (contact) > 0) &&
          (num_keysets (contact) > 0)) {  /* contact and message exist */
        if (broadcast) {
          printf ("sending broadcast messages not implemented yet\n");
        } else {
          /* sending takes too long, so do it in a separate thread */
          uint64_t expected = highest_seq_any_key (contact, MSG_TYPE_SENT) + 1;
          size_t size = sizeof (struct send_args_struct);
          struct send_args_struct * a = malloc_or_fail (size, "gui_send");
          a->sock = allnet_sock;
          a->contact = strcpy_malloc (contact, "gui_send_message contact");
          a->message = strcpy_malloc (to_send, "gui_send_message message");
          a->expected_seq = expected;
          pthread_t t;
          pthread_create (&t, NULL, send_message_thread, a);
          pthread_detach (t);
          writeb64 (reply_header + 1, expected);
        }
      }
    }
  }
  gui_send_buffer (gui_sock, reply_header, sizeof (reply_header));
}

static void gui_init_key_exchange (const char * message, int64_t length,
                                   int gui_sock, int allnet_sock)
{
/* message format: 1-byte hop count, contact name and one or two secrets,
 * all null terminated */
/* reply format: 1-byte code, 1-byte result: 1 for success, 0 failure,
   and two normalized secrets, null terminated */
  char reply_header [2];
  reply_header [0] = GUI_KEY_EXCHANGE;
  reply_header [1] = 0;  /* failure */
  char * reply = reply_header;
  size_t rheadersize = sizeof (reply_header);
  size_t rsize = rheadersize;
  int hops = * ((unsigned char *)message);
  const char * contact = message + 1;
  if (length > 1 + strlen (contact) + 1 + 2 + 1) {
    const char * raw_secret1 = contact + (strlen (contact) + 1);
    const char * raw_secret2 = 
      ((length > (1 + strlen (contact) + 1 + strlen (raw_secret1) + 1)) ?
       (contact + (strlen (contact) + 1 + strlen (raw_secret1) + 1)) : NULL);
    rsize += strlen (raw_secret1) + 1 +
             ((raw_secret2 != NULL) ? strlen (raw_secret2) : 0) + 1;
    reply = malloc_or_fail (rsize, "gui_init_key_exchange");
    memcpy (reply, reply_header, rheadersize);
    char * norm_secret1 = reply + rheadersize;
    strcpy (norm_secret1, raw_secret1); 
    normalize_secret (norm_secret1);
    char * norm_secret2 = reply + rheadersize + strlen (norm_secret1) + 1;
    *norm_secret2 = '\0';    /* in case raw_secret2 is NULL */
    if (raw_secret2 != NULL) {
      strcpy (norm_secret2, raw_secret2); 
      normalize_secret (norm_secret2);
    }
    reply [1] =
      create_contact_send_key (allnet_sock, contact,
                               norm_secret1, norm_secret2, hops);
  } else {
    printf ("gui_init_key_exchange error: length %" PRId64
            ", contact %s (%zd)\n", length, contact, strlen (contact));
  }
  gui_send_buffer (gui_sock, reply, rsize);
  if (rsize > rheadersize)
    free (reply);
}

static void gui_subscribe (char * message, int64_t length,
                           int gui_sock, int allnet_sock)
{
/* message format: ahra, not null-terminated */
/* reply format: 1-byte code, 1-byte result: 1 for success, 0 failure */
  char reply_header [2];
  reply_header [0] = GUI_SUBSCRIBE;
  reply_header [1] = 0;  /* failure */
  if (length > 0) {
    char * ahra = contact_name_from_buffer (message, length);
    reply_header [1] = subscribe_broadcast (allnet_sock, ahra);
    free (ahra);
  }
  gui_send_buffer (gui_sock, reply_header, sizeof (reply_header));
}

static void gui_trace (char * message, int64_t length,
                       int gui_sock, int allnet_sock)
{
/* message format: 1-byte nhops, 1-byte nbits, 1-byte record intermediates,
   8-byte address */
/* reply format: 1-byte code, 16-byte trace ID (all 0s for failure) */
  char reply_header [1 + MESSAGE_ID_SIZE];
  reply_header [0] = GUI_TRACE;
  memset (reply_header + 1, 0, sizeof (reply_header) - 1);
  if (length >= 3 + ADDRESS_SIZE) {
    int nhops = ((unsigned char *)message) [0];
    int nbits = ((unsigned char *)message) [1];
    int inter =                   message  [2];
    unsigned char addr [ADDRESS_SIZE];
    memcpy (addr, message + 3, ADDRESS_SIZE);
    if (! start_trace (allnet_sock, addr, nbits, nhops, inter,
                       reply_header + 1, 1000))
      memset (reply_header + 1, 0, sizeof (reply_header) - 1);
  }
  gui_send_buffer (gui_sock, reply_header, sizeof (reply_header));
}

static void gui_busy_wait (int gui_sock, int allnet_sock)
{
/* reply format: 1-byte code */
  do_request_and_resend (allnet_sock); 
  char reply_header [1];
  reply_header [0] = GUI_BUSY_WAIT;
  gui_send_buffer (gui_sock, reply_header, sizeof (reply_header));
}

static void interpret_from_gui (char * message, int64_t length,
                                int gui_sock, int allnet_sock)
{
  switch ((unsigned char) (message [0])) {
  case GUI_CONTACTS:
    gui_contacts (gui_sock);
    break;
  case GUI_SUBSCRIPTIONS:
    gui_subscriptions (gui_sock);
    break;
  case GUI_CONTACT_EXISTS:
    gui_contact_exists (message + 1, length - 1, gui_sock);
    break;
  case GUI_CONTACT_IS_GROUP:
    gui_contact_is_group (message + 1, length - 1, gui_sock);
    break;
  case GUI_HAS_PEER_KEY:
    gui_contact_has_peer_key (message + 1, length - 1, gui_sock);
    break;

  case GUI_CREATE_GROUP:
    gui_create_group (message + 1, length - 1, gui_sock);
    break;
  case GUI_MEMBERS :
    gui_members (message [0], message + 1, length - 1, gui_sock, 0);
    break;
  case GUI_MEMBERS_RECURSIVE:
    gui_members (message [0], message + 1, length - 1, gui_sock, 1);
    break;
  case GUI_MEMBER_OF_GROUPS :
    gui_member_of (message [0], message + 1, length - 1, gui_sock, 0);
    break;
  case GUI_MEMBER_OF_GROUPS_RECURSIVE:
    gui_member_of (message [0], message + 1, length - 1, gui_sock, 1);
    break;

  case GUI_RENAME_CONTACT:
    gui_rename_contact (message + 1, length - 1, gui_sock);
    break;
  case GUI_DELETE_CONTACT:
    gui_delete_contact (message + 1, length - 1, gui_sock);
    break;
  case GUI_CLEAR_CONVERSATION:
    gui_clear_conversation (message + 1, length - 1, gui_sock);
    break;

  case GUI_QUERY_VARIABLE:
    gui_variable (message + 1, length - 1, -1, gui_sock);
    break;
  case GUI_SET_VARIABLE:
    gui_variable (message + 1, length - 1, 1, gui_sock);
    break;
  case GUI_UNSET_VARIABLE:
    gui_variable (message + 1, length - 1, 0, gui_sock);
    break;

  case GUI_GET_MESSAGES:
    gui_get_messages (message + 1, length - 1, gui_sock);
    break;
  case GUI_SEND_MESSAGE:
    gui_send_message (message + 1, length - 1, 0, gui_sock, allnet_sock);
    break;
  case GUI_SEND_BROADCAST:
    gui_send_message (message + 1, length - 1, 1, gui_sock, allnet_sock);
    break;

  case GUI_KEY_EXCHANGE:
    gui_init_key_exchange (message + 1, length - 1, gui_sock, allnet_sock);
    break;
  case GUI_SUBSCRIBE:
    gui_subscribe (message + 1, length - 1, gui_sock, allnet_sock);
    break;
  case GUI_TRACE:
    gui_trace (message + 1, length - 1, gui_sock, allnet_sock);
    break;

  case GUI_BUSY_WAIT:
    gui_busy_wait (gui_sock, allnet_sock); 
    break;

  default:
    printf ("command from GUI has unknown code %d\n", message [0]); 
    break;
  }
}

void * gui_respond_thread (void * arg)
{
  int * socks = (int*)arg;
  int gui_sock = socks [0];
  int allnet_sock = socks [1];
  free (arg);
#ifdef DEBUG_PRINT
  printf ("gui_respond_thread (%d, %d) started\n", gui_sock, allnet_sock);
#endif /* DEBUG_PRINT */
  char * message = NULL;
  int64_t mlen = 0;
  while ((mlen = receive_buffer (gui_sock, &message)) > 0) {
    interpret_from_gui (message, mlen, gui_sock, allnet_sock);
    free (message);
    message = NULL;
  }
#ifdef DEBUG_PRINT
  printf ("gui_respond_thread socket closed, receive thread exiting\n");
#endif /* DEBUG_PRINT */
  stop_chat_and_exit (0);
  return NULL;
}

