/* gui_callback.c: send callbacks to the GUI */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lib/util.h"
#include "lib/keys.h"
#include "lib/app_util.h"
#include "gui_socket.h"
#include "xcommon.h"
#include "cutil.h"

static void gui_callback_message_received (const char * peer,
                                           const char * message,
                                           const char * desc,
                                           uint64_t seq, time_t mtime,
                                           int broadcast, int gui_sock)
{
/* format: code, 1-byte broadcast, 8-byte sequence, 8-byte time,
           then null_terminated peer, message, and description */
  size_t string_alloc = strlen (peer) + strlen (message) +
                        ((desc == NULL) ? 0 : strlen (desc)) + 3;
#define RECEIVED_MESSAGE_HEADER_SIZE	18
  size_t alloc = RECEIVED_MESSAGE_HEADER_SIZE + string_alloc;
  char * reply = malloc_or_fail (alloc, "gui_callback_message_received");
  reply [0] = GUI_CALLBACK_MESSAGE_RECEIVED;
  reply [1] = broadcast;
  writeb64 (reply + 2, seq);
  writeb64 (reply + 10, mtime);
  char * p = reply + 18;
  strcpy (p, peer);
  p += strlen (peer) + 1;
  strcpy (p, message);
  p += strlen (message) + 1;
  if (desc != NULL) {
    strcpy (p, desc);
    p += strlen (desc) + 1;
  } else {       /* only put the terminating null character */
    *p = '\0';
    p++;
  }
  gui_send_buffer (gui_sock, reply, alloc);
  free (reply);
#undef RECEIVED_MESSAGE_HEADER_SIZE
}

static void gui_callback_message_acked (const char * peer, uint64_t ack,
                                        int gui_sock)
{
/* format: code, 8-byte ack, null-terminated peer */
  size_t string_alloc = strlen (peer) + 1;
#define RECEIVED_ACK_HEADER_SIZE			9
  size_t alloc = RECEIVED_ACK_HEADER_SIZE + string_alloc;
  char * reply = malloc_or_fail (alloc, "gui_callback_message_acked");
  reply [0] = GUI_CALLBACK_MESSAGE_ACKED;
  writeb64 (reply + 1, ack);
  strcpy (reply + RECEIVED_ACK_HEADER_SIZE, peer);
  gui_send_buffer (gui_sock, reply, alloc);
  free (reply);
#undef RECEIVED_ACK_HEADER_SIZE
}

static void gui_callback_created (int code, const char * peer, int gui_sock)
{
/* format: code, null_terminated peer */
  size_t alloc = 1 + strlen (peer) + 1;
  char * reply = malloc_or_fail (alloc, "gui_callback_created");
  reply [0] = code;
  strcpy (reply + 1, peer);
  gui_send_buffer (gui_sock, reply, alloc);
  free (reply);
}

static void gui_callback_trace_response (struct allnet_mgmt_trace_reply * trp,
                                         int gui_sock)
{
/* format: code, 1-byte intermediate (0 final), 1-byte num entries,
 * 16-byte trace-id (19 bytes), then for each entry:
 * 1-byte precision, 1-byte nbits, 1-byte hops, 8-byte seconds, 8-byte fraction,
 * and 8-byte address (27 bytes per entry) */
#define RECEIVED_TRACE_HEADER_SIZE	(1 + 1 + 1 + MESSAGE_ID_SIZE) /* 19 */
#define RECEIVED_TRACE_ENTRY_SIZE	(1 + 1 + 1 + ALLNET_TIME_SIZE /* 27 */ \
                                        + ALLNET_TIME_SIZE + ADDRESS_SIZE)
  size_t alloc = RECEIVED_TRACE_HEADER_SIZE
               + trp->num_entries * RECEIVED_TRACE_ENTRY_SIZE;
  char * reply = malloc_or_fail (alloc, "gui_callback_trace_received");
  reply [0] = GUI_CALLBACK_TRACE_RESPONSE;
  reply [1] = trp->intermediate_reply;
  reply [2] = trp->num_entries;
  memcpy (reply + 3, trp->trace_id, MESSAGE_ID_SIZE);
  int index = RECEIVED_TRACE_HEADER_SIZE;
  int ie;
  for (ie = 0; ie < trp->num_entries; ie++) {
    reply [index    ] = trp->trace [ie].precision;
    reply [index + 1] = trp->trace [ie].nbits;
    reply [index + 2] = trp->trace [ie].hops_seen;
    memcpy (reply + index + 3, trp->trace [ie].seconds, ALLNET_TIME_SIZE);
    memcpy (reply + index + 3 + ALLNET_TIME_SIZE,
            trp->trace [ie].seconds_fraction, ALLNET_TIME_SIZE);
    memcpy (reply + index + 3 + ALLNET_TIME_SIZE + ALLNET_TIME_SIZE,
            trp->trace [ie].address, ADDRESS_SIZE);
    index += RECEIVED_TRACE_ENTRY_SIZE;
  }
  if (index != alloc)
    printf ("error in gui_callback_trace_response: alloc %zd, index %d\n",
            alloc, index);
  gui_send_buffer (gui_sock, reply, alloc);
  free (reply);
#undef RECEIVED_TRACE_ENTRY_SIZE
#undef RECEIVED_TRACE_HEADER_SIZE
}

/* returns 1 if the contact is visible, 0 otherwise.
 * needed because is_visible only works for non-broadcast contacts */
static int local_is_visible (const char * contact, int broadcast)
{
  if (broadcast)
    return (get_other_bc_key (contact) != NULL);
  return is_visible (contact);
}

void gui_socket_main_loop (int gui_sock, int allnet_sock, pd p)
{
  int rcvd = 0;
  char * packet;
  unsigned int pri;
  int timeout = 100;      /* sleep up to 1/10 second */
  char * old_contact = NULL;
  keyset old_kset = -1;
  while ((rcvd = local_receive (timeout, &packet, &pri)) >= 0) {
#if 0
  while ((rcvd = receive_pipe_message_any (p, timeout, &packet, &pipe, &pri))
         >= 0) {
#endif /* 0 */
    int verified = 0, duplicate = -1, broadcast = -2;
    uint64_t seq = 0;
    char * peer = NULL;
    keyset kset = 0;
    char * desc = NULL;
    char * message = NULL;
    struct allnet_ack_info acks;
    acks.num_acks = 0;
    struct allnet_mgmt_trace_reply * trace = NULL;
    time_t mtime = 0;
    int mlen = handle_packet (allnet_sock, packet, rcvd, pri,
                              &peer, &kset, &message, &desc,
                              &verified, &seq, &mtime,
                              &duplicate, &broadcast, &acks, &trace);
#ifdef DEBUG_PRINT
if (mlen != 0) printf ("handle_packet returned %d\n", mlen);
#endif /* DEBUG_PRINT */
    if ((mlen > 0) && (verified) && (! duplicate)) {
      if (! duplicate) {
        if (broadcast) /* broadcast messages don't have time in their header */
          mtime = allnet_time ();
        if (local_is_visible (peer, broadcast))
          gui_callback_message_received (peer, message, desc, seq,
                                         mtime, broadcast, gui_sock);
        char ** groups = NULL;
        int ngroups = member_of_groups_recursive (peer, &groups);
        int ig;
        for (ig = 0; ig < ngroups; ig++) {
          if (is_visible (groups [ig]))
            gui_callback_message_received (groups [ig], message, desc, seq,
                                           mtime, broadcast, gui_sock);
        }
        if (groups != NULL)
          free (groups);
      }
      if ((! broadcast) &&
          ((old_contact == NULL) ||
           (strcmp (old_contact, peer) != 0) || (old_kset != kset))) {
        request_and_resend (allnet_sock, peer, kset, 1);
        if (old_contact != NULL)
          free (old_contact);
        old_contact = peer;
        old_kset = kset;
      } else { /* same peer or broadcast, do nothing */
        free (peer);
      }
      free (message);
      if (! broadcast)
        free (desc);
    } else if (mlen == -1) {   /* confirm successful key exchange */
      gui_callback_created (GUI_CALLBACK_CONTACT_CREATED, peer, gui_sock);
    } else if (mlen == -2) {   /* confirm successful subscription */
      gui_callback_created (GUI_CALLBACK_SUBSCRIPTION_COMPLETE, peer, gui_sock);
    } else if (mlen == -4) {   /* got a trace reply */
      gui_callback_trace_response (trace, gui_sock);
    }
    /* handle_packet may have changed what has and has not been acked */
    int i;
    for (i = 0; i < acks.num_acks; i++) {
      gui_callback_message_acked (acks.peers [i], acks.acks [i], gui_sock);
      free (acks.peers [i]);
    }
  }
  printf ("xchat_socket pipe closed, exiting\n");
}
