/* xchats.c: send xchat messages */
/* parameters are: name of contact and message */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <inttypes.h>

#include "lib/packet.h"
#include "lib/util.h"
#include "lib/priority.h"
#include "lib/allnet_log.h"
#include "lib/app_util.h"
#include "chat.h"
#include "cutil.h"
#include "retransmit.h"
#include "xcommon.h"
#include "message.h"

/* returns the number of ms from now until the deadline, or 0 if the
 * deadline has passed */
static int until_deadline (struct timeval * deadline)
{
  struct timeval now;
  gettimeofday (&now, NULL);
  int result = (deadline->tv_sec  - now.tv_sec ) * 1000 +
               (deadline->tv_usec - now.tv_usec) / 1000;
/*  printf ("%2ld.%06ld, %4d until deadline %2ld.%06ld\n",
          now.tv_sec % 100, now.tv_usec, result,
          deadline->tv_sec % 100, deadline->tv_usec); */
  if (result < 0)
    return 0;
  return result;
}

static void add_time (struct timeval * time, unsigned int ms)
{
  time->tv_usec += ms * 1000;
  time->tv_sec += time->tv_usec / 1000000;
  time->tv_usec = time->tv_usec % 1000000;
}

int main (int argc, char ** argv)
{
  log_to_output (get_option ('v', &argc, argv));
  if (argc < 2) {
    printf ("usage: %s contact-name [message]\n", argv [0]);
    printf ("   or: %s -k contact-name [hops [secret]] (hops defaults to 1)\n",
            argv [0]);
    return 1;
  }

  int sock = xchat_init (argv [0], NULL, 0);
  if (sock < 0)
    return 1;

  int ack_expected = 0;
  uint64_t sent_seq = 0;
  char * contact = argv [1];  /* contact we send to, peer we receive from */

#define MAX_SECRET	15  /* including a terminating null character */
  char secret_buf [MAX_SECRET + 1000];
  unsigned int wait_time = 5000;   /* 5 seconds to wait for acks and such */
  unsigned long long int start_time = allnet_time_ms ();

  int exchanging_key = 0;
  int print_duplicates = 1;
  char * kcontact = "no contact";
  unsigned int khop = 1;
  if (strcmp (contact, "-k") == 0) {   /* send a key */
    exchanging_key = 1;
    print_duplicates = 0;
    if ((argc != 3) && (argc != 4) && (argc != 5)) {
      printf ("usage: %s -k contact-name [hops [secret]] (%d)\n",
              argv [0], argc);
      return 1;
    }
    kcontact = argv [2];
    if (argc >= 4) {
      char * end;
      int n = strtol (argv [3], &end, 10);
      if (end != argv [3])
        khop = n;
    }
    char * whose = "peer";
    if (argc >= 5) {
      snprintf (secret_buf, sizeof (secret_buf), "%s", argv [4]);
    } else {
      whose = "my";
      random_string (secret_buf, MAX_SECRET);
      if (khop <= 1)
        secret_buf [6] = '\0';   /* for direct contacts, truncate to 6 chars */
    }
    printf ("%d hops, %s secret string is '%s'", khop, whose, secret_buf);
    normalize_secret (secret_buf);
    printf (" (or %s)\n", secret_buf);

    wait_time = 10 * 24 * 3600 * 1000;   /* wait up to 10 days for a key */
    if (! create_contact_send_key (sock, kcontact, secret_buf, NULL, khop))
      return 1;
  } else { /* send the data packet */
    int i;
    keyset * keys = NULL;
    int nkeys = all_keys (contact, &keys);
    if (nkeys > 0) {
      int max_key = 0;
      for (i = 0; i < nkeys; i++) {
        allnet_rsa_prvkey key;
        int ksize = get_my_privkey (keys [i], &key);
        if (ksize > max_key)
          max_key = ksize;
      }
      static char text [ALLNET_MTU] = "";
      int size = sizeof (text) - CHAT_DESCRIPTOR_SIZE -
                 ALLNET_SIZE (ALLNET_TRANSPORT_ACK_REQ) -
                 max_key; /* the maximum size of a signature */
      char * p = text;
      int printed = 0;
      for (i = 2; i < argc; i++) {
        int n = snprintf (p, size, "%s%s", argv [i], (i + 1 < argc) ? " " : "");
        printed += n;
        p += n;
        size -= n;
      }
      if ((printed == 0) || (strlen (text) == 0)) {  /* read from stdin */
        int c = '\0';
        while ((printed + 1 < size) && ((c = getchar ()) != EOF))
          text [printed++] = c;
        text [printed] = '\0';  /* make it into a valid C string */
      }
   /* printf ("sending %d chars: '%s'\n", printed, text); */
      if ((printed > 0) && (strlen (text) >= 0)) {  /* read from stdin */
        sent_seq = send_data_message (sock, contact, text, printed);
        if (sent_seq == 0)
          printf ("error sending message\n");
        ack_expected = 1;
      } else
        printf ("no content to send, not sending message\n");
      free (keys);
    } else if (nkeys == 0) {
      printf ("error: no keys for contact '%s'\n", contact);
    } else if (nkeys < 0) {
      printf ("error: contact '%s' does not exist\n", contact);
    }
  }
  unsigned long long int send_time = allnet_time_ms () - start_time;
  if ((! exchanging_key) && (20 * send_time > wait_time))
    wait_time = 20 * send_time;
  if (exchanging_key && (send_time > 1000))
    printf ("took %lld seconds to generate the key\n", (send_time / 1000));

  struct timeval start, deadline;
  gettimeofday (&start, NULL);
  gettimeofday (&deadline, NULL);
  add_time (&deadline, wait_time);
  int max_wait = until_deadline (&deadline);
  int key_received = 0;
  keyset kcontact_kset = -1;
  while (exchanging_key || (max_wait > 0)) {
    char * packet;
    unsigned int pri;
    int actual_wait = ((max_wait > 100) ? 100 : max_wait);
    int found = local_receive (actual_wait, &packet, &pri);
    if (found < 0) {
      printf ("xchats pipe closed, exiting\n");
      exit (1);
    }
    int verified = 0, duplicate = -1, broadcast = -2;
    uint64_t rcvd_seq = 0;
    char * desc = NULL;
    char * message = NULL;
    char * peer = NULL;
    struct allnet_ack_info acks;
    acks.num_acks = 0;
    keyset kset = -1;
    int mlen = handle_packet (sock, packet, found, pri, &peer, &kset,
                              &message, &desc, &verified, &rcvd_seq, NULL,
                              NULL, &duplicate, &broadcast, &acks, NULL);
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
        bc_mess = "broadcast ";
        dup_mess = "";
        desc = "";
      }
      if ((! duplicate) || print_duplicates)
        printf ("from '%s'%s got %s%s%s\n  %s\n",
                peer, ver_mess, dup_mess, bc_mess, desc, message);
    } else if (mlen == -1) {  /* successful key exchange */
      if (strcmp (peer, kcontact) == 0) {
        if (! key_received) {
          kcontact_kset = kset;
          printf ("success!  got remote key for %s\n", peer);
          printf ("please press <enter> once your contact has %s\n",
                  "also received the key");
          key_received = 1;
        }
      }
    }
  /* handle_packet may change what has been acked */
    int i;
    for (i = 0; i < acks.num_acks; i++) {
      if ((ack_expected) && (sent_seq == acks.acks [i]) &&
          (strcmp (contact, acks.peers [i]) == 0)) {
        struct timeval finish;
        gettimeofday (&finish, NULL);   /* how long did the ack take? */
        long long int delta = (finish.tv_sec  - start.tv_sec ) * 1000000LL +
                              (finish.tv_usec - start.tv_usec);
        printf ("got ack from %s in %lld.%06llds\n", contact,
                delta / 1000000, delta % 1000000);
        gettimeofday (&deadline, NULL);   /* wait another wait_time */
        add_time (&deadline, wait_time);  /* for additional messages */
        ack_expected = 0;
      }
    }
    for (i = 0; i < acks.num_acks; i++)
      free (acks.peers [i]);
    if (mlen > 0) {
      free (peer);
      free (message);
      if (! broadcast)
        free (desc);
    }
    max_wait = until_deadline (&deadline);
    if (key_received) {
      struct timeval tv;
      tv.tv_usec = 0;
      tv.tv_sec = 0;
      fd_set fds;
      FD_ZERO (&fds);
      FD_SET (STDIN_FILENO, &fds);
      int ready = select (STDIN_FILENO + 1, &fds, NULL, NULL, &tv);
      if (ready > 0) {
        printf ("confirmed, thank you\n");
        /* complete the exchange */
        incomplete_exchange_file (kcontact, kcontact_kset, NULL, NULL);
        /* make contact visible */
        make_visible (kcontact);
        break;
      } else if (ready < 0) {
        perror ("select(stdin)");
      }
    }
  }
printf ("xchats main exiting\n");
  return 0;
}
