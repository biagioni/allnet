/* arems.c: execute command from trusted remote senders (Allnet REMote Shell) */
/* invoke as "arems -s sender1 sender2 ... senderN" to invoke as a server */
/* invoke as "arems receiver command" to invoke as a client */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "lib/packet.h"
#include "lib/media.h"
#include "lib/util.h"
#include "lib/app_util.h"
#include "lib/priority.h"
#include "lib/cipher.h"
#include "lib/keys.h"
#include "lib/media.h"

#define MAX_STRING_LENGTH	450  /* maximum length of command or response */
#define MEDIA_ID	ALLNET_MEDIA_TEXT_PLAIN
#define APP_ID		"REMS"

/* returns a pointer to the start of the allnet payload,
 * after the message ack if any, or NULL in case of errors */
static char * send_ack (struct allnet_header * hp, int msize)
{
  char * result = ALLNET_DATA_START (hp, hp->transport, msize);
  if ((hp->transport & ALLNET_TRANSPORT_ACK_REQ) == 0) {
    /* printf ("packet not requesting an ack, no ack sent\n"); */
    return result;
  }
  const unsigned char * message_ack = (const unsigned char *) result;
  result += MESSAGE_ID_SIZE;   /* skip over the ack */
  unsigned int size;
  char buffer [ALLNET_ACK_MIN_SIZE];
  struct allnet_header * ackp = init_ack (hp, message_ack, NULL, ADDRESS_BITS,
                                          buffer, &size);
  if (ackp == NULL)
    return result;
  local_send ((char *) ackp, size, ALLNET_PRIORITY_LOCAL);
print_buffer (message_ack, MESSAGE_ID_SIZE, "sent ack", 8, 1);
  return result;
}

static int my_system (const char * command, char * result, int rsize,
                      const char * contact)
{
  int syslog_option = LOG_DAEMON | LOG_WARNING;
  int pipes [2];
  if (pipe (pipes) != 0) {
    perror ("pipe");
    return 0;
  }
  pid_t pid = fork ();
  if (pid == 0) {
printf ("executing '%s' from %s\n", command, contact);
syslog (syslog_option, "executing '%s' from %s\n", command, contact);
    close (STDIN_FILENO);
    close (STDOUT_FILENO);
    close (STDERR_FILENO);
    close (pipes [0]);
    dup2 (pipes [1], STDOUT_FILENO);
    dup2 (pipes [1], STDERR_FILENO);
    execlp ("/bin/bash", "bash", "-c", command, NULL);
    perror ("execlp");
    exit (1);  /* in case of exec errors */
  }
  close (pipes [1]);
  int status = 0;
  waitpid (pid, &status, 0);
  int n = 0;
  int total = 0;
  int esize = rsize - 1;  /* effective size remaining */
  while ((total + 1 < rsize) &&
         ((n = read (pipes [0], result + total, esize)) > 0)) {
    total += n;
    esize -= n;
  }
  close (pipes [0]);
  result [total] = '\0';
  if (total + 1 < rsize)
    snprintf (result + total, rsize - total, "status %x\n", status);
printf ("sending response:\n%s", result);
syslog (syslog_option, "sending response: '%s'\n", result);
  return strlen (result);
}

static void encrypt_sign_send (const char * data, int dsize, int hops,
                               const char * contact, keyset k)
{
  allnet_rsa_prvkey priv_key;
  allnet_rsa_pubkey key;
  int priv_ksize = get_my_privkey (k, &priv_key);
  int ksize = get_contact_pubkey (k, &key);
  if ((priv_ksize == 0) || (ksize == 0)) {
    printf ("unable to locate key %d for contact %s (%d, %d)\n",
            k, contact, priv_ksize, ksize);
    return;
  }
  struct allnet_app_media_header amh;
  memcpy (amh.app, APP_ID, sizeof (amh.app));
  writeb32u (amh.media, MEDIA_ID);
  char data_with_amh [MAX_STRING_LENGTH + sizeof (amh)];
  memcpy (data_with_amh, &amh, sizeof (amh));
  memcpy (data_with_amh + sizeof (amh), data, dsize);
  char * encrypted = NULL;
  char * signature = NULL;
  int esize = allnet_encrypt (data_with_amh, dsize + sizeof (amh), key,
                              &encrypted);
  if (esize == 0) {
    printf ("unable to encrypt, contact %s key %d, data %p %d bytes\n",
            contact, k, data, dsize);
    return;
  } /* else, sign */
  int ssize = allnet_sign (encrypted, esize, priv_key, &signature);
  if (ssize == 0) {
    printf ("unable to sign, contact %s key %d, data %p %d bytes esize %d\n",
            contact, k, data, dsize, esize);
    return;
  } /* else, create a packet and send it */
  int payload_size = esize + ssize + 2;
  /* note if we ever add acks: if ack is not NULL, init_packet adds
   * MESSAGE_ID_SIZE to the size, so we should subtract it from payload_size */
  char buffer [ALLNET_MTU];
  unsigned char local_address [ADDRESS_SIZE];
  unsigned char remote_address [ADDRESS_SIZE];
  int sbits = get_local (k, local_address);
  int dbits = get_remote (k, remote_address);
  struct allnet_header * hp =
    init_packet (buffer, payload_size, ALLNET_TYPE_DATA, hops,
                 ALLNET_SIGTYPE_RSA_PKCS1,
                 local_address, sbits, remote_address, dbits, NULL, NULL);
  char * payload = buffer + ALLNET_SIZE (hp->transport);
  memcpy (payload, encrypted, esize);
  memcpy (payload + esize, signature, ssize);
  writeb16 (payload + esize + ssize, ssize);
  int size = ALLNET_SIZE (hp->transport) + payload_size;
  local_send ((char *) buffer, size, ALLNET_PRIORITY_LOCAL);
  if (encrypted != NULL)
    free (encrypted);
  if (signature != NULL)
    free (signature);
}

/* returns 1 if the receive loop should exit, 0 if it should continue
 * hops is the number of hops visited by the incoming packet. */
typedef int (* received_packet_handler) (void * state,
                                         const char * data, int dsize, int hops,
                                         const char * contact, keyset k);

/* timeout is in ms, -1 to never time out */
static void receive_packet_loop (received_packet_handler handler, void * state,
                                 char ** authorized, int nauth, int timeout)
{
  long long int quitting_time = allnet_time_ms () + timeout;
  int msize = 0;
  char * message = NULL;
  unsigned int priority;
  while (((timeout < 0) || (allnet_time_ms () <= quitting_time)) &&
         (msize = local_receive (timeout, &message, &priority)) > 0) {
    if (message == NULL) {
      printf ("error: received null message, msize %d\n", msize);
      continue;   /* next packet, please */
    }
    char * error_desc = NULL;
    if (! is_valid_message (message, msize, &error_desc))
      continue;   /* next packet, please */
    if ((msize < ALLNET_HEADER_SIZE) || (message [1] != ALLNET_TYPE_DATA))
      continue;   /* next packet, please */
#ifdef DEBUG_PRINT
    print_buffer (message, msize, "received", 10, 0);
    printf (", dst ");
    print_buffer (message + 16, 8, NULL, 2, 1);
#endif /* DEBUG_PRINT */
    char * contact = NULL;
    keyset k;
    char * text = NULL;
    struct allnet_header * hp = (struct allnet_header *) message;
    char * payload = message + ALLNET_SIZE (hp->transport);
    int psize = msize - ALLNET_SIZE (hp->transport);
    if (psize > 0) {
      int tsize = decrypt_verify (ALLNET_SIGTYPE_RSA_PKCS1, payload, psize,
                                  &contact, &k, &text,
                                  (char *) hp->source, hp->src_nbits,
                                  (char *) hp->destination, hp->dst_nbits, 0);
      if (tsize > 8) {
        int i;
        int is_authorized = 0;
        for (i = 0; i < nauth; i++) {
          if (strcmp (contact, authorized [i]) == 0)
            is_authorized = 1;
        }
        if (! is_authorized) {
          printf ("got message from %s, who is not authorized\n", contact);
          continue;   /* next packet, please */
        }
        char * p = text + ((hp->transport & ALLNET_TRANSPORT_ACK_REQ) ?
                           MESSAGE_ID_SIZE : 0);
        struct allnet_app_media_header * amhp =
          (struct allnet_app_media_header *) p;
        if ((memcmp (amhp->app, APP_ID, sizeof (amhp->app)) != 0) ||
            (readb32u (amhp->media) != MEDIA_ID)) {
          char print_app [5];
          memcpy (print_app, amhp->app, 4);
          print_app [4] = '\0';
          printf ("from %s unexpected app %s media %ld, expected %s %d\n",
                  contact, print_app, readb32u (amhp->media), APP_ID, MEDIA_ID);
          continue;   /* next packet, please */
        }
        send_ack (hp, msize);
        char string [ALLNET_MTU + 1];  /* a null-terminated C string */
        memcpy (string, text + sizeof (struct allnet_app_media_header),
                tsize - sizeof (struct allnet_app_media_header));
        string [tsize - sizeof (struct allnet_app_media_header)] = '\0';
        /* printf ("got %d-byte message '%s' from %s/%d\n",
                tsize, string, contact, k); */
        if (handler (state, string, strlen (string), hp->hops, contact, k))
          break;
        free (text);
        free (contact);
      }
    }
  }
}

static int client_handler (void * state, /* ignored for now */
                           const char * data, int dsize, int hops,
                           const char * contact, keyset k)
{
  int * timed_out = (int *) state;
  printf ("from %s got response:\n%s", contact, data);
  *timed_out = 0;
  return 1;  /* exit */
}

static int server_handler (void * state, /* ignored for now */
                           const char * data, int dsize, int hops,
                           const char * contact, keyset k)
{
  char result [MAX_STRING_LENGTH];
  int rsize = my_system (data, result, sizeof (result), contact);
  encrypt_sign_send (result, rsize, hops + 2, contact, k);
  return 0;  /* continue the loop */
}

static void client_rpc (const char * data, int dsize, char * contact)
{
  printf ("sending command '%s' to %s\n", data, contact);
  keyset * k = NULL;
  int nkeys = all_keys (contact, &k);
  if (nkeys != 1) {
    printf ("error: contact %s has %d keys, 1 expected, aborting\n",
            contact, nkeys);
    return;
  }
  encrypt_sign_send (data, dsize, 10, contact, k [0]);
  char * authorized [1] = { contact };
  int timed_out = 1;
  receive_packet_loop (&client_handler, &timed_out, authorized, 1, 5000);
  if (timed_out)
    printf ("command timed out after 5 seconds\n");
}

static void server_loop (char ** const authorized, int nauth)
{
  receive_packet_loop (&server_handler, NULL, authorized, nauth, -1);
}

/* if it is a server, returns the updated list of authorized users
 * (modified from argv by replacing the "-s" arg with the last user)
 * otherwise returns NULL */
static char ** is_server (int argc, char ** argv, int * nauth)
{
  int found_switch = 0;
  int i;
  for (i = 1; i < argc; i++) {
    if (strcmp (argv [i], "-s") == 0)
      found_switch = i;
    else if (num_keysets (argv [i]) <= 0) {
      if (found_switch)
        printf ("found server switch -s, but user %s is unknown\n", argv [i]);
      return NULL;   /* not an authorized user */
    }
  }
  if (! found_switch)
    return NULL;
  if (found_switch + 1 < argc) {  /* swap the "-s" with the last parameter */
    argv [found_switch] = argv [argc - 1];
    argv [argc - 1] = NULL;
  }
  *nauth = argc - 2;
/* printf ("argv is now:");
  for (i = 0; i < *nauth; i++) printf (" %s", (argv + 1) [i]);
  printf (", nauth %d\n", *nauth); */
  return (argv + 1);
} 

int main (int argc, char ** argv)
{
  if (argc < 2) {
    printf ("%s: needs at least one remote authorized user\n", argv [0]);
    printf ("usage: %s -s authorized-user+\n", argv [0]);
    printf (" or    %s receiver command\n", argv [0]);
    exit (1);
  }
  int nauth = 0;
  char ** authorized = is_server (argc, argv, &nauth);
  int server = (authorized != NULL);
  int sock = connect_to_local (argv [0], argv [0], NULL, 1, 1);
  if (sock < 0) {
    printf ("error: unable to connect to allnet daemon\n");
    exit (1);
  }
  if (server) {
    int i;
    printf ("arems -s: will execute commands from: ");
    for (i = 0; i < nauth; i++)
      printf ("%s%s", authorized [i], ((i + 1 >= nauth) ? "\n" : ", "));
    server_loop (authorized, nauth);  /* infinite loop */
  } else if (argc > 2) {
    char * contact = argv [1];
    char command [MAX_STRING_LENGTH];
    int off = 0;
    int i;
    for (i = 2; (i < argc) && (off < sizeof (command)); i++)
      off += snprintf (command + off, sizeof (command) - off, "%s%s",
                       argv [i], ((i + 1 < argc) ? " " : ""));
    client_rpc (command, strlen (command), contact);
  }
}
