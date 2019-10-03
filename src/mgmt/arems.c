/* arems.c: execute command from trusted remote senders (Allnet REMote Shell) */
/* invoke as "arems -s sender1 sender2 ... senderN" to invoke as a server */
/* invoke as "arems receiver command" to invoke as a client */
/* commands and responses are sent with a per-contact counter (persistently
 * kept in ~/.allnet/contacts/.../arems_counter).  Only new counter values
 * will be executed, older commands are ignored. */

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
#include "lib/sha.h"

#define MAX_STRING_LENGTH	450  /* maximum length of command or response */
#define MEDIA_ID	ALLNET_MEDIA_TEXT_PLAIN
#define APP_ID		"REMS"
#define COUNTER_SIZE	8

struct arems_header {
  unsigned char message_ack [MESSAGE_ID_SIZE];  /* if no ack, random or 0 */
  struct allnet_app_media_header app_media;
#define COUNTER_TYPE_LOCAL	8  /* commands we send, responses we receive */
#define COUNTER_TYPE_REMOTE	9  /* commands we receive, responses we send */
  unsigned char counter     [   COUNTER_SIZE];
#define MESSAGE_TYPE_COMMAND	1  /* commands we send or receive */
#define MESSAGE_TYPE_RESPONSE	2  /* responses we send or receive */
  unsigned char type;       /* 1 for command, 2 for response */
  unsigned char padding     [7];
};

/* returns -1 in case of errors */
static long long int get_counter (const char * contact, keyset k, int ctype)
{
  char * kd = key_dir (k);
  if (kd == NULL) {
    printf ("get_counter: key_dir is NULL for %d\n", k);
    return -1;
  }
  char fname [PATH_MAX];
  snprintf (fname, sizeof (fname), "%s/arems_counter", kd);
  free (kd);
  char * content = NULL;
  int csize = read_file_malloc (fname, &content, 1);
  if (csize <= 0)
    return -1;
  char copy [100];
  if (csize >= sizeof (copy)) {
    printf ("error: arems_counter file has size %d\n", csize);
    return -1;
  }
  memcpy (copy, content, csize);
  copy [csize] = '\0';
  long long int local_counter;
  long long int remote_counter;
  int found = sscanf (copy, "%lld %lld", &local_counter, &remote_counter);
  if (found == 2) {
    if (ctype == COUNTER_TYPE_LOCAL)
      return local_counter;
    else if (ctype == COUNTER_TYPE_REMOTE)
      return remote_counter;
  }
  printf ("error: arems_counter copy '%s', found %d\n", copy, found);
  return -1;
}

static void save_counter (const char * contact, keyset k, long long int counter,
                          int ctype)
{
  long long int local_counter = 0;
  long long int remote_counter = 0;
  if (ctype == COUNTER_TYPE_LOCAL) {
    local_counter  = counter;
    remote_counter = get_counter (contact, k, COUNTER_TYPE_REMOTE);
  } else {
    local_counter  = get_counter (contact, k, COUNTER_TYPE_LOCAL );
    remote_counter = counter;
  }
  if (remote_counter < 0) remote_counter = 0;
  if (local_counter  < 0) local_counter  = 0;
  char * kd = key_dir (k);
  if (kd == NULL) {
    printf ("save_counter: key_dir is NULL for %d\n", k);
    return;
  }
  char fname [PATH_MAX];
  snprintf (fname, sizeof (fname), "%s/arems_counter", kd);
  free (kd);
  char content [100];
  snprintf (content, sizeof (content),
            "%lld %lld", local_counter, remote_counter);
  write_file (fname, content, strlen (content), 1);
}

static int command_timeout = 5;     /* time out commands after 5s by default */

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
/* print_buffer (message_ack, MESSAGE_ID_SIZE, "sent ack", 8, 1); */
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

/* report whether this message was recently received,
 * and if not, add it to the cache */
static int recently_received (const char * message, int msize)
{
  struct message_cache {
    char message [ALLNET_MTU];
    int msize;  /* 0 for a message that is not in here */
  };
#define RECENTLY_RECEIVED_MESSAGES	50
  static struct message_cache recent_messages [RECENTLY_RECEIVED_MESSAGES];
  static int last_message = -1;  /* after init, 0..99 */
  if ((msize > sizeof (recent_messages [0].message)) ||
      (msize <= ALLNET_HEADER_SIZE))
    return 0;
  const struct allnet_header * hp = (const struct allnet_header *) message;
  int hsize = ALLNET_SIZE (hp->transport);
  if (msize <= hsize)
    return 0;
  message += hsize;
  msize -= hsize;
  int i;
  if (last_message < 0) {
    for (i = 0; i < RECENTLY_RECEIVED_MESSAGES; i++)
      recent_messages [i].msize = 0;
    last_message = 0;
  }
  for (i = 0; i < RECENTLY_RECEIVED_MESSAGES; i++)
    if ((recent_messages [i].msize > 0) &&
        (recent_messages [i].msize == msize) &&
        (memcmp (recent_messages [i].message, message, msize) == 0))
      return 1;
  /* not found.  Add the message to the cache */
  last_message = (last_message + 1) % RECENTLY_RECEIVED_MESSAGES;
  recent_messages [last_message].msize = msize;
  memcpy (recent_messages [last_message].message, message, msize);
  return 0;
}

/* encrypts and signs the data and saves the result in destination_buffer
 * returns the size of the signed and encrypted content if all goes well
 * this size will always be <= dest_size and > 0.
 * returns 0 otherwise, i.e. in case of errors */
static int public_key_encrypt (const char * data, int dsize,
                               long long int counter, int message_type,
                               const char * contact, keyset k,
                               char * destination_buffer, int dest_size)
{
  allnet_rsa_prvkey priv_key;
  allnet_rsa_pubkey key;
  int priv_ksize = get_my_privkey (k, &priv_key);
  int ksize = get_contact_pubkey (k, &key);
  if ((priv_ksize == 0) || (ksize == 0)) {
    printf ("unable to locate key %d for contact %s (%d, %d)\n",
            k, contact, priv_ksize, ksize);
    return 0;
  }
  char * encrypted = NULL;
  char * signature = NULL;
  int esize = allnet_encrypt (data, dsize, key, &encrypted);
  if (esize == 0) {
    printf ("unable to encrypt, contact %s key %d, data %p %d bytes\n",
            contact, k, data, dsize);
    return 0;
  } /* else, sign */
  int ssize = allnet_sign (encrypted, esize, priv_key, &signature);
  if (ssize == 0) {
    printf ("unable to sign, contact %s key %d, data %p %d bytes esize %d\n",
            contact, k, data, dsize, esize);
    return 0;
  } /* else, create a packet and send it */
  int payload_size = esize + ssize + 2;
  if (payload_size > dest_size) {
    printf ("unable to save signed/encrypted data, %d available, %d needed\n",
            dest_size, payload_size);
    return 0;
  }
  memcpy (destination_buffer, encrypted, esize);
  memcpy (destination_buffer + esize, signature, ssize);
  writeb16 (destination_buffer + esize + ssize, ssize);
  if (encrypted != NULL)
    free (encrypted);
  if (signature != NULL)
    free (signature);
  return payload_size;
}

static int symmetric_key_encrypt (const char * data, int dsize,
                                  long long int counter, int message_type,
                                  const char * contact, keyset k,
                                  char * destination_buffer, int dest_size)
{
  unsigned int sksize = has_symmetric_key (contact, NULL, 0);
  if (sksize != ALLNET_STREAM_KEY_SIZE) {  /* invalid symmetric key */
    if (sksize != 0)
      printf ("in symmetric_key_encrypt for %s, %d != %d\n", contact,
              sksize, ALLNET_STREAM_KEY_SIZE);
    return 0;
  }
  /* sksize >= ALLNET_STREAM_KEY_SIZE */
  struct allnet_stream_encryption_state sym_state;
  if (! symmetric_key_state (contact, &sym_state)) { /* initialize the state */
    char sym_key [ALLNET_STREAM_KEY_SIZE];
    char secret [ALLNET_STREAM_SECRET_SIZE];
    if (sizeof (sym_key) != sksize) {  /* error */
      printf ("error in symmetric_key_encrypt: %zd != %u, %s\n",
              sizeof (sym_key), sksize, contact);
      return 0;
    }
    sksize = has_symmetric_key (contact, sym_key, sksize);
    if ((sizeof (sym_key) != sksize) ||
        (sizeof (secret) != SHA512_SIZE)) { /* serious error */
      printf ("error in symmetric_key_encrypt: %zd != %u or %zd != %d, %s\n",
              sizeof (sym_key), sksize, sizeof (secret), SHA512_SIZE, contact);
      exit (1);
    }
    /* hash the key to make a secret */
    sha512 (sym_key, sksize, secret);
    allnet_stream_init (&sym_state, sym_key, 0, secret, 0, 8, 32);
    save_key_state (contact, &sym_state);
  }
  int esize = dsize + sym_state.counter_size + sym_state.hash_size;
  if ((esize > dest_size) || (esize <= 0)) {
    printf ("unable to save encrypted data, %d available, %d needed\n",
            dest_size, esize);
    return 0;
  }
  int esize2 = allnet_stream_encrypt_buffer (&sym_state, data, dsize,
                                             destination_buffer, esize);
  if ((esize != esize2) || (esize > dest_size) || (esize <= 0)) {
    printf ("unable to save encrypted data, %d available, %d =? %d needed\n",
            dest_size, esize, esize2);
    return 0;
  }
  save_key_state (contact, &sym_state);
  return esize;
}

static void encrypt_sign_send (const char * data, int dsize, int hops,
                               long long int counter,
                               unsigned long long int expiration,
                               int message_type,
                               const char * contact, keyset k)
{
  struct arems_header ah;
  memset (&ah, 0, sizeof (ah));
  random_bytes ((char *)ah.message_ack, sizeof (ah.message_ack));
  memcpy (ah.app_media.app, APP_ID, sizeof (ah.app_media.app));
  writeb32u (ah.app_media.media, MEDIA_ID);
  writeb64u (ah.counter, counter);
  ah.type = message_type;
  char data_with_ah [MAX_STRING_LENGTH + sizeof (ah)];
  memcpy (data_with_ah, &ah, sizeof (ah));
  memcpy (data_with_ah + sizeof (ah), data, dsize);
  char ebuf [ALLNET_MTU];
  int esize = symmetric_key_encrypt (data_with_ah, sizeof (ah) + dsize,
                                     counter, message_type,
                                     contact, k, ebuf, sizeof (ebuf));
  int sigtype = ALLNET_SIGTYPE_NONE; /* the hash provides the authentication */
  if (esize <= 0) {
    esize = public_key_encrypt (data_with_ah, sizeof (ah) + dsize,
                                counter, message_type,
                                contact, k, ebuf, sizeof (ebuf));
    sigtype = ALLNET_SIGTYPE_RSA_PKCS1;  /* explicit signature */
  }
  if (esize <= 0)
    return;
  char buffer [ALLNET_MTU];
  unsigned char ack [MESSAGE_ID_SIZE];
  random_bytes ((char *)ack, sizeof (ack));
  unsigned char local_address [ADDRESS_SIZE];
  unsigned char remote_address [ADDRESS_SIZE];
  int sbits = get_local (k, local_address);
  int dbits = get_remote (k, remote_address);
  struct allnet_header * hp =
    init_packet (buffer, esize + ALLNET_TIME_SIZE, ALLNET_TYPE_DATA,
                 hops, sigtype, local_address, sbits, remote_address, dbits,
                 NULL, ack);
  hp->transport = hp->transport | ALLNET_TRANSPORT_EXPIRATION;
  if ((expiration == 0) || (expiration < allnet_time () + command_timeout))
    expiration = allnet_time () + command_timeout;
  writeb64 (ALLNET_EXPIRATION (hp, hp->transport, sizeof (buffer)), expiration);
  int hsize = ALLNET_SIZE (hp->transport);
  char * payload = buffer + hsize;
  if (esize + hsize > sizeof (buffer)) {
    printf ("error: esize %d + hsize %d > %zd\n", esize, hsize, sizeof buffer);
    return;
  }
  memcpy (payload, ebuf, esize);
  /* save in the cache, so we don't try to process it */
  recently_received (buffer, hsize + esize);
  local_send (buffer, hsize + esize, ALLNET_PRIORITY_LOCAL);
}

/* similar to decrypt_verify (with which it may eventually be integrated),
 * but uses symmetric keys if available, and gives up otherwise */
static int
  symmetric_decrypt_verify (int sig_algo, char * encrypted, int esize,
                            char ** contact, keyset * kset, char ** text,
                            char * sender, int sbits, char * dest, int dbits,
                            int maxcontacts)
{
  *contact = NULL;
  *kset = -1;
  *text = NULL;
  if (sig_algo != ALLNET_SIGTYPE_NONE)  /* not a symmetric key */
    return 0;
  int cindex;
  int count = 0;
  int decrypt_count = 0;
  char ** contacts = NULL;
  int ncontacts = all_individual_contacts (&contacts);
#if 0  /* maybe re-enable later -- but should not count contacts w/o sym key */
  if ((maxcontacts > 0) && (maxcontacts < ncontacts)) {
    contacts = randomize_contacts (contacts, ncontacts, maxcontacts);
    ncontacts = maxcontacts;
  }
#endif
  for (cindex = 0; ((*contact == NULL) && (cindex < ncontacts)); cindex++) {
    count++;
    unsigned int sksize = has_symmetric_key (contacts [cindex], NULL, 0);
    if (sksize < ALLNET_STREAM_KEY_SIZE)  /* invalid symmetric key */
      continue;                           /* try the next contact */
    /* sksize >= ALLNET_STREAM_KEY_SIZE */
    struct allnet_stream_encryption_state sym_state;
    if (! symmetric_key_state (contacts [cindex], &sym_state)) {
      /* initialize the state */
      char * sym_key = malloc_or_fail (sksize * 2, "symmetric_decrypt_verify");
      sksize = has_symmetric_key (contacts [cindex], sym_key, sksize);
      char secret [ALLNET_STREAM_SECRET_SIZE];
      sha512 (sym_key, sksize, secret);
      allnet_stream_init (&sym_state, sym_key, 0, secret, 0, 8, 32);
      free (sym_key);
      /* save the state only if we are successful */
    }
    int tsize = esize - (sym_state.counter_size + sym_state.hash_size); 
    char buf [ALLNET_MTU];
    if (tsize > sizeof (buf)) {
      printf ("error: %s asked to decrypt %d bytes, %zd max\n",
              contacts [cindex], tsize, sizeof (buf));
      continue;
    }
    decrypt_count++;
    if (allnet_stream_decrypt_buffer (&sym_state, encrypted, esize,
                                      buf, tsize)) {   /* success! */
      save_key_state (contacts [cindex], &sym_state);
      *contact = strcpy_malloc (contacts [cindex], "symmetric_decrypt_verify2");
      *text = memcpy_malloc (buf, tsize, "symmetric_decrypt_verify3");
      keyset * kp = NULL;
      if (all_keys (contacts [cindex], &kp) > 0) {
        *kset = kp [0];
        free (kp);
      }
      return tsize;
    }  /* else, not a match, try the next */
if (decrypt_count == maxcontacts)
printf ("symmetric key decryption trying more than %d contacts\n", maxcontacts);
  }
  return 0;
}

/* returns 1 if the receive loop should exit, 0 if it should continue
 * hops is the number of hops visited by the incoming packet.
 * if the packet has no expiration, expiration is 0 */
typedef int (* received_packet_handler) (void * state,
                                         const char * data, int dsize, int hops,
                                         long long int counter,
                                         unsigned long long int expiration,
                                         const char * contact, keyset k);

static int receive_timeout (char ** message, unsigned int * priority,
                            int timeout, long long int quitting_time)
{
  if ((timeout != -1) && (allnet_time_ms () > quitting_time))
    return -1;
  int result = local_receive (timeout, message, priority);
  if (((timeout == -1) && (result <= 0)) || (result < 0))
    return -1;
  return result;
}

/* timeout is in ms, -1 to never time out */
static void receive_packet_loop (received_packet_handler handler, void * state,
                                 int mtype,
                                 char ** authorized, int nauth, int timeout,
                                 int print_unauth)
{
  long long int quitting_time = allnet_time_ms () + timeout;
  int msize = 0;
  char * message = NULL;
  unsigned int priority;
  while ((msize = receive_timeout (&message, &priority,
                                   timeout, quitting_time)) >= 0) {
    if (msize <= ALLNET_HEADER_SIZE)
      continue;   /* next packet, please */
    if (message == NULL) {
      printf ("error: received null message, msize %d\n", msize);
      continue;   /* next packet, please */
    }
    char * error_desc = NULL;
    if (! is_valid_message (message, msize, &error_desc))
      continue;   /* next packet, please */
    if (message [1] != ALLNET_TYPE_DATA)
      continue;   /* next packet, please */
    if (recently_received (message, msize))
      continue;   /* duplicate: next packet, please */
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
      int tsize =
        symmetric_decrypt_verify (hp->sig_algo, payload, psize,
                                  &contact, &k, &text,
                                  (char *) hp->source, hp->src_nbits,
                                  (char *) hp->destination, hp->dst_nbits, 0);
#ifdef DEBUG_RECEIVE
if (tsize <= 8) printf ("unable to symmetric_decrypt_verify\n");
#endif /* DEBUG_RECEIVE */
      if ((tsize <= 8) && (hp->sig_algo == ALLNET_SIGTYPE_RSA_PKCS1))
        tsize = decrypt_verify (hp->sig_algo, payload, psize,
                                &contact, &k, &text,
                                (char *) hp->source, hp->src_nbits,
                                (char *) hp->destination, hp->dst_nbits, 0);
#ifdef DEBUG_RECEIVE
if (tsize <= 8) printf ("unable to decrypt_verify\n");
#endif /* DEBUG_RECEIVE */
      if (tsize > 8) {
        int i;
        int is_authorized = 0;
        for (i = 0; i < nauth; i++) {
          if (strcmp (contact, authorized [i]) == 0)
            is_authorized = 1;
        }
        if (! is_authorized) {
          if (print_unauth)
            printf ("got message from %s, who is not authorized\n", contact);
          continue;   /* next packet, please */
        }
        struct arems_header * ahp = (struct arems_header *) text;
        if ((memcmp (ahp->app_media.app, APP_ID,
                     sizeof (ahp->app_media.app)) != 0) ||
            (readb32u (ahp->app_media.media) != MEDIA_ID)) {
          char print_app [5];
          memcpy (print_app, ahp->app_media.app, 4);
          print_app [4] = '\0';
          printf ("from %s unexpected app %s media %lx, expected %s %x\n",
                  contact, print_app, readb32u (ahp->app_media.media),
                  APP_ID, MEDIA_ID);
          continue;   /* next packet, please */
        }
        if (ahp->type != mtype) {
          printf ("got message type %d, expected %d\n", ahp->type, mtype);
          continue;   /* next packet, please */
        }
        send_ack (hp, msize);
        if (readb64u (ahp->counter) < 0) {
          printf ("got negative counter %lld\n", readb64u (ahp->counter));
          continue;   /* next packet, please */
        }
        char string [ALLNET_MTU + 1];  /* a null-terminated C string */
        int stsize = tsize - sizeof (struct arems_header);
        memcpy (string, text + sizeof (struct arems_header), stsize);
        string [stsize] = '\0';
        char * ep = ALLNET_EXPIRATION (hp, hp->transport, msize);
        unsigned long long int expiration = ((ep == NULL) ? 0 : readb64 (ep));
        /* printf ("got %d/%d-byte message '%s' from %s/%d, counter %lld\n",
                tsize, stsize, string, contact, k, readb64u (ahp->counter)); */
        if (handler (state, string, strlen (string), hp->hops,
                     readb64u (ahp->counter), expiration, contact, k))
          break;
        free (text);
        free (contact);
      }
    }
  }
}

static int num_tries = 1;

/* *((int *)state) is set to 0 if we got a message */
static int client_handler (void * state,
                           const char * data, int dsize, int hops,
                           long long int counter,
                           unsigned long long int expiration,
                           const char * contact, keyset k)
{
  long long int last_counter = get_counter (contact, k, COUNTER_TYPE_LOCAL);
  if (counter != last_counter) {
    printf ("client_handler: received counter %lld, expected %lld\n",
            counter, last_counter);
    return 0;  /* continue the loop */
  }
  int * timed_out = (int *) state;
  if (num_tries > 1)
    printf ("from %s got response on try %d:\n%s", contact, num_tries, data);
  else
    printf ("from %s got response:\n%s", contact, data);
  if ((strlen (data) > 0) && (data [strlen (data) - 1] != '\n'))
    printf (" [output may be truncated]\n");
  *timed_out = 0;
  return 1;    /* exit the loop*/
}

static int client_rpc (const char * data, int dsize, char * contact)
{
  printf ("sending command '%s' to %s\n", data, contact);
  keyset * k = NULL;
  int nkeys = all_keys (contact, &k);
  if (nkeys != 1) {
    printf ("error: contact %s has %d keys, 1 expected, aborting\n",
            contact, nkeys);
    if (k != NULL)
      free (k);
    return -1;
  }
  long long int counter = get_counter (contact, k [0], COUNTER_TYPE_LOCAL) + 1;
  if (counter < 0)
    counter = 0;
  save_counter (contact, k [0], counter, COUNTER_TYPE_LOCAL);
  encrypt_sign_send (data, dsize, 10, counter, 0, MESSAGE_TYPE_COMMAND,
                     contact, k [0]);
  free (k);
  char * authorized [1] = { contact };
  int timed_out = 1;   /* if nothing happens, we time out */
  receive_packet_loop (&client_handler, &timed_out, MESSAGE_TYPE_RESPONSE,
                       authorized, 1, command_timeout * 1000, 0);
  if (timed_out) {
    printf ("command timed out after %d seconds\n", command_timeout);
    num_tries++;
    return 0;
  }
  return 1;
}

static int server_handler (void * state, /* ignored for now */
                           const char * data, int dsize, int hops,
                           long long int counter,
                           unsigned long long int expiration,
                           const char * contact, keyset k)
{
  static int printed = 0;
  long long int last_counter = get_counter (contact, k, COUNTER_TYPE_REMOTE);
  if ((last_counter < 0) || (counter > last_counter)) {
    char result [MAX_STRING_LENGTH];
    int rsize = my_system (data, result, sizeof (result), contact);
    save_counter (contact, k, counter, COUNTER_TYPE_REMOTE);
    encrypt_sign_send (result, rsize, hops + 2, counter, expiration,
                       MESSAGE_TYPE_RESPONSE, contact, k);
  } else if ((counter <= last_counter) && (printed++ < 5))
    printf ("got duplicate counter %lld, latest %lld\n", counter, last_counter);
  return 0;     /* continue the loop */
}

static void server_loop (char ** const authorized, int nauth)
{
  receive_packet_loop (&server_handler, NULL, MESSAGE_TYPE_COMMAND,
                       authorized, nauth, -1, 1);
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
    else if (strcmp (argv [i], "-t") == 0)
      return NULL;   /* not a server */
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
  for (i = 1; i < *nauth; i++) {
    if (found_switch && (num_keysets (argv [i]) <= 0)) {
      printf ("found server switch -s, but user %s is unknown\n", argv [i]);
      exit (1);   /* not an authorized user */
    }
  }
  return (argv + 1);
} 

int main (int argc, char ** argv)
{
  if (argc < 2) {
    printf ("%s: needs at least one remote authorized user\n", argv [0]);
    printf ("usage: %s -s authorized-user+\n", argv [0]);
    printf (" or    %s [-t seconds] receiver command\n", argv [0]);
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
    /* arems -r -t seconds name command -- must be specified in that order */
    int nextindex = 1;   /* index of the next argument to look at */
    int repeat_until_response = 0;  /* by default, only try once */
    if (strcmp (argv [nextindex], "-r") == 0) {
      repeat_until_response = 1;
      nextindex++;
    }
    if (strcmp (argv [nextindex], "-t") == 0) {
      char * end = NULL;
      errno = 0;
      int arg2 = strtol (argv [nextindex + 1], &end, 10);
      if ((errno == 0) && (*end == '\0'))
        command_timeout = arg2;
      nextindex += 2;
    }
    char * contact = argv [nextindex];
    char command [MAX_STRING_LENGTH];
    int off = 0;
    int i;
    for (i = nextindex + 1; (i < argc) && (off < sizeof (command)); i++)
      off += snprintf (command + off, minz (sizeof (command), off), "%s%s",
                       argv [i], ((i + 1 < argc) ? " " : ""));
    int success;
    do {
      success = client_rpc (command, strlen (command), contact);
    } while ((success == 0) && (repeat_until_response));
    return ((success > 0) ? 0 : 1);
  }
}
