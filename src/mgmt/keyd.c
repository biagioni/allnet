/* keyd.c: standalone application to respond to key requests */

#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <sys/types.h>

#include <openssl/rsa.h>

#include "packet.h"
#include "lib/util.h"
#include "lib/app_util.h"
#include "lib/pipemsg.h"
#include "lib/priority.h"
#include "lib/sha.h"
#include "lib/log.h"
#include "lib/cipher.h"
#include "lib/keys.h"

#define CONFIG_DIR	"~/.allnet/keys"

static void send_key (int sock, struct bc_key_info * key, char * return_key,
                      int rksize, char * address, int abits, int hops)
{
/* printf ("send_key ((%p, %d), %p)\n", key->pub_key,
           key->pub_klen, return_key); */
  char * data = key->pub_key;
  int dlen = key->pub_klen;
  int type = ALLNET_TYPE_CLEAR;
  int allocated = 0;
  if ((return_key != NULL) && (rksize > 0)) {  /* encrypt the key */
    type = ALLNET_TYPE_DATA;
    char * cipher;
/* printf ("calling encrypt (%p, %d, %p, %d) ==> %p\n",
        body, key->pub_klen, return_key, rksize, &cipher); */
    int csize = encrypt (data, dlen, return_key, rksize, &cipher);
    if (csize <= 0) {
      snprintf (log_buf, LOG_SIZE, "send_key: encryption error\n");
      log_print ();
      return;
    }
    data = cipher;
    dlen = csize;
    allocated = 1;
  }
  int bytes;
  struct allnet_header * hp =
    create_packet (dlen, type, hops, ALLNET_SIGTYPE_NONE, key->address, 16,
                   address, abits, NULL, &bytes);
  char * dp = ALLNET_DATA_START(hp, hp->transport, bytes);
  memcpy (dp, data, dlen);
  if (allocated)
    free (data);

  /* send with relatively low priority */
  char * message = (char *) hp;
  send_pipe_message (sock, message, bytes, ONE_EIGHT);
}

void ** keyd_debug = NULL;

static void handle_packet (int sock, char * message, int msize)
{
  struct allnet_header * hp = (struct allnet_header *) message;
  if (hp->message_type != ALLNET_TYPE_KEY_REQ)
    return;
/* print_packet (message, msize, "key request", 1); */
  packet_to_string (message, msize, "key request", 1, log_buf, LOG_SIZE);
  log_print ();
  char * kp = message + ALLNET_SIZE (hp->transport);
/* keyd_debug = ((void **) (&kp)); */
  unsigned int nbits = (*kp) & 0xff;
  int offset = (nbits + 7) / 8;
  /* ignore the fingerprint for now -- not implemented */
  kp += offset + 1;
  int ksize = msize - (kp - message);
/* printf ("kp is %p\n", kp); */
  if (((msize - (kp - message)) != 513) ||
      (*kp != KEY_RSA4096_E65537)) {
    snprintf (log_buf, LOG_SIZE,
              "msize %d - (%p - %p = %zd) =? 513, *kp %d\n",
              msize, kp, message, kp - message, *kp);
    log_print ();
    kp = NULL;
    ksize = 0;
  }
/* printf (" ==> kp is %p (%d bytes)\n", kp, ksize); */

  struct bc_key_info * keys;
  unsigned int nkeys = get_own_keys (&keys);
/* printf (" ==> kp %p, keys %p\n", kp, keys); */
  if (nkeys <= 0) {
    snprintf (log_buf, LOG_SIZE, "no keys found\n");
    log_print ();
    return;
  }

  int i;
  for (i = 0; i < nkeys; i++) {
    int matching_bits =
      matches (hp->destination, hp->dst_nbits, keys [i].address, ADDRESS_BITS);
    snprintf (log_buf, LOG_SIZE, "%02x <> %02x: %d matching bits, %d needed\n",
              hp->destination [0] & 0xff,
              keys [i].address [0] & 0xff, matching_bits, hp->dst_nbits);
    log_print ();
    if (matching_bits >= hp->dst_nbits) {  /* send the key */
      /* printf ("sending key %d, kp %p, %d bytes\n", i, kp, ksize); */
      send_key (sock, keys + i, kp, ksize,
                hp->source, hp->src_nbits, hp->hops + 4);
    }
  }
}

int main (int argc, char ** argv)
{
  int sock = connect_to_local (argv [0]);
  if (sock < 0)
    return 1;
  add_pipe (sock);

  while (1) {  /* loop forever */
    int pipe;
    int pri;
    char * message;
    int found = receive_pipe_message_any (PIPE_MESSAGE_WAIT_FOREVER,
                                          &message, &pipe, &pri);
    if (found <= 0) {
      snprintf (log_buf, LOG_SIZE, "keyd pipe closed, exiting\n");
      log_print ();
      exit (1);
    }
    if (is_valid_message (message, found))
      handle_packet (sock, message, found);
    free (message);
  }
  snprintf (log_buf, LOG_SIZE, "keyd infinite loop ended, exiting\n");
  log_print ();
}

