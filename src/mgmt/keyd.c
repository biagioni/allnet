/* keyd.c: standalone application to respond to key requests */

#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <sys/types.h>

#include <openssl/rsa.h>

#include "lib/packet.h"
#include "lib/media.h"
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
                      int rksize, unsigned char * address, int abits, int hops)
{
#ifdef DEBUG_PRINT
  printf ("send_key ((%p, %d), %p)\n", key->pub_key, key->pub_klen, return_key);
#endif /* DEBUG_PRINT */
  char * data = key->pub_key;
  int dlen = key->pub_klen;
  int type = ALLNET_TYPE_CLEAR;
  int allocated = 0;
#if 0   /* if want to support, must encrypt allnet_app_media_header */
  if ((return_key != NULL) && (rksize > 0)) {  /* encrypt the key */
    type = ALLNET_TYPE_DATA;
    char * cipher;
#ifdef DEBUG_PRINT
    printf ("calling encrypt (%p/%d, %d, %p, %d) ==> %p\n",
            data, dlen, key->pub_klen, return_key, rksize, &cipher);
#endif /* DEBUG_PRINT */
    int csize = allnet_encrypt (data, dlen, return_key, rksize, &cipher);
    if (csize <= 0) {
      snprintf (log_buf, LOG_SIZE, "send_key: encryption error\n");
      log_print ();
      return;
    }
    data = cipher;
    dlen = csize;
    allocated = 1;
  }
#endif /* 0 */
  int amhsize = sizeof (struct allnet_app_media_header);
  int bytes;
  struct allnet_header * hp =
    create_packet (dlen + amhsize, type, hops, ALLNET_SIGTYPE_NONE,
                   key->address, 16, address, abits, NULL, &bytes);
  char * adp = ALLNET_DATA_START(hp, hp->transport, bytes);
  struct allnet_app_media_header * amhp =
    (struct allnet_app_media_header *) adp;
  writeb32u (amhp->app, 0x6b657964 /* keyd */ );
  writeb32u (amhp->media, ALLNET_MEDIA_PUBLIC_KEY);
  char * dp = adp + amhsize;
  memcpy (dp, data, dlen);
  if (allocated)
    free (data);
  print_buffer (dp, dlen, "key", 10, 1);
printf ("verification is %d\n", verify_bc_key ("testxyzzy@by_sign.that_health", dp, dlen, "en", 16, 0));

  /* send with relatively low priority */
  char * message = (char *) hp;
  send_pipe_message (sock, message, bytes, ALLNET_PRIORITY_DEFAULT);
}

#ifdef DEBUG_PRINT
void ** keyd_debug = NULL;
#endif /* DEBUG_PRINT */

static void handle_packet (int sock, char * message, int msize)
{
  struct allnet_header * hp = (struct allnet_header *) message;
  if (hp->message_type != ALLNET_TYPE_KEY_REQ)
    return;
#ifdef DEBUG_PRINT
  print_packet (message, msize, "key request", 1);
#endif /* DEBUG_PRINT */
  packet_to_string (message, msize, "key request", 1, log_buf, LOG_SIZE);
  log_print ();
  char * kp = message + ALLNET_SIZE (hp->transport);
#ifdef DEBUG_PRINT
  keyd_debug = ((void **) (&kp));
#endif /* DEBUG_PRINT */
  unsigned int nbits = (*kp) & 0xff;
  int offset = (nbits + 7) / 8;
  /* ignore the fingerprint for now -- not implemented */
  kp += offset + 1;
  int ksize = msize - (kp - message);
#ifdef DEBUG_PRINT
  printf ("kp is %p\n", kp);
#endif /* DEBUG_PRINT */
  if (((msize - (kp - message)) != 513) ||
      (*kp != KEY_RSA4096_E65537)) {
    snprintf (log_buf, LOG_SIZE,
              "msize %d - (%p - %p = %zd) =? 513, *kp %d\n",
              msize, kp, message, kp - message, *kp);
    log_print ();
    kp = NULL;
    ksize = 0;
  }
#ifdef DEBUG_PRINT
  printf (" ==> kp is %p (%d bytes)\n", kp, ksize);
#endif /* DEBUG_PRINT */

  struct bc_key_info * keys;
  unsigned int nkeys = get_own_keys (&keys);
#ifdef DEBUG_PRINT
  printf (" ==> kp %p, %d keys %p\n", kp, nkeys, keys);
#endif /* DEBUG_PRINT */
  if (nkeys <= 0) {
    snprintf (log_buf, LOG_SIZE, "no keys found\n");
    log_print ();
    return;
  }

  int i;
  for (i = 0; i < nkeys; i++) {
    int matching_bits =
      matches (hp->destination, hp->dst_nbits,
               (unsigned char *) (keys [i].address), ADDRESS_BITS);
    printf ("%02x <> %02x (%s): %d matching bits, %d needed\n",
            hp->destination [0] & 0xff, keys [i].address [0] & 0xff,
            keys [i].identifier, matching_bits, hp->dst_nbits);
    snprintf (log_buf, LOG_SIZE, "%02x <> %02x: %d matching bits, %d needed\n",
              hp->destination [0] & 0xff,
              keys [i].address [0] & 0xff, matching_bits, hp->dst_nbits);
    log_print ();
    if (matching_bits >= hp->dst_nbits) {  /* send the key */
#ifdef DEBUG_PRINT
      printf ("sending key %d, kp %p, %d bytes to %x/%d\n", i, kp, ksize,
hp->source [0] & 0xff, hp->src_nbits);
#endif /* DEBUG_PRINT */
      send_key (sock, keys + i, kp, ksize,
                hp->source, hp->src_nbits, hp->hops + 4);
    }
  }
}

void keyd_main (char * pname)
{
  int sock = connect_to_local (pname, pname);
  if (sock < 0)
    return;

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

#ifndef NO_MAIN_FUNCTION
/* global debugging variable -- if 1, expect more debugging output */
/* set in main */
int allnet_global_debugging = 0;

int main (int argc, char ** argv)
{
  int verbose = get_option ('v', &argc, argv);
  if (verbose)
    allnet_global_debugging = verbose;
  keyd_main (argv [0]);
  return 0;
}
#endif /* NO_MAIN_FUNCTION */

