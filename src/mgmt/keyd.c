/* keyd.c: standalone application to respond to key requests */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <dirent.h>
#include <time.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>

#include "lib/packet.h"
#include "lib/media.h"
#include "lib/util.h"
#include "lib/app_util.h"
#include "lib/priority.h"
#include "lib/sha.h"
#include "lib/allnet_log.h"
#include "lib/cipher.h"
#include "lib/keys.h"

#define CONFIG_DIR	"~/.allnet/keys"

static struct allnet_log * alog = NULL;

static void keyd_send_key (struct bc_key_info * key, const char * return_key,
                           int rksize, unsigned char * address, int abits,
                           int hops)
{
#ifdef DEBUG_PRINT
  printf ("keyd_send_key ((%p, %d), %p)\n", key->pub_key,
          allnet_rsa_pubkey_size (key->pub_key), return_key);
#endif /* DEBUG_PRINT */
  int dlen = allnet_rsa_pubkey_size (key->pub_key) + 1;
  char * data = malloc_or_fail (dlen, "keyd_send_key");
  int klen = allnet_pubkey_to_raw (key->pub_key, data, dlen);
  if ((klen > dlen) || (klen == 0)) {
    snprintf (alog->b, alog->s, "error in keyd_send_key: %d, %d\n", klen, dlen);
    log_print (alog);
    return;
  }
  int type = ALLNET_TYPE_CLEAR;
  unsigned int allocated = 0;
  unsigned int amhsize = sizeof (struct allnet_app_media_header);
  unsigned int bytes;
  struct allnet_header * hp =
    create_packet (dlen + amhsize + KEY_RANDOM_PAD_SIZE, type, hops,
                   ALLNET_SIGTYPE_NONE, key->address, 16, address, abits,
                   NULL, NULL, &bytes);
  char * adp = ALLNET_DATA_START(hp, hp->transport, (unsigned int) bytes);
  struct allnet_app_media_header * amhp =
    (struct allnet_app_media_header *) adp;
  writeb32u (amhp->app, 0x6b657964 /* keyd */ );
  writeb32u (amhp->media, ALLNET_MEDIA_PUBLIC_KEY);
  char * dp = adp + amhsize;
  memcpy (dp, data, dlen);
  if (allocated)
    free (data);
#ifdef DEBUG_PRINT
  print_buffer (dp, dlen, "keyd_send_key", 12, 1);
#endif /* DEBUG_PRINT */
  char * r = dp + klen;
  random_bytes (r, KEY_RANDOM_PAD_SIZE);

  /* send with relatively low priority */
  char * message = (char *) hp;
  local_send (message, bytes, ALLNET_PRIORITY_DEFAULT);
}

#ifdef DEBUG_PRINT
void ** keyd_debug = NULL;
#endif /* DEBUG_PRINT */

#ifdef ALLNET_USE_FORK  /* do not allow external calls to this function */
static
#endif /* ALLNET_USE_FORK */
 void keyd_handle_packet (const char * message, int msize)
{
  struct allnet_header * hp = (struct allnet_header *) message;
  if (hp->message_type != ALLNET_TYPE_KEY_REQ)
    return;
#ifdef DEBUG_PRINT
  print_packet (message, msize, "key request", 1);
#endif /* DEBUG_PRINT */
  packet_to_string (message, msize, "key request", 1, alog->b, alog->s);
  log_print (alog);
  const char * kp = message + ALLNET_SIZE (hp->transport);
#ifdef DEBUG_PRINT
  keyd_debug = ((void **) (&kp));
#endif /* DEBUG_PRINT */
  unsigned int nbits = (*kp) & 0xff;
  int offset = (nbits + 7) / 8;
  /* ignore the fingerprint for now -- not implemented */
  kp += offset + 1;
  size_t ksize = msize - (kp - message);
#ifdef DEBUG_PRINT
  printf ("kp is %p\n", kp);
#endif /* DEBUG_PRINT */
  if (((msize - (kp - message)) != 513) ||
      (*kp != KEY_RSA4096_E65537)) {
    snprintf (alog->b, alog->s,
              "msize %d - (%p - %p = %d) =? 513, *kp %d\n",
              msize, kp, message, (int)(kp - message), *kp);
    log_print (alog);
    kp = NULL;
    ksize = 0;
  }
#ifdef DEBUG_PRINT
  printf (" ==> kp is %p (%zd bytes)\n", kp, ksize);
#endif /* DEBUG_PRINT */

  struct bc_key_info * keys;
  unsigned int nkeys = get_own_keys (&keys);
#ifdef DEBUG_PRINT
  printf (" ==> kp %p, %d keys %p\n", kp, nkeys, keys);
#endif /* DEBUG_PRINT */
  if (nkeys <= 0) {
    snprintf (alog->b, alog->s, "no keys found\n");
    log_print (alog);
    return;
  }

  unsigned int i;
  for (i = 0; i < nkeys; i++) {
    int matching_bits =
      matches (hp->destination, hp->dst_nbits,
               (unsigned char *) (keys [i].address), ADDRESS_BITS);
#ifdef DEBUG_PRINT
    printf ("%02x <> %02x (%s): %d matching bits, %d needed\n",
            hp->destination [0] & 0xff, keys [i].address [0] & 0xff,
            keys [i].identifier, matching_bits, hp->dst_nbits);
#endif /* DEBUG_PRINT */
    snprintf (alog->b, alog->s, "%02x <> %02x: %d matching bits, %d needed\n",
              hp->destination [0] & 0xff,
              keys [i].address [0] & 0xff, matching_bits, hp->dst_nbits);
    log_print (alog);
    if (matching_bits >= hp->dst_nbits) {  /* send the key */
#ifdef DEBUG_PRINT
      printf ("keyd sending key %d (%s), kp %p, %zd bytes to %02x.%02x./%d\n",
              i, keys [i].identifier, kp, ksize,
              hp->source [0] & 0xff, hp->source [1] & 0xff, hp->src_nbits);
#endif /* DEBUG_PRINT */
      keyd_send_key (keys + i, kp, (int)ksize,
                     hp->source, hp->src_nbits, hp->hops + 4);
    }
  }
}

/* used for debugging the generation of spare keys */
/* #define DEBUG_PRINT_SPARES */

/* ok to call with bsize == 0, will not gather any random bytes */
/* only returns after time "until" has been reached */
/* returns the number of bytes gathered, if any, 0 otherwise */
/* should never return more than bsize */
static int gather_random_and_wait (int bsize, char * buffer, time_t until)
{
  int fd = -1;
  int count = 0;
  if (bsize > 0) {
    fd = open ("/dev/random", O_RDONLY);
    while ((fd >= 0) && (count < bsize)) {
#ifdef DEBUG_PRINT_SPARES
      if ((count < 4) || (count + 4 >= bsize) || ((count % 128) == 127))
        printf ("graw, count %d, bsize %d\n", count, bsize);
#endif /* DEBUG_PRINT_SPARES */
      char data [1];
      ssize_t found = read (fd, data, 1);
      if (found == 1)
        buffer [count++] = data [0];
      else if (found < 0) {  /* some kind of error */
perror ("gather_random_and_wait read /dev/random");
        close (fd);
        fd = -1;
      }
    }
    if (fd >= 0)
      close (fd);
  }
#ifdef DEBUG_PRINT_SPARES
  printf ("at %ld: generated %d bytes, until %ld\n", time (NULL), count, until);
#endif /* DEBUG_PRINT_SPARES */
  time_t now;
  while ((now = time (NULL)) < until) {
#ifdef DEBUG_PRINT_SPARES
    printf ("graw, time %ld, until %ld\n", time (NULL), until);
#endif /* DEBUG_PRINT_SPARES */
    time_t interval = until - now;
    if (sleep ((int)interval)) {  /* interrupted */
#ifdef DEBUG_PRINT_SPARES
      printf ("graw killed\n");
#endif /* DEBUG_PRINT_SPARES */
      exit (1);
    }
  }
  if ((bsize > 0) && ((fd < 0) || (count > bsize)))
    printf ("gather_random_and_wait error: %d > %d (%d)\n", count, bsize, fd);
  if (fd >= 0)
    return count;
  else
    return 0;
}

#define KEY_GEN_BITS	4096
#define KEY_GEN_BYTES	(KEY_GEN_BITS / 8)
#define MIN_SPARES	8  /* below this, generate keys without stopping */
#define HEALTHY_SPARES	100  /* do not generate more than this */
/* run from astart as a separate process */
void keyd_generate (char * pname)
{
  if (alog == NULL)
    alog = init_log ("keyd_generate");
#ifdef ALLNET_USE_FORK
  if (setpriority (PRIO_PROCESS, 0, 15) != 0) {
    snprintf (alog->b, alog->s,
              "keyd unable to lower process priority, continuing anyway\n");
    log_print (alog);
  }
#endif /* ALLNET_USE_FORK */
  /* sleep 10 min, or 100 * the time to generate a key, whichever is longer */
  time_t sleep_time = 60 * 10;  /* 10 minutes, in seconds */
  int existing_spares = create_spare_key (-1, NULL, 0);
  if (existing_spares < MIN_SPARES)  /* create keys as fast as possible */
    sleep_time = 1;
  char buffer [KEY_GEN_BYTES];
  int bytes_in_buffer = 0;
  /* generate up to 100 keys (8 in low-power mode), then generate more
   * as they are used */
  while (1) {
    time_t start = time (NULL);
    time_t finish = start + sleep_time;
    int min_spares = MIN_SPARES; /* stop generating when we have 8 spare keys */
    if (speculative_computation_is_ok ())  /* or 100 if plenty of power */
      min_spares = HEALTHY_SPARES;
    int gather_bytes = KEY_GEN_BYTES - bytes_in_buffer;
#ifdef DEBUG_PRINT_SPARES
    printf ("gathering %d bytes (have %d) and waiting %ld until %ld\n",
            gather_bytes, bytes_in_buffer, finish - time (NULL), finish);
#endif /* DEBUG_PRINT_SPARES */
    bytes_in_buffer +=
      gather_random_and_wait (gather_bytes, buffer + bytes_in_buffer, finish);
    existing_spares = create_spare_key (-1, NULL, 0);
    if (existing_spares < min_spares)  /* for now, report how many we have */
      printf ("%ld: %d spare keys, min %d\n",
              start, existing_spares, min_spares);
#ifdef DEBUG_PRINT_SPARES
    printf ("%ld: %d spare keys, min %d\n",
            start, existing_spares, min_spares);
    printf ("gathered %d bytes, done waiting, now %ld (and %d spares)\n",
            bytes_in_buffer, time (NULL), create_spare_key (-1, NULL, 0));
#endif /* DEBUG_PRINT_SPARES */
    sleep_time = (60 * 10);  /* sleep for 10 minutes, or 100x key gen time */
    if ((existing_spares < min_spares) && (bytes_in_buffer >= KEY_GEN_BYTES)) {
      start = time (NULL);
#ifdef DEBUG_PRINT_SPARES
      printf ("creating spare key, start time %ld\n", start);
#endif /* DEBUG_PRINT_SPARES */
      create_spare_key (KEY_GEN_BITS, buffer, KEY_GEN_BYTES);
      bytes_in_buffer = 0;   /* used all the bytes */
      time_t done = time (NULL);
      time_t delta = done - start;
      /* sleep time is 100 * generation time or 10min, whichever is more */
      time_t sleep_time_from_key_gen = delta * 100;
      if (sleep_time < sleep_time_from_key_gen)
        sleep_time = sleep_time_from_key_gen;
#ifdef DEBUG_PRINT_SPARES
      printf ("%ld: created, sleep %ld (from %ld)\n", done, sleep_time, delta);
#endif /* DEBUG_PRINT_SPARES */
    }
    existing_spares = create_spare_key (-1, NULL, 0);
    if (existing_spares < MIN_SPARES)  /* create keys as fast as possible */
      sleep_time = 1;
  }
}

#ifdef ALLNET_USE_FORK  /* this is a new process, do everything */
void keyd_main (char * pname)
{
  alog = init_log ("keyd");
  int sock = connect_to_local (pname, pname, NULL, 0, 1);
  if (sock < 0)
    return;
  while (1) {  /* loop forever */
    unsigned int pri;
    char * message;                      /* sleep for up to a minute */
    int found = local_receive (60 * 1000, &message, &pri);
    if (found < 0) {
      snprintf (alog->b, alog->s, "keyd pipe closed, exiting\n");
      log_print (alog);
      exit (1);
    }
    if ((found > 0) && (is_valid_message (message, found, NULL)))
      keyd_handle_packet (message, found);
    if (found > 0)
      free (message);
  }
  snprintf (alog->b, alog->s, "keyd infinite loop ended, exiting\n");
  log_print (alog);
}
#endif /* ALLNET_USE_FORK */

#ifdef DAEMON_MAIN_FUNCTION
int main (int argc, char ** argv)
{
  log_to_output (get_option ('v', &argc, argv));
  keyd_main (argv [0]);
  return 0;
}
#endif /* DAEMON_MAIN_FUNCTION */

