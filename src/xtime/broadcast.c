/* broadcast.c: send text as broadcast */
/* the first argument to the call is the key for signing messages */
/* the second argument determines how many hops the messages are sent */
/* if no argument is specified, the default is 10 hops */
/* the text to send is taken from the standard input, and sent one line
 * per message */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>

#include "lib/packet.h"
#include "lib/media.h"
#include "lib/util.h"
#include "lib/app_util.h"
#include "lib/pipemsg.h"
#include "lib/priority.h"
#include "lib/cipher.h"
#include "lib/keys.h"
#include "lib/log.h"

static int init_broadcast (char * arg0)
{
  int sock = connect_to_local ("cmdline_broadcast", arg0);
  if (sock < 0)
    exit (1);
  return sock;
}

/* need to keep reading and emptying the socket buffer, otherwise
 * it will fill and alocal will get an error from sending to us,
 * and so close the socket. */
static void * receive_ignore (void * arg)
{
  int * sockp = (int *) arg;
  while (1) {
    char * message;
    int priority;
    int n = receive_pipe_message (*sockp, &message, &priority);
    if (n > 0)    /* ignore the message and recycle the storage */
      free (message);
    else          /* some error -- quit */
      return NULL;
  }
  return NULL;
}

static void broadcast (int sock, char * data, int dsize, int hops,
                       char * key, int ksize,
                       unsigned char * source, int sbits,
                       unsigned char * dest, int dbits)
{
  static char buffer [ALLNET_MTU];
  bzero (buffer, sizeof (buffer));
  struct allnet_header * hp =
    init_packet (buffer, sizeof (buffer), ALLNET_TYPE_CLEAR, hops,
                 ALLNET_SIGTYPE_NONE, source, sbits, dest, dbits, NULL);
  int hsize = ALLNET_SIZE (hp->transport);
  int h2size = sizeof (struct allnet_app_media_header);
  if (hsize + h2size + dsize + ksize + 2 > ALLNET_MTU) {
    printf ("broadcast error: %d + %d + %d + %d + 2 > %d\n", 
            hsize, h2size, dsize, ksize, ALLNET_MTU);
    return;
  }
  struct allnet_app_media_header * amhp =
    (struct allnet_app_media_header *) (buffer + hsize);
  writeb32u (amhp->app, 0);
  writeb32u (amhp->media, ALLNET_MEDIA_TEXT_PLAIN);
  char * dp = buffer + hsize + h2size;
  memcpy (dp, data, dsize);
  int ssize = 0;
  if ((key != NULL) && (ksize > 0)) {
    char * sig;
    ssize = allnet_sign (dp, dsize, key, ksize, &sig);
    if (ssize > 0) {
      int size = hsize + dsize + ssize + 2;
      if (size > ALLNET_MTU) {
        printf ("error, buffer size %d, wanted %d, not adding sig\n",
                ALLNET_MTU, size);
        ssize = 0;
      } else {
        hp->sig_algo = ALLNET_SIGTYPE_RSA_PKCS1;
        char * sp = dp + dsize;
        memcpy (sp, sig, ssize);
        writeb16 (sp + ssize, ssize);
        ssize += 2;
      }
      free (sig);
    }
  }
  int send_size = hsize + h2size + dsize + ssize;
  /* send with relatively low priority */
  send_pipe_message (sock, buffer, send_size, ALLNET_PRIORITY_LOCAL_LOW);
}

/* global debugging variable -- if 1, expect more debugging output */
/* set in main */
int allnet_global_debugging = 0;

int main (int argc, char ** argv)
{
  int verbose = get_option ('v', &argc, argv);
  if (verbose)
    allnet_global_debugging = verbose;

  int hops = 10;
  if (argc < 2) {
    printf ("%s: needs at least a signing address\n", argv [0]);
    exit (1);
  }
  char * address = argv [1];
  if (argc > 2)
    hops = atoi (argv [2]);
  struct bc_key_info * key = get_own_bc_key (address);
  if (key == NULL) {
    printf ("key '%s' not found\n", address);
    exit (1);
  }
/*
  printf ("%s: got %d-byte public, %d-byte private key, address %02x.%02x\n",
          argv [0], key->pub_klen, key->priv_klen, key->address [0] & 0xff,
          key->address [1] & 0xff);
*/
  
  int sock = init_broadcast (argv [0]);
  pthread_t receive_thread;
  if (pthread_create (&receive_thread, NULL, receive_ignore, &sock) != 0) {
    perror ("xtime pthread_create/receive");
    return 1;
  }

  char buffer [100000];
  while (fgets (buffer, sizeof (buffer), stdin) == buffer) {
    char * eol = rindex (buffer, '\n');
    if ((eol != NULL) && (strlen (buffer) == 1 + (eol - buffer)))
       *eol = '\0';
    broadcast (sock, buffer, strlen (buffer), hops,
               key->priv_key, key->priv_klen,
               key->address, ADDRESS_BITS, key->address, ADDRESS_BITS);
  }
  return 0;
}
