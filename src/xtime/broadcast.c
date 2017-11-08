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
#include "lib/allnet_log.h"

static struct allnet_log * log = NULL;

static int init_broadcast (char * arg0, pd p)
{
  int sock = connect_to_local ("cmdline_broadcast", arg0, NULL, p);
  if (sock < 0)
    exit (1);
  return sock;
}

struct thread_arg {
  int sock;
  pd p;
};

/* need to keep reading and emptying the socket buffer, otherwise
 * it will fill and alocal will get an error from sending to us,
 * and so close the socket. */
static void * receive_ignore (void * arg)
{
  struct thread_arg * tap = (struct thread_arg *) arg;
  int sock = tap->sock;
  pd p = tap->p;
  while (1) {
    char * message;
    unsigned int priority;
    int n = receive_pipe_message (p, sock, &message, &priority);
    if (n > 0)    /* ignore the message and recycle the storage */
      free (message);
    else          /* some error -- quit */
      break;
  }
  return NULL;
}

static void broadcast (int sock, char * data, int dsize, int hops,
                       allnet_rsa_prvkey key,
                       unsigned char * source, int sbits,
                       unsigned char * dest, int dbits,
                       struct allnet_log * log)
{
  static char buffer [ALLNET_MTU];
  memset (buffer, 0, sizeof (buffer));
  struct allnet_header * hp =
    init_packet (buffer, sizeof (buffer), ALLNET_TYPE_CLEAR, hops,
                 ALLNET_SIGTYPE_NONE, source, sbits, dest, dbits, NULL, NULL);
  int hsize = ALLNET_SIZE (hp->transport);
  int h2size = sizeof (struct allnet_app_media_header);
  int rsa_size = allnet_rsa_prvkey_size (key);
  if (hsize + h2size + dsize + rsa_size + 2 > ALLNET_MTU) {
    printf ("broadcast error: %d + %d + %d + %d + 2 > %d\n", 
            hsize, h2size, dsize, rsa_size, ALLNET_MTU);
    return;
  }
  char * sp = buffer + hsize;
  struct allnet_app_media_header * amhp = (struct allnet_app_media_header *) sp;
  writeb32u (amhp->app, 0);
  writeb32u (amhp->media, ALLNET_MEDIA_TEXT_PLAIN);
  char * dp = buffer + hsize + h2size;
  memcpy (dp, data, dsize);
  int ssize = 0;
  if (rsa_size > 0) {
    char * sig;
    ssize = allnet_sign (sp, h2size + dsize, key, &sig);
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
/* printf ("sending %d = %d + %d + %d + %d bytes\n",
send_size, hsize, h2size, dsize, ssize); */
  /* send with relatively low priority */
  send_pipe_message (sock, buffer, send_size, ALLNET_PRIORITY_LOCAL_LOW, log);
}

int main (int argc, char ** argv)
{
  log_to_output (get_option ('v', &argc, argv));
  int hops = 10;
  if (argc < 2) {
    printf ("%s: needs at least a signing address (optional hops)\n",
            argv [0]);
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
printf ("sending using key %s\n", key->identifier);
/*
  printf ("%s: got %d-byte public, %d-byte private key, address %02x.%02x\n",
          argv [0], key->pub_klen, key->priv_klen, key->address [0] & 0xff,
          key->address [1] & 0xff);
*/
  
  log = init_log ("xtime/broadcast");
  pd p = init_pipe_descriptor (log);
  int sock = init_broadcast (argv [0], p);
  pthread_t receive_thread;
  static struct thread_arg arg;
  arg.sock = sock;
  arg.p = p;
  if (pthread_create (&receive_thread, NULL, receive_ignore, &arg) != 0) {
    perror ("xtime pthread_create/receive");
    return 1;
  }

  char buffer [100000];
  while (fgets (buffer, sizeof (buffer), stdin) == buffer) {
    char * eol = strrchr (buffer, '\n');
    if ((eol != NULL) && (((int) strlen (buffer)) == 1 + (eol - buffer)))
       *eol = '\0';
    broadcast (sock, buffer, strlen (buffer), hops, key->prv_key,
               key->address, ADDRESS_BITS, key->address, ADDRESS_BITS,
               pipemsg_log (p));
  }
  return 0;
}
