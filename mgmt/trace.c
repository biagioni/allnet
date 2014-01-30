/* trace.c: standalone application to generate and handle AllNet traces */
/* can be called as daemon (traced) or client (any other name)
/* both the daemon and the client take 1 or two arguments:
   - an address (in hex, with or without separating :,. )
   - optionally, a number of bits of the address we want to send out, in 0..64
     if not specified, the number of bytes provided * 8 is used
 * for the daemon, the specified address is my address, used to fill in
   the response.
 * for the client, the specified address is the address to trace
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/rsa.h>

#include "../packet.h"
#include "../mgmt.h"
#include "../lib/pipemsg.h"
#include "../lib/priority.h"

static int get_nybble (char * string, int * offset)
{
  char * p = string + *offset;
  while ((*p == ':') || (*p == ',') || (*p == '.'))
    p++;
  *offset = (p + 1) - string;
  if ((*p >= '0') && (*p <= '9'))
    return *p - '0';
  if ((*p >= 'a') && (*p <= 'f'))
    return 10 + *p - 'a';
  if ((*p >= 'A') && (*p <= 'F'))
    return 10 + *p - 'A';
  return -1;
}

static int get_byte (char * string, int * offset)
{
  int first = get_nybble (string, offset);
  if (first != -1) {
    int second = get_nybble (string, offset);
    if (second != -1)
      return (first << 8) | second;
  }
  return -1;
}

static int get_address (char * address, char * result, int rsize)
{
  int offset = 0;
  int value = 0;
  int index = 0;
  while ((index < rsize) && ((value = get_byte (address, &offset)) >= 0))
    result [index++] = value;
  return index * 8;
}

static void callback (int type, int count, void * arg)
{
  if (type == 0)
    printf (".");
  else if (type == 1)
    printf (",");
  else if (type == 2)
    printf ("!");
  else if (type == 3)
    printf (":");
  else
    printf ("?");
  fflush (stdout);
}

/* returns the size of the message to send, or 0 in case of failure */
/* id may be NULL */
static int make_trace_reply (struct allnet_header * inhp, int insize,
                             struct allnet_trace_entry * th, char * id,
                             char * my_address, int abits,
                             char * result, int rsize)
{
  int size_needed = ALLNET_MGMT_HEADER_SIZE (0) +
                    sizeof (struct allnet_mgmt_trace_path);

  if (rsize < size_needed) printf ("need %d, have %d\n", size_needed, rsize);
  if (rsize < size_needed)
    return 0;
  bzero (result, size_needed);

  char * tracep = ALLNET_TRACE (inhp, inhp->transport, insize);
  if (tracep == NULL)
    return 0;

  struct allnet_header * hp = (struct allnet_header *) result;
  hp->version = ALLNET_VERSION;
  hp->message_type = ALLNET_TYPE_MGMT;
  hp->hops = 0;
  hp->max_hops = inhp->max_hops + 4;
  hp->src_nbits = abits;
  hp->dst_nbits = inhp->src_nbits;
  hp->sig_algo = ALLNET_SIGTYPE_NONE;
  hp->transport = 0;
  memcpy (hp->source, my_address, (abits + 7) / 8);
  memcpy (hp->destination, inhp->source, (hp->dst_nbits + 7) / 8);

  struct allnet_header_mgmt * mp =
    (struct allnet_header_mgmt *) ALLNET_DATA_START (hp, 0, size_needed);
  if (mp == NULL)
    return 0;
  mp->mgmt_type = ALLNET_MGMT_TRACE_PATH;
  struct allnet_mgmt_trace_path * mtp =
    (struct allnet_mgmt_trace_path *)
      (result + ALLNET_MGMT_HEADER_SIZE (0));
  mtp->trace_type = ALLNET_MGMT_TRACE_ID;
  memcpy (mtp->id_or_ack, id, MESSAGE_ID_SIZE);
  memcpy (mtp->trace, tracep, ALLNET_TRACE_SIZE);
  return size_needed;
}

static void respond_to_trace (int sock, char * message, int msize,
                              char * my_address, int abits)
{
  if (msize <= ALLNET_HEADER_SIZE)
    return;
  struct allnet_header * hp = (struct allnet_header *) message;
  /* we only respond to trace messages */
  if (hp->transport & ALLNET_TRANSPORT_TRACE == 0)
    return;
  struct allnet_trace_entry * th =
    (struct allnet_trace_entry *) (ALLNET_TRACE (hp, hp->transport, msize));
  if ((th == NULL) || (! ALLNET_VALID_TRACE (th, ALLNET_NUM_TRACES - 1))) {
    printf ("invalid trace header");
    return;
  }
  static char response [ALLNET_MTU];
  memset (response, 0, sizeof (response));
  char * id = ALLNET_PACKET_ID (hp, hp->transport, msize);
  if (id == NULL)
    id = ALLNET_MESSAGE_ID (hp, hp->transport, msize);
  /* id may still be null */
  if (id == NULL)  /* do not trace -- no point, really */
    return;
  int rsize = make_trace_reply (hp, msize, th, id, my_address, abits,
                                response, sizeof (response));
  if (rsize <= 0)
    return;
  if (! send_pipe_message (sock, response, rsize, EPSILON))
    printf ("unable to send trace response\n");
}

static void main_loop (int sock, char * my_address, int nbits)
{
  while (1) {
    char * message;
    int pipe, pri;
    int timeout = PIPE_MESSAGE_WAIT_FOREVER;
    int found = receive_pipe_message_any (timeout, &message, &pipe, &pri);
    if (found < 0) {
      printf ("pipe closed, exiting\n");
      exit (1);
    }
    respond_to_trace (sock, message, found, my_address, nbits);
    free (message);
  }
}

static void send_trace (int sock, char * address, int asize, char * nonce)
{
  static char buffer [ALLNET_MTU];
  memset (buffer, 0, sizeof (buffer));
  struct allnet_header * hp = (struct allnet_header *) buffer;
  hp->version = ALLNET_VERSION;
  hp->message_type = ALLNET_TYPE_CLEAR;
  hp->hops = 0;
  hp->max_hops = 10;
  hp->src_nbits = 0;
  hp->dst_nbits = asize;
  hp->sig_algo = ALLNET_SIGTYPE_NONE;
  hp->transport = ALLNET_TRANSPORT_TRACE;
  memcpy (hp->destination, address, (asize + 7) / 8);
  int send_size = ALLNET_SIZE (hp->transport) + MESSAGE_ID_SIZE;
  if (send_size > sizeof (buffer)) {  /* seems unlikely */
    printf ("error: sending %d, buffer size %zd\n",
            send_size, sizeof (buffer));
    return;
  }
  memcpy (ALLNET_DATA_START (hp, hp->transport, ALLNET_MTU),
          nonce, MESSAGE_ID_SIZE);
  if (! send_pipe_message (sock, buffer, send_size, THREE_QUARTERS))
    printf ("unable to send trace message\n");
}

static void handle_packet (char * message, int msize, char * seeking)
{
  int min_size = ALLNET_HEADER_SIZE + sizeof (struct allnet_header_mgmt) +
                 sizeof (struct allnet_mgmt_trace);
  if (msize <= min_size)
    return;
  struct allnet_header * hp = (struct allnet_header *) message;
  if (hp->message_type != ALLNET_TYPE_MGMT)
    return;

  struct allnet_header_mgmt * mp =
    (struct allnet_header_mgmt *) (message + ALLNET_SIZE (hp->transport));
  if (mp->mgmt_type != ALLNET_MGMT_TRACE_PATH)
    return;

  char * ep = ((char *) mp) + sizeof (struct allnet_header_mgmt);
  struct allnet_mgmt_trace_path * mtp = (struct allnet_mgmt_trace_path *) ep;
  char * nonce = mtp->id_or_ack;
  if (memcmp (nonce, seeking, MESSAGE_ID_SIZE) != 0) {
    printf ("received nonce does not match expected nonce\n");
    print_buffer (seeking, MESSAGE_ID_SIZE, "expected nonce", 100, 1);
    print_buffer (  nonce, MESSAGE_ID_SIZE, "received nonce", 100, 1);
    return;
  }
  print_packet (message, msize, "trace packet received", 1);
  printf ("received with hop count %d\n", hp->hops);
}

static void wait_for_responses (int sock, char * address, int asize,
                                char * nonce, int sec)
{
  time_t start = time (NULL);
  int min_size = ALLNET_HEADER_SIZE + sizeof (struct allnet_header_mgmt) +
                 sizeof (struct allnet_mgmt_trace);
  int remaining = time (NULL) - start;
  while (remaining < sec) {
    int pipe;
    int pri;
    char * message;
    int ms = remaining * 1000 + 999;
    int found = receive_pipe_message_any (ms, &message, &pipe, &pri);
    if (found <= 0) {
      printf ("pipe closed, exiting\n");
      exit (1);
    }
    handle_packet (message, found, nonce);
    free (message);
    remaining = time (NULL) - start;
  }
  printf ("timeout\n");
}

static void usage (char * pname)
{
  printf ("usage: %s <my_address_in_hex> <number_of_bits>\n", pname);
}

int main (int argc, char ** argv)
{
  if (argc < 2) {
    usage (argv [0]);
    return 1;
  }

  char address [100];
  int asize = get_address (argv [1], address, sizeof (address));
  if (asize <= 0) {
    usage (argv [0]);
    return 1;
  }
  int nbits = asize;
  if (argc >= 3) {
    char * end;
    int abits = strtol (argv [2], &end, 10);
    if ((end != argv [2]) && (abits > 0) && (abits < nbits))
      nbits = abits;
  }

  int sock = connect_to_local ();
  if (sock < 0)
    return 1;
  add_pipe (sock);

  if (strstr (argv [0], "traced") != NULL) {  /* called as daemon */
    main_loop (sock, address, nbits);
    printf ("trace error: main loop returned\n");
  } else {                                    /* called as client */
    char nonce [MESSAGE_ID_SIZE];
    random_bytes (nonce, sizeof (nonce));
    send_trace (sock, address, asize, nonce);
    wait_for_responses (sock, address, asize, nonce, 60);
  }
}
