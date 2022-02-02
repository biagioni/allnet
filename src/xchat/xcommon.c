/* xcommon.c: send and receive messages for xchat */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <inttypes.h>
#include <assert.h>
#include <pthread.h>
#include <sys/stat.h>

#include "chat.h"
#include "xcommon.h"
#include "message.h"
#include "cutil.h"
#include "store.h"
#include "retransmit.h"
#include "lib/media.h"
#include "lib/util.h"
#include "lib/app_util.h"
#include "lib/priority.h"
#include "lib/cipher.h"
#include "lib/priority.h"
#include "lib/allnet_log.h"
#include "lib/sha.h"
#ifndef ALLNET_KEYTYPE_RSA
#include "lib/dh.h"
#endif /* ALLNET_KEYTYPE_RSA/DH */
#include "lib/mapchar.h"
#include "lib/dcache.h"
#include "lib/routing.h"
#include "lib/configfiles.h"

/* #define DEBUG_PRINT */
#define HAVE_REQUEST_THREAD   /* run a thread to request data */

static struct allnet_log * alog = NULL;

/* time constants for requesting cached and missing data */
#define SLEEP_INITIAL_MIN	12   /* seconds -- should be 3 or more */
#define SLEEP_INITIAL_MAX	20   /* seconds */
#define SLEEP_INCREASE_NUMERATOR	12  /* 12/10, 20% increase */
#define SLEEP_INCREASE_DENOMINATOR	10
#define SLEEP_INCREASE_MIN	5    /* each time increase by at least 5s */
#define SLEEP_MAX_THRESHOLD	240  /* seconds -- 4min */
#define SLEEP_MAX		300  /* seconds -- 5min */

/* return a number between 1 and 10, with 1 twice as likely as 2,
 * 2 twice as likely as 3, and so on. */
static int random_hop_count ()
{
  int n = (int)random_int (0, 511);
  int hops = 1;
  /* set hops to 1 + the number of final 1 bits in n */
  while ((n & 1) != 0) {
    hops++;
    n = n >> 1;
  }
  return hops;
}

/* returns 1 if successfully sent something,
 * -1 if it is too soon to send,
 * 0 otherwise
 * if not NULL, start must be at least ALLNET_TIME_SIZE, 8 bytes
 * send at most once every 10 seconds (independently of start) */
static int send_data_request (int sock, int priority, char * start)
{
  static pthread_mutex_t sdr_mutex = PTHREAD_MUTEX_INITIALIZER;
  static unsigned long long int last_sent = 0;
  int do_execute = 1;
  unsigned long long int now = allnet_time ();
  pthread_mutex_lock (&sdr_mutex);
  if (now < last_sent + (SLEEP_INITIAL_MIN - 2))
    do_execute = 0;
  else
    last_sent = now;
  pthread_mutex_unlock (&sdr_mutex);
  if (! do_execute)
    return -1;
#define BITMAP_BITS_LOG	8  /* 11 or less to keep packet size below 1K */
#define BITMAP_BITS	(1 << BITMAP_BITS_LOG)
#define BITMAP_BYTES	(BITMAP_BITS / 8)
  unsigned int size;
  /* adr is an allnet_data_request */
  /* adr_size has room for each of the bitmaps */
  unsigned int adr_size =
    sizeof (struct allnet_data_request) + BITMAP_BYTES * 2;
  int hops = random_hop_count ();
  struct allnet_header * hp =
    create_packet (adr_size, ALLNET_TYPE_DATA_REQ, hops, ALLNET_SIGTYPE_NONE,
                   NULL, 0, NULL, 0, NULL, NULL, &size);
  hp->transport = ALLNET_TRANSPORT_DO_NOT_CACHE;
  struct allnet_data_request * adr =
    (struct allnet_data_request *)
       (ALLNET_DATA_START (hp, hp->transport, size));
  memset (adr, 0, adr_size);  /* clear everything */
  routing_local_token (adr->token);
  /* memset (adr->since, 0, sizeof (adr->since)); -- already cleared */
  if (start != NULL)
    memcpy (adr->since, start, ALLNET_TIME_SIZE);
  adr->dst_bits_power_two = BITMAP_BITS_LOG;
  adr->src_bits_power_two = BITMAP_BITS_LOG;
  adr->mid_bits_power_two = 0;
  random_bytes ((char *) (adr->padding), sizeof (adr->padding));
  unsigned char * dst = adr->dst_bitmap;
  unsigned char * src = dst + BITMAP_BYTES;
  unsigned char * ack = dst;
  /* requesting acks is slow, so do it once every 10 times */
  static int request_acks = 0;
  if (request_acks < 9) {
    if ((fill_bits (dst, BITMAP_BITS_LOG, FILL_LOCAL_ADDRESS ) < 0) ||
        (fill_bits (src, BITMAP_BITS_LOG, FILL_REMOTE_ADDRESS) < 0)) {
      size -= BITMAP_BYTES * 2;
      adr->dst_bits_power_two = 0;
      adr->src_bits_power_two = 0;
    }
    request_acks++;
  } else {   /* time to request missing acks */
    adr->dst_bits_power_two = 0;
    adr->src_bits_power_two = 0;
    adr->mid_bits_power_two = BITMAP_BITS_LOG;
    size -= BITMAP_BYTES;  /* just the mid instead of dst and src */
    if (fill_bits (ack, BITMAP_BITS_LOG, FILL_ACK) < 0) {
      size -= BITMAP_BYTES;
      adr->mid_bits_power_two = 0;
    }
    request_acks = 0;
  }
#ifdef DEBUG_PRINT
  print_packet (((const char *) hp), size, "sending data request", 1);
#endif /* DEBUG_PRINT */
  int r = local_send ((char *) (hp), size, priority);
  free (hp);
  if (! r) {
    snprintf (alog->b, alog->s, "unable to request data on %d\n", sock);
    log_print (alog);
    return 0;
  }
  return 1;
}

#ifdef HAVE_REQUEST_THREAD
static void * request_cached_data (void * arg)
{
  int sock = * (int *) arg;
  /* initial sleep is 12s-20s, slowly grow to ~5min */
  int sleep_time = (int)random_int (SLEEP_INITIAL_MIN, SLEEP_INITIAL_MAX);
  /* subsequent sleep (used on mobile devices when pushed) is much shorter */
  static int first_call = 1;
  if (! first_call)
    sleep_time = 3;   /* request almost immediately */
  first_call = 0;
  while (send_data_request (sock, ALLNET_PRIORITY_LOCAL_LOW, NULL) != 0) {
    /* loop forever, unless the socket is closed */
    sleep (sleep_time);
    if (sleep_time >= SLEEP_MAX_THRESHOLD)  /* sleep 4-5min */
      sleep_time = (int)random_int (SLEEP_MAX_THRESHOLD, SLEEP_MAX);
    else  /* increase sleep time by 1.2 plus 5 seconds */
      sleep_time = (int)random_int (sleep_time + SLEEP_INCREASE_MIN,
                                    ((sleep_time * SLEEP_INCREASE_NUMERATOR) /
                                     SLEEP_INCREASE_DENOMINATOR) +
                                    SLEEP_INCREASE_MIN);
  }
  snprintf (alog->b, alog->s, 
            "unable to request cached data on %d, ending request thread\n",
            sock);
  log_print (alog);
  return NULL;
}

static pthread_t request_thread;

#endif /* HAVE_REQUEST_THREAD */

/* returns the socket if successful, -1 otherwise */
int xchat_init (const char * arg0, const char * path, int optional_port_number)
{
  if (alog == NULL)
    alog = init_log ("xchat/xcommon");
  int sock = connect_to_local ("xcommon", arg0, path,
                               (optional_port_number == 0), 1,
                               optional_port_number);
  if (sock < 0)
    return -1;
#ifdef SO_NOSIGPIPE
  int option = 1;
  if (setsockopt (sock, SOL_SOCKET, SO_NOSIGPIPE, &option, sizeof (int)) != 0)
    perror ("xchat_init setsockopt nosigpipe");
#endif /* SO_NOSIGPIPE */
#ifdef HAVE_REQUEST_THREAD
  static int arg;
  arg = sock;
  /* request_cached_data loops forever, so do it in a separate thread */
  pthread_create (&request_thread, NULL, request_cached_data, (void *)(&arg));
  pthread_detach (request_thread);
#endif /* HAVE_REQUEST_THREAD */
#ifdef TEST_PUSH_REQUEST
const char public_key [] =
"-----BEGIN RSA PUBLIC KEY-----\n"
"MIICCgKCAgEA22TQgMWDQ8HqpEh96L+eb9UpvY26bqtTZAR+9zTIM5bC880Bn/t1\n"
"81znkrJjVyors3POm5JKrBHfnC5WNIF+YUXqwxzQsAPD5k6/6R5G9mfcW7jFKpbr\n"
"FGH/V59HPUwCzDg0S2PTZBIlv4vhcT1uBh+KBATEd1j+HCPSLm/FosGRW2MyG1Zh\n"
"sGmKcboNXwhQf9Fzd8SeISIbdG4ZBXhSuWaxM0YT9U8W/V/ZKuh/opDHNC0rKK5p\n"
"K69RafPXB6iLVd3eFzV6GAj3LbPR6HRmI2qmxiTYVrNkYQeMc8+SNmLPMrETvpFU\n"
"nkEgECwck0Ij37mvXAI75F83ZZGVrurYjmeqzTlzRy5xsYSCSR0WzOjvUC4UmRX6\n"
"e0rUJBMJ22Mv+xLMFO2WAYwVMDCxsD0L49TcwoLOfglYTuLz+Z9nM60WGluWHBxG\n"
"ldRzQOssEYeOpXflFx4SChwkhZ7BZuDHqp8xj5lIqwOggQHVTjbo4uXO641fmfpP\n"
"1xYKTIrHK4cjU5H4fEA4jxjl3B04w6nO2O5l2MTTRcKhSklc0ghWCLFsnZaHNJzE\n"
"8/LNRA31BTjPDbsW7K3ZhIpfQ1d2seWe/5LoN/HHWKubtPxUpCqZLPSsiVb2NrID\n"
"pbTwtDNiNsjkyY+Vox3f+tWiocIop3MZsSiGceqTxlY1NgN9lZl/AyECAwEAAQ==\n"
"-----END RSA PUBLIC KEY-----\n";
char token [] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                  0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
                  0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
                  0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
                  0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
                  0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f };
char buf [ALLNET_MTU];
char since [] = { 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47 };
int r =
  create_push_request (public_key, strlen (public_key), ALLNET_PUSH_APNS_ID,
                       token, sizeof (token), since, buf, sizeof (buf));
print_buffer (buf, r, "push request", sizeof (buf), 1);
#endif /* TEST_PUSH_REQUEST */

  return sock;
}

/* optional... */
void xchat_end (int sock)
{
  close (sock);
#ifdef HAVE_REQUEST_THREAD
#ifndef ANDROID   /* android doesn't have pthread_cancel */
  pthread_cancel (request_thread);
#endif /* ANDROID */
#endif /* HAVE_REQUEST_THREAD */
}

/* 1 ID hash for each of the data messages and the acks, and
 * one for the acks of the data messages (which is hashed on the message ID,
 * not the ack) */
#define ID_HASH_COUNT	    16384  /* *MESSAGE_ID_SIZE = 256K bytes each */
#define ID_HASH_COUNT_BITS  14     /* log_2(ID_HASH_COUNT) */

#define MESSAGE_ID_HASH_INDEX	0
#define  MESSAGE_ID_ACK_INDEX	1   /* not actually a hash */
#define      ACK_ID_HASH_INDEX	2
/* C initializes static data to 0, which is good */
static unsigned char id_hashes [3] [ID_HASH_COUNT] [MESSAGE_ID_SIZE];

static int idhash_index (const unsigned char * id)
{
  uint32_t index = ((uint32_t) readb32u (id)) >> (32 - ID_HASH_COUNT_BITS);
  return (int)index;
}

/* returns 1 if already found in hash.
 * if not found, returns 0.
 * ID must be at least MESSAGE_ID_SIZE */
static int idhash_check (int hash_index, const unsigned char * id)
{
  int index = idhash_index (id);
  if (memcmp (id_hashes [hash_index] [index], id, MESSAGE_ID_SIZE) == 0)
    return 1;
  return 0;
}

static int idhash_check_and_add (int hash_index, const unsigned char * id)
{
  int index = idhash_index (id);
  if (memcmp (id_hashes [hash_index] [index], id, MESSAGE_ID_SIZE) == 0)
    return 1;
  memcpy (id_hashes [hash_index] [index], id, MESSAGE_ID_SIZE);
  return 0;
}

#ifdef TRACK_RECENTLY_SENT_ACKS   /* no longer seems useful */
#define NUM_ACKS	100
/* initial contents should not matter, accidental match is unlikely */
static char recently_sent_acks [NUM_ACKS] [MESSAGE_ID_SIZE];
static int currently_sent_ack = 0;

static int is_recently_sent_ack (char * message_ack)
{
  int i;
  for (i = 0; i < NUM_ACKS; i++)
    if (memcmp (message_ack, recently_sent_acks [i], MESSAGE_ID_SIZE) == 0)
      return 1;
  return 0;
}
#endif /* TRACK_RECENTLY_SENT_ACKS */

/* send an ack for the given message and message ID */
static void send_ack (int sock, struct allnet_header * hp,
                      unsigned char * message_ack,
                      int send_resend_request, char * contact, keyset kset)
{
  if ((hp->transport & ALLNET_TRANSPORT_ACK_REQ) == 0) {
#ifdef DEBUG_PRINT
    printf ("packet not requesting an ack, no ack sent\n");
#endif /* DEBUG_PRINT */
    return;
  }
  /* make sure the ack is in the hash */
  idhash_check_and_add (ACK_ID_HASH_INDEX, message_ack);
  unsigned int size;
  char buffer [ALLNET_ACK_MIN_SIZE];
  struct allnet_header * ackp =
    init_ack (hp, message_ack, NULL, ADDRESS_BITS, buffer, &size);
  if (ackp == NULL)
    return;
#ifdef TRACK_RECENTLY_SENT_ACKS   /* no longer seems useful */
  /* also save in the (very likely) event that we receive our own ack */
  currently_sent_ack = (currently_sent_ack + 1) % NUM_ACKS;
  memcpy (recently_sent_acks [currently_sent_ack], message_ack,
          MESSAGE_ID_SIZE);
#endif /* TRACK_RECENTLY_SENT_ACKS */
#ifdef DEBUG_PRINT
  printf ("sending ack to contact %s: ", contact);
  print_packet ((char *) ackp, size, "ack", 1);
#endif /* DEBUG_PRINT */
  local_send ((char *) ackp, size, ALLNET_PRIORITY_LOCAL);
/* after sending the ack, see if we can get any outstanding
 * messages from the peer */
  if (send_resend_request)
    request_and_resend (sock, contact, kset, 1);
}

/* fill in the next contact and keyset,
 * and if not NULL, the total number of keysets for all individual contacts
 * return 1 if returning a valid contact and keyset, 0 otherwise */
static int next_keyset (char ** contact_p, keyset * k_p, int * total_keysets_p)
{
  static char * * contacts = NULL;
  static int num_contacts = 0;
  static keyset * keysets = NULL;
  static int num_current_keysets = 0;
  static int total_keysets = 0;
  static int current_contact = 0;
  static int current_keyset = 0;
  *contact_p = NULL;
  *k_p = -1;
  if (total_keysets_p != NULL)
    *total_keysets_p = total_keysets;
  if ((num_contacts > 0) && (current_contact < num_contacts) &&
      (num_current_keysets > 0) && (keysets != NULL) &&
      (current_keyset < num_current_keysets)) {
    /* note: this branch not usually taken, it is not common for
     * an individual contact to have more than one keyset.
     * We usually fall through to the next case. */
    *contact_p = contacts [current_contact];
    *k_p = keysets [current_keyset];
    current_keyset++;   /* refer to the next keyset, if any */
    return 1;           /* success */
  } /* else: these keyset(s) are finished, try the next contact(s) */
  if (keysets != NULL)
    free (keysets);
  /* get the next contact with keys, or if necessary, restart the list */
  int do_twice;
  int next_contact = current_contact + 1;
  for (do_twice = 0; do_twice < 2; do_twice++) {
    while (next_contact < num_contacts) {
      num_current_keysets = all_keys (contacts [next_contact], &keysets);
      if (num_current_keysets > 0) {  /* found */
        current_contact = next_contact;
        current_keyset = 1;  /* the next keyset, if any */
        *contact_p = contacts [current_contact];
        *k_p = keysets [0];  /* return the current keyset */
        return 1;            /* success */
      }
      next_contact++;
    }
    if (do_twice == 0) {   /* first time around, reset the list of contacts */
      if (contacts != NULL)
        free (contacts);
      num_contacts = all_individual_contacts (&contacts);
      next_contact = 0;     /* restart the while loop from the beginning */
      current_contact = num_contacts;  /* if success, set in the while loop */
      total_keysets = 0;    /* recompute the total keysets, may have changed */
      int c;
      for (c = 0; c < num_contacts; c++) {
        int nk = num_keysets (contacts [c]);
        total_keysets += ((nk > 0) ? nk : 0);
      }
      if (total_keysets_p != NULL)
        *total_keysets_p = total_keysets;
    }
  }
  return 0;    /* nothing to return */
}

/* call every once in a while, e.g. every 1-10s, to poke all our
 * contacts and get any outstanding messages. */
/* each time it is called, queries a different contact or keyset */
void do_request_and_resend (int sock)
{
  static unsigned long long int last_time = 0;
  unsigned long long int now = allnet_time ();
  if (last_time == now)  /* allow at most one call per second */
    return;
  last_time = now;
  char * contact = NULL;
  keyset k = 0;
  int num_loops = 0;
  if (! next_keyset (&contact, &k, &num_loops))
    return;   /* nothing to do */
  int i;      /* at most, try once for every keyset of every contact */
  for (i = 0; i < num_loops; i++) {
    int r = request_and_resend (sock, contact, k, 0);
/* request_and_resend returns 1 if sent, -1 if it is too soon,
 * 0 for nothing missing for this contact and keyset */
#ifdef DEBUG_PRINT
    if (r >= 0) { /* tried to send */
      time_t ctime_now = time (NULL);
      char * now_string = ctime (&ctime_now);
      char start_string [20];
      memset (start_string, 0, sizeof (start_string));
      memcpy (start_string, now_string, sizeof (start_string) - 1);
      printf ("%s: request_and_resend %d for %s/%d(%d)\n",
              start_string, r, contact, k, num_loops);
    }
#endif /* DEBUG_PRINT */
    if (r != 0) /* r == 1 means sent, we are done */
      return;   /* r == -1 means too soon, stop trying for now */
                /* r == 0 means nothing to send for this contact/keyset */
    if (! next_keyset (&contact, &k, NULL))
      return;   /* nothing to do */
  }
}

static void handle_ack (int sock, char * packet, unsigned int psize,
                        unsigned int hsize, struct allnet_ack_info * acks)
{
  struct allnet_header * hp = (struct allnet_header *) packet;
  /* save the acks */
  char * ack = packet + ALLNET_SIZE (hp->transport);
  int count = (psize - hsize) / MESSAGE_ID_SIZE; 
  int i;
  unsigned int ack_count = 0;
  for (i = 0; i < count; i++) {
    if (idhash_check_and_add (ACK_ID_HASH_INDEX, (unsigned char *) ack)) {
      /* the ack has already been seen, do not return it to the caller */
      ack += MESSAGE_ID_SIZE;
      continue;     /* go on to the next ack */
    }  /* otherwise, not found, but added.  Record for the caller */
    char * peer = NULL;
    keyset kset;
    int new_ack = 0;
    uint64_t ack_number = ack_received (ack, &peer, &kset, &new_ack);
    int free_peer = (peer != NULL);
    if ((ack_number > 0) && (peer != NULL)) {
      if (new_ack) {
        if ((acks != NULL) && (ack_count < ALLNET_MAX_ACKS)) {
          acks->acks [ack_count] = ack_number;
          acks->peers [ack_count] = peer;
          free_peer = 0;   /* saving ack, do not free the peer string */
        }
        ack_count++;
        reload_unacked_cache (peer, kset);
        request_and_resend (sock, peer, kset, 1);
      }
#ifdef DEBUG_PRINT
      printf ("sequence number %lld acked%s\n", ack_number,
              new_ack ? ", (new)" : "");
#endif /* DEBUG_PRINT */
    }
#ifdef TRACK_RECENTLY_SENT_ACKS   /* no longer seems useful */
      else if (is_recently_sent_ack (ack)) {
      /* printf ("received my own ack\n"); */
    } else {
      /* print_buffer (ack, MESSAGE_ID_SIZE, "unknown ack rcvd",
                    MESSAGE_ID_SIZE, 1); */
    }
    fflush (NULL);
#endif /* TRACK_RECENTLY_SENT_ACKS */
    if (free_peer)
      free (peer);
    ack += MESSAGE_ID_SIZE;
  }
  if (acks != NULL)
    acks->num_acks = ack_count;
}

static int cache_match (void * s1, void * s2)
{
  return (strcmp (s1, s2) == 0);
}

/* returns 0 for a new message, 1 for a message that was already cached */
static int cache_message (const char * data, unsigned int dsize,
                          const char * contact)
{
  static void * cache = NULL;
  if (cache == NULL)
    cache = cache_init (300, free, "xcommon.c cache_message");
  size_t len = strlen (data) + strlen (contact) + 3;
  char * copy = malloc_or_fail (len, "xcommon.c cache_message");
  snprintf (copy, len, "%s:%s\n", contact, data);
  void * found = cache_get_match (cache, cache_match, copy);
  if (found == NULL) {   /* not found */
    cache_add (cache, copy);
    return 0;
  } else {               /* already in the cache */
    free (copy);
    return 1;
  }
}

static int handle_clear (struct allnet_header * hp, char * data,
                         unsigned int dsize,
                         char ** contact, char ** message,
                         int * verified, int * duplicate, int * broadcast)
{
  if (hp->sig_algo == ALLNET_SIGTYPE_NONE) {
#ifdef DEBUG_PRINT
    printf ("ignoring unsigned clear packet of size %d\n", dsize);
#endif /* DEBUG_PRINT */
    return 0;
  }
  struct allnet_app_media_header * amhp =
    (struct allnet_app_media_header *) data;
  char * verif = data;
  uint32_t media = 0;
  if (dsize >= sizeof (struct allnet_app_media_header) + 2)
    media = (uint32_t)readb32u (amhp->media);
  if ((media != ALLNET_MEDIA_TEXT_PLAIN) &&
      (media != ALLNET_MEDIA_TIME_TEXT_BIN)) {
#ifdef DEBUG_PRINT
    printf ("handle_clear ignoring unknown media type %08" PRIx32 ", dsize %d\n",
            media, dsize);
#endif /* DEBUG_PRINT */
    return 0;
  }
  unsigned int ssize = readb16 (data + (dsize - 2)) + 2;  /* size of the sig */
  if ((ssize <= 2) || (dsize <= ssize)) {
    printf ("data packet size %d less than sig %d, dropping\n", dsize, ssize);
    print_buffer ((char *) hp, dsize + ALLNET_SIZE (hp->transport),
                  "original data", dsize + ALLNET_SIZE (hp->transport), 1);
    return 0;
  }
  data += sizeof (struct allnet_app_media_header);
  int text_size = dsize - sizeof (struct allnet_app_media_header) - ssize;
  char * sig = data + text_size;
#ifdef DEBUG_PRINT
  printf ("data size %d, text %d + sig %d\n", dsize, text_size, ssize);
#endif /* DEBUG_PRINT */
  struct bc_key_info * keys;
  int nkeys = get_other_keys (&keys);
  int i;
#ifdef DEBUG_PRINT
  print_buffer (verif, dsize - ssize, "verifying BC message", dsize, 1);
#endif /* DEBUG_PRINT */
  for (i = 0; i < nkeys; i++) {
    if ((matches ((unsigned char *) (keys [i].address), ADDRESS_BITS,
                  hp->source, hp->src_nbits) > 0) &&
        (allnet_verify (verif, dsize - ssize, sig, ssize - 2,
                        keys [i].pub_key))) {
      *contact = strcpy_malloc (keys [i].identifier,
                                "handle_message broadcast contact");
      *message = malloc_or_fail (text_size + 1, "handle_clear message");
      memcpy (*message, data, text_size);
      (*message) [text_size] = '\0';   /* null-terminate the message */
      *broadcast = 1;
      *verified = 1;
      *duplicate = cache_message (*message, text_size, *contact);
#ifdef DEBUG_PRINT
      printf ("verified bc message, contact %s, %d bytes\n",
              keys [i].identifier, text_size);
#endif /* DEBUG_PRINT */
      return text_size;
    } 
#ifdef DEBUG_PRINT
      else {
      printf ("matches (%02x%02x, %02x%02x/%d) == %d\n",
              keys [i].address [0] & 0xff, keys [i].address [1] & 0xff,
              hp->source [0] & 0xff, hp->source [1] & 0xff, hp->src_nbits,
              matches (keys [i].address, ADDRESS_BITS,
                       hp->source, hp->src_nbits));
      printf ("verify (%d/%d: %p/%d, %p/%d %d) == %d\n",
              i, nkeys, data, dsize - ssize, sig, ssize - 2, i,
              allnet_verify (verif, dsize - ssize, sig, ssize - 2,
                             keys [i].pub_key));
    }
#endif /* DEBUG_PRINT */
  }
#ifdef DEBUG_PRINT
  printf ("unable to verify bc message\n");
#endif /* DEBUG_PRINT */
  return 0;   /* did not match */
}

static int handle_data (int sock, struct allnet_header * hp, unsigned int psize,
                        char * data, unsigned int dsize,
                        char ** contact, keyset * kset,
                        char ** message, char ** desc, int * verified,
                        uint64_t * seqp, time_t * sent, uint64_t * prev_missing,
                        int * duplicate, int * broadcast)
{
  char * message_id = ALLNET_MESSAGE_ID (hp, hp->transport, psize);
  char message_ack [MESSAGE_ID_SIZE];
/* relatively quick check to see if we may have gotten this message before */
  if ((hp->transport & ALLNET_TRANSPORT_ACK_REQ) && (message_id != NULL) &&
      (idhash_check (MESSAGE_ID_HASH_INDEX, (unsigned char *) message_id))) {
    int index = idhash_index ((unsigned char *)message_id);
    memcpy (message_ack, id_hashes [MESSAGE_ID_ACK_INDEX] [index],
            MESSAGE_ID_SIZE);
#ifdef DEBUG_PRINT
    print_buffer (message_ack, MESSAGE_ID_SIZE,
                  "xcommon handle_data sending quick ack",
                  MESSAGE_ID_SIZE, 0);
    print_buffer (message_id, MESSAGE_ID_SIZE, ", message id",
                  MESSAGE_ID_SIZE, 1);
#endif /* DEBUG_PRINT */
#ifdef DEBUG_FOR_DEVELOPER
    /* printf ("sending quick ack for cached message\n"); */
    printf ("%lld: ", allnet_time_us ());
    print_buffer (message_ack, MESSAGE_ID_SIZE, "quick ack",
                  MESSAGE_ID_SIZE, 1);
#endif /* DEBUG_FOR_DEVELOPER */
    send_ack (sock, hp, (unsigned char *)message_ack, 0, "unknown", 0);
    return 0;
  }
  int hops = hp->hops;
  int verif = 0;
  char * text = NULL;
  int max_contacts = 0;  /* try all contacts */
  if (hp->src_nbits + hp->dst_nbits < 4)
    /* addresses are not very selective, don't try too many contacts */
    max_contacts = 30;  /* if we have a lot of contacts, don't try all */
#ifdef DEBUG_PRINT
  unsigned long long int start = allnet_time_us ();
#endif /* DEBUG_PRINT */
  int tsize = decrypt_verify (hp->sig_algo, data, dsize, contact, kset, &text,
                              (char *) (hp->source), hp->src_nbits,
                              (char *) (hp->destination), hp->dst_nbits,
                              max_contacts);
  if (tsize == 0) {
#ifdef DEBUG_PRINT
    printf ("unable to decrypt packet, dropping\n");
#endif /* DEBUG_PRINT */
    return 0;
  }
#ifdef DEBUG_PRINT
if (tsize > 0) {
  printf ("decrypt_verify %lluus, result %d, transport 0x%x, ",
          allnet_time_us () - start, tsize, hp->transport);
  printf ("%d hops %04x -> %04x, ",
          hops, readb16u (hp->source), readb16u (hp->destination));
if (hp->transport & ALLNET_TRANSPORT_ACK_REQ)
  print_buffer (ALLNET_MESSAGE_ID (hp, hp->transport, psize), 16, "id", 16, 1);
else {
  int msize = tsize - CHAT_DESCRIPTOR_SIZE;
  char * debug = malloc_or_fail (msize + 1, "debugging in xcommon.c");
  memcpy (debug, text + CHAT_DESCRIPTOR_SIZE, msize);
  debug [msize] = '\0';
  printf ("%s %lx, ", debug, readb32 (text));
  print_buffer (text, msize, NULL, 16, 1);
} }
#endif /* DEBUG_PRINT */
#ifdef DEBUG_PRINT
  if (tsize > (int)CHAT_DESCRIPTOR_SIZE) {
    int64_t print_seq = readb64 (text + 24);
    if (print_seq == -1) {
      printf ("from %s received control seq %" PRI64d ", %d bytes\n",
              *contact, print_seq, tsize);
    } else {
      int msize = tsize - CHAT_DESCRIPTOR_SIZE;
      char * debug = malloc_or_fail (msize + 1, "debugging in xcommon.c");
      memcpy (debug, text + CHAT_DESCRIPTOR_SIZE, msize);
      debug [msize] = '\0';
      printf ("from %s received seq %" PRI64d ", %d bytes, '%s'\n",
              *contact, print_seq, msize, debug);
    }
  }
#endif /* DEBUG_PRINT */
  if (tsize < 0) {
    printf ("no signature to verify, but decrypted from %s\n", *contact);
    tsize = -tsize;
  } else if (tsize > 0) {
    verif = 1;
  }
  if (tsize < (int) CHAT_DESCRIPTOR_SIZE) {
#ifdef DEBUG_PRINT
    printf ("decrypted packet has size %d, min is %zd, dropping\n",
            tsize, CHAT_DESCRIPTOR_SIZE);
#endif /* DEBUG_PRINT */
    return 0;
  }
  if (*contact == NULL) {
#ifdef DEBUG_PRINT
    printf ("contact not known, discarding packet\n");
#endif /* DEBUG_PRINT */
    if (text != NULL) free (text);
    return 0;
  }
#ifdef DEBUG_PRINT
  printf ("got %d-byte packet from contact %s\n", tsize, *contact);
#endif /* DEBUG_PRINT */
  struct chat_descriptor * cdp = (struct chat_descriptor *) text;
  struct chat_control    * ccp = (struct chat_control    *) text;

  /* save in the hash */
  if ((hp->transport & ALLNET_TRANSPORT_ACK_REQ) && (message_id != NULL)) {
    int index = idhash_index ((unsigned char *) message_id);
    memcpy (id_hashes [MESSAGE_ID_HASH_INDEX] [index],
            message_id, MESSAGE_ID_SIZE);
    memcpy (id_hashes [MESSAGE_ID_ACK_INDEX] [index],
            cdp->message_ack, MESSAGE_ID_SIZE);
  }

  unsigned long int app = readb32u (cdp->app_media.app);
  if (app != XCHAT_ALLNET_APP_ID) {
    printf ("handle_data ignoring unknown app %08lx\n", app);
#ifdef DEBUG_PRINT
    printf ("handle_data ignoring unknown app %08lx\n", app);
    print_buffer (text, CHAT_DESCRIPTOR_SIZE, "chat descriptor", 100, 1);
#endif /* DEBUG_PRINT */
    if (text != NULL) free (text);
    return 0;
  }
  unsigned long int media = readb32u (cdp->app_media.media);
  uint64_t seq = readb64u (cdp->counter);
#ifdef DEBUG_FOR_DEVELOPER
printf ("got chat message with sequence %lx\n", seq);
#endif /* DEBUG_FOR_DEVELOPER */
  if (seq == COUNTER_FLAG) {
    if ((app == XCHAT_ALLNET_APP_ID) &&
        (media == ALLNET_MEDIA_DATA) &&
        (ccp->type == CHAT_CONTROL_TYPE_REQUEST)) {
#ifdef DEBUG_PRINT
      printf ("got chat control message from %s, responding\n", *contact);
#endif /* DEBUG_PRINT */
      static long long int last_sent = 0;  /* only do once every 10s */
      if ((last_sent == 0) || (allnet_time () > last_sent + 10)) {
        do_chat_control (*contact, *kset, text, tsize, sock, hops + 4);
        last_sent = allnet_time ();
      }
      if ((hp->transport & ALLNET_TRANSPORT_ACK_REQ) && (message_id != NULL)) {
        send_ack (sock, hp, cdp->message_ack, verif, *contact, *kset);
      }
    } else if ((app == XCHAT_ALLNET_APP_ID) &&
               (ccp->type == CHAT_CONTROL_TYPE_KEY_ACK)) {
      printf ("received ack of key for contact %s\n", *contact);
    } else {
      printf ("chat control media type %08lx/%d, only %08x valid, ignoring\n",
              media, ccp->type, ALLNET_MEDIA_DATA);
      print_buffer (text, CHAT_DESCRIPTOR_SIZE, "chat descriptor", 100, 1);
    }
    if (*contact != NULL) { free (*contact); *contact = NULL; }
    if (text != NULL) free (text);
#ifdef DEBUG_FOR_DEVELOPER
printf ("control packet, not saving, media %lx\n", media);
#endif /* DEBUG_FOR_DEVELOPER */
    return 0;
  }

  if ((media != ALLNET_MEDIA_TEXT_PLAIN) &&
      (media != ALLNET_MEDIA_PUBLIC_KEY)) {
#ifdef DEBUG_PRINT
    printf ("handle_data ignoring media type %08lx (valid %08x %08x)\n",
            media, ALLNET_MEDIA_TEXT_PLAIN, ALLNET_MEDIA_PUBLIC_KEY);
    print_buffer (text, CHAT_DESCRIPTOR_SIZE, "chat descriptor", 100, 1);
#endif /* DEBUG_PRINT */
    if (text != NULL) free (text);
#ifdef DEBUG_FOR_DEVELOPER
printf ("unknown media %lx, not saving\n", media);
#endif /* DEBUG_FOR_DEVELOPER */
    return 0;
  }

  char * cleartext = text + CHAT_DESCRIPTOR_SIZE;
  int msize = tsize - CHAT_DESCRIPTOR_SIZE;

  *broadcast = 0;
  *duplicate = 0;
  if (was_received (*contact, *kset, seq)) {
printf ("duplicate seq %" PRId64 ", not saving for %s\n", seq, *contact);
#ifdef DEBUG_FOR_DEVELOPER
#endif /* DEBUG_FOR_DEVELOPER */
    *duplicate = 1;
  } else {
#ifdef DEBUG_FOR_DEVELOPER
printf ("saving seq %" PRId64 " for %s\n", seq, *contact);
#endif /* DEBUG_FOR_DEVELOPER */
    save_incoming (*contact, *kset, cdp, cleartext, msize, prev_missing);
  }

  if (media == ALLNET_MEDIA_PUBLIC_KEY) {
    cleartext = "received a key for an additional device";
    msize = (int)strlen (cleartext);
  }

  *desc = chat_descriptor_to_string (cdp, 0, 0);
  *seqp = seq;
  *verified = verif;
  if (sent != NULL)
    *sent = (readb64u (cdp->timestamp) >> 16) & 0xffffffff;

  *message = malloc_or_fail (msize + 1, "handle_data message");
  memcpy (*message, cleartext, msize);
  (*message) [msize] = '\0';   /* null-terminate the message */

  if ((hp->transport & ALLNET_TRANSPORT_ACK_REQ) && (message_id != NULL)) {
#ifdef DEBUG_FOR_DEVELOPER
printf ("sending regular ack\n");
#endif /* DEBUG_FOR_DEVELOPER */
    send_ack (sock, hp, cdp->message_ack, verif, *contact, *kset);
  }
  /* contact may be reachable, try to resend anything missing */
  request_and_resend (sock, *contact, *kset, 1);
  free (text);
  return msize;
}

/* return 1 if successfully matched a pending subscription,
 * 0 if it is not a key response,
 * -1 if it is a non-matching key response */
static int handle_sub (int sock, struct allnet_header * hp,
                       char * data, unsigned int dsize,
                       char ** subscription)
{
  *subscription = NULL;
  /* check the packet first */
  struct allnet_app_media_header * amhp =
    (struct allnet_app_media_header *) data;
  assert (ALLNET_APP_ID_SIZE == 4);
  assert (ALLNET_MEDIA_ID_SIZE == 4);
  unsigned long int media = 0;
  if (dsize >= sizeof (struct allnet_app_media_header) + 2 +
               KEY_RANDOM_PAD_SIZE)
    media = readb32u (amhp->media);
  if ((memcmp ("keyd", &(amhp->app), ALLNET_APP_ID_SIZE) != 0) ||
      (media != ALLNET_MEDIA_PUBLIC_KEY)) {
#ifdef DEBUG_PRINT
    printf ("handle_sub %s %ld, media type %08lx, dsize %u\n",
            "ignoring unknown app", readb32u (amhp->app), media, dsize);
#endif /* DEBUG_PRINT */
    return 0;
  }
  data += sizeof (struct allnet_app_media_header);
  dsize -= sizeof (struct allnet_app_media_header) + KEY_RANDOM_PAD_SIZE;
  char ** ahras = NULL;
  int na = requested_bc_keys (&ahras);
  if ((na > 0) && (ahras != NULL)) {
    int ia;
    for (ia = 0; ia < na; ia++) {
#ifdef DEBUG_PRINT
      printf ("handle_sub calling verify_bc_key for %s (%d/%d)\n",
              ahras [ia], ia, na);
#endif /* DEBUG_PRINT */
      if (verify_bc_key (ahras [ia], data, dsize, "en", 16, 1)) {
        printf ("received key does verify %s, saved\n", ahras [ia]);
        *subscription = strcpy_malloc (ahras [ia], "handle_sub");
        free (ahras);
        finished_bc_key_request (*subscription);
        return 1;
      }
    }
    free (ahras);
  }
  return -1;
}

static int get_dh_pubkey (int kset, char * result)
{
  char dh_secret [DH448_SIZE];
  if (get_dh_secret (kset, dh_secret, result, 1) > 0)
    return DH448_SIZE;
  printf ("unable to get dh pubkey for key %d\n", kset);
  return 0;
}

/* returns 1 for success, 0 for failure */
static int send_key (int sock, const char * contact, keyset kset,
                     const char * secret, unsigned char * address, int abits,
                     int max_hops, int send_even_if_recent)
{
  static char most_recent_contact [100] = "";
  static char most_recent_secret [100] = "";
  static long long int most_recent_send = 0;
  if ((! send_even_if_recent) &&
      (most_recent_send + 60 >= allnet_time ()) && /* sent in the last minute */
      (strcmp (most_recent_contact, contact) == 0) &&
      (strcmp (most_recent_secret, secret) == 0)) {
#ifdef DEBUG_PRINT
    printf ("skipping send key %s to %s, %lld + 60 >= %lld\n",
            secret, contact, most_recent_send, allnet_time ());
#endif /* DEBUG_PRINT */
    return 0;
  }
  most_recent_send = allnet_time ();
  snprintf (most_recent_contact, sizeof (most_recent_contact), "%s", contact);
  snprintf (most_recent_secret, sizeof (most_recent_secret), "%s", secret);

#ifdef ALLNET_KEYTYPE_RSA
  allnet_rsa_pubkey k;
  int ksize = get_my_pubkey (kset, &k);
  if (ksize <= 0) {
    printf ("unable to send key, no public key found for contact %s (%d/%d)\n",
            contact, kset, ksize);
    return 0;
  }
  char my_public_key [ALLNET_MTU];
  int pub_ksize = allnet_pubkey_to_raw (k, my_public_key,
                                        sizeof (my_public_key));
#else /* ALLNET_KEYTYPE_DH */
  char dh_pubkey [DH448_SIZE + 1];
  int pub_ksize = get_dh_pubkey (kset, dh_pubkey + 1) + 1;
  dh_pubkey [0] = ALLNET_KEY_XCHG_DH_AES_SECRET;
#endif /* ALLNET_KEYTYPE_RSA/DH */
  if (pub_ksize <= 0) {
    printf ("unable to send key, no public key found for contact %s (%d/%d)\n",
            contact, kset, pub_ksize);
    return 0;
  }
  int dsize = pub_ksize + SHA512_SIZE + KEY_RANDOM_PAD_SIZE;

  unsigned int size;
  struct allnet_header * hp =
    create_packet (dsize, ALLNET_TYPE_KEY_XCHG, max_hops, ALLNET_SIGTYPE_NONE,
                   address, abits, NULL, 0, NULL, NULL, &size);
  char * message = (char *) hp;

  char * data = message + ALLNET_SIZE (hp->transport);
#ifdef ALLNET_KEYTYPE_RSA
  memcpy (data, my_public_key, pub_ksize);
  sha512hmac (my_public_key, pub_ksize, secret, (int)strlen (secret),
              /* hmac is written directly into the packet */
              data + pub_ksize);
  random_bytes (data + pub_ksize + SHA512_SIZE, KEY_RANDOM_PAD_SIZE);
#else /* ALLNET_KEYTYPE_DH */
  memcpy (data, dh_pubkey, pub_ksize);
  sha512hmac (dh_pubkey, pub_ksize, secret, (int)strlen (secret),
              /* hmac is written directly into the packet */
              data + pub_ksize);
  random_bytes (data + pub_ksize + SHA512_SIZE, KEY_RANDOM_PAD_SIZE);
#endif /* ALLNET_KEYTYPE_RSA/DH */

#ifdef DEBUG_PRINT
  printf ("sending key of size %d\n", size);
#endif /* DEBUG_PRINT */
  int r = local_send (message, size, ALLNET_PRIORITY_LOCAL);
  free (message);
  if (! r) {
    printf ("unable to send %d-byte key exchange packet to %s\n",
            size, contact);
    return 0;
  }
  return 1;
}

#define KEY_CACHE_SIZE	10
struct key_cache_entry {
  struct allnet_header hp;
  char buffer [ALLNET_MTU];
  int dsize;
};
static struct key_cache_entry key_cache [KEY_CACHE_SIZE];
static int key_cache_next = -1;

static void init_key_cache ()
{
  if (key_cache_next >= 0)
    return;
  int i;
  for (i = 0; i < KEY_CACHE_SIZE; i++)
    key_cache [i].dsize = 0;
  key_cache_next = 0;
}

static void save_key_in_cache (struct allnet_header * hp,
                               char * data, int dsize)
{
  init_key_cache ();
  if ((dsize > ALLNET_MTU) || (dsize <= KEY_RANDOM_PAD_SIZE))
    return;
#ifdef DEBUG_KEY_CACHE_PRINT
  printf ("saving key, dsize %d\n", dsize);
#endif /* DEBUG_KEY_CACHE_PRINT */
  /* when comparing keys, ignore the random padding */
  int cmp_size = dsize - KEY_RANDOM_PAD_SIZE;
  int free = -1;
  int i;
  for (i = 0; i < KEY_CACHE_SIZE; i++) {
    if (key_cache [i].dsize == 0)
      free = i;
    else if ((key_cache [i].dsize == dsize) &&
             (memcmp (key_cache [i].buffer, data, cmp_size) == 0))
      return;  /* saved already */
  }
  if (free == -1) { /* replace the oldest in the cache */
    key_cache_next = (key_cache_next + 1) % KEY_CACHE_SIZE;
    free = key_cache_next;
  }
#ifdef DEBUG_KEY_CACHE_PRINT
  printf ("assigning %d to cache location %d (was %d)\n",
          dsize, free, key_cache [free].dsize);
#endif /* DEBUG_KEY_CACHE_PRINT */
  key_cache [free].dsize = dsize;
  memcpy (key_cache [free].buffer, data, dsize);
  key_cache [free].hp = *hp;
}

/* contents should have a hop count, followed by one or two secrets,
 * all separated by newlines.
 * if successful, points secret1, and possibly secret2, into contents.
 * returns 1 if successful, 0 otherwise */
static int parse_exchange_info (char * contents, int * hops,
                                char ** secret1, char ** secret2)
{
  *secret1 = NULL;
  *secret2 = NULL;
  *hops = 0;
  if (contents == NULL)
    return 0;
  char * saveptr = NULL;
  char * first = strtok_r (contents, "\n", &saveptr);
  if (first == NULL)  /* there should be a hop count and a secret */
    return 0;
  *secret1 = strtok_r (NULL, "\n", &saveptr);
  if (*secret1 == NULL) /* at least one secret is required */
    return 0;
  /* make sure the first string is a hop count */
  char * endptr;
  *hops = (int)strtol (first, &endptr, 10);
  if (endptr == first) { /* conversion failed */
    *hops = 0;
    *secret1 = NULL;
    return 0;
  }
  /* secret2 is optional */
  *secret2 = strtok_r (NULL, "\n", &saveptr);
#ifdef DEBUG_PRINT
  printf ("%d hops, secrets '%s' (%p) and (maybe) '%s' (%p)\n",
          *hops, *secret1, *secret1, *secret2, *secret2);
#endif /* DEBUG_PRINT */
  return 1;
}

/* returns 1 for a successful parse, 0 otherwise */
/* *s1 and *s2, if not NULL, are malloc'd (as needed), should be free'd */
int parse_exchange_file (const char * contact, int * nhops,
                         char ** s1, char ** s2)
{
  if (s1 != NULL)
    *s1 = NULL;
  if (s2 != NULL)
    *s2 = NULL;
  char * content = NULL;
  int size = contact_file_get (contact, "exchange", &content);
  if ((size <= 0) || (content == NULL))
    return 0;
  /* s1p and s2p point into "content", cannot be returned directly */
  char * s1p = NULL;
  char * s2p = NULL;
  int result = parse_exchange_info (content, nhops, &s1p, &s2p);
  if (result) {    /* copy the secrets before freeing contents */
    if ((s1 != NULL) && (s1p != NULL))
      *s1 = strcpy_malloc (s1p, "parse_exchange_file secret 1");
    if ((s2 != NULL) && (s2p != NULL))
      *s2 = strcpy_malloc (s2p, "parse_exchange_file secret 2");
  }
  free (content);
  return result;
}

/* for an incomplete key exchange, resends the key
 * return 1 if successful, 0 for failure (e.g. the key exchange is complete) */
int resend_contact_key (int sock, const char * contact)
{
  char * s1 = NULL;
  char * s2 = NULL;
  int nhops;
  int result = 0;
  if (parse_exchange_file (contact, &nhops, &s1, &s2))
    result = create_contact_send_key (sock, contact, s1, s2, nhops);
  if (s1 != NULL)
    free (s1);
  if (s2 != NULL)
    free (s2);
  return result;
}

/* return the number of secrets returned, 0, 1 (only s1), or 2 */
int key_exchange_secrets (const char * contact, char ** s1, char ** s2)
{
  int nhops;
  char * s1p = NULL;
  char * s2p = NULL;
  int result = 0;
  if (parse_exchange_file (contact, &nhops, &s1p, &s2p)) {
    /* get the right result, being tolerant of NULL s1 and/or s2 */
    if (s1p != NULL) {
      result = 1;
      if (s1 != NULL)
        *s1 = s1p;
      else
        free (s1p);
      if (s2p != NULL) {
        result = 2;
        if (s2 != NULL)
          *s2 = s2p;
        else
          free (s2p);
      }
    }
  }
  return result;
}

static int received_my_pubkey (keyset k, char * data, unsigned int dsize,
                               unsigned int ksize)
{
#ifdef ALLNET_KEYTYPE_RSA
  allnet_rsa_pubkey pubkey;
  int key_size = get_my_pubkey (k, &pubkey);
  if (key_size <= 0) {
    printf ("received_my_pubkey: keyset %d has %d-sized public key\n",
            k, key_size);
    return 0;   /* not my key */
  }
  char test_key [ALLNET_MTU];
  int pub_ksize = allnet_pubkey_to_raw (pubkey, test_key, sizeof (test_key));
#else /* ALLNET_KEYTYPE_DH */
  char test_key [DH448_SIZE + 1];
  int pub_ksize = get_dh_pubkey (k, test_key + 1) + 1;
  test_key [0] = ALLNET_KEY_XCHG_DH_AES_SECRET;
#endif /* ALLNET_KEYTYPE_RSA/DH */
  if ((pub_ksize == ksize) && (memcmp (data, test_key, ksize) == 0)) {
#ifdef DEBUG_PRINT
    printf ("received_my_pubkey: got my own key\n");
#endif /* DEBUG_PRINT */
    return 1;
  }
  return 0;   /* keys do not match */
}

static int received_matching_key (keyset k, char * data, unsigned int dsize,
                                  unsigned int ksize, const char * secret)
{
  if ((secret == NULL) || (dsize < ksize + SHA512_SIZE))
    return 0;
  char * received_hmac = data + ksize;
  char hmac [SHA512_SIZE];
  sha512hmac (data, ksize, secret, (int)strlen (secret), hmac);
  return (memcmp (hmac, received_hmac, SHA512_SIZE) == 0);
}

static void resend_peer_key (const char * contact, keyset k,
                             const char * secret,
                             unsigned char * addr, unsigned int abits,
                             int max_hops, int sock)
{
  if (! send_key (sock, contact, k, secret, addr, abits, max_hops, 1))
#ifdef DEBUG_PRINT
    printf ("send_key failed for key %d\n", k)
#endif /* DEBUG_PRINT */
    ;
}

/* if successful, returns -1, otherwise 0 */
static int handle_key (int sock, struct allnet_header * hp,
                       char * data, unsigned int dsize,
                       char ** peer, keyset * kset)
{
#ifdef DEBUG_PRINT
  printf ("in handle_key (%d)\n", dsize);
#endif /* DEBUG_PRINT */
  char ** contacts = NULL;
  keyset * keys = NULL;
  int * status = NULL;
  int ni = incomplete_key_exchanges (&contacts, &keys, &status);
#ifdef DEBUG_PRINT
  if (ni <= 0)   /* we're not expecting any keys, and cannot respond */
    printf ("got key, but no incomplete key exchanges %d\n", ni);
#endif /* DEBUG_PRINT */
  if (ni <= 0)   /* we're not expecting any keys, and cannot respond */
    return 0;
  int result = 0;
  if (dsize > SHA512_SIZE + KEY_RANDOM_PAD_SIZE + 2) {
    unsigned int ksize = dsize - SHA512_SIZE - KEY_RANDOM_PAD_SIZE;
    /* find the incomplete contact if any for which this key matches a secret */
    int ii;
    for (ii = 0; ii < ni; ii++) {
      /* secrets are listed in exchange files, so check that this has a file */
      int hops;
      char * s1 = NULL;
      char * s2 = NULL;
#ifdef DEBUG_PRINT
      printf ("testing contact %s, status %x & %x\n",
              contacts [ii], status [ii], KEYS_INCOMPLETE_HAS_EXCHANGE_FILE);
#endif /* DEBUG_PRINT */
      if ((status [ii] & KEYS_INCOMPLETE_HAS_EXCHANGE_FILE) &&
          (((status [ii] & KEYS_INCOMPLETE_NO_CONTACT_PUBKEY) != 0) ||
           ((status [ii] & KEYS_INCOMPLETE_DH) != 0)) &&
          (parse_exchange_file (contacts [ii], &hops, &s1, &s2)) &&
          (! received_my_pubkey (keys [ii], data, dsize, ksize))) {
        int r1 = received_matching_key (keys [ii], data, dsize, ksize, s1);
        int r2 = ((! r1) && (s2 != NULL) && (strlen (s2) > 0) &&
                  (received_matching_key (keys [ii], data, dsize, ksize, s2)));
if (r1 || r2)
        printf ("contact %s, received matching key %d (%d bytes), r %d %d\n",
                contacts [ii], keys [ii], ksize, r1, r2);
#ifdef DEBUG_PRINT
#endif /* DEBUG_PRINT */
        if (r1 || r2) {
          int record_remote_address = 0;
          if ((ksize == DH448_SIZE + 1) &&
              (data [0] == ALLNET_KEY_XCHG_DH_AES_SECRET)) {  /* DH key xchg */
char debug [DH448_SIZE];
printf ("processing DH key exchange (%d, %d)\n",
get_dh_secret (keys [ii], debug, NULL, 1),
get_dh_secret (keys [ii], debug, NULL, 0));
            char dh_local [DH448_SIZE];
            char dh_shared [DH448_SIZE];
            if ((get_dh_secret (keys [ii], dh_local, NULL, 1)) &&
                (! get_dh_secret (keys [ii], dh_shared, NULL, 0))) {
              if (allnet_x448 (dh_local, data + 1, dh_shared)) {
printf ("saving remote dh secret\n");
                set_dh_secret (keys [ii], dh_shared, 0);
                record_remote_address = 1;
                printf ("send_key_ack (contacts [%d] = %s, keys [%d] = %d);\n",
                        ii, contacts [ii], ii, keys [ii]);
              } else {
                printf ("allnet_x448 (handle_key) returned 0\n");
              }
            }
          } else {   /* RSA public key */
            record_remote_address =
              set_contact_pubkey (keys [ii], data, ksize);
          }
printf ("record_remote_address %d, hp->src_nbits %d\n", record_remote_address,
hp->src_nbits);
          if (record_remote_address &&
              (hp->src_nbits > 0) && (hp->src_nbits <= ADDRESS_BITS))
            set_contact_remote_addr (keys [ii], hp->src_nbits, hp->source);
          unsigned char my_addr [ADDRESS_SIZE];
          unsigned int abits = get_local (keys [ii], my_addr);
          if (r1)
            resend_peer_key (contacts [ii], keys [ii], s1,
                             my_addr, abits, hops, sock);
          else
            resend_peer_key (contacts [ii], keys [ii], s2,
                             my_addr, abits, hops, sock);
          *peer = strcpy_malloc (contacts [ii], "handle_key");
          *kset = keys [ii];
          result = -1;   /* success */
          if (s1 != NULL) free (s1);
          if (s2 != NULL) free (s2);
          break;           /* found a match, so we are done */
        }
      }
      if (s1 != NULL) free (s1);
      if (s2 != NULL) free (s2);
    }
  }
  free (contacts);
  free (keys);
  free (status);
  return result;
}

/* result is -4 if this is a trace reply, 0 otherwise */
static int handle_mgmt (int sock, struct allnet_header * hp,
                        char * packet, unsigned int psize,
                        struct allnet_mgmt_trace_reply ** trace_reply)
{
  if (trace_reply == NULL)
    return 0;
  if (ALLNET_TRACE_REPLY_SIZE (hp->transport, 1) < psize) {
    struct allnet_mgmt_header * mp =
      (struct allnet_mgmt_header *) (packet + ALLNET_SIZE (hp->transport));
    if (mp->mgmt_type == ALLNET_MGMT_TRACE_REPLY) {
      struct allnet_mgmt_trace_reply * trp =
        (struct allnet_mgmt_trace_reply *)
          (packet + ALLNET_MGMT_HEADER_SIZE (hp->transport));
      size_t size = sizeof (struct allnet_mgmt_trace_reply)
                  + trp->num_entries * sizeof (struct allnet_mgmt_trace_entry);
      *trace_reply = malloc_or_fail (size, "handle_mgmt");
      struct allnet_mgmt_trace_reply * fill = *trace_reply;
      *fill = *trp;   /* copy all the basic fields */
      int i;
      for (i = 0; i < trp->num_entries; i++)
        fill->trace [i] = trp->trace [i];
      return -4;
    }
  }
  return 0;
}

static char packet_cache [ALLNET_MTU * 10];  /* about 128K */
static int packet_cache_used = 0; /* how many bytes are in the packet cache */
static pthread_mutex_t packet_cache_mutex = PTHREAD_MUTEX_INITIALIZER;

static int packet_cache_get (char ** packet_result, int * should_free)
{
  *packet_result = NULL;
  *should_free = 0;
  pthread_mutex_lock (&packet_cache_mutex);
  int size = 0;
  if (packet_cache_used > 2) {
    size = readb16 (packet_cache);
    int size_with_length = 2 + size;
    if (packet_cache_used >= size_with_length) {
      *packet_result = memcpy_malloc (packet_cache + 2, size,
                                      "packet_cache_get");
      *should_free = 1;
      packet_cache_used -= size_with_length;  /* new size */
      if (packet_cache_used > 0)
        /* shift the other cached packets to the front of the cache */
        /* use memmove instead of memcpy because copying within same array */
        memmove (packet_cache, packet_cache + size_with_length,
                 packet_cache_used);
    } else {
      printf ("error sizes: packet %d, cache %d\n", size, packet_cache_used);
      size = 0;                /* invalid cache size, return no packet */
      packet_cache_used = 0;   /* clear cache too */
    }
  } else if (packet_cache_used > 0) { /* some error */
    printf ("error sizes 2: packet %d, cache %d\n", size, packet_cache_used);
    size = 0;                /* invalid cache size, return no packet */
    packet_cache_used = 0;   /* clear cache too */
  }
  pthread_mutex_unlock (&packet_cache_mutex);
  return size;
}

static void packet_cache_save (char * packet, int psize)
{
  if ((packet == NULL) || (psize <= 0))
    return;
  int size_with_length = 2 + psize;
  pthread_mutex_lock (&packet_cache_mutex);
  if (packet_cache_used + size_with_length <= sizeof (packet_cache)) {
    writeb16 (packet_cache + packet_cache_used, psize);
    memcpy (packet_cache + packet_cache_used + 2, packet, psize);
    packet_cache_used += size_with_length;
  }  /* else do nothing, the packet is discarded */
  pthread_mutex_unlock (&packet_cache_mutex);
}

/* if a previously received key matches one of the secrets, returns 1,
 * otherwise returns 0 */
int key_received_before (int sock, char ** peer, keyset * kset)
{
  init_key_cache ();
  int i;
  for (i = 0; i < KEY_CACHE_SIZE; i++) {
    if ((key_cache [i].dsize > 0) &&
        (handle_key (sock, &(key_cache [i].hp), key_cache [i].buffer,
                     key_cache [i].dsize, peer, kset) == -1)) {
#ifdef DEBUG_KEY_CACHE_PRINT
      printf ("using previously saved key, i %d, dsize %d\n",
              i, key_cache [i].dsize);
#endif /* DEBUG_KEY_CACHE_PRINT */
      key_cache [i].dsize = 0;   /* don't use it again */
      return 1;
    }
  }
  return 0;
}

/* drop packets if we are spending too much time on incoming messages */
static int too_much_time (int message_type, unsigned int priority,
                          long long int start_time,
                          long long int ** nstp,
                          long long int *multiplier)
{
  static long long int no_sooner_than_high_priority = 0;
  static long long int no_sooner_than_mid_priority = 0;
  static long long int no_sooner_than_low_priority = 0;
  static long long int no_sooner_than_ack = 0;
  if (message_type == ALLNET_TYPE_ACK) {  /* acks are special */
    *nstp = &no_sooner_than_ack;
    *multiplier = 3;   /* allow acks to consume 33% of the time */
  } else if (priority >= ALLNET_PRIORITY_FRIENDS_HIGH) {
    *nstp = &no_sooner_than_high_priority;
    *multiplier = 5;   /* allow receipt of my packets to take 20% of the time */
  } else if (priority >= ALLNET_PRIORITY_FRIENDS_LOW) {
    *nstp = &no_sooner_than_mid_priority;
    *multiplier = 20;  /* packet receipt for friends may take 5% of the time */
  } else {            /* lowest priority traffic */
    *nstp = &no_sooner_than_low_priority;
    *multiplier = 100;   /* allow packet receipt to consume 1% of the time */
  }
  if (start_time >= **nstp) { /* will process this packet */
    if (**nstp == 0)          /* first packet */
      *multiplier = 1;        /* give a free pass to the first packet */
  }
  return 0;                   /* too soon, drop the packet */
}

/* handle an incoming packet, acking it if it is a data packet for us
 * if psize is 0, checks internal buffer for previously unprocessed packets
 * and behaves as if a data packet was received.
 *
 * returns the message length > 0 if this was a valid data message from a peer.
 * if it gets a valid key, returns -1 (details below)
 * if it gets a new valid subscription, returns -2 (details below)
 * if it gets a new valid ack, returns -3 (details below)
 * if it gets a new valid trace message, returns -4 (details below)
 * Otherwise returns 0 and does not fill in any of the following results.
 *
 * if it is a data message, it is saved in the xchat log
 * if it is a valid data message from a peer or a broadcaster,
 * fills in verified and broadcast
 * fills in contact, message (to point to malloc'd buffers, must be freed)
 * if not broadcast, fills in desc (also malloc'd), seq, sent (if not null)
 * and duplicate.
 * if verified and not broadcast, fills in kset.
 * the data message (if any) is null-terminated
 *
 * if it is a key exchange message matching one of my pending key
 * exchanges, saves the key, fills in *peer, and returns -1.
 *
 * if it is an ack for a key exchange, fills in *peer, and returns -5.
 *
 * if it is a broadcast key message matching a pending key request,
 * saves the key, fills in *peer, and returns -2.
 *
 * if it is a new ack to something we sent, saves it in the xchat log
 * and if acks is not null, fills it in.  Returns -3
 *
 * if it is a trace reply, fills in trace_reply if not null (must be free'd),
 * and returns -4
 */
int handle_packet (int sock, char * packet, unsigned int psize,
                   unsigned int priority,
                   char ** contact, keyset * kset,
                   char ** message, char ** desc, int * verified,
                   uint64_t * seq, time_t * sent, uint64_t * prev_missing,
                   int * duplicate, int * broadcast,
                   struct allnet_ack_info * acks,
                   struct allnet_mgmt_trace_reply ** trace_reply)
{
  if (acks != NULL)
    acks->num_acks = 0;
  if (prev_missing != NULL)
    *prev_missing = 0;
  if (trace_reply != NULL)
    *trace_reply = NULL;
  int free_packet = 0;
  if ((psize == 0) || (packet == NULL)) /* may have a cached packet */
    psize = packet_cache_get (&packet, &free_packet);
  if ((packet == NULL) || (! is_valid_message (packet, psize, NULL)))
    return ((key_received_before (sock, contact, kset)) ? -1 : 0);

  struct allnet_header * hp = (struct allnet_header *) packet;
  unsigned int hsize = ALLNET_SIZE (hp->transport);
  if (psize < hsize) {
    return 0;
  }

  long long int start_time = allnet_time_us();
  long long int * nstp = NULL;
  long long int multiplier = 100;
  if (too_much_time (hp->message_type, priority, start_time,
                     &nstp, &multiplier)) {
    packet_cache_save (packet, psize); /* can't handle it now, try later */
    if (free_packet)
      free (packet);
    return ((key_received_before (sock, contact, kset)) ? -1 : 0);
  }

  do_request_and_resend (sock);

  int result = 0;

#ifdef DEBUG_PRINT
  if (hp->hops > 0)  /* not my own packet */
    print_packet (packet, psize, "xcommon received", 1);
#endif /* DEBUG_PRINT */

  if (hp->message_type == ALLNET_TYPE_ACK) {
    handle_ack (sock, packet, psize, hsize, acks);
    result = -3;
  } else if (hp->message_type == ALLNET_TYPE_CLEAR) { /* a broadcast packet */
    int sub = handle_sub (sock, hp, packet + hsize, psize - hsize, contact);
    if (sub > 0) {
#ifdef DEBUG_PRINT
      printf ("handle_sub (%d, %p, %p, %d, %s, %p, %d) ==> %d\n",
              sock, hp, packet + hsize, psize - hsize);
#endif /* DEBUG_PRINT */
      /* received a key in response to our subscription */
      result = -2;
    } else if (sub == 0) {  /* not a subscription packet */
      result = handle_clear (hp, packet + hsize, psize - hsize,
                             contact, message, verified, duplicate, broadcast);
    }
  } else if (hp->message_type == ALLNET_TYPE_DATA) { /* encrypted data packet */
    result = handle_data (sock, hp, psize, packet + hsize, psize - hsize,
                          contact, kset, message, desc, verified, seq, sent,
                          prev_missing, duplicate, broadcast);
  } else if (hp->message_type == ALLNET_TYPE_KEY_XCHG) {
    result = handle_key (sock, hp, packet + hsize, psize - hsize,
                         contact, kset);
    if (result == 0)   /* key not expected, save in case we need it later */
      save_key_in_cache (hp, packet + hsize, psize - hsize);
  } else if (hp->message_type == ALLNET_TYPE_MGMT) {
    result = handle_mgmt (sock, hp, packet, psize, trace_reply);
  }

  if ((result == 0) && (key_received_before (sock, contact, kset))) {
    result = -1;   /* key received before */
  }

  long long int finish_time = allnet_time_us();
  *nstp = finish_time + (finish_time - start_time) * multiplier;
  if (free_packet)
    free (packet);
  return result;
}

/* send this message and save it in the xchat log. */
/* returns the sequence number of this message, or 0 for errors */
uint64_t send_data_message (int sock, const char * peer,
                            const char * message, int mlen)
{
  if (mlen <= 0) {
    printf ("unable to send a data message of size %d\n", mlen);
    return 0;
  }

  static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
  pthread_mutex_lock (&mutex);    /* only one send at a time, please */
  static char buffer [ALLNET_MTU];
  int dsize = mlen + CHAT_DESCRIPTOR_SIZE;
  if (dsize >= sizeof (buffer)) {
    printf ("message size %d + %zd > %d, not sending\n", mlen,
            CHAT_DESCRIPTOR_SIZE, ALLNET_MTU);
    return 0;
  }
  memcpy (buffer + CHAT_DESCRIPTOR_SIZE, message, mlen);
  /* send_to_contact initializes the message ack in buffer */
  uint64_t seq = send_to_contact (buffer, dsize, peer, sock,
                                  6, ALLNET_PRIORITY_LOCAL, 1);
  int i;
  keyset * ks = NULL;
  int nks = all_keys (peer, &ks);
  for (i = 0; i < nks; i++)
    reload_unacked_cache (peer, ks [i]);
  if (ks != NULL)
    free (ks);
#ifdef DEBUG_PRINT
  printf ("sent seq %ju:\n", (uintmax_t)seq);
  print_buffer (data_with_cd, dsize, "sending", 64, 1);
#endif /* DEBUG_PRINT */
  pthread_mutex_unlock (&mutex);  /* next, please */
  return seq;
}

/* resend any pending keys: at most once a minute, with the time increasing
 * in proportion to 1% of the time since the key was created */
/* if not found, adds it to the list to be sent */
/* returns 1 to resend, 0 to not resend */
static int time_to_resend_key (keyset k, unsigned long long int now)
{
  struct key_info {
    keyset k;
    unsigned long long int sent_time;
    unsigned long long int created_time;
  };
/* info can only grow, never shrink, but its size is limited
 * to the number of keys */
  static struct key_info * info = NULL;
  static unsigned int num_info = 0;
  int i;
  for (i = 0; i < num_info; i++) {
/* if info is NULL, num_info is 0, and we never enter loop */
    if (info [i].k == k) {
#define DENOMINATOR	100
      unsigned long long int alive =  /* never less than DENOMINATOR */
        (now > info [i].created_time + DENOMINATOR) ?
        (now - info [i].created_time) : DENOMINATOR;
      /* send at most once a minute, and at most every 1% of the
       * time since creation */
      if (now > info [i].sent_time + (60 + alive / DENOMINATOR)) {
        info [i].sent_time = now;
        return 1;
      } else {  /* found, but too soon to send */
        return 0;
      }
#undef DENOMINATOR
    }
  }  /* not found, add */
  void * new_info = realloc (info, (num_info + 1) * sizeof (struct key_info));
  if (new_info != NULL) { /* realloc succeeded, save */
    info = new_info;
    info [num_info].k = k;
    info [num_info].sent_time = now;
    info [num_info].created_time = now;  /* if we can't get creation time */
    char * dir = key_dir (k);   /* find the creation time */
    char * hs = NULL;
    if (dir != NULL) {
      hs = strcat_malloc (dir, "/exchange", "time_to_resend_keys exchange");
      struct stat s;
      if ((stat (hs, &s) == 0) && (s.st_mtime > ALLNET_Y2K_SECONDS_IN_UNIX))
        info [num_info].created_time = s.st_mtime - ALLNET_Y2K_SECONDS_IN_UNIX;
#ifdef DEBUG_PRINT
      printf ("%s: creation time %llu (%lu), now %llu\n", hs,
              info [num_info].created_time, s.st_mtime, now);
#endif /* DEBUG_PRINT */
      free (hs);
      free (dir);
    }
    num_info++;
  }
  return 1;  /* saved or not, send the key */
}

static void resend_pending_keys (int sock, unsigned long long int now)
{
  char ** contacts = NULL;
  keyset * keys = NULL;
  int * status = NULL;
  int nc = incomplete_key_exchanges (&contacts, &keys, &status);
  int ic;
  for (ic = 0; ic < nc; ic++) {
    keyset k = keys [ic];
    /* we can only resend if there is an exchange file */
    if (((status [ic] & KEYS_INCOMPLETE_HAS_EXCHANGE_FILE) != 0) &&
        (time_to_resend_key (k, now))) {
      char * content = NULL;
      incomplete_exchange_file (contacts [ic], k, &content, NULL);
      if (content != NULL) {
        char * secret1 = NULL;  /* if parse successful, points into content */
        char * secret2 = NULL;
        int hops = 0;
        if (parse_exchange_info (content, &hops, &secret1, &secret2))
          /* resend */
          create_contact_send_key (sock, contacts [ic], secret1, secret2, hops);
        else
          printf ("exchange file parse error (%s) %p %p %d\n",
                  content, secret1, secret2, hops);
        free (content);
      } else {
        printf ("likely error: no key exchange file for contact %s",
                contacts [ic]);
      }
    }
  }
  if (contacts != NULL)
    free (contacts);
  if (keys != NULL)
    free (keys);
  if (status != NULL)
    free (status);
}

/* expiration must be at least ALLNET_TIME_SIZE, 8 bytes */
static void compute_expiration (char * expiration, 
                                unsigned long long int now,
                                unsigned long long int last,
                                unsigned long long int least)
{
  /* should expire now - last (but not less than least) seconds in the future */
  unsigned long long int delta = least;
  if ((last != 0) && (now > last) && (now - last > delta))
      delta = now - last;
  writeb64 (expiration, now + delta);
}

/* if there is anyting unacked, resends it.  If any sequence number is known
 * to be missing, requests it, but not too often */
/* returns:
 *    -1 if it is too soon to request again
 *    0 if it did not send a retransmit request for this contact/key 
 *      (e.g. if nothing is known to be missing)
 *    1 if it sent a retransmit request
 *    2 if it sent one or more unacked packets, but no retransmit request
 */
/* eagerly should be set when there is some chance that our peer is online,
 * i.e. when we've received a message or an ack from the peer.  In this
 * case, we retransmit and request data right away, independently of the
 * time since the last request */
int request_and_resend (int sock, char * contact, keyset kset, int eagerly)
{
  static unsigned long long int last_successful_call = 0;
  unsigned long long int now = allnet_time ();
  if ((last_successful_call >= now) && (! eagerly))
    return -1; /* if not eagerly, only allow one call per second */
#ifdef DEBUG_PRINT
  printf ("request and resend for %s\n", contact);
#endif /* DEBUG_PRINT */
  if (get_counter (contact) <= 0) {
    printf ("unable to request and resend for %s, peer not found\n", contact);
    return 0;
  }
  /* request retransmission of any missing messages */
  int hops = 10;
  /* let requests expire so on average at most ~3 will be cached at any time */
  static unsigned long long int last_retransmit = 0;
  int result = -1;   /* too soon */
  if (last_retransmit + 30 <= now) {  /* send at most once every 30s */
    char expiration [ALLNET_TIME_SIZE];
    compute_expiration (expiration, now, last_retransmit, 100);
    result = 0;      /* unable to send to this contact */
    if (send_retransmit_request (contact, kset, sock,
                                 hops, ALLNET_PRIORITY_LOCAL_LOW, expiration)) {
      last_retransmit = now;   /* sent something, update time */
      result = 1;    /* transmission successful */
      last_successful_call = now;
    }
  }
  /* send a data request, again at a very limited rate */
  static unsigned long long int last_data_request = 0;
  static unsigned long long int sleep_time = SLEEP_INITIAL_MIN;
/* printf ("request_and_resend (sock %d, peer %s) => %d, ",
        sock, contact, result);
   printf ("last %llu + sleep %llu = %llu <=> %llu\n",
        last_data_request, sleep_time, last_data_request + sleep_time, now); */
  if (last_data_request + sleep_time <= now) {
    char start [ALLNET_TIME_SIZE];
    writeb64 (start, last_data_request);
    if (send_data_request (sock, ALLNET_PRIORITY_LOCAL_LOW, start) > 0) {
      last_data_request = now;
      sleep_time += SLEEP_INCREASE_MIN;  /* but may adjust downwards below */
      if (sleep_time >= SLEEP_MAX_THRESHOLD)
        sleep_time = random_int (SLEEP_MAX_THRESHOLD, SLEEP_MAX);
      else  /* increase sleep time by about 1.2 */
        sleep_time = random_int (sleep_time,
                                 (sleep_time * SLEEP_INCREASE_NUMERATOR) /
                                 SLEEP_INCREASE_DENOMINATOR);
    }
  }
  /* resend any unacked messages, but less than once per minute (or eagerly) */
  static unsigned long long int last_resend = 0;
  if (eagerly || (last_resend + 60 <= now)) {  /* ru_ means resend-unacked */
    const char * ru_contact = contact;  /* don't change contact and kset */
    keyset ru_kset = kset;              /* ru is for Resend Unacked */
    int count = 1;
    char ** contacts = NULL;
    int send_to_all = (last_resend == 0);    /* first time, send to all */
    if (send_to_all)
      count = all_individual_contacts (&contacts);
    int ic;
    for (ic = 0; ic < count; ic++) {  /* only loops once, unless send_to_all */
      if ((send_to_all) && (contacts != NULL))
        ru_contact = contacts [ic];
      keyset * kp = NULL;
      int nk = 1;
      if (send_to_all)
        nk = all_keys (ru_contact, &kp);
      int ik;
      for (ik = 0; ik < nk; ik++) {  /* only loops once, unless send_to_all */
        if ((send_to_all) && (kp != NULL))
          ru_kset = kp [ik];
        uint64_t sent_time;
        uint64_t rcvd_time;
        int msg_type_s = most_recent_record (ru_contact, ru_kset, MSG_TYPE_SENT,
                                             NULL, &sent_time, NULL, NULL,
                                             NULL, NULL, NULL);
        int msg_type_r = most_recent_record (ru_contact, ru_kset, MSG_TYPE_RCVD,
                                             NULL, NULL, NULL, &rcvd_time,
                                             NULL, NULL, NULL);
        if ((msg_type_s == MSG_TYPE_DONE) && (msg_type_r == MSG_TYPE_DONE))
          continue;   /* next key, next contact, or done */
        if (msg_type_s == MSG_TYPE_DONE) 
          sent_time = rcvd_time;
        else if (msg_type_r == MSG_TYPE_DONE) 
          rcvd_time = sent_time;
        long long int delta = ((sent_time > rcvd_time) ?
                               now - sent_time : now - rcvd_time);
        /* heuristic: the longer it's been since we've communicated with
         * this contact, the less likely we should be to resend any unacked.
         * we'd like to send with 10% probability if the contact hasn't been
         * heard from in 10 days, 1% for 100 days, .1% for 1000 days, etc
         * we represent 100% as 10^6, 10% as 10^5, etc.  If the time has
         * been less than a day (86400 seconds), we always send */
	long long int prob_millionths = 1000000;
        unsigned long long int this_random = 0;  /* always send */
        if (delta > 86400) {  /* more than 1 day, send with probability */
	  prob_millionths = 86400000000LL / delta + 1;
          this_random = random_int (0, 1000000);
        }
        if (prob_millionths > this_random) {
#ifdef DEBUG_PRINT
          printf ("resending unacked to contact %s\n", ru_contact);
#endif /* DEBUG_PRINT */
          if (resend_unacked (ru_contact, ru_kset, sock, hops,
                              ALLNET_PRIORITY_LOCAL_LOW, 10) > 0) {
            last_resend = now;
            last_successful_call = now;
            if (result != 1)
              result = 2;
          }
        }
      }
      if (kp != NULL)
        free (kp);
    }
    if (contacts != NULL)
      free (contacts);
  }
  /* resend pending keys, not more (and usually less) than once per minute */
  /* ignore eagerly, since it doesn't apply to incomplete key exchanges */
  static unsigned long long int last_key_resend = 0;
  if (last_key_resend + 60 <= now) {
    resend_pending_keys (sock, now);
    last_key_resend = now;
  }
  return result;
}

/* create the contact and key, and send
 * the public key followed by
 *   the hmac of the public key using the secret as the key for the hmac.
 * the secrets should be normalized by the caller
 * secret2 may be NULL, secret1 should not be.
 * return 1 if successful, 0 for failure (usually if the contact already
 * exists, but other errors are possible) */
int create_contact_send_key (int sock, const char * contact,
                             const char * secret1, const char * secret2,
                             unsigned int hops)
{
  int error_tracker = 1;  /* for debugging */
  unsigned char addr [ADDRESS_SIZE];
  if ((contact == NULL) || (strlen (contact) == 0)) {
    printf ("empty contact, cannot send key\n");
#ifdef DEBUG_PRINT
#endif /* DEBUG_PRINT */
    return 0;
  }
  error_tracker = 2;      /* for debugging */
  if ((secret1 == NULL) || (strlen (secret1) == 0)) {
    printf ("empty secret1, cannot send key\n");
#ifdef DEBUG_PRINT
#endif /* DEBUG_PRINT */
    return 0;
  }
  error_tracker = 3;      /* for debugging */
  keyset kset;
  unsigned int abits = 16;  /* static for now */
  if (num_keysets (contact) < 0) {
    if (abits > ADDRESS_BITS)
      abits = ADDRESS_BITS;
    memset (addr, 0, ADDRESS_SIZE);
    random_bytes ((char *) addr, (abits + 7) / 8);
#ifdef ALLNET_KEYTYPE_RSA
    kset = create_contact (contact, 4096, 1,
                           NULL, 0, addr, abits, NULL, 0);
#else /* ALLNET_KEYTYPE_DH -- DH448_SIZE * 8 is 448 */
    kset = create_contact (contact, DH448_SIZE * 8, addr, abits, NULL, 0);
#endif /* ALLNET_KEYTYPE_RSA/DH */
    error_tracker = 4;    /* for debugging */
    if (kset < 0) {
      printf ("contact %s already exists\n", contact);
      return 0;
    }
    error_tracker = 5;    /* for debugging */
    char * dir = key_dir (kset);   /* create the exchange file */
    char * hs = NULL;
    if (dir != NULL) {
      error_tracker = 6;  /* for debugging */
      hs = strcat_malloc (dir, "/exchange", "create_contact_send_key exchange");
      char content [ALLNET_MTU];
      if (secret2 != NULL)
        snprintf (content, sizeof (content), "%d\n%s\n%s\n",
                  hops, secret1, secret2);
      else
        snprintf (content, sizeof (content), "%d\n%s\n", hops, secret1);
      write_file (hs, content, (int)strlen (content), 1);
      free (hs);
      error_tracker = 7;  /* for debugging */
    }
  } else {  /* contact already exists, get the keyset and the address */
    error_tracker = 8;    /* for debugging */
    keyset * keysets = NULL;
    int n = all_keys (contact, &keysets);
    if (n <= 0) {
      error_tracker = 9;  /* for debugging */
      printf ("contact %s already exists, but not found! %d\n", contact, n);
      return 0;
    }
    kset = keysets [0];
    free (keysets);
    abits = get_local (kset, addr);
  }
  if (send_key (sock, contact, kset, secret1, addr, abits, hops, 1)) {
    error_tracker = 10;   /* for debugging */
    char time_string [100];
    allnet_time_string (allnet_time (), time_string);
    error_tracker = 11;   /* for debugging */
    if ((secret2 != NULL) && (strlen (secret2) > 0) &&
        (send_key (sock, contact, kset, secret2, addr, abits, hops, 1)))
      error_tracker = 12;   /* for debugging */
#ifdef DEBUG_PRINT
    if (error_tracker == 12)
      printf ("%s: sent key to contact %s, %d hops, %s+%s\n",
              time_string, contact, hops, secret1, secret2);
    else
      printf ("%s: sent key to contact %s, %d hops, %s\n",
              time_string, contact, hops, secret1);
#endif /* DEBUG_PRINT */
    return 1;
  }
  printf ("send_key failed for create_contact_send_key (%d)\n", error_tracker);
  return 0;
}

static int send_key_request (int sock, const char * phrase)
{
  /* compute the destination address from the phrase */
  unsigned char source [ADDRESS_SIZE]; /* create a random source address */
  random_bytes ((char *)source, sizeof (source));
  unsigned char destination [ADDRESS_SIZE];
  char * mapped;
  int mlen = map_string (phrase, &mapped);
  sha512_bytes (mapped, mlen, (char *) destination, 1);
  free (mapped);

#define EMPTY_FINGERPRINT_SIZE  1  /* nbits_fingerprint plus the fingerprint */
  unsigned int dsize = EMPTY_FINGERPRINT_SIZE + KEY_RANDOM_PAD_SIZE;
  unsigned int psize = 0;
  struct allnet_header * hp =
    create_packet (dsize, ALLNET_TYPE_KEY_REQ, 10, ALLNET_SIGTYPE_NONE,
                   source, ADDRESS_BITS, destination, 8, NULL, NULL, &psize);
  
  if (hp == NULL) {
    printf ("send_key_request: unable to create packet of size %d/%d\n",
            dsize, psize);
    return 0;
  }
  unsigned int hsize = ALLNET_SIZE(hp->transport);
  if (psize != hsize + dsize) {
    printf ("send_key_request error: psize %d != %d = %d + %d\n", psize,
            hsize + dsize, hsize, dsize);
    return 0;
  }
  char * packet = (char *) hp;

  struct allnet_key_request * kp =
    (struct allnet_key_request *) (packet + hsize);
  kp->nbits_fingerprint = 0;
  char * r = ((char *) kp) + EMPTY_FINGERPRINT_SIZE;
  random_bytes (r, KEY_RANDOM_PAD_SIZE);

#ifdef DEBUG_PRINT
  printf ("sending %d-byte key request\n", psize);
#endif /* DEBUG_PRINT */
  int res = local_send (packet, psize, ALLNET_PRIORITY_LOCAL);
  if (! res) {
    printf ("unable to send key request message\n");
    return 0;
  }
  return 1;
}

/* sends out a request for a key matching the subscription.
 * returns 1 for success, 0 for failure */
int subscribe_broadcast (int sock, char * ahra)
{
  char * phrase;
  char * reason;
  if (! parse_ahra (ahra, &phrase, NULL, NULL, NULL, NULL, &reason)) {
    printf ("subcribe_broadcast unable to parse '%s': %s\n", ahra, reason);
    return 0;
  }
  /* record that we are requesting a broadcast key */
  requesting_bc_key (ahra);
  if (! send_key_request (sock, phrase))
    return 0;
  return 1;
}
