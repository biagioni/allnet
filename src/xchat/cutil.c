/* cutil.c: utility functions for chat */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <ctype.h>

#include "lib/packet.h"
#include "lib/media.h"
#include "lib/util.h"
#include "lib/pipemsg.h"
#include "lib/sha.h"
#include "lib/priority.h"
#include "lib/keys.h"
#include "lib/cipher.h"
#include "lib/allnet_log.h"
#include "chat.h"
#include "cutil.h"
#include "message.h"
#include "store.h"

/* strip most non-alphabetic characters, and convert the rest to uppercase */
void normalize_secret (char * s)
{
  while (*s != '\0') {
    if (! isalnum (*s)) {
      char * from = s + 1;  /* delete the char */
      char * to = s;
      while (*from != '\0')
        *(to++) = *(from++);
      *to = '\0';
    } else if ((*s == '0') /* zero */ || (toupper (*s) == 'O')) {
      *s = 'Q';  /* use Q as in Quebec for either zero or o/Oscar */
      s++;
    } else if ((*s == '1') || (toupper (*s) == 'I')) {
      *s = 'L';  /* use L for 1 or i */
      s++;
    } else if (isdigit (*s)) {
      *s = ('A' + ((*s) - '2'));  /* use A..H for any other digit */
      s++;
    } else {  /* make it uppercase */
      *s = toupper (*s);
      s++;
    }
  }
}

/* only really works within 24 hours -- otherwise, too complicated */
/* should use mktime, but does not translate GMT/UTC time */
static int delta_minutes (struct tm * local, struct tm * gm)
{
  int delta_hour = local->tm_hour - gm->tm_hour;
  if (local->tm_wday == ((gm->tm_wday + 8) % 7)) {
    delta_hour += 24;
  } else if (local->tm_wday == ((gm->tm_wday + 6) % 7)) {
    delta_hour -= 24;
  } else if (local->tm_wday != gm->tm_wday) {
    printf ("assertion error: weekday %d != %d +- 1\n",
            local->tm_wday, gm->tm_wday);
    exit (1);
  }
  int delta_min = local->tm_min - gm->tm_min;
  if (delta_min < 0) {
    delta_hour -= 1;
    delta_min += 60;
  }
  int result = delta_hour * 60 + delta_min;
  /*
  printf ("delta minutes is %02d:%02d = %d\n", delta_hour, delta_min, result);
  */
  return result;
}

/* returns the number of minutes between local time and UTC,
 * as a signed integer */
static int local_time_offset ()
{
  time_t now = time (NULL);

  struct tm now_ltime_tm;
  localtime_r (&now, &now_ltime_tm);
  struct tm gtime_tm;
  gmtime_r (&now, &gtime_tm);
/*
  printf ("local time %s", asctime (&now_ltime_tm));
  printf ("   gm time %s", asctime (&gtime_tm));
  printf ("local time %d:%02d:%02d, gm time %d:%02d:%02d\n",
          now_ltime_tm.tm_hour, now_ltime_tm.tm_min, now_ltime_tm.tm_sec,
          gtime_tm.tm_hour, gtime_tm.tm_min, gtime_tm.tm_sec);
  printf ("local time offset %d\n", delta_minutes (&now_ltime_tm, &gtime_tm));
*/
  return (delta_minutes (&now_ltime_tm, &gtime_tm));
}

/* returns 1 if successful, 0 otherwise */
int init_chat_descriptor (struct chat_descriptor * cp, const char * contact)
{
  uint64_t counter = get_counter (contact);
  if (counter == 0) {
    printf ("unable to locate key for contact '%s'\n", contact);
    return 0;
  }
  writeb64 ((char *) (cp->counter), counter);

  int my_time_offset = local_time_offset ();
  uint64_t now = allnet_time ();

  uint64_t compound = make_time_tz (now, my_time_offset);
  writeb64 ((char *) (cp->timestamp), compound);

  /* the fixed part of the header */
  writeb32 ((char *) (cp->app_media.app), XCHAT_ALLNET_APP_ID);
  writeb32 ((char *) (cp->app_media.media), ALLNET_MEDIA_TEXT_PLAIN);
  return 1;
}

/* return 1 if the message was sent, or if the key was invalid (i.e. should
 * try the next key).
 * returns 0 if the encryption or transmission failed, and it would probably
 * be best to stop trying */
/* can only do_save if also do_ack */
static int send_to_one (keyset k, char * data, unsigned int dsize,
                        const char * contact, int sock,
                        unsigned char * src, unsigned int sbits,
                        unsigned char * dst, unsigned int dbits,
                        unsigned int hops, unsigned int priority,
                        const char * expiration,
                        int do_ack, const unsigned char * ack, int do_save,
                        int debug_sending)
{
  if (dsize <= 0)
    return 0;
  static struct allnet_log * log = NULL;
  if (log == NULL) /* initialize */
    log = init_log ("cutil send_to_one");
/* printf ("sending to contact %s, keyset %d\n", contact, k); */
  unsigned int sksize = has_symmetric_key (contact, NULL, 0);
  struct allnet_stream_encryption_state sym_state;
  int has_sym_state = 0;
  if (symmetric_key_state (contact, &sym_state)) {
    has_sym_state = 1;
  } else if (sksize >= ALLNET_STREAM_KEY_SIZE) {  /* initialize the state */
    char * sym_key = malloc_or_fail (sksize * 2, "cutil.c send_to_one sym_key");
    sksize = has_symmetric_key (contact, sym_key, sksize);
    /* copy the key to the upper part of sym_key, to make a secret */
    memmove (sym_key + sksize, sym_key, sksize);
    allnet_stream_init (&sym_state, sym_key, 0, sym_key, 0, 8, 32);
    free (sym_key);
    save_key_state (contact, &sym_state);
    has_sym_state = 1;
  }
  /* if not already specified, get the addresses for the specific key */
  unsigned char a1 [ADDRESS_SIZE];
  if (src == NULL) {
    unsigned int nbits = get_local (k, a1);
    if (nbits < sbits)
      sbits = nbits;
    src = a1;
  }
  unsigned char a2 [ADDRESS_SIZE];
  if (dst == NULL) {
    unsigned int nbits = get_remote (k, a2);
    if (nbits < dbits)
      dbits = nbits;
    dst = a2;
  }
  /* set the message ack */
  unsigned char * message_ack = NULL;
  if (do_ack) {
    if (ack != NULL)
      memcpy (data, ack, MESSAGE_ID_SIZE);
    else
      random_bytes (data, MESSAGE_ID_SIZE);
    message_ack = (unsigned char *) data;
  } /* else message_ack is null, to make sure we don't ack, below */

  if (do_ack && do_save)
    save_outgoing (contact, k, (struct chat_descriptor *) data,
                   data + CHAT_DESCRIPTOR_SIZE, dsize - CHAT_DESCRIPTOR_SIZE);

  /* encrypt */
  int priv_ksize = 0;
  int ksize = 0;
  allnet_rsa_prvkey priv_key;
  allnet_rsa_pubkey key;
  char * encrypted = NULL;
  char * signature = NULL;
  unsigned int esize = 0;    /* size of the encrypted content */
  unsigned int sendsize = 0; /* size of the encrypted content + signature */
  unsigned int ssize = 0;    /* size of the signature */
  int sigtype = ALLNET_SIGTYPE_RSA_PKCS1;
  if (has_sym_state) {
    esize = dsize + sym_state.counter_size + sym_state.hash_size;
    encrypted = malloc_or_fail (esize, "cutil.c send_to_one encrypted msg");
    esize = allnet_stream_encrypt_buffer (&sym_state, data, dsize,
                                          encrypted, esize);
    save_key_state (contact, &sym_state);
    sigtype = ALLNET_SIGTYPE_NONE;  /* the hash provides the authentication */
    sendsize = esize;
  } else {
    priv_ksize = get_my_privkey (k, &priv_key);
    ksize = get_contact_pubkey (k, &key);
    if ((priv_ksize == 0) || (ksize == 0)) {
      printf ("unable to locate key %d for contact %s (%d, %d)\n",
              k, contact, priv_ksize, ksize);
      return 1;  /* skip to the next key */
    }
    esize = allnet_encrypt (data, dsize, key, &encrypted);
    if (esize > 0) {
      /* sign */
      ssize = allnet_sign (encrypted, esize, priv_key, &signature);
      if (ssize == 0) {
        printf ("unable to sign outgoing packet\n");
        if (encrypted != NULL) free (encrypted);
        if (signature != NULL) free (signature);
        return 0;  /* exit the loop */
      }
      sendsize = esize + ssize + 2;
    }
  }
  if ((esize == 0) || (encrypted == NULL) || (sendsize == 0)) {
    /* some serious problem */
    printf ("unable to encrypt retransmit request for key %d of %s: %d %p %d\n",
            k, contact, esize, encrypted, sendsize);
    if (encrypted != NULL) free (encrypted);
    if (signature != NULL) free (signature);
    return 0;  /* exit the loop */
  }

  unsigned int csize = sendsize;
  /* create_packet wants size without message ack */
  if ((message_ack != NULL) && (sendsize >= MESSAGE_ID_SIZE))
    csize = sendsize - MESSAGE_ID_SIZE;
  else if (message_ack != NULL) {
    printf ("error: csize %u, sendsize %u, id_size %d\n", 
            csize, sendsize, MESSAGE_ID_SIZE);
    return 0;  /* exit the loop */
  }
  if (expiration != NULL)
    csize += ALLNET_TIME_SIZE;
  unsigned int psize;
  struct allnet_header * hp =
    create_packet (csize, ALLNET_TYPE_DATA, hops, sigtype,
                   src, sbits, dst, dbits, NULL, message_ack, &psize);
  if (expiration != NULL) {
    hp->transport = hp->transport | ALLNET_TRANSPORT_EXPIRATION;
    char * header_exp = ALLNET_EXPIRATION (hp, hp->transport, psize);
    memcpy (header_exp, expiration, ALLNET_TIME_SIZE);
  }
  unsigned int hsize = ALLNET_SIZE (hp->transport);
  unsigned int msize = hsize + sendsize;
  if (psize != msize) {
    printf ("error: computed message size %d, actual %d\n", msize, psize);
    printf ("  hsize %d (%x, %p, %d), sendsize %d = e %d + s %d + 2\n",
            hsize, hp->transport, message_ack, do_ack, sendsize, esize, ssize);
    exit (1);
  }
  char * message = (char *) hp;
#ifdef DEBUG_PRINT
  if (debug_sending) {
    print_buffer (message, psize, "created packet", psize, 1);
    print_buffer (encrypted, esize, "encrypted", esize, 1);
    if (ssize > 0)
      print_buffer (signature, ssize, "sig", ssize, 1);
  }
#endif /* DEBUG_PRINT */

  memcpy (message + hsize, encrypted, esize);
  if (encrypted != NULL) free (encrypted);
  if ((signature != NULL) && (ssize > 0)) {
    memcpy (message + hsize + esize, signature, ssize);
    free (signature);
    writeb16 (message + hsize + esize + ssize, ssize);
  }

#ifdef DEBUG_PRINT
  if (expiration != NULL)
    print_packet (message, msize, "sending packet with expiration", 1);
#endif /* DEBUG_PRINT */

#ifdef DEBUG_PRINT
  print_packet (message, msize, "sending", 1);
#endif /* DEBUG_PRINT */
if ((readb16 (message + hsize + esize + ssize) != 512)) print_buffer (message, msize, "final", msize, 1);
  int result = 1;
  if (! send_pipe_message_free (sock, message, msize, priority, log)) {
    perror ("send_pipe_message_free");
    printf ("unable to send packet to %s, key %d, socket %d\n",
            contact, k, sock);
    result = 0;  /* still save if possible */
  } /* else
    printf ("sent packet to %s\n", peer); */
  return result;
}

/* same as send_to_contact, but only sends to the one key corresponding
 * to key, and does not save outgoing.  Does request ack, and
 * uses the addresses saved for the contact. */
int resend_packet (char * data, unsigned int dsize, const char * contact,
                   keyset key, int sock, unsigned int hops,
                   unsigned int priority)
{
  /* ack should already be in the packet data */
  unsigned char ack [MESSAGE_ID_SIZE];
  memcpy (ack, data, MESSAGE_ID_SIZE);
  return send_to_one (key, data, dsize, contact, sock, NULL, ADDRESS_BITS,
                      NULL, ADDRESS_BITS, hops, priority, NULL, 1, ack, 0, 1);
}

/* send to the contact's specific key, returning 1 if successful, 0 otherwise */
/* the xchat_descriptor must already have been initialized */
int send_to_key (char * data, unsigned int dsize,
                 const char * contact, keyset key, int sock,
                 unsigned int hops, unsigned int priority,
                 const char * expiration, int do_ack, int do_save)
{
  unsigned char src [ADDRESS_SIZE];
  unsigned char dst [ADDRESS_SIZE];
  unsigned int sbits = get_local (key, src);
  unsigned int dbits = get_remote (key, dst);
  return send_to_one (key, data, dsize, contact, sock,
                      src, sbits, dst, dbits, hops, priority,
                      expiration, do_ack, NULL, do_save, 0);
}

static unsigned long long int
  send_to_group (int depth, char * data, unsigned int dsize,
                 const char * contact, int sock,
                 unsigned int hops, unsigned int priority, int ack_and_save)
{
  if (depth > 100)  /* oo recursion, something wrong */
    return 0;
  if (! is_group (contact))
    return 0;
  char ** members = NULL;
  int n = group_contacts (contact, &members);
  if ((n <=0) || (members == NULL))
    return 0;
  unsigned long long int result = 0;
  int success = 1;
  int i;
  for (i = 0; ((success) && (i < n)); i++) {
    unsigned long long int seq = 0;
    if (is_group (members [i])) {
      printf ("error: result %s (%d/%d) from group_contacts (%s) is group\n",
              members [i], i, n, contact);
    } else {
#ifdef DEBUG_PRINT
      printf ("send_to_group %s sending to contact %s\n",
              contact, members [i]);
#endif /* DEBUG_PRINT */
      seq = send_to_contact (data, dsize, members [i], sock,
                             hops, priority, ack_and_save);
    }
    success = (seq > 0);
    if (seq > result)
      result = seq;
  }
  free (members);
  if (! success)
    return 0;
  return result;
}

/* send to the contact, returning the sequence number if successful, else 0 */
/* the message ACK (if any) must be set at the start of the data */
/* unless ack_and_save is 0, requests an ack, and calls save_outgoing. */
/* if contact is a group, sends to each member of the group and returns
 * the largest sequence number */
/* the message must include room for the chat descriptor 
 * and (if ack_and_save) for the ack, both initialized by this call. */
unsigned long long int send_to_contact (char * data, unsigned int dsize,
                                        const char * contact, int sock,
                                        unsigned int hops,
                                        unsigned int priority,
                                        int ack_and_save)
{
  if (is_group (contact)) {
      return send_to_group (0, data, dsize, contact, sock,
                            hops, priority, ack_and_save);
  }
  if (dsize < (int) (sizeof (struct chat_descriptor)))
    return 0;
  if (! init_chat_descriptor ((struct chat_descriptor *) data, contact))
    return 0;
  struct chat_descriptor * cp = (struct chat_descriptor *) data;
  /* get the keys */
  keyset * keys = NULL;
  int nkeys = all_keys (contact, &keys);
  if (nkeys <= 0) {
    printf ("unable to locate key for contact %s (%d)\n", contact, nkeys);
    return 0;
  }
  int k;
  int success = 1;
  for (k = 0; ((success) && (k < nkeys)); k++)
    success = send_to_key (data, dsize, contact, keys [k], sock,
                           hops, priority, NULL, ack_and_save, ack_and_save);
  free (keys);
  if (success)
    return (readb64u (cp->counter));
  return 0;  /* ! success */
}

char * chat_time_to_string (unsigned char * t, int static_result)
{
  static char buffer [40];   /* actually, 36 would be enough */
  int size = sizeof (buffer);
  char * result = buffer;
  if (! static_result)
    result = malloc_or_fail (size, "chat_time_to_string");

  uint64_t time;
  int time_offset;
  get_time_tz (readb64 ((char *) t), &time, &time_offset);
  int my_time_offset = local_time_offset ();

  struct tm time_tm;
  time_t time_t_time = (time_t) (time + ALLNET_Y2K_SECONDS_IN_UNIX);
  localtime_r (&time_t_time, &time_tm);
  asctime_r (&time_tm, result);
  /* delete the final \n by overwriting it with the null character */
  int eol_index = (int)strlen (result) - 1;
  if (result [eol_index] == '\n')
    result [eol_index] = '\0';
  if (time_offset == my_time_offset) { /* easy case, we are almost finished */
    tzset ();     /* set the tzname timezone variables */
    int index = 0;
#ifndef __OpenBSD__
    if (daylight)
      index = 1;
#endif /* __OpenBSD__ */
    snprintf (result + eol_index, size, " %s", tzname [index]);
    return result;
  }
#ifdef DEBUG_PRINT
  printf ("time offset %d, my time offset %d\n", time_offset, my_time_offset);
#endif /* DEBUG_PRINT */
  int print_offset = (int)strlen (result);
  int delta = time_offset - my_time_offset;
  while (delta < 0)
    delta += 0x10000;
/*  printf ("delta is %d\n", delta); */
  int neg = delta >= 0x8000;
  if (neg) {
    delta = 0x10000 - delta;
    int delta_min = delta % 60;
    int delta_hour = delta / 60;
/*  printf ("offset is %d - %d = %02d:%02d\n",
            time_offset, my_time_offset, delta_hour, delta_min); */
    snprintf (result + print_offset, size - print_offset, " (%+d:%02d)",
              -delta_hour, delta_min);
  } else {
    int delta_min = delta % 60;
    int delta_hour = delta / 60;
/*  printf ("offset is %d - %d = %02d:%02d\n",
            time_offset, my_time_offset, delta_hour, delta_min); */
    snprintf (result + print_offset, size - print_offset, " (%+d:%02d)",
              delta_hour, delta_min);
  }

  return result;
}

/* rsize should be at least 3 * dsize */
/* returns the number of characters in the final result */
static unsigned int make_hex (char * data, unsigned int dsize,
                              char * result, unsigned int rsize)
{
  unsigned int i;
  unsigned int total = 0;
  for (i = 0; i < dsize; i++) {
    int chars = snprintf (result, rsize, "%02x%s", data [i] & 0xff,
                          (i + 1 < dsize) ? ":" : "");
    total += chars;
    result += chars;
    rsize -= chars;
  }
  return total;
}

char * chat_descriptor_to_string (struct chat_descriptor * cdp,
                                  int show_id, int static_result)
{
  static char buffer [MESSAGE_ID_SIZE * 3 + COUNTER_SIZE * 3 + 40];
  int size = sizeof (buffer);
  char * result = buffer;
  if (! static_result)
    result = malloc_or_fail (size, "chat_descriptor_to_string");
  char * p = result;

  int written = 0;
  if (show_id) {
    written = snprintf (p, size, "id ");
    p += written; size -= written;
    written = make_hex ((char *) (cdp->message_ack), 6, p, size);
    p += written; size -= written;
    written = snprintf (p, size, ", ");
    p += written; size -= written;
  }

  unsigned long long int counter = readb64 ((char *) (cdp->counter));
  char * time_string = chat_time_to_string (cdp->timestamp, 1);
  written = snprintf (p, size, "sequence %lld, time %s", counter, time_string);
  p += written; size -= written;

  return result;
}

/* the chat descriptor stores time with the main part in the first 48 bits,
 * and the time zone (in signed minutes from UTC -- positive is East) in
 * the lower 16 bits */
void get_time_tz (uint64_t raw, uint64_t * time, int * tz)
{
  *time = (raw >> 16) & 0xffffffffffff;
  *tz   =  raw        & 0xffff;
  if (*tz > 0x7fff)
    *tz = - (0x10000 - *tz);
/* printf ("get_time_tz (%llx) ==> %llx, %d\n", raw, *time, *tz); */
}

uint64_t make_time_tz (uint64_t time, int tz)
{
/* printf ("make_time_tz (%llx, %d) => %llx\n",
time, tz, (time << 16) | (tz & 0xffff)); */
  return (time << 16) | (tz & 0xffff);
}

