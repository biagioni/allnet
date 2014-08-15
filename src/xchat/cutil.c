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
#include "lib/log.h"
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
    } else if ((*s == '0') /* zero */ || (toupper (*s) == 'Q')) {
      *s = 'O';  /* use O as in Oscar for either zero or q */
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
int init_chat_descriptor (struct chat_descriptor * cp, char * contact)
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
static int send_to_one (keyset k, char * data, int dsize, char * contact,
                        int sock, unsigned char * src, int sbits,
                        unsigned char * dst, int dbits,
                        int hops, int priority, int do_ack,
                        unsigned char * ack, int do_save)
{
  char * priv_key;
  char * key;
  int priv_ksize = get_my_privkey (k, &priv_key);
  int ksize = get_contact_pubkey (k, &key);
  if ((priv_ksize == 0) || (ksize == 0)) {
    printf ("unable to locate key %d for contact %s (%d, %d)\n",
            k, contact, priv_ksize, ksize);
    return 1;  /* skip to the next key */
  }
  /* if not already specified, get the addresses for the specific key */
  unsigned char a1 [ADDRESS_SIZE];
  if (src == NULL) {
    int nbits = get_local (k, a1);
    if (nbits < sbits)
      sbits = nbits;
    src = a1;
  }
  unsigned char a2 [ADDRESS_SIZE];
  if (dst == NULL) {
    int nbits = get_remote (k, a2);
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

  /* encrypt */
  char * encrypted;
  int esize = allnet_encrypt (data, dsize, key, ksize, &encrypted);
  if (esize == 0) {  /* some serious problem */
    printf ("unable to encrypt retransmit request for key %d of %s\n",
            k, contact);
    return 0;  /* exit the loop */
  }
  /* sign */
  char * signature;
  int ssize = allnet_sign (encrypted, esize, priv_key, priv_ksize, &signature);
  if (ssize == 0) {
    printf ("unable to sign retransmit request\n");
    free (encrypted);
    return 0;  /* exit the loop */
  }

  int sendsize = esize + ssize + 2;
  int csize = sendsize;
  if (message_ack != NULL)
    csize = sendsize - MESSAGE_ID_SIZE;
  int psize;
  struct allnet_header * hp =
    create_packet (csize, ALLNET_TYPE_DATA, hops, ALLNET_SIGTYPE_RSA_PKCS1,
                   src, sbits, dst, dbits, message_ack, &psize);
  int hsize = ALLNET_SIZE (hp->transport);
  int msize = hsize + sendsize;
  if (psize != msize) {
    printf ("error: computed message size %d, actual %d\n", msize, psize);
    printf ("  hsize %d (%x, %p, %d), sendsize %d = e %d + s %d + 2\n",
            hsize, hp->transport, message_ack, do_ack, sendsize, esize, ssize);
    exit (1);
  }
  char * message = (char *) hp;

  memcpy (message + hsize, encrypted, esize);
  free (encrypted);
  memcpy (message + hsize + esize, signature, ssize);
  free (signature);
  writeb16 (message + hsize + esize + ssize, ssize);

#ifdef DEBUG_PRINT
  print_packet (message, msize, "sending", 1);
#endif /* DEBUG_PRINT */
  if (! send_pipe_message_free (sock, message, msize, priority)) {
    printf ("unable to request retransmission from %s\n", contact);
    return 0;
  } /* else
    printf ("requested retransmission from %s\n", peer); */
  if (do_ack && do_save)
    save_outgoing (contact, k, (struct chat_descriptor *) data,
                   data + CHAT_DESCRIPTOR_SIZE, dsize - CHAT_DESCRIPTOR_SIZE);
  return 1;
}

/* same as send_to_contact, but only sends to the one key corresponding
 * to key, and does not save outgoing.  Does request ack, and
 * uses the addresses saved for the contact. */
int resend_packet (char * data, int dsize, char * contact, keyset key, int sock,
                   int hops, int priority)
{
  /* ack should already be in the packet data */
  unsigned char ack [MESSAGE_ID_SIZE];
  memcpy (ack, data, MESSAGE_ID_SIZE);
  return send_to_one (key, data, dsize, contact, sock, NULL, ADDRESS_BITS,
                      NULL, ADDRESS_BITS, hops, priority, 1, ack, 0);
}

/* send to the contact, returning 1 if successful, 0 otherwise */
/* if src is NULL, source address is taken from get_local, likewise for dst */
/* if so, uses the lesser of s/dbits and the address bits */
/* the message ACK must be set at the start of the data */
/* unless ack_and_save is 0, requests an ack, and after the message is sent,
 * calls save_outgoing. */
int send_to_contact (char * data, int dsize, char * contact, int sock,
                     unsigned char * src, int sbits,
                     unsigned char * dst, int dbits,
                     int hops, int priority, int ack_and_save)
{
  /* get the keys */
  keyset * keys;
  int nkeys = all_keys (contact, &keys);
  if (nkeys <= 0) {
    printf ("unable to locate key for contact %s (%d)\n", contact, nkeys);
    return 0;
  }

  int result = 1;
  int k;
  for (k = 0; ((result) && (k < nkeys)); k++)
    result = send_to_one (keys [k], data, dsize, contact, sock, src, sbits,
                          dst, dbits, hops, priority,
                          ack_and_save, NULL, ack_and_save);
  return result;
}

char * chat_time_to_string (unsigned char * t, int static_result)
{
  static char buffer [40];   /* actually, 36 would be enough */
  int size = sizeof (buffer);
  char * result = buffer;
  if (! static_result)
    result = malloc (size);

  uint64_t time;
  int time_offset;
  get_time_tz (readb64 ((char *) t), &time, &time_offset);
  int my_time_offset = local_time_offset ();

  struct tm time_tm;
  time_t time_t_time = time + ALLNET_Y2K_SECONDS_IN_UNIX;
  localtime_r (&time_t_time, &time_tm);
  asctime_r (&time_tm, result);
  /* delete the final \n by overwriting it with the null character */
  int eol_index = strlen (result) - 1;
  if (result [eol_index] == '\n')
    result [eol_index] = '\0';
  if (time_offset == my_time_offset) { /* easy case, we are almost finished */
    tzset ();     /* set the timezone variables */
    strcat (result, " ");
    if (daylight)
      strcat (result, tzname [1]);
    else
      strcat (result, tzname [0]);
    return result;
  }
#ifdef DEBUG_PRINT
  printf ("time offset %d, my time offset %d\n", time_offset, my_time_offset);
#endif /* DEBUG_PRINT */
  int print_offset = strlen (result);
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
static int make_hex (char * data, int dsize, char * result, int rsize)
{
  int i;
  int total = 0;
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
    result = malloc (size);
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

