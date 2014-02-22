/* cutil.c: utility functions for chat */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include "../packet.h"
#include "../lib/util.h"
#include "../lib/sha.h"
#include "../lib/priority.h"
#include "../lib/keys.h"
#include "chat.h"
#include "cutil.h"
#include "store.h"

/* strip most non-alphabetic characters, and convert the rest to uppercase */
void normalize_secret (char * s)
{
  char * original = s;
  while (*s != '\0') {
    if ((! isalpha (*s)) && (*s != '0') && (*s != '1')) {
      char * from = s + 1;  /* delete the char */
      char * to = s;
      while (*from != '\0')
        *(to++) = *(from++);
      *to = '\0';
    } else if (*s == '0') {   /* zero */
      *s = 'O';  /* O as in Oscar */
      s++;
    } else if ((*s == '1') || (toupper (*s) == 'I')) {
      *s = 'L';  /* use L for 1 or i */
      s++;
    } else {  /* make it uppercase */
      *s = toupper (*s);
      s++;
    }
  }
  printf ("normalized secret is '%s'\n", original);
}

/* only really works within 24 hours -- otherwise, too complicated */
/* should use mktime, but does not translated GMT/UTC time */
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
  return (delta_minutes (&now_ltime_tm, &gtime_tm) & 0xffff);
}

/* returns 1 if successful, 0 otherwise */
int init_chat_descriptor (struct chat_descriptor * cp, char * contact,
                          char * message_ack_hash)
{
  bzero (message_ack_hash, MESSAGE_ID_SIZE);
  random_bytes (cp->message_ack, MESSAGE_ID_SIZE);
  sha512_bytes (cp->message_ack, MESSAGE_ID_SIZE,
                message_ack_hash, MESSAGE_ID_SIZE);

  unsigned long long int counter = get_counter (contact);
  if (counter == 0) {
    printf ("unable to locate key for contact '%s'\n", contact);
    return 0;
  }
  writeb64 (cp->counter, counter);

  int my_time_offset = local_time_offset ();
  unsigned long long int now = time (NULL);
  writeb48 (cp->timestamp, now);
  writeb16 (cp->timestamp + 6, my_time_offset);
  return 1;
}

/* send to the contact, returning 1 if successful, 0 otherwise */
/* if src is NULL, source address is taken from get_source, likewise for dst */
/* if so, uses the lesser of s/dbits and the address bits */
int send_to_contact (char * data, int dsize, char * contact, int sock,
                     char * src, int sbits, char * dst, int dbits,
                     int hops, int priority)
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
  for (k = 0; k < nkeys; k++) {
    char * priv_key;
    char * key;
    int priv_ksize = get_my_privkey (keys [k], &priv_key);
    int ksize = get_contact_pubkey (keys [k], &key);
    char a1 [ADDRESS_SIZE];
    char a2 [ADDRESS_SIZE];
    if (src == NULL) {
      int nbits = get_source (keys [k], a1);
      if (nbits < sbits)
        sbits = nbits;
      src = a1;
    }
    if (dst == NULL) {
      int nbits = get_destination (keys [k], a2);
      if (nbits < dbits)
        dbits = nbits;
      dst = a2;
    }
    if ((priv_ksize == 0) || (ksize == 0)) {
      printf ("unable to locate key %d for contact %s (%d, %d)\n",
              k, contact, priv_ksize, ksize);
      continue;  /* skip to the next key */
    }
    /* set the message ack */
    struct chat_descriptor * cdp = (struct chat_descriptor *) data;
    random_bytes (cdp->message_ack, MESSAGE_ID_SIZE);
    char message_ack_hash [MESSAGE_ID_SIZE];
    sha512_bytes (cdp->message_ack, MESSAGE_ID_SIZE,
                  message_ack_hash, MESSAGE_ID_SIZE);
    /* encrypt */
    char * encrypted;
    int esize = encrypt (data, dsize, key, ksize, &encrypted);
    if (esize == 0) {  /* some serious problem */
      printf ("unable to encrypt retransmit request for key %d of %s\n",
              k, contact);
      result = 0;
      break;  /* exit the loop */
    }
    /* sign */
    char * signature;
    int ssize = sign (encrypted, esize, priv_key, priv_ksize, &signature);
    if (ssize == 0) {
      printf ("unable to sign retransmit request\n");
      free (encrypted);
      result = 0;
      break;  /* exit the loop */
    }

    int transport = ALLNET_TRANSPORT_ACK_REQ;

    int hsize = ALLNET_SIZE (transport);
    int msize = hsize + esize + ssize + 2;
    char * message = malloc_or_fail (msize, "retransmit_request message");
    bzero (message, msize);
    struct allnet_header * hp = (struct allnet_header *) message;
    hp->version = ALLNET_VERSION;
    hp->message_type = ALLNET_TYPE_DATA;
    hp->hops = 0;
    hp->max_hops = hops;
    hp->src_nbits = sbits;
    hp->dst_nbits = dbits;
    hp->sig_algo = ALLNET_SIGTYPE_RSA_PKCS1;
    hp->transport = transport;
    memcpy (hp->source, src, ADDRESS_SIZE);
    memcpy (hp->destination, dst, ADDRESS_SIZE);
    memcpy (ALLNET_MESSAGE_ID(hp, transport, msize),
            message_ack_hash, MESSAGE_ID_SIZE);

    memcpy (message + hsize, encrypted, esize);
    free (encrypted);
    memcpy (message + hsize + esize, signature, ssize);
    free (signature);
    writeb16 (message + hsize + esize + ssize, ssize);

    if (! send_pipe_message (sock, message, msize, priority))
      printf ("unable to request retransmission from %s\n", contact);
    /* else
        printf ("requested retransmission from %s\n", peer); */
    free (message);
  }
  return result;
}

char * chat_time_to_string (unsigned char * t, int static_result)
{
  static char buffer [40];   /* actually, 36 would be enough */
  int size = sizeof (buffer);
  char * result = buffer;
  if (! static_result)
    result = malloc (size);
  char * p = result;

  unsigned long long int time = readb48 (t);
  int time_offset = readb16 (t + 6);
  int my_time_offset = local_time_offset ();

  struct tm time_tm;
  time_t time_t_time = time;
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
    written = make_hex (cdp->message_ack, 6, p, size);
    p += written; size -= written;
    written = snprintf (p, size, ", ");
    p += written; size -= written;
  }

  unsigned long long int counter = readb64 (cdp->counter);
  char * time_string = chat_time_to_string (cdp->timestamp, 1);
  written = snprintf (p, size, "sequence %lld, time %s", counter, time_string);
  p += written; size -= written;

  return result;
}


