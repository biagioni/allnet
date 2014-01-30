/* cutil.c: utility functions for chat */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include "sha.h"
#include "priority.h"
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
                          char * packet_id_hash)
{
  bzero (packet_id_hash, PACKET_ID_SIZE);
  random_bytes (cp->packet_id, PACKET_ID_SIZE);
  sha512_bytes (cp->packet_id, PACKET_ID_SIZE, packet_id_hash, PACKET_ID_SIZE);

  unsigned long long int counter = get_counter (contact);
  if (counter == 0) {
    printf ("unable to locate key for contact '%s'\n", contact);
    return 0;
  }
  write_big_endian64 (cp->counter, counter);

  int my_time_offset = local_time_offset ();
  unsigned long long int now = time (NULL);
  write_big_endian48 (cp->timestamp, now);
  write_big_endian16 (cp->timestamp + 6, my_time_offset);
  return 1;
}

char * chat_time_to_string (unsigned char * t, int static_result)
{
  static char buffer [40];   /* actually, 36 would be enough */
  int size = sizeof (buffer);
  char * result = buffer;
  if (! static_result)
    result = malloc (size);
  char * p = result;

  unsigned long long int time = read_big_endian48 (t);
  int time_offset = read_big_endian16 (t + 6);
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
  static char buffer [PACKET_ID_SIZE * 3 + COUNTER_SIZE * 3 + 40];
  int size = sizeof (buffer);
  char * result = buffer;
  if (! static_result)
    result = malloc (size);
  char * p = result;

  int written = 0;
  if (show_id) {
    written = snprintf (p, size, "id ");
    p += written; size -= written;
    written = make_hex (cdp->packet_id, 6, p, size);
    p += written; size -= written;
    written = snprintf (p, size, ", ");
    p += written; size -= written;
  }

  unsigned long long int counter = read_big_endian64 (cdp->counter);
  char * time_string = chat_time_to_string (cdp->timestamp, 1);
  written = snprintf (p, size, "sequence %lld, time %s", counter, time_string);
  p += written; size -= written;

  return result;
}


