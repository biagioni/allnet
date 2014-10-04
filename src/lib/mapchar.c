/* mapchar.c: encode characters to 4-bit strings in ways that make it more
 *            difficult to make mistakes.
 * also encode numeric positions as memorable strings
 * and finally, a homage to the humble mapcar of LISP fame.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "mapchar.h"

/*
#define		MAPCHAR_IGNORE_CHAR	16
#define		MAPCHAR_UNKNOWN_CHAR	17
#define		MAPCHAR_EOS		18
*/

#define MAPCHAR_SIZE	(MAPCHAR_IGNORE_CHAR + 1)

static char * default_charmap [MAPCHAR_SIZE] = { "0oOgGPpQq",
                                                 "1LlIiJjHh",
                                                 "2Kk",
                                                 "3Mm",
                                                 "4Nn",
                                                 "5SsZz",
                                                 "6Rr",
                                                 "7Tt",
                                                 "8UuVvWwYy",
                                                 "9Xx",
                                                 "Aa",
                                                 "Bb",
                                                 "Cc",
                                                 "Dd",
                                                 "Ee",
                                                 "Ff",
/* the last entry are the characters we don't want to map to anything */
/* because of the difficulty of representing \n within files, it is always
 * included in these characters by the code itself */
           " \t\r`~!@#$%^&*()-_=+[]{}\\|;:'\",.<>/?"};

/* returns true if it is a known cjk character, in which case the code
 * will be c % 16 */
static int known_cjk (long long int c)
{
  if (((c >=  0x3400) && (c <=  0x3DBF)) ||  /* extension A */
      ((c >=  0x4E00) && (c <=  0x9FFF)) ||  /* CJK unified */
      ((c >= 0x20000) && (c <= 0x2A6DF)) ||  /* extension B */
      ((c >= 0x2A700) && (c <= 0x2B73F)) ||  /* extension C */
      ((c >= 0x2B740) && (c <= 0x2B81F)))    /* extension D */
    return 1;
  return 0;
}

/* return -1 for an invalid character, or the character encoding otherwise */
static long long int get_next_char (char * string, char ** next)
{
  long long int first = (*string) & 0xff;
  if (first < 0x80) {  /* ASCII character */
    *next = string + 1;
    return first;
  }
  int count = 1;
  while ((count < 6) && ((string [count] & 0xC0) == 0x80))
    count++;
  switch (count) {
  case 1:
    printf ("mapchar get_next_char error: illegal count 1\n");
    return -1;
  case 2:
    if ((first & 0xe0) != 0xC0)
      return -1;
    *next = string + 2;
    return (((first & 0x1f) << 6) | ((long long int) (string [1] & 0x3f)));
  case 3:
    if ((first & 0xf0) != 0xe0)
      return -1;
    *next = string + 3;
    return (((first & 0x1f) << 12) |
            (((long long int) (string [1] & 0x3f)) << 6) |
             ((long long int) (string [2] & 0x3f)));
  case 4:
    if ((first & 0xf8) != 0xf0)
      return -1;
    *next = string + 4;
    return (((first & 0x1f) << 18) |
            (((long long int) (string [1] & 0x3f)) << 12) |
            (((long long int) (string [2] & 0x3f)) <<  6) |
             ((long long int) (string [3] & 0x3f)));
  /* note: the following are not valid unicode characters */
  case 5:
    if ((first & 0xfc) != 0xf8)
      return -1;
    printf ("invalid 5-byte unicode character\n");
    *next = string + 5;
    return (((first & 0x1f) << 24) |
            (((long long int) (string [1] & 0x3f)) << 18) |
            (((long long int) (string [2] & 0x3f)) << 12) |
            (((long long int) (string [3] & 0x3f)) <<  6) |
             ((long long int) (string [4] & 0x3f)));
  case 6:
    if ((first & 0xfe) != 0xfc)
      return -1;
    printf ("invalid 6-byte unicode character\n");
    *next = string + 6;
    return (((first & 0x1f) << 30) |
            (((long long int) (string [1] & 0x3f)) << 24) |
            (((long long int) (string [2] & 0x3f)) << 18) |
            (((long long int) (string [3] & 0x3f)) << 12) |
            (((long long int) (string [4] & 0x3f)) <<  6) |
             ((long long int) (string [5] & 0x3f)));
  default:
    printf ("unknown utf-8 encoding of size %d\n", count);
    return -1;
  }
}

static int prefix_match (char * s1, char * s2, int length)
{
  int i;
  for (i = 0; i < length; i++)
    if (s1 [i] != s2 [i])
      return 0;
  return 1;
}

static int string_length (char * s)
{
  int result = 0;
  while (s [result] != '\0')
    result++;
  return result;
}

/* return 1 if the substring is found in string, 0 otherwise */
static int string_in_string (char * substring, int substring_length,
                             char * string)
{
  if (substring_length == 1) {   /* optimization for common case */
    while (*string != '\0') {
      if (*substring == *string)
        return 1;
      string++;
    }
    return 0;
  }
  int slen = string_length (string);
  int i;
  for (i = 0; i + substring_length <= slen; i++)
    if (prefix_match (substring, string + i, substring_length))
      return 1;
  return 0;
}

/* convert the first character pointed to by char into an int, and return it */
/* the return value is in 0..15 for valid characters, MAPCHAR_IGNORE_CHAR
 * for recognized characters that we ignore, and MAPCHAR_UKNOWN_CHAR for
 * any unrecognized character.  MAPCHAR_EOS is returned at the end of the
 * string. */
/* the second argument is set to point to the next character,
 * except in the case of MAPCHAR_EOS, when it is set to the first argument
 * in case of errors, it is not set. */
int map_char (char * string, char ** next)
{
  /* printf ("mapchar (%s) ==> ", string); */
  long long int unicode = get_next_char (string, next);
  if (unicode < 0)
    return MAPCHAR_UNKNOWN_CHAR;
  if (unicode == 0) {
    *next = string;
    /* printf ("EOS (%d)\n", MAPCHAR_EOS); */
    return MAPCHAR_EOS;
  }
  if (unicode == '\n') {   /* special case */
    *next = string;
    /* printf ("IGNORE (%d)\n", MAPCHAR_IGNORE_CHAR); */
    return MAPCHAR_IGNORE_CHAR;
  }
  if (known_cjk (unicode))
    return unicode % MAPCHAR_IGNORE_CHAR;
/* for now, always use the default char map */
  int i;
  for (i = 0; i < MAPCHAR_IGNORE_CHAR; i++) {
    if (string_in_string (string, (*next) - string, default_charmap [i])) {
      /* printf ("%d\n", i); */
      return i;
    }
  }
  if (string_in_string (string, (*next) - string,
                        default_charmap [MAPCHAR_IGNORE_CHAR])) {
    /* printf ("IGNORE (%d)\n", MAPCHAR_IGNORE_CHAR); */
    return MAPCHAR_IGNORE_CHAR;
  }
  /* printf ("UNKNOWN (%d) for '%s'\n", MAPCHAR_UNKNOWN_CHAR, string); */
  return MAPCHAR_UNKNOWN_CHAR;
}

/* convert each character in the string, and return a newly allocated
 * char array with the mapped characters.  The number of bytes in the newly
 * allocated char array is returned.
 * If the last byte only has one character, it is padded with 4 zero bits */
int map_string (char * string, char ** result)
{
  char * p = string;
  int count = 0;
  while (1) {
    char * next;
    int c = map_char (p, &next);
    if ((c == MAPCHAR_EOS) || (c == MAPCHAR_UNKNOWN_CHAR))
      break;
    if (c != MAPCHAR_IGNORE_CHAR)
      count++;
    p = next;
  }
  int bytes = (count + 1) / 2;
  if (bytes <= 0) {
    printf ("mapchar.c map_string: no bytes (%d) to map\n", bytes);
    return 0;
  }
  *result = malloc (bytes);
  if (*result == NULL) {
    printf ("mapchar.c map_string: unable to malloc %d bytes\n", bytes);
    return 0;
  }
  char * r = *result;
  p = string;
  int index = 0;
  int odd = 0;
  while (1) {
    char * next;
    int c = map_char (p, &next);
    if ((c == MAPCHAR_EOS) || (c == MAPCHAR_UNKNOWN_CHAR))
      break;
    if (c != MAPCHAR_IGNORE_CHAR) {
      if (odd) {
        r [index] = (r [index] & 0xf0) | (c & 0x0f);
        index++;
        odd = 0;
      } else {
        r [index] = (c << 4) & 0xf0;
        odd = 1;
      }
    }
    p = next;
  }
  if (odd)
    index++;
  return index;
}

/* functions to encode numeric positions as memorable strings */ 

/* #define MAX_AADDR_CODE		16383 */

#define NUM_CODE_WORDS	128
static char * default_pre [NUM_CODE_WORDS] = {
   "the", "be", "of", "to", "a", "in", "have", "for", "that", "on", "with",
   "do", "as", "this", "at", "from", "by", "will", "say", "go", "so",
   "all", "about", "if", "one", "there", "which", "get", "would", "think",
   "like", "more", "their", "when", "what", "make", "who", "see", "some",
   "out", "good", "other", "very", "just", "take", "because", "could", "use",
   "also", "than", "into", "only", "want", "these", "new", "give", "first",
   "any", "over", "after", "find", "where", "most", "should", "need", "much",
   "how", "may", "such", "here", "really", "even", "those", "many", "tell",
   "last", "before", "change", "long", "too", "pause", "still", "write",
   "same", "great", "leave", "both", "meet", "help", "own", "ask", "put",
   "each", "become", "another", "high", "next", "why", "live", "must",
   "never", "study", "might", "let", "hear", "seem", "around", "during",
   "keep", "big", "follow", "every", "important", "always", "provide",
   "begin", "run", "since", "early", "bring", "without", "offer", "build",
   "hope", "learn", "until", "yet", "probably"};

static char * default_post [NUM_CODE_WORDS] = {
   "time", "people", "year", "well", "work", "way", "show", "life",
   "lot", "place", "talk", "try", "number", "part", "start", "school",
   "world", "week", "play", "house", "group", "home", "course",
   "case", "system", "book", "set", "turn", "area", "move", "fact",
   "result", "month", "name", "word", "today", "plan", "program",
   "student", "form", "room", "car", "hour", "level", "city", "idea",
   "reason", "learn", "person", "sort", "term", "line", "train",
   "view", "story", "color", "party", "bit", "letter", "center", "test",
   "water", "care", "subject", "mind", "past", "office", "force", "town",
   "light", "class", "food", "figure", "future", "answer", "note", "minute",
   "game", "music", "computer", "sound", "team", "film", "design", "door",
   "paper", "cover", "event", "phone", "table", "role", "data", "action",
   "health", "travel", "site", "step", "teacher", "range", "vote", "quality",
   "wish", "land", "sign", "news", "list", "act", "sport", "road", "picture",
   "stage", "rest", "focus", "society", "limit", "space", "chance", "choice",
   "ground", "source", "street", "park", "court", "finish", "page", "art",
   "skill", "nature" };

/* for now, only use the defaults, later look for files */

/* allocates and return a string representing the value.  If the value
 * is greater than or equal to 2^14 (16384), returns NULL */
/* if the language is unavailable, returns an available language,
 * usually english */
char * aaddr_encode_value (int value, char * lang)
{
  if (value > MAX_AADDR_CODE)
    return NULL;
  int pre = value / 128;
  int post = value % 128;
  int length = string_length (default_pre [pre]) +
               string_length (default_post [post]) + 2;
  char * result = malloc (length);
  if (result == NULL) {
    printf ("unable to allocate %d bytes for aaddr_encode_value\n", length);
    return result;
  }
  snprintf (result, length, "%s_%s", default_pre [pre], default_post [post]); 
  return result;
} 

static void aaddr_copy (char * buf, int bsize, char * in)
{
  int i = 0;
  while ((i + 1 < bsize) && (in [i] != '\0') && (isalpha (in [i]))) {
    buf [i] = in [i];
    i ++;
  }
  buf [i] = '\0';
}

/* return a value encoded by the string, or -1 in case of errors. */
int aaddr_decode_value (char * string, int slen) 
{
  char * middle = index (string, '_');
  if (middle == NULL) 
    middle = index (string, '-');
  if (middle == NULL) 
    middle = index (string, ' ');  /* using spaces is bad form */
  if (middle == NULL) { 
    printf ("unable to decode value %s, no underscore\n", string);
    return -1;
  }
  char pre_buf [1000];
  aaddr_copy (pre_buf, sizeof (pre_buf), string);
  char post_buf [1000];
  aaddr_copy (post_buf, sizeof (post_buf), middle + 1);

  int pre, post;
  int first = -1;
  for (pre = 0; pre < 128; pre++) {
    if (strcmp (default_pre [pre], pre_buf) == 0) {
      first = pre;
      break;
    }
  }
  if (first < 0) {
    printf ("unable to decode value %s, pre-word not found\n", string);
    return -1;
  }
  int second = -1;
  for (post = 0; post < 128; post++) {
    if (strcmp (default_post [post], post_buf) == 0) {
      second = post;
      break;
    }
  }
  if (second < 0) {
    printf ("unable to decode value %s, post-word not found\n", string);
    return -1;
  }
  int result = first * 128 + second;
  /* printf ("%s gives pre-word %d and post-word %d => %d\n",
          string, first, second, result); */
  return result;
}

/* returns the maximum length of a pair in the given language */
int max_pair_len (char * lang)
{
  int pre = 0;
  int post = 0;
  int i;
  for (i = 0; i < 128; i++) {
    if (string_length (default_pre [i]) > pre)
      pre = string_length (default_pre [i]);
    if (string_length (default_post [i]) > post)
      post = string_length (default_post [i]);
  }
  return pre + post + 2;
}
