/* generate.c: generate and save allnet addresses */
/* parameters: a personal phrase (in quotes)
     optional: a minimum number of pairs of words (default is 2)
     optional: a language for the encoding (default is en)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <time.h>

#include "lib/util.h"
#include "lib/keys.h"
#include "lib/app_util.h"

#define KEY_LENGTH	4096		/* in bits */
static unsigned long long int power (unsigned long long int base,
                                     unsigned long long int exp)
{
  unsigned long long int result = 1;
  while (exp > 0) {
    result *= base;
    exp--;
  }
  return result;
}

static void usage (char * pname, char * reason)
{
  printf ("%s: 'personal phrase' (in quotes) followed by any options \n",
          pname);
  printf ("     option: the number of word pairs for security\n");
  printf ("             more is better, default is 2\n");
  printf ("     option: the language for encoding the word pairs\n");
  printf ("             default is en (English)\n");
  printf ("your command %s\n", reason);
  exit (1);
}

/* global debugging variable -- if 1, expect more debugging output */
/* set in main */
int allnet_global_debugging = 0;

int main (int argc, char ** argv)
{
  int verbose = get_option ('v', &argc, argv);
  if (verbose)
    allnet_global_debugging = verbose;

  if (argc < 2)
    usage (argv [0],
           "did not provide at least one argument, the personal phrase");
  char * phrase = argv [1];
  char * language = "en";
  int numpairs = 2;
  int i;
  for (i = 2; i < argc; i++) {
    char * check;
    int n = strtol (argv [i], &check, 10);
    if (check != argv [i])     /* number of word pairs */
      numpairs = n;
    else                       /* language */
      language = argv [i];
  }
  int bitstring_bits = BITSTRING_BITS;
  /* bitstring_bits = 20; */
  printf ("searching for key for '%s', language %s, minimum %d word pairs\n",
          phrase, language, numpairs);
  int numpos = KEY_LENGTH - bitstring_bits + 1;
  unsigned long long int estimate = power (power (2, bitstring_bits) /
                                           numpos, numpairs);
  printf ("expect to try an average of %lld random keys for each match\n",
          estimate);
  printf ("  to stop, press Control-C or use the command 'pkill %s'\n",
           argv [0]);
  while (1) {
    fflush (stdout);
    char * result =
      generate_key (KEY_LENGTH, phrase, language, bitstring_bits, numpairs, 1);
    printf ("\nfound key '%s'\n", result);
    free (result);
  }
}

