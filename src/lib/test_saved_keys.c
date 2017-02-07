/* test_saved_keys.c: make sure can load the keys in the .allnet directory
 * (at some points in the past, we saved some broken keys)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>

#include "wp_rsa.h"

extern int b64_decode (const char * data, int dsize, char * result, int rsize);

int main (int argc, char ** argv)
{
  char * path = "/home/esb/.allnet/own_spare_keys";
  if (argc > 1)
    path = argv [1];
  printf ("path is %s\n", path);
  DIR * dir = opendir (path);
  if (dir == NULL) {
    perror ("opendir");
    printf ("unable to open directory %s\n", path);
    return 1;
  }
  struct dirent * dep;
  while ((dep = readdir (dir)) != NULL) {
    if (strlen (dep->d_name) == 14) {
#ifdef SUB_LOOP
      char * final = "my_key";
      /* char * final = "contact_pubkey */
      size_t len = strlen (path) + 1 + strlen (dep->d_name) + 1
                 + strlen (final) + 1;
#else /* !SUB_LOOP */
      size_t len = strlen (path) + 1 + strlen (dep->d_name) + 1;
#endif /* SUB_LOOP */
      char * fname = malloc (len);
#ifdef SUB_LOOP
      snprintf (fname, len, "%s/%s/%s\n", path, dep->d_name, final);
#else /* !SUB_LOOP */
      snprintf (fname, len, "%s/%s\n", path, dep->d_name);
#endif /* SUB_LOOP */
      int nbits;
      wp_rsa_key_pair key;
      int res = wp_rsa_read_key_from_file (fname, &nbits, &key);
      printf ("result of reading %s is %d\n", fname, res);
      free (fname);
    }
  }
  closedir (dir);
  return 0;
}
