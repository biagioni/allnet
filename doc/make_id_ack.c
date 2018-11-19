/* makeidack.c: compute sha512 on 16-byte values, either given or random */
/* gcc -o make_id_ack make_id_ack.c sha.c */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "sha.h"

int main (int argc, char ** argv)
{
  srandom (time (NULL));
  if (argc > 1) {
    for (int arg = 1; arg < argc; arg++) {
      char ack [16];
      char * p = argv [arg];
      for (int i = 0; i < sizeof (ack); i++) {
        if (sscanf (p, "%2x", (unsigned int *) (ack + i)) != 1)
          printf ("error on %s (%d, %s), %d\n", argv [arg], arg, p, i);
        p += 2;
      }
      for (int i = 0; i < sizeof (ack); i++)
        printf ("%02x", ack [i] & 0xff);
      printf (" ");
      char id [sizeof (ack)];
      sha512_bytes (ack, sizeof (ack), id, sizeof (id));
      for (int i = 0; i < sizeof (id); i++)
        printf ("%02x", id [i] & 0xff);
      printf ("\n");
    }
  } else {
    char ack [16];
    for (int i = 0; i < sizeof (ack); i++) {
      ack [i] = random ();
      printf ("%02x", ack [i] & 0xff);
    }
    printf (" ");
    char id [sizeof (ack)];
    sha512_bytes (ack, sizeof (ack), id, sizeof (id));
    for (int i = 0; i < sizeof (id); i++)
      printf ("%02x", id [i] & 0xff);
    printf ("\n");
  }
}
