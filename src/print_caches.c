/* print the contents of the caches */

#include <stdio.h>

/* normally we do not #include a .c file.  However, we simply want
 * compile pcache.c with -DPRINT_CACHE_FILES, and this does the trick */

#define PRINT_CACHE_FILES

#include "lib/pcache.c"
