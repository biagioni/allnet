/* wp_aes.c: AES encryption */

/* this library is named for W. Wesley Peterson, who wrote the code this
 * library is loosely based on before he passed away in 2009 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "wp_aes.h"

/* for AES in counter mode, only encryption is used
 * in, out may be the same or different buffer, both should
 * have WP_AES_BLOCK_SIZE bytes
 * ksize must be 16, 24, or 32 */
void wp_aes_encrypt_block (int ksize, char * key, char * in, char * out)
{
  printf ("wp_aes_encrypt_block is not implemented, aborting\n");
  exit (1);
}

#ifdef AES_UNIT_TEST
int main (int argc, char ** argv)
{
  char key [] =   /* not random */
   {  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15, 16,
     17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};

  /* ECBVarTxt256.rsp, test 1, the key is all zeros */
  bzero (key, sizeof (key));
  char data [WP_AES_BLOCK_SIZE];
  bzero (data, sizeof (data));
  data [0] = 0x80;
  char result [WP_AES_BLOCK_SIZE];
  char expected [] = { 0xdd, 0xc6, 0xbf, 0x79, 0x0c, 0x15, 0x76, 0x0d,
                       0x8d, 0x9a, 0xeb, 0x6f, 0x9a, 0x75, 0xfd, 0x4e };

  wp_aes_encrypt_block (32, key, data, result);
  if (memcmp (expected, result, sizeof (result)) != 0) {
    printf ("error: AES did not give the right result\n");
    return 1;
  }
  return 0;
}
#endif /* AES_UNIT_TEST */
