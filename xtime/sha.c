/* sha.c: compute sha512 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <openssl/evp.h>    /* for hash computation */
#include <openssl/hmac.h>   /* for hmac computation */

#include "sha.h"

static EVP_MD_CTX sha512_ctx;
static const EVP_MD * sha512_md = NULL;

static void init_globals ()
{
  if (sha512_md == NULL) {
    OpenSSL_add_all_digests ();  /* supposedly required */
    sha512_md = EVP_get_digestbyname ("sha512");
    if (EVP_MD_size (sha512_md) != SHA512_SIZE) {
      printf ("error: expected hash result size is %d, %d expected\n",
              EVP_MD_size (sha512_md), SHA512_SIZE);
      exit (1);
    }
  }
}

/* the result array must have size SHA512_SIZE */
/* #define SHA512_SIZE	64 */
void sha512 (char * data, int dsize, char * result)
{
  init_globals ();
  EVP_DigestInit (&sha512_ctx, sha512_md);
  EVP_DigestUpdate (&sha512_ctx, data, dsize);
  unsigned int result_size;
  EVP_DigestFinal (&sha512_ctx, result, &result_size);
  if (result_size != SHA512_SIZE)
    printf ("error: hash result size is %ud, %d expected\n",
            result_size, SHA512_SIZE);
}

/* the result array must have size rsize, only the first rsize bytes
 * of the hash are saved (or the hash is padded with zeros) */
void sha512_bytes (char * data, int dsize, char * result, int rsize)
{
  char sha [SHA512_SIZE];
  sha512 (data, dsize, sha);
  if (rsize <= SHA512_SIZE) {
    memcpy (result, sha, rsize);
  } else {
    memcpy (result, sha, SHA512_SIZE);
    bzero (result + SHA512_SIZE, rsize - SHA512_SIZE);
  }
}


/* the result array must have size SHA512_SIZE */
void sha512hmac (char * data, int dsize, char * key, int ksize, char * result)
{
  init_globals ();

  int rsize;
  char * static_hmac = HMAC (sha512_md, key, ksize, data, dsize, NULL, &rsize);
  if (rsize != SHA512_SIZE) {
    printf ("error: hmac got rsize %d, expected %d\n", rsize, SHA512_SIZE);
    printf ("EVP_MAX_MD_SIZE is %d\n", EVP_MAX_MD_SIZE);
    exit (1);
  }
  memcpy (result, static_hmac, SHA512_SIZE);
}

