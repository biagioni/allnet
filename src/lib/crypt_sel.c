/* crypt_sel.c: interface to different implementations of crypto primitives */

#include <stdio.h>
#include <unistd.h>
#include <string.h>
/* #include <sys/types.h> */
/* #include <sys/stat.h> */
#include <fcntl.h>

#include "crypt_sel.h"
#include "cipher.h"
#include "util.h"
#include "wp_rsa.h"
#include "wp_arith.h"

allnet_rsa_pubkey allnet_rsa_private_to_public (allnet_rsa_prvkey key)
{
#ifdef HAVE_OPENSSL
  /* this one is easy -- RSA keys are the same for private and public */
  return key;
#else /* HAVE_OPENSSL */
  allnet_rsa_pubkey result;
  result.nbits = key.nbits;
  wp_copy (key.nbits, result.n, key.n);
  result.e = key.e;
  return result;
#endif /* HAVE_OPENSSL */
}

int allnet_rsa_pubkey_size (allnet_rsa_pubkey key)
{
#ifdef HAVE_OPENSSL
  if (key == NULL)
    return 0;
  return RSA_size (key);
#else /* HAVE_OPENSSL */
  return key.nbits / 8;
#endif /* HAVE_OPENSSL */
}

int allnet_rsa_prvkey_size (allnet_rsa_prvkey key)
{
#ifdef HAVE_OPENSSL
  if (key == NULL)
    return 0;
  return RSA_size (key);
#else /* HAVE_OPENSSL */
  return key.nbits / 8;
#endif /* HAVE_OPENSSL */
}

/* these return the size (in bytes) of the internalized key (0 for failure) */
int allnet_get_pubkey (const char * key, int ksize, allnet_rsa_pubkey * rsa)
{
#ifdef HAVE_OPENSSL
  *rsa = RSA_new ();
  if (rsa == NULL) {
    printf ("unable get RSA public key\n");
    return 0;
  }
  (*rsa)->n = BN_bin2bn ((const unsigned char *) key, ksize, NULL);
  (*rsa)->e = NULL; 
  BN_dec2bn (&((*rsa)->e), "65537");
  return RSA_size (*rsa);
#else /* HAVE_OPENSSL */
  rsa->nbits = ksize * 8;
  wp_from_bytes (rsa->nbits, rsa->n, ksize, key);
  rsa->e = 65537;
  return ksize;
#endif /* HAVE_OPENSSL */
}

int allnet_get_prvkey (const char * key, int ksize, allnet_rsa_prvkey * rsa)
{
#ifdef HAVE_OPENSSL
  BIO * mbio = BIO_new_mem_buf ((void *) key, ksize);
  *rsa = PEM_read_bio_RSAPrivateKey (mbio, NULL, NULL, NULL);
  BIO_free (mbio);
  if (*rsa == NULL) {
    printf ("unable get RSA private key\n");
    return 0;
  }
  return RSA_size (*rsa);
#else /* HAVE_OPENSSL */
  int nbits;
  if (! wp_rsa_read_key_from_bytes (key, ksize, &nbits, rsa)) {
    printf ("unable to find key:\n%s\n", key);
    return 0;
  }
  return nbits / 8;
#endif /* HAVE_OPENSSL */
}

/* these return the size (in bytes) of the externalized key (0 for failure) */
int allnet_pubkey_to_raw (allnet_rsa_pubkey rsa, char * storage, int ssize)
{
#ifdef HAVE_OPENSSL
  if (rsa == NULL)
    return 0;
  int size = BN_num_bytes (rsa->n);
  if (size + 1 > ssize)
    return 0;
  BN_bn2bin (rsa->n, (unsigned char *) (storage + 1));
#else /* HAVE_OPENSSL */
  int size = rsa.nbits / 8;
  if (size + 1 > ssize)
    return 0;
  wp_to_bytes (rsa.nbits, rsa.n, ssize - 1, storage + 1);
#endif /* HAVE_OPENSSL */
  storage [0] = KEY_RSA4096_E65537;
  return size + 1;
}

/* returns the number of bytes used of the externalized key (0 for failure) */
int allnet_pubkey_from_raw (allnet_rsa_pubkey * rsa,
                            const char * key, int ksize)
{
  if (key [0] != KEY_RSA4096_E65537)
    return 0;
#ifdef HAVE_OPENSSL
  *rsa = RSA_new ();
  (*rsa)->n = BN_bin2bn ((const unsigned char *) (key + 1), ksize - 1, NULL);
  (*rsa)->e = NULL; 
  BN_dec2bn (&((*rsa)->e), "65537");
#else /* HAVE_OPENSSL */
  rsa->nbits = (ksize - 1) * 8;
  wp_from_bytes (rsa->nbits, rsa->n, ksize - 1, key + 1);
  rsa->e = 65537;
#endif /* HAVE_OPENSSL */
  return ksize;
}

/* keys should be freed when no longer needed */
void allnet_rsa_free_pubkey (allnet_rsa_pubkey rsa)
{
#ifdef HAVE_OPENSSL
  RSA_free (rsa);
#endif /* HAVE_OPENSSL */
}

void allnet_rsa_free_prvkey (allnet_rsa_prvkey rsa)
{
#ifdef HAVE_OPENSSL
  RSA_free (rsa);
#endif /* HAVE_OPENSSL */
}

/* default initializer, equivalent to NULL */
void allnet_rsa_null_pubkey (allnet_rsa_pubkey * rsa)
{
#ifdef HAVE_OPENSSL
  *rsa = NULL;
#else /* HAVE_OPENSSL */
  memset (rsa, 0, sizeof (*rsa));
#endif /* HAVE_OPENSSL */
}

void allnet_rsa_null_prvkey (allnet_rsa_prvkey * rsa)
{
#ifdef HAVE_OPENSSL
  *rsa = NULL;
#else /* HAVE_OPENSSL */
  memset (rsa, 0, sizeof (*rsa));
#endif /* HAVE_OPENSSL */
}

/* checks for the null value */
int allnet_rsa_pubkey_is_null (allnet_rsa_pubkey rsa)
{
#ifdef HAVE_OPENSSL
  return (rsa == NULL);
#else /* HAVE_OPENSSL */
  return rsa.nbits == 0;
#endif /* HAVE_OPENSSL */
}

int allnet_rsa_prvkey_is_null (allnet_rsa_prvkey rsa)
{
#ifdef HAVE_OPENSSL
  return (rsa == NULL);
#else /* HAVE_OPENSSL */
  return rsa.nbits == 0;
#endif /* HAVE_OPENSSL */
}

#ifdef HAVE_OPENSSL
static int read_RSA_file (const char * fname, RSA * * key, int expect_private)
{
  *key = NULL;
  char * bytes;
  int size = read_file_malloc (fname, &bytes, 0);
  if (size > 0) {
    BIO * mbio = BIO_new_mem_buf (bytes, size);
    if (expect_private)
      *key = PEM_read_bio_RSAPrivateKey (mbio, NULL, NULL, NULL);
    else
      *key = PEM_read_bio_RSAPublicKey (mbio, NULL, NULL, NULL);
    if (*key == NULL) {
      ERR_load_crypto_strings ();
      ERR_print_errors_fp (stdout);
      printf ("unable to read %s RSA from file %s\n",
              expect_private ? "private" : "public", fname);
      return 0;
    }
    BIO_free (mbio);
    free (bytes);
    return 1;
  }
  return 0;
}

static int write_RSA_file (const char * fname, RSA * key, int write_priv)
{
  BIO * mbio = BIO_new (BIO_s_mem ());
  if (write_priv)
    PEM_write_bio_RSAPrivateKey (mbio, key, NULL, NULL, 0, NULL, NULL);
  else
    PEM_write_bio_RSAPublicKey (mbio, key);
  char * keystore;
  long ksize = BIO_get_mem_data (mbio, &keystore);
  int success = write_file (fname, keystore, (int)ksize, 1);
  BIO_free (mbio);
  return success;
}
#endif /* HAVE_OPENSSL */

int allnet_rsa_read_pubkey (const char * fname, allnet_rsa_pubkey * key)
{
#ifdef HAVE_OPENSSL
  return read_RSA_file (fname, key, 0);
#else /* HAVE_OPENSSL */
  wp_rsa_key_pair full;
  if (allnet_rsa_read_prvkey (fname, &full)) {
    *key = wp_rsa_get_public_key (&full);
    return 1;
  }
  return 0;
#endif /* HAVE_OPENSSL */
}

int allnet_rsa_read_prvkey (const char * fname, allnet_rsa_prvkey * key)
{
#ifdef HAVE_OPENSSL
  return read_RSA_file (fname, key, 1);
#else /* HAVE_OPENSSL */
  int nbits;
  if (wp_rsa_read_key_from_file (fname, &nbits, key))
    return 1;
  return 0;
#endif /* HAVE_OPENSSL */
}

int allnet_rsa_write_pubkey (const char * fname, allnet_rsa_pubkey key)
{
#ifdef HAVE_OPENSSL
  return write_RSA_file (fname, key, 0);
#else /* HAVE_OPENSSL */
  allnet_rsa_prvkey new_key;
  new_key.nbits = key.nbits;
  wp_copy (new_key.nbits, new_key.n, key.n);
  new_key.e = key.e;
  wp_init (new_key.nbits, new_key.d, 0);
  return wp_rsa_write_key_to_file (fname, &new_key);
#endif /* HAVE_OPENSSL */
}

int allnet_rsa_write_prvkey (const char * fname, allnet_rsa_prvkey key)
{
#ifdef HAVE_OPENSSL
  return write_RSA_file (fname, key, 1);
#else /* HAVE_OPENSSL */
  return wp_rsa_write_key_to_file (fname, &key);
#endif /* HAVE_OPENSSL */
}

/* padding should be 0 for no padding, 1 for PKCS1 OAEP
 * rsize should be at least as large as the key size
 * for no padding, dsize should equal the key size
 * for PKCS1 OAEP padding, dsize should be less than the key size - 41
 * returns the key size for success, -1 for failure */
int allnet_rsa_encrypt (allnet_rsa_pubkey rsa, const char * data, int dsize,
                        char * result, int rsize, int padding)
{
  if ((padding > 1) || (padding < 0))
    return 0;
  int bytes;
#ifdef HAVE_OPENSSL
  if (rsize < RSA_size (rsa))
    return 0;
/*
printf ("openssl n = %s\n", BN_bn2hex (rsa->n));
printf ("openssl e = %s\n", BN_bn2hex (rsa->e));
print_buffer (data, dsize, "openssl data", 1000, 1);
*/
  int rsa_padding = RSA_PKCS1_OAEP_PADDING;
  if (padding == 0)
    rsa_padding = RSA_NO_PADDING;
  bytes = RSA_public_encrypt (dsize, (const unsigned char *) data,
                              (unsigned char *) result, rsa, rsa_padding);
  if (bytes <= 0) {
    ERR_load_crypto_strings ();
    ERR_print_errors_fp (stdout);
    bytes = 0;
  }
#else /* HAVE_OPENSSL */
  if (rsize * 8 < rsa.nbits)
    return 0;
/*
printf ("wp_rsa n = %s\n", wp_itox (rsa.nbits, rsa.n));
printf ("wp_rsa e = %llx\n", rsa.e);
*/
  int rsa_padding = WP_RSA_PADDING_PKCS1_OAEP;
  if (padding == 0)
    rsa_padding = WP_RSA_PADDING_NONE;
  bytes = wp_rsa_encrypt (&rsa, data, dsize, result, rsize, rsa_padding);
#endif /* HAVE_OPENSSL */
  return bytes;
}

/* padding should be 0 for no padding, 1 for PKCS1 OAEP
 * dsize should be exactly as large as the key size (but may be more)
 * for no padding, rsize should equal the key size
 * for PKCS1 OAEP padding, rsize should be at least the key size - 41
 * returns the number of decrypted bytes for success, -1 for failure */
int allnet_rsa_decrypt (allnet_rsa_prvkey rsa, const char * data, int dsize,
                        char * result, int rsize, int padding)
{
  if ((padding > 1) || (padding < 0))
    return -1;
#ifdef HAVE_OPENSSL
  int rsa_size = RSA_size (rsa);
#else /* HAVE_OPENSSL */
  int rsa_size = rsa.nbits / 8;
#endif /* HAVE_OPENSSL */

  if (dsize < rsa_size)
    return -1;
  if (dsize > rsa_size)
    dsize = rsa_size;
  if ((rsize < rsa_size - 41) || ((! padding) && (rsize < rsa_size)))
    return -1;
  int bytes;
#ifdef HAVE_OPENSSL
/*
printf ("openssl n = %s\n", BN_bn2hex (rsa->n));
printf ("openssl e = %s\n", BN_bn2hex (rsa->e));
*/
  int rsa_padding = RSA_PKCS1_OAEP_PADDING;
  if (padding == 0)
    rsa_padding = RSA_NO_PADDING;
  bytes = RSA_private_decrypt (rsa_size, (const unsigned char *) data,
                               (unsigned char *) result, rsa, rsa_padding);
  if (bytes <= 0) {
    ERR_load_crypto_strings ();
    ERR_print_errors_fp (stdout);
    bytes = -1;
  }
#else /* HAVE_OPENSSL */
/*
printf ("wp_rsa n = %s\n", wp_itox (rsa.nbits, rsa.n));
printf ("wp_rsa e = %llx\n", rsa.e);
*/
  int rsa_padding = WP_RSA_PADDING_PKCS1_OAEP;
  if (padding == 0)
    rsa_padding = WP_RSA_PADDING_NONE;
  bytes = wp_rsa_decrypt (&rsa, data, dsize, result, rsize, rsa_padding);
#endif /* HAVE_OPENSSL */
  return bytes;
}

/* padding should be zero for no padding, 1 for SHA512 padding
 * hash should be the output of a SHA512 hash, and hsize should be 64 (or more)
 * ssize must be at least as large as the key size (and may be more)
 * returns 1 for success, 0 for failure */
int allnet_rsa_sign (allnet_rsa_prvkey rsa, const char * hash, int hsize,
                     char * sig, int ssize)
{
#ifdef HAVE_OPENSSL
  int rsa_size = RSA_size (rsa);
#else /* HAVE_OPENSSL */
  int rsa_size = rsa.nbits / 8;
#endif /* HAVE_OPENSSL */
  if ((hsize < 64) || (ssize < rsa_size))
    return 0;

#ifdef HAVE_OPENSSL
/*
printf ("sign openssl n = %s\n", BN_bn2hex (rsa->n));
printf ("sign openssl e = %s, hsize %d\n", BN_bn2hex (rsa->e), hsize);
print_buffer (hash, hsize, "hash to be signed", 64, 1);
*/
  unsigned int siglen;
  int success = RSA_sign (NID_sha512, (unsigned char *) hash, hsize,
                          (unsigned char *) sig, &siglen, rsa);
  if (! success) {
    unsigned long e = ERR_get_error ();
    printf ("RSA signature (%d) failed %ld: %s\n", rsa_size, e,
            ERR_error_string (e, NULL));
  }
  return success;
#else /* HAVE_OPENSSL */
/*
printf ("sign wp_rsa n = %s\n", wp_itox (rsa.nbits, rsa.n));
printf ("sign wp_rsa e = %llx, hsize %d\n", rsa.e, hsize);
print_buffer (hash, hsize, "hash to be signed", 64, 1);
*/
  return wp_rsa_sign (&rsa, hash, hsize, sig, ssize,
                      WP_RSA_SIG_ENCODING_SHA512);
#endif /* HAVE_OPENSSL */
}

/* hash should be the output of a SHA512 hash, and hsize should be 64 (or more)
 * ssize must be at least as large as the key size (and may be more)
 * returns 1 for successful verification, 0 for anything else */
int allnet_rsa_verify (allnet_rsa_pubkey rsa, 
                       const char * hash, int hsize,
                       const char * sig, int ssize)
{
#ifdef HAVE_OPENSSL
  int rsa_size = RSA_size (rsa);
#else /* HAVE_OPENSSL */
  int rsa_size = rsa.nbits / 8;
#endif /* HAVE_OPENSSL */
  if ((hsize < 64) || (ssize < rsa_size))
    return 0;

#ifdef HAVE_OPENSSL
/*
printf ("openssl n = %s\n", BN_bn2hex (rsa->n));
printf ("openssl e = %s, hsize %d\n", BN_bn2hex (rsa->e), hsize);
print_buffer (hash, hsize, "hash to be verified", 64, 1);
*/
  int verifies = RSA_verify (NID_sha512, (unsigned char *) hash, hsize,
                             (unsigned char *) sig, ssize, rsa);
  /* for now (2014/09/23, allnet release 3.1), accept older style
   * signatures as well */
  /* I think this is secure because the hash is still SHA512, and only
   * the ASN.1 shows MD5.  It may use fewer bytes (16) than SHA512 (64) */
  if ((! verifies) &&
      (RSA_verify (NID_md5, (unsigned char *) hash, hsize,
                   (unsigned char *) sig, ssize, rsa))) {
#ifdef DEBUG_PRINT
    printf ("accepting an SSH512/MD5-encoded signature\n");
#endif /* DEBUG_PRINT */
    verifies = 1;
  }
  return verifies;
#else /* HAVE_OPENSSL */
/*
printf ("wp_rsa n = %s\n", wp_itox (rsa.nbits, rsa.n));
printf ("wp_rsa e = %llx, hsize %d\n", rsa.e, hsize);
print_buffer (hash, hsize, "hash to be verified", 64, 1);
*/
  return wp_rsa_verify (&rsa, hash, hsize, sig, ssize,
                        WP_RSA_SIG_ENCODING_SHA512);
#endif /* HAVE_OPENSSL */
}

#ifdef HAVE_OPENSSL
static void no_feedback (int type, int count, void * arg)
{
  /* use the arguments to avoid warnings. */
  if ((type > count) || (arg == NULL))
    return;
}
#endif /* HAVE_OPENSSL */
/* may be slow
 * if random is not NULL, uses rsize bytes from random
 * to help randomize the key -- this may make it faster */
allnet_rsa_prvkey allnet_rsa_generate_key (int bits,
                                           char * random, int rsize)
{
#ifdef HAVE_OPENSSL
  if (random != NULL)
    RAND_seed (random, rsize);
  return RSA_generate_key (bits, RSA_E65537_VALUE, no_feedback, NULL);
#else /* HAVE_OPENSSL */
  allnet_rsa_prvkey result;
  if (wp_rsa_generate_key_pair_e (bits, &result, RSA_E65537_VALUE,
                                  1, random, rsize))
    return result;
  allnet_rsa_null_prvkey (&result);
  return result;
#endif /* HAVE_OPENSSL */
}

/* should be called if /dev/random is not defined, to increase the randomness
 * of key generation and other operations, such as padding, that require 
 * randomness 
 * a single call with 16 bytes of randomness may be sufficient for
 * many purposes */
void allnet_rsa_seed_rng (char * buffer, int bsize)
{
#ifdef HAVE_OPENSSL
  RAND_seed (buffer, bsize);
#else /* HAVE_OPENSSL */
  wp_rsa_randomize (buffer, bsize);
#endif /* HAVE_OPENSSL */
}


/* key should be AES256_SIZE bytes long.
 * in and out should be AES_BLOCK_SIZE bytes long.
 * returns 1 for success, 0 for failure */
int allnet_aes_encrypt_block (char * key, char * in, char * out)
{
#ifdef HAVE_OPENSSL
  AES_KEY aes_key;
  if (AES_set_encrypt_key ((unsigned char *) key, AES256_SIZE * 8,
                           &aes_key) < 0) {
    printf ("unable to set AES encryption key");
    return 0;
  }
  AES_encrypt ((unsigned char *) in, (unsigned char *) out, &aes_key);
#else /* HAVE_OPENSSL */
  wp_aes_encrypt_block (32, key, in, out);
#endif /* HAVE_OPENSSL */
  return 1;
}
