/* crypt_sel.h: interface to different implementations of crypto primitives */

#ifndef ALLNET_CRYPT_SELECTOR_H
#define ALLNET_CRYPT_SELECTOR_H

#ifdef HAVE_OPENSSL
#include <openssl/rsa.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

typedef RSA *           allnet_rsa_pubkey;
typedef RSA *           allnet_rsa_prvkey;

#else /* HAVE_OPENSSL */

#include "wp_arith.h"
#include "wp_rsa.h"
#include "wp_aes.h"

typedef wp_rsa_key      allnet_rsa_pubkey;
typedef wp_rsa_key_pair allnet_rsa_prvkey;

#endif /* HAVE_OPENSSL */


extern allnet_rsa_pubkey allnet_rsa_private_to_public (allnet_rsa_prvkey key);

extern int allnet_rsa_pubkey_size (allnet_rsa_pubkey key);
extern int allnet_rsa_prvkey_size (allnet_rsa_prvkey key);

/* these return the size (in bytes) of the internalized key (0 for failure) */
extern int allnet_get_pubkey (const char * key, int ksize,
                              allnet_rsa_pubkey * rsa);
extern int allnet_get_prvkey (const char * key, int ksize,
                              allnet_rsa_prvkey * rsa);
/* returns the size (in bytes) of the externalized key (0 for failure) */
extern int allnet_pubkey_to_raw (allnet_rsa_pubkey rsa,
                                 char * storage, int ssize);
/* returns the number of bytes used of the externalized key (0 for failure) */
extern int allnet_pubkey_from_raw (allnet_rsa_pubkey * rsa,
                                   const char * external_key, int ksize);
/* keys should be freed when no longer needed */
extern void allnet_rsa_free_pubkey (allnet_rsa_pubkey rsa);
extern void allnet_rsa_free_prvkey (allnet_rsa_prvkey rsa);
/* default initializer, equivalent to NULL */
extern void allnet_rsa_null_pubkey (allnet_rsa_pubkey * rsa);
extern void allnet_rsa_null_prvkey (allnet_rsa_prvkey * rsa);
/* checks for the null value */
extern int allnet_rsa_pubkey_is_null (allnet_rsa_pubkey rsa);
extern int allnet_rsa_prvkey_is_null (allnet_rsa_prvkey rsa);

/* return 1 for success, 0 for failure */
extern int allnet_rsa_read_pubkey (const char * fname, allnet_rsa_pubkey * key);
extern int allnet_rsa_read_prvkey (const char * fname, allnet_rsa_prvkey * key);
extern int allnet_rsa_write_pubkey (const char * fname, allnet_rsa_pubkey key);
extern int allnet_rsa_write_prvkey (const char * fname, allnet_rsa_prvkey key);

/* padding should be 0 for no padding, 1 for PKCS1 OAEP
 * rsize should be at least as large as the key size
 * for no padding, dsize should equal the key size
 * for PKCS1 OAEP padding, dsize should be less than the key size - 41
 * returns the key size for success, 0 for failure */
extern int allnet_rsa_encrypt (allnet_rsa_pubkey rsa,
                               const char * data, int dsize,
                               char * result, int rsize, int padding);
/* padding should be 0 for no padding, 1 for PKCS1 OAEP
 * dsize should be exactly as large as the key size (but may be more)
 * for no padding, rsize should equal the key size
 * for PKCS1 OAEP padding, rsize should be at least the key size - 41
 * returns the number of decrypted bytes for success, -1 for failure */
extern int allnet_rsa_decrypt (allnet_rsa_prvkey rsa,
                               const char * data, int dsize,
                               char * result, int rsize, int padding);

/* hash should be the output of a SHA512 hash, and hsize should be 64 (or more)
 * ssize must be at least as large as the key size (and may be more)
 * returns 1 for success, 0 for failure */
extern int allnet_rsa_sign (allnet_rsa_prvkey rsa, const char * hash, int hsize,
                            char * sig, int ssize);

/* hash should be the output of a SHA512 hash, and hsize should be 64 (or more)
 * ssize must be at least as large as the key size (and may be more)
 * returns 1 for successful verification, 0 for anything else */
extern int allnet_rsa_verify (allnet_rsa_pubkey rsa,
                              const char * hash, int hsize,
                              const char * sig, int ssize);

/* may be slow
 * if random is not NULL and rsize >= bits / 8, uses bytes from random
 * to randomize the key -- this may make it faster */
extern allnet_rsa_prvkey allnet_rsa_generate_key (int bits,
                                                  char * random, int rsize);

/* should be called if /dev/random is not defined, to increase the randomness
 * of key generation and other operations, such as padding, that require
 * randomness
 * a single call with 16 bytes of randomness may be sufficient for
 * many purposes */
extern void allnet_rsa_seed_rng (char * buffer, int bsize);

/* =======================  AES section  ========================= */

#ifndef AES256_SIZE
#define AES256_SIZE     (256 / 8)       /* 32 */
#endif /* AES256_SIZE */
#ifndef AES_BLOCK_SIZE  /* defined in openssl/aes.h if using openssl */
#define AES_BLOCK_SIZE  (128 / 8)       /* 16 */
#endif /* AES_BLOCK_SIZE */


/* key should be AES256_SIZE bytes long.
 * in and out should be AES_BLOCK_SIZE bytes long.
 * returns 1 for success, 0 for failure */
extern int allnet_aes_encrypt_block (char * key, char * in, char * out);

#endif /* ALLNET_CRYPT_SELECTOR_H */
