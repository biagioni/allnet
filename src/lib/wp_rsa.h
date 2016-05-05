/* wp_rsa.h: header file for RSA encryption and decryption */
/* this implementation of RSA does not use malloc/free */

/* this library is named for W. Wesley Peterson, who wrote the code this
 * library is loosely based on before he passed away in 2009 */

#ifndef RSA_H 
#define RSA_H 

#include <stdint.h>

#include "sha.h"

#define WP_RSA_MAX_KEY_BITS	4096

#define WP_RSA_MAX_KEY_WORDS	(WP_RSA_MAX_KEY_BITS / (8 * sizeof (uint64_t)))
/* p, q, and other quantities only have half as many bits/bytes as n, d */
#define WP_RSA_HALF_KEY_WORDS	(WP_RSA_MAX_KEY_WORDS / 2)
#define WP_RSA_MAX_KEY_BYTES	(WP_RSA_MAX_KEY_BITS / 8)
#define WP_RSA_HALF_KEY_BYTES	(WP_RSA_MAX_KEY_BYTES / 2)

typedef struct {
  int nbits;
  uint64_t n [WP_RSA_MAX_KEY_WORDS];
  uint64_t e;
} wp_rsa_key;

typedef struct {
  int nbits;
  uint64_t n [WP_RSA_MAX_KEY_WORDS];
  uint64_t e;   			/* usually 65537 */
  uint64_t d [WP_RSA_MAX_KEY_WORDS];
/* used for faster implementation of decryption and signing */
  uint64_t p [WP_RSA_HALF_KEY_WORDS];
  uint64_t q [WP_RSA_HALF_KEY_WORDS];
  uint64_t dp [WP_RSA_HALF_KEY_WORDS];
  uint64_t dq [WP_RSA_HALF_KEY_WORDS];
  uint64_t qinv [WP_RSA_HALF_KEY_WORDS];
} wp_rsa_key_pair;

/* get the public key part of the key pair */
extern wp_rsa_key wp_rsa_get_public_key (wp_rsa_key_pair * key);

/* read the key from the given bytes, returning 1 if read a private
 * and public key pair, 2 for just the public key, or 0 for error
 * if this is a public key, key->d will be set to zero */
extern int wp_rsa_read_key_from_bytes (const char * bytes, int bsize,
                                       int * nbits, wp_rsa_key_pair * key);
/* same as wp_rsa_read_key_from_bytes */
extern int wp_rsa_read_key_from_file (const char * fname, int * nbits,
                                      wp_rsa_key_pair * key);
/* writes the key to the file, returning 1 for success or 0 for error
 * if key->d is zero, only saves the public key, otherwise saves both
 * the public and private keys */
extern int wp_rsa_write_key_to_file (const char * fname,
                                     const wp_rsa_key_pair * key);

/* uses /dev/random to generate bits of the key
 * nbits should be a power of two <= RSA_MAX_KEY_BITS
 * the security level is the number of primality tests to run
 * on candidate primes -- 1 is fine for normal usage
 * if random is not NULL and rsize > 0, up to rsize bytes from random are
 * used in generating the key (rsize == nbits / 8 is sufficient)
 * returns 1 if successful, and if so, fills in key
 * returns 0 if the number of bits > RSA_MAX_KEY_BITS */
extern int wp_rsa_generate_key_pair (int nbits, wp_rsa_key_pair * key,
                                     int security, char * random, int rsize);
extern int wp_rsa_generate_key_pair_e (int nbits, wp_rsa_key_pair * key,
                                       long int e, int security_level,
                                       char * random, int rsize);

#define WP_RSA_PADDING_NONE		0 /* repeatable, but not secure */
#define WP_RSA_PADDING_VANILLA		1 /* repeatable, but not secure */
#define WP_RSA_PADDING_PKCS1_OAEP	2 /* different each time, secure */

/* each padding system other than NONE requires some bytes, which
 * are not available for the plaintext */
#define WP_RSA_PADDING_VANILLA_SIZE	1  /* one byte for the length */
#define WP_RSA_PADDING_PKCS1_OAEP_SIZE	(2 + SHA1_SIZE + SHA1_SIZE) /* 42 */

/* data and result may be the same buffer.
 * ndata <= key->nbits / 8 - padding_size
 *   (for PADDING_NONE, must have ndata == key->nbits / 8)
 * nresult >= key->nbits / 8
 * returns key->nbits / 8 if successful, and if so, fills in result
 * otherwise returns -1 */
extern int wp_rsa_encrypt (wp_rsa_key * key, const char * data, int dsize,
                           char * result, int rsize, int padding);

/* data and result may be the same buffer.
 * ndata == key->nbits / 8, nresult >= key->nbits / 8 - padding_size
 * returns the size of the decrypted message if successful
 *   (the size is always key->nbits / 8 - 1 for RSA_PADDING_NONE),
 * otherwise returns -1 */
extern int wp_rsa_decrypt (wp_rsa_key_pair * key, const char * data,
                           int dsize, char * result, int rsize,
                           int padding);

/* used if and only if /dev/random and /dev/urandom are not available
 * buffer should contain bsize truly random bytes */
extern void wp_rsa_randomize (char * buffer, int bsize);

#define WP_RSA_SIG_ENCODING_NONE	0
#define WP_RSA_SIG_ENCODING_SHA512	1

/* hash and sig may be the same buffer.
 * hsize <= key->nbits / 8,  nsig >= key->nbits / 8
 * if sig_encoding is WP_RSA_SIG_ENCODING_SHA512, hsize must be 64
 * returns 1 if successful, otherwise returns 0 */
extern int wp_rsa_sign (wp_rsa_key_pair * key, const char * hash, int hsize,
                        char * sig, int ssize, int sig_encoding);

/* hsize <= key->nbits / 8,  nsig == key->nbits / 8
 * if sig_encoding is WP_RSA_SIG_ENCODING_SHA512, hsize must be 64
 * returns 1 if successful, otherwise returns 0 */
extern int wp_rsa_verify (wp_rsa_key * key, const char * hash, int hsize,
                          const char * sig, int ssize, int sig_encoding);

#endif /* RSA_H */
