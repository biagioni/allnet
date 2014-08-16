/* cipher.c: provide enciphering/deciphering and
 *                   authentication/verification operations.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/pem.h>

#include "packet.h"
#include "util.h"
#include "sha.h"
#include "keys.h"
#include "cipher.h"

#define AES256_SIZE	(256 / 8)	/* 32 */
/* defined in openssl/aes.h #define AES_BLOCK_SIZE	(128 / 8) */  /* 16 */

static void inc_ctr (unsigned char * ctr)
{
  int i;
  int carry = 1;  /* initially add 1 */
  for (i = AES_BLOCK_SIZE - 1; i >= 0; i--) {
    int value = ctr [i] + carry;
    ctr [i] = value % 256;
    carry = value / 256;
  }
}

/* for CTR mode, encryption and decryption are identical */
static void aes_ctr_crypt (unsigned char * key, unsigned char * ctr,
                           const char * data, int dsize, char * result)
{
/*
  printf ("aes_ctr_crypt (AES %p/%02x%02x%02x%02x, ctr %p/%02x%02x%02x%02x, ",
                          key, key [0] & 0xff, key [1] & 0xff,
                               key [2] & 0xff, key [3] & 0xff,
                          ctr, ctr [0] & 0xff, ctr [1] & 0xff,
                               ctr [2] & 0xff, ctr [3] & 0xff);
  printf ("data %p, dsize = %d)\n", data, dsize);
*/
  AES_KEY aes;
  if (AES_set_encrypt_key (key, AES256_SIZE * 8, &aes) < 0) {
    printf ("unable to set encryption key\n");
    exit (1);
  }
  unsigned char in [AES_BLOCK_SIZE];
  memcpy (in, ctr, AES_BLOCK_SIZE);
  unsigned char out [AES_BLOCK_SIZE];
  int i;
  for (i = 0; i < dsize; i++) {
    if ((i % AES_BLOCK_SIZE) == 0) {   /* compute the next block */
      AES_encrypt (in, out, &aes);
      inc_ctr (in);
    }
    result [i] = data [i] ^ out [i % AES_BLOCK_SIZE];
  }
#ifdef DEBUG_PRINT
  printf ("AES encryption complete\n"); */
#endif /* DEBUG_PRINT */
}

/* returns the number of encrypted bytes if successful, and 0 otherwise */
/* if successful, *res is dynamically allocated and must be free'd */
int allnet_encrypt (const char * text, int tsize,
                    const char * key, int ksize, char ** res)
{
#ifdef DEBUG_PRINT
  print_buffer (text, tsize, "encrypting", 16, 1);
#endif /* DEBUG_PRINT */

  *res = NULL;
  unsigned char * aes = NULL;
  unsigned char * nonce = NULL;

  /* convert key into internal format */
  if (*key != KEY_RSA4096_E65537) {
    printf ("key with unknown format %d, unable to encrypt\n", (*key) & 0xff);
    return 0;
  }
  RSA * rsa = RSA_new ();
  rsa->n = BN_bin2bn ((const unsigned char *) (key + 1), ksize - 1, NULL);
  rsa->e = NULL;
  BN_dec2bn (&(rsa->e), RSA_E65537_STRING);

  int rsa_encrypt_size = tsize;
  int rsa_size = RSA_size (rsa);
  int result_size = rsa_size;
  int max_rsa = RSA_size (rsa) - 42;  /* PKCS #1 v2 requires 42 bytes */
  unsigned char * new_text = NULL;
  if (max_rsa < tsize) {
    /* compute an AES-256 key and a nonce.  Prepend the key and the nonce
     * to the message.  Encrypt the first max_rsa bytes (of the AES, nonce,
     * and text) using RSA, and the remainder using AES in counter mode,
     * with the nonce being the initial value of the counter. */
    rsa_encrypt_size = max_rsa;
    /* the AES key and nonce and the first max_rsa bytes of the text go into
     * the first rsa_encrypt_size of the result.  The rest gets 1:1 encrypted
     * using AES */
    int input_size = tsize + AES256_SIZE + AES_BLOCK_SIZE;
    new_text = malloc_or_fail (input_size, "encrypt final plaintext");
    aes = new_text;
    nonce = new_text + AES256_SIZE;
    random_bytes ((char *) new_text, AES256_SIZE + AES_BLOCK_SIZE);
    memcpy (new_text + (AES256_SIZE + AES_BLOCK_SIZE), text, tsize);
    text = (const char *) new_text;
    tsize = input_size;
    rsa_encrypt_size = max_rsa;
    result_size = tsize + (RSA_size (rsa) - max_rsa);
#ifdef DEBUG_PRINT
    printf ("result size = %d + (%d - %d) = %d\n",
            tsize, RSA_size (rsa), max_rsa, result_size);
#endif /* DEBUG_PRINT */
  }

  char * result = malloc_or_fail (result_size, "encrypt result");

  /* encrypt either the entire message, or just the first max_rsa bytes */
  int bytes = RSA_public_encrypt (rsa_encrypt_size,
                                  (const unsigned char *) text,
                                  (unsigned char *) result, rsa,
                                  RSA_PKCS1_OAEP_PADDING);
  RSA_free (rsa);
  if (bytes != rsa_size) {
    ERR_load_crypto_strings ();
    ERR_print_errors_fp (stdout);
    printf ("RSA failed to encrypt %d bytes, %d\n", rsa_encrypt_size, bytes);
    print_buffer ((const char *) (key + 1), ksize - 1, "public key", ksize, 1);
    if (new_text != NULL) free (new_text);
    free (result);
    return 0;
  }
/* else print_buffer (key + 1, ksize - 1, "successful public key", 12, 1); */

/* printf ("input size %d, output size %d, bytes %d, rsa encrypted %d\n",
          tsize, result_size, bytes, rsa_encrypt_size); */
  /* encrypt any remaining bytes using AES */
  int remaining = tsize - rsa_encrypt_size;
/*  printf ("%d bytes to be encrypted using AES\n", remaining); */
  if (remaining > 0)
    aes_ctr_crypt (aes, nonce, text + rsa_encrypt_size, remaining,
                   result + bytes);

  if (new_text != NULL) free (new_text);
  *res = result;
#ifdef DEBUG_PRINT
  print_buffer (result, result_size, "encrypted", 16, 1);
#endif /* DEBUG_PRINT */
  return result_size;
}

#ifdef TEST_RSA_ENCRYPTION
static void test_rsa_encryption (char * key, int ksize)
{
  /* convert key into internal formats */
  BIO * mbio = BIO_new_mem_buf (key, ksize);
  RSA * pub_rsa = PEM_read_bio_RSAPublicKey (mbio, NULL, NULL, NULL);
  BIO_free (mbio);
  unsigned char fake_key [513];
  fake_key [0] = KEY_RSA4096_E65537;
  int bn_size = BN_num_bytes (pub_rsa->n);
  if (bn_size != 512) {
    snprintf (log_buf, LOG_SIZE, "error: key size %d\n", bn_size);
    log_print ();
    return;
  }
  BN_bn2bin (pub_rsa->n, fake_key + 1);
  RSA_free (pub_rsa);
  print_buffer ((char *) fake_key, sizeof (fake_key), "fake key", 16, 1);

  char text [] = "hello world";
  int tsize = sizeof (text);   /* include the terminating null character */ 
  print_buffer (text, tsize, "plaintext", 16, 1);
  char * cipher;
  int csize = allnet_encrypt (text, tsize, (char *) fake_key,
                              sizeof (fake_key), &cipher);
  print_buffer (cipher, csize, "ciphertext", 16, 1);

  char * decrypted;
  int dsize = allnet_decrypt (cipher, csize, key, ksize, &decrypted);
  print_buffer (decrypted, dsize, "decrypted", 16, 1);
}
#endif /* TEST_RSA_ENCRYPTION */


/* returns the number of decrypted bytes if successful, and 0 otherwise */
/* if successful, *res is dynamically allocated and must be free'd */
int allnet_decrypt (const char * cipher, int csize,
                    const char * key, int ksize, char ** res)
{
  if ((cipher == NULL) || (key == NULL) || (res == NULL) ||
      (csize < 0) || (ksize <= 0)) {
    printf ("cipher.c decrypt: %p %p %p %d %d, returning 0\n",
            cipher, key, res, csize, ksize);
    return 0;
  }
#ifdef DEBUG_PRINT
#endif /* DEBUG_PRINT */
  /* print_buffer (cipher, csize, "decrypting", 16, 1); */
  *res = NULL;

  /* convert key into internal format */
  BIO * mbio = BIO_new_mem_buf ((void *) key, ksize);
  RSA * rsa = PEM_read_bio_RSAPrivateKey (mbio, NULL, NULL, NULL);
  BIO_free (mbio);

  if (rsa == NULL) {
    printf ("unable get RSA private key, unable to decrypt\n");
    return 0;
  }

  int rsa_size = RSA_size (rsa);
  unsigned char * rsa_text = malloc_or_fail (rsa_size, "decrypt RSA plaintext");
  int bytes = RSA_private_decrypt (rsa_size, (const unsigned char *) cipher,
                                   rsa_text, rsa, RSA_PKCS1_OAEP_PADDING);
  RSA_free (rsa);
  if (bytes < 0) {
#ifdef DEBUG_PRINT
    ERR_load_crypto_strings ();
    ERR_print_errors_fp (stdout);
    printf ("RSA failed to decrypt %d bytes, got %d, cipher size %d\n",
            rsa_size, bytes, csize);
#endif /* DEBUG_PRINT */
    free (rsa_text);
#ifdef TEST_RSA_ENCRYPTION
    static int first_time = 1;
    if (first_time) {
      first_time = 0;
      test_rsa_encryption (key, ksize);
    }
#endif /* TEST_RSA_ENCRYPTION */
    return 0;
  }
  if (csize <= rsa_size) {  /* almost done! rsa text is our plaintext */
    *res = (char *) rsa_text;
    return bytes;
  }
  /* else: use AES to decrypt the remaining bytes */
  unsigned char * aes = rsa_text;
  unsigned char * nonce = rsa_text + AES256_SIZE;
  unsigned char * rsa_real_text = nonce + AES_BLOCK_SIZE;
  int rsa_real_size = bytes - (AES256_SIZE + AES_BLOCK_SIZE);
  int aes_size = csize - rsa_size;
  const char * aes_cipher = cipher + rsa_size;
  int rsize = rsa_real_size + aes_size;
#ifdef DEBUG_PRINT
  printf ("decrypt: %d bytes, rsa real %d, aes %d/%d, rsize %d\n",
          bytes, rsa_real_size, aes_size, AES256_SIZE + AES_BLOCK_SIZE, rsize);
#endif /* DEBUG_PRINT */
  char * result = malloc_or_fail (rsize, "decrypt result");
  memcpy (result, rsa_real_text, rsa_real_size);
  aes_ctr_crypt (aes, nonce, aes_cipher, aes_size, result + rsa_real_size);
  free (rsa_text);
  *res = result;
#ifdef DEBUG_PRINT
  print_buffer (result, rsize, "decrypted", 16, 1);
#endif /* DEBUG_PRINT */
  return rsize;
}

/* returns 1 if it verifies, 0 otherwise */
int allnet_verify (char * text, int tsize, char * sig, int ssize,
                   char * key, int ksize)
{
  if ((text == NULL) || (sig == NULL) || (key == NULL) ||
      (tsize < 0) || (ssize <= 0) || (ksize <= 0)) {
/* null sig or 0 ssize are not really errors, I think */
    if ((text == NULL) || (key == NULL) || (tsize < 0) || (ksize <= 0))
      printf ("cipher.c verify: %p %p %p %d %d %d, returning 0\n",
              text, sig, key, tsize, ssize, ksize);
    return 0;
  }
  /* convert key into internal format */
  if (*key != KEY_RSA4096_E65537) {
    printf ("key with unknown format %d, unable to verify\n", (*key) & 0xff);
    return 0;
  }
  RSA * rsa = RSA_new ();
  rsa->n = BN_bin2bn ((unsigned char *) (key + 1), ksize - 1, NULL);
  rsa->e = NULL;
  BN_dec2bn (&(rsa->e), RSA_E65537_STRING);
  int rsa_size = RSA_size (rsa);
  if (rsa_size > ssize) {
    printf ("public key has %d-byte signature, only %d bytes given\n",
            RSA_size (rsa), ssize);
    RSA_free (rsa);
    return 0;
  }
  if (ssize != rsa_size)
    printf ("notice: public key has %d-byte signature, %d bytes given\n",
            RSA_size (rsa), ssize);

  /* hash the contents, verify that the signature matches the hash */
  char hash [SHA512_SIZE];
  int hsize = rsa_size - 42;  /* PKCS #1 v2 requires 42 bytes */
  if (hsize > SHA512_SIZE)
    hsize = SHA512_SIZE;
  sha512_bytes (text, tsize, hash, hsize);

  int verifies = RSA_verify (NID_md5, (unsigned char *) hash, hsize,
                             (unsigned char *) sig, ssize, rsa);
  RSA_free (rsa);
#ifdef DEBUG_PRINT
  printf ("RSA_verify returned %d\n", verifies);
#endif /* DEBUG_PRINT */
  
  return verifies;
}
#undef DEBUG_PRINT

/* returns the size of the signature and mallocs the signature into result */
int allnet_sign (char * text, int tsize, char * key, int ksize, char ** result)
{
  /* convert key into internal format */
  BIO * mbio = BIO_new_mem_buf (key, ksize);
  RSA * rsa = PEM_read_bio_RSAPrivateKey (mbio, NULL, NULL, NULL);
  BIO_free (mbio);

  if (rsa == NULL) {
    printf ("unable get RSA private key, unable to decrypt\n");
    return 0;
  }

  int rsa_size = RSA_size (rsa);
  *result = malloc_or_fail (rsa_size, "signature");;
  unsigned int siglen;

  /* hash the contents, sign the hash */
  char hash [SHA512_SIZE];
  int hsize = rsa_size - 42;  /* PKCS #1 v2 requires 42 bytes */
  if (hsize > SHA512_SIZE)
    hsize = SHA512_SIZE;
  sha512_bytes (text, tsize, hash, hsize);

  if (! RSA_sign (NID_md5, (unsigned char *) hash, hsize,
                  (unsigned char *) (*result), &siglen, rsa)) {
    unsigned long e = ERR_get_error ();
    printf ("RSA signature (%d) failed %ld: %s\n", rsa_size, e,
            ERR_error_string (e, NULL));
    siglen = 0;
    free (*result);
    *result = NULL;
  }
  RSA_free (rsa);
  return siglen;
}

/* #define DEBUG_PRINT */

/* returns the data size > 0, and malloc's and fills in the contact, if able
 * to decrypt and verify the packet.
 * If there is no signature but it is able to decrypt, returns the
 * negative of the data size < 0, and fills in the contact matching
 * the public key used to decrypt.
 * With either of these, malloc's and fills in *text.
 * if decryption does not work, returns 0 and sets *contact and *text to NULL
 *
 * if maxcontacts > 0, only tries to match up to maxcontacts (to be implemented)
 */
int decrypt_verify (int sig_algo, char * encrypted, int esize,
                    char ** contact, keyset * kset, char ** text,
                    char * sender, int sbits, char * dest, int dbits,
                    int maxcontacts)
{
  *contact = NULL;
  *kset = -1;
  *text = NULL;
  char ** contacts;
  int ncontacts = all_contacts (&contacts);
  int ssize = 0;
  if (sig_algo != ALLNET_SIGTYPE_NONE)  /* has signature */
    ssize = readb16 (encrypted + esize - 2) + 2;
  if (ssize > esize)
    return 0;
  int csize = esize - ssize;  /* size of ciphertext to decrypt */
  char * sig = encrypted + csize;  /* only used if ssize != 0 */
  int i, j;
  for (i = 0; ((*contact == NULL) && (i < ncontacts)); i++) {
#ifdef DEBUG_PRINT
    printf ("to do: randomize and limit the number of contacts tried\n");
#endif /* DEBUG_PRINT */
    keyset * keys;
    int nkeys = all_keys (contacts [i], &keys);
    for (j = 0; ((*contact == NULL) && (j < nkeys)); j++) {
      int do_decrypt = 1;  /* for now, try to decrypt unsigned messages */
      if (sig_algo != ALLNET_SIGTYPE_NONE) {  /* verify signature */
        do_decrypt = 0;
        char * pub_key;
        int pub_ksize = get_contact_pubkey (keys [j], &pub_key);
        if ((pub_key != NULL) && (pub_ksize > 0)) {
          do_decrypt =
            allnet_verify (encrypted, csize, sig, ssize - 2,
                           pub_key, pub_ksize);
        }
      }
      if (do_decrypt) {
#ifdef DEBUG_PRINT
        printf ("signature match for contact %s, key %d\n", contacts [i], j);
#endif /* DEBUG_PRINT */
        char * priv_key;
        int priv_ksize = get_my_privkey (keys [j], &priv_key);
        int res = 0;
        if ((priv_key != NULL) && (priv_ksize > 0))
          res = allnet_decrypt (encrypted, csize, priv_key, priv_ksize, text);
        if (res) {
          *contact = strcpy_malloc (contacts [i], "verify contact");
          *kset = keys [j];
          if (sig_algo != ALLNET_SIGTYPE_NONE)
            return res;
          else
            return -res;
        } else if (sig_algo != ALLNET_SIGTYPE_NONE) {
          printf ("signed msg from %s key %d verifies but does not decrypt\n",
                  contacts [i], j);
        }
      }
    }
  }
#ifdef DEBUG_PRINT
  printf ("unable to decrypt packet, dropping\n");
#endif /* DEBUG_PRINT */
  return 0;
}
