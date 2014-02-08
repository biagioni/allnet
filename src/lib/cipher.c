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

#include "util.h"
#include "sha.h"
#include "../xchat/store.h"
#include "cipher.h"

#define AES256_SIZE	(256 / 8)	/* 32 */
/* defined in openssl/aes.h #define AES_BLOCK_SIZE	(128 / 8)	/* 16 */

static void inc_ctr (char * ctr)
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
static void aes_ctr_crypt (char * key, char * ctr, char * data, int dsize,
                           char * result)
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
  char in [AES_BLOCK_SIZE];
  memcpy (in, ctr, AES_BLOCK_SIZE);
  char out [AES_BLOCK_SIZE];
  int i;
  for (i = 0; i < dsize; i++) {
    if ((i % AES_BLOCK_SIZE) == 0) {   /* compute the next block */
      AES_encrypt (in, out, &aes);
      inc_ctr (in);
    }
    result [i] = data [i] ^ out [i % AES_BLOCK_SIZE];
  }
  printf ("AES encryption complete\n");
}

/* returns the number of encrypted bytes if successful, and 0 otherwise */
/* if successful, *res is dynamically allocated and must be free'd */
int encrypt (char * text, int tsize, char * key, int ksize, char ** res)
{
#ifdef DEBUG_PRINT
  print_buffer (text, tsize, "encrypting", 16, 1);
#endif /* DEBUG_PRINT */

  *res = NULL;
  char * aes = NULL;
  char * nonce = NULL;

  /* convert key into internal format */
  if (*key != KEY_RSA4096_E65537) {
    printf ("key with unknown format %d, unable to encrypt\n", (*key) & 0xff);
    return 0;
  }
  RSA * rsa = RSA_new ();
  rsa->n = BN_bin2bn (key + 1, ksize - 1, NULL);
  rsa->e = NULL;
  BN_dec2bn (&(rsa->e), RSA_E65537_STRING);

  int rsa_encrypt_size = tsize;
  int rsa_size = RSA_size (rsa);
  int result_size = rsa_size;
  int max_rsa = RSA_size (rsa) - 12;  /* PKCS #1 v1.5 requires 12 bytes */
  int free_text = 0;
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
    char * new_text = malloc_or_fail (input_size, "encrypt final plaintext");
    aes = new_text;
    nonce = new_text + AES256_SIZE;
    random_bytes (new_text, AES256_SIZE + AES_BLOCK_SIZE);
    memcpy (new_text + (AES256_SIZE + AES_BLOCK_SIZE), text, tsize);
    text = new_text;
    tsize = input_size;
    rsa_encrypt_size = max_rsa;
    result_size = tsize + (RSA_size (rsa) - max_rsa);
    printf ("result size = %d + (%d - %d) = %d\n",
            tsize, RSA_size (rsa), max_rsa, result_size);
    free_text = 1;
  }

  char * result = malloc_or_fail (result_size, "encrypt result");

  /* encrypt either the entire message, or just the first max_rsa bytes */
  int bytes = RSA_public_encrypt (rsa_encrypt_size, text, result, rsa,
                                  RSA_PKCS1_PADDING);
  RSA_free (rsa);
  if (bytes != rsa_size) {
    unsigned long e = ERR_get_error ();
    printf ("RSA encryption failed %ld/%s %d\n", e, ERR_error_string (e, NULL),
            bytes);
    if (free_text) free (text);
    free (result);
    return 0;
  }

/* printf ("input size %d, output size %d, bytes %d, rsa encrypted %d\n",
          tsize, result_size, bytes, rsa_encrypt_size); */
  /* encrypt any remaining bytes using AES */
  int remaining = tsize - rsa_encrypt_size;
/*  printf ("%d bytes to be encrypted using AES\n", remaining); */
  if (remaining > 0)
    aes_ctr_crypt (aes, nonce, text + rsa_encrypt_size, remaining,
                   result + bytes);

  if (free_text) free (text);
  *res = result;
#ifdef DEBUG_PRINT
  print_buffer (result, result_size, "encrypted", 16, 1);
#endif /* DEBUG_PRINT */
  return result_size;
}


static void test_rsa_encryption (char * key, int ksize)
{
  /* convert key into internal formats */
  BIO * mbio = BIO_new_mem_buf (key, ksize);
  RSA * pub_rsa = PEM_read_bio_RSAPublicKey (mbio, NULL, NULL, NULL);
  BIO_free (mbio);
  char fake_key [513];
  fake_key [0] = KEY_RSA4096_E65537;
  int bn_size = BN_num_bytes (pub_rsa->n);
  BN_bn2bin (pub_rsa->n, fake_key + 1);
  RSA_free (pub_rsa);
  print_buffer (fake_key, sizeof (fake_key), "fake key", 16, 1);

  char text [] = "hello world";
  int tsize = sizeof (text);   /* include the terminating null character */ 
  print_buffer (text, tsize, "plaintext", 16, 1);
  char * cipher;
  int csize = encrypt (text, tsize, fake_key, sizeof (fake_key), &cipher);
  print_buffer (cipher, csize, "ciphertext", 16, 1);

  char * decrypted;
  int dsize = decrypt (cipher, csize, key, ksize, &decrypted);
  print_buffer (decrypted, dsize, "decrypted", 16, 1);
}


/* returns the number of decrypted bytes if successful, and 0 otherwise */
/* if successful, *res is dynamically allocated and must be free'd */
int decrypt (char * cipher, int csize, char * key, int ksize, char ** res)
{
#ifdef DEBUG_PRINT
#endif /* DEBUG_PRINT */
  /* print_buffer (cipher, csize, "decrypting", 16, 1); */
  *res = NULL;

  /* convert key into internal format */
  BIO * mbio = BIO_new_mem_buf (key, ksize);
  RSA * rsa = PEM_read_bio_RSAPrivateKey (mbio, NULL, NULL, NULL);
  BIO_free (mbio);

  if (rsa == NULL) {
    printf ("unable get RSA private key, unable to decrypt\n");
    return 0;
  }

  int rsa_size = RSA_size (rsa);
  char * rsa_text = malloc_or_fail (rsa_size, "decrypt RSA plaintext");
  int bytes = RSA_private_decrypt (rsa_size, cipher, rsa_text, rsa,
                                   RSA_PKCS1_PADDING);
  RSA_free (rsa);
  if (bytes < 0) {
/*
    unsigned long e = ERR_get_error ();
    printf ("RSA decryption failed %ld/%s %d\n", e, ERR_error_string (e, NULL),
            bytes);
*/
    free (rsa_text);
/*
static int first_time = 1;
if (first_time) {
first_time = 0;
test_rsa_encryption (key, ksize);
}
*/
    return 0;
  }
  if (csize <= rsa_size) {  /* almost done! rsa text is our plaintext */
    *res = rsa_text;
    return bytes;
  }
  /* else: use AES to decrypt the remaining bytes */
  char * aes = rsa_text;
  char * nonce = rsa_text + AES256_SIZE;
  char * rsa_real_text = nonce + AES_BLOCK_SIZE;
  int rsa_real_size = bytes - (AES256_SIZE + AES_BLOCK_SIZE);
  int aes_size = csize - rsa_size;
  char * aes_cipher = cipher + rsa_size;
  int rsize = rsa_real_size + aes_size;
#ifdef DEBUG_PRINT
  printf ("decrypt: rsa real %d, aes %d, rsize %d\n", rsa_real_size, aes_size,
          rsize);
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
int verify (char * text, int tsize, char * sig, int ssize,
            char * key, int ksize)
{
  /* convert key into internal format */
  if (*key != KEY_RSA4096_E65537) {
    printf ("key with unknown format %d, unable to verify\n", (*key) & 0xff);
    return 0;
  }
  RSA * rsa = RSA_new ();
  rsa->n = BN_bin2bn (key + 1, ksize - 1, NULL);
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
  int hsize = rsa_size - 12;
  if (hsize > SHA512_SIZE)
    hsize = SHA512_SIZE;
  sha512_bytes (text, tsize, hash, hsize);

  int verifies = RSA_verify (NID_md5, hash, hsize, sig, ssize, rsa);
  RSA_free (rsa);
#ifdef DEBUG_PRINT
  printf ("RSA_verify returned %d\n", verifies);
#endif /* DEBUG_PRINT */
  
  return verifies;
}

/* returns the size of the signature and mallocs the signature into result */
int sign (char * text, int tsize, char * key, int ksize, char ** result)
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
  int siglen;

  /* hash the contents, sign the hash */
  char hash [SHA512_SIZE];
  int hsize = rsa_size - 12;
  if (hsize > SHA512_SIZE)
    hsize = SHA512_SIZE;
  sha512_bytes (text, tsize, hash, hsize);

  if (! RSA_sign (NID_md5, hash, hsize, *result, &siglen, rsa)) {
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
                    char ** contact, char ** text,
                    char * sender, int sbits, char * dest, int dbits,
                    int maxcontacts)
{
  *contact = NULL;
  *text = NULL;
  if (sig_algo != ALLNET_SIGTYPE_NONE) {  /* verify signature */
    int ssize = ((encrypted [esize - 2] & 0xff) << 8) +
                 (encrypted [esize - 1] & 0xff) + 2;
    char * sig = encrypted + (esize - ssize);
    char ** contacts;
    int ncontacts = all_contacts (&contacts);
    int i;
#ifdef DEBUG_PRINT
    printf ("to do: limit this loop to only matching source addresses\n");
    if (maxcontacts > 0)
      printf ("to do: randomize and limit the number of contacts tried\n");
#endif /* DEBUG_PRINT */
    for (i = 0; ((*contact == NULL) && (i < ncontacts)); i++) {
      char * key;
      int ksize = get_contact_pubkey (contacts [i], &key);
      if (verify (encrypted, esize - ssize, sig, ssize - 2, key, ksize)) {
        *contact = strcpy_malloc (contacts [i], "verify contact");
#ifdef DEBUG_PRINT
        printf ("packet verified for contact %s\n", *contact);
#endif /* DEBUG_PRINT */
      } else {
#ifdef DEBUG_PRINT
        printf ("packet not verified for contact %s\n", *contact);
#endif /* DEBUG_PRINT */
      }
      free (key);
    }
    free_contacts (contacts);
    if (*contact == NULL) {
#ifdef DEBUG_PRINT
      printf ("signature algorithm %d, verification unsuccessful\n", sig_algo);
#endif /* DEBUG_PRINT */
      return 0;
    }
    /* contact is known, go ahead and decrypt */
    char * priv_key;   /* different from the contact public key above */
    int priv_ksize = get_my_privkey (*contact, &priv_key);
    if (priv_ksize <= 0) {
      printf ("error (%d): unable to get my privkey for %s\n", priv_ksize,
              *contact);
      return 0;
    }
    int res = decrypt (encrypted, esize - ssize, priv_key, priv_ksize, text);
    free (priv_key);
    return res;
  }
  /* no signature, try the different decryption keys, see if one works */
#ifdef DEBUG_PRINT
  printf ("to do: randomize and limit the number of contacts tried\n");
#endif /* DEBUG_PRINT */
  char ** contacts;
  int ncontacts = all_contacts (&contacts);
  int i;
  for (i = 0; i < ncontacts; i++) {
/*    printf ("attempting decryption for contact %s\n", contacts [i]); */
    char * key;
    int ksize = get_my_privkey (contacts [i], &key);
    if (ksize <= 0) {
      printf ("error (%d): no my privkey for %s\n", ksize, contacts [i]);
      free_contacts (contacts);
      return 0;
    }
    int res = decrypt (encrypted, esize, key, ksize, text);
    free (key);
    if (res > 0) {  /* success (without verification)! */
      *contact = strcpy_malloc (contacts [i], "decrypt contact");
      printf ("decrypted for contact %s\n", *contact);
      free_contacts (contacts);
      return - res;
    }
  }
  /* packet may or may not have been decrypted, as indicated by tsize > 0 */
  free_contacts (contacts);
#ifdef DEBUG_PRINT
  printf ("unable to decrypt packet, dropping\n");
#endif /* DEBUG_PRINT */
  return 0;
}

