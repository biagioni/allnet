/* cipher.c: provide enciphering/deciphering and
 *                   authentication/verification operations.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypt_sel.h"

#include "packet.h"
#include "util.h"
#include "sha.h"
#include "keys.h"
#include "cipher.h"

static void inc_ctr (char * ctr)
{
  int i;
  int carry = 1;  /* initially add 1 */
  for (i = AES_BLOCK_SIZE - 1; i >= 0; i--) {
    int value = (ctr [i] & 0xff) + carry;
    ctr [i] = value % 256;
    carry = value / 256;
  }
}

/* for CTR mode, encryption and decryption are identical */
static void aes_ctr_crypt (char * key, char * ctr,
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
  char in [AES_BLOCK_SIZE];
  memcpy (in, ctr, AES_BLOCK_SIZE);
  char out [AES_BLOCK_SIZE];
  int i;
  for (i = 0; i < dsize; i++) {
    if ((i % AES_BLOCK_SIZE) == 0) {   /* compute the next block */
      if (! allnet_aes_encrypt_block (key, in, out))
        exit (1);
      inc_ctr (in);
    }
    result [i] = data [i] ^ out [i % AES_BLOCK_SIZE];
  }
#ifdef DEBUG_PRINT
  printf ("AES encryption complete\n");
#endif /* DEBUG_PRINT */
}

/* returns the number of encrypted bytes if successful, and 0 otherwise */
/* if successful, *res is dynamically allocated and must be free'd */
int allnet_encrypt (const char * text, int tsize,
                    allnet_rsa_pubkey key, char ** res)
{
#ifdef DEBUG_PRINT
  print_buffer (text, tsize, "encrypting", 16, 1);
#endif /* DEBUG_PRINT */

  *res = NULL;
  char * aes = NULL;
  char * nonce = NULL;

  int rsa_size = allnet_rsa_pubkey_size (key);
  int rsa_encrypt_size = tsize;
  int result_size = rsa_size;
  int max_rsa = rsa_size - 42;  /* PKCS #1 v2 requires 42 bytes */
  char * new_text = NULL;
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
    result_size = tsize + (rsa_size - max_rsa);
#ifdef DEBUG_PRINT
    printf ("result size = %d + (%d - %d) = %d\n",
            tsize, rsa_size, max_rsa, result_size);
#endif /* DEBUG_PRINT */
  }

  char * result = malloc_or_fail (result_size, "encrypt result");

  int bytes = allnet_rsa_encrypt (key, text, rsa_encrypt_size,
                                  result, result_size, 1);
  if (bytes != rsa_size) {
    printf ("RSA failed to encrypt %d bytes, %d\n", rsa_encrypt_size, bytes);
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

/* returns the number of decrypted bytes if successful, and 0 otherwise */
/* if successful, *res is dynamically allocated and must be free'd */
int allnet_decrypt (const char * cipher, int csize,
                    allnet_rsa_prvkey key, char ** res)
{
#ifdef DEBUG_PRINT
#define DEBUG_PRINT_TIMES
#endif /* DEBUG_PRINT */
#ifdef DEBUG_PRINT_TIMES
  unsigned long long int start = allnet_time_us ();
#endif /* DEBUG_PRINT_TIMES */
  if ((cipher == NULL) || (res == NULL) || (csize < 0)) {
    printf ("cipher.c decrypt: %p %p %d, returning 0\n", cipher, res, csize);
    return 0;
  }
#ifdef DEBUG_PRINT
#endif /* DEBUG_PRINT */
  /* print_buffer (cipher, csize, "decrypting", 16, 1); */
  *res = NULL;

  int rsa_size = allnet_rsa_prvkey_size (key);
  if (rsa_size <= 0) {
    printf ("unable get RSA private key, unable to decrypt\n");
    return 0;
  }
  char * rsa_text = malloc_or_fail (rsa_size, "decrypt RSA plain");

  int bytes = allnet_rsa_decrypt (key, cipher, csize, rsa_text, rsa_size, 1);

  if (bytes < 0) {
#ifdef DEBUG_PRINT
    printf ("RSA failed to decrypt %d bytes, got %d, cipher size %d\n",
            rsa_size, bytes, csize);
#endif /* DEBUG_PRINT */
    free (rsa_text);
    return 0;
  }

  if (csize <= rsa_size) {  /* almost done! rsa text is our plaintext */
    *res = (char *) rsa_text;
    return bytes;
  }
  /* else: use AES to decrypt the remaining bytes */
  char * aes = rsa_text;
  char * nonce = rsa_text + AES256_SIZE;
  char * rsa_real_text = nonce + AES_BLOCK_SIZE;
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
#ifdef DEBUG_PRINT_TIMES
  unsigned long long int time_delta = allnet_time_us () - start;
  printf ("successful decryption took %lld.%06lld seconds\n",
          time_delta / 1000000, time_delta % 1000000);
#endif /* DEBUG_PRINT_TIMES */
  return rsize;
}

static void debug_public_key_size (const char * text, int tsize,
                                   const char * sig, int ssize, int rsa_size)
{
  if (ssize != rsa_size) {
    char buffer [10000];
    snprintf (buffer, sizeof (buffer),
              "public key has %d-byte signature, only %d bytes given",
              rsa_size, ssize);
    if (rsa_size < ssize)
      snprintf (buffer, sizeof (buffer),
                "notice: public key has %d-byte signature, %d bytes given",
                rsa_size, ssize);
    pipemsg_debug_last_received (buffer);
  }
#ifdef DEBUG_PRINT
#endif /* DEBUG_PRINT */
}

/* returns 1 if it verifies, 0 otherwise */
int allnet_verify (const char * text, int tsize, const char * sig, int ssize,
                   allnet_rsa_pubkey key)
{
  if ((text == NULL) || (sig == NULL) || (tsize < 0) || (ssize <= 0)) {
/* null sig or 0 ssize are not really errors, I think */
    if ((text == NULL) || (tsize < 0))
      printf ("cipher.c verify: %p %p %d %d, returning 0\n",
              text, sig, tsize, ssize);
    return 0;
  }
  int rsa_size = allnet_rsa_pubkey_size (key);
  debug_public_key_size (text, tsize, sig, ssize, rsa_size);
  if (rsa_size > ssize)
    return 0;

  /* hash the contents, verify that the signature matches the hash */
  char hash [SHA512_SIZE];
  int hsize = rsa_size - 42;  /* PKCS #1 v2 requires 42 bytes */
  if (hsize > SHA512_SIZE)
    hsize = SHA512_SIZE;
  sha512_bytes (text, tsize, hash, hsize);

  int verifies = allnet_rsa_verify (key, hash, hsize, sig, ssize);

#ifdef DEBUG_PRINT
  printf ("RSA_verify returned %d\n", verifies);
#endif /* DEBUG_PRINT */
  
  return verifies;
}
#undef DEBUG_PRINT

/* returns the size of the signature and mallocs the signature into result */
int allnet_sign (const char * text, int tsize, allnet_rsa_prvkey key,
                 char ** result)
{
  int rsa_size = allnet_rsa_prvkey_size (key);
  if (rsa_size <= 0) {
    printf ("unable to sign\n");
    return 0;
  }
  *result = malloc_or_fail (rsa_size, "signature");;

  /* hash the contents, sign the hash */
  char hash [SHA512_SIZE];
  int hsize = rsa_size - 42;  /* PKCS #1 v2 requires 42 bytes */
  if (hsize > SHA512_SIZE)
    hsize = SHA512_SIZE;
  sha512_bytes (text, tsize, hash, hsize);

  int success = allnet_rsa_sign (key, hash, hsize, *result, rsa_size);
  if (! success) {
    printf ("RSA signature failed: %d %d\n", rsa_size, hsize);
    free (*result);
    *result = NULL;
    return 0;
  }
  return rsa_size;
}

static char ** deep_copy (char ** original, int n)
{
  size_t needed = 0;
  int i;
  for (i = 0; i < n; i++)
    needed += strlen (original [i]) + 1 + sizeof (char *);
  char ** result = malloc_or_fail (needed, "cipher.c deep_copy");
  char * strings = (char *) (&(result [n]));
  for (i = 0; i < n; i++) {
    result [i] = strings;
    strcpy (result [i], original [i]);
    strings += strlen (original [i]) + 1;
  }
  return result;
}

/* deep copy everything, then permute so a random subset is at the front */
static char ** randomize_contacts (char ** original, int n, int max)
{
  char ** result = deep_copy (original, n);
  int * permutation = random_permute (n);
  char ** copy = malloc_or_fail (sizeof (char *) * max, "cipher.c randomize");
  int i;
  for (i = 0; i < max; i++)  /* save the contact pointers we will try */
    copy [i] = result [permutation [i]];
  free (permutation);
  /* now save the pointers back in result */
  for (i = 0; i < max; i++)
    result [i] = copy [i];
  free (copy);
  return result;
}

/* #define DEBUG_PRINT */

/* returns the data size > 0, and malloc's and fills in the contact, if able
 * to decrypt and verify the packet.
 * If there is no signature but it is able to decrypt, returns the
 * negative of the data size < 0, and fills in the contact matching
 * the public key used to decrypt.
 * With either of these, malloc's and fills in *text.
 * The contact and keyset always identify an individual contact, never a group
 * if decryption does not work, returns 0 and sets *contact and *text to NULL
 *
 * if maxcontacts > 0, only tries to match up to maxcontacts
 */
int decrypt_verify (int sig_algo, char * encrypted, int esize,
                    char ** contact, keyset * kset, char ** text,
                    char * sender, int sbits, char * dest, int dbits,
                    int maxcontacts)
{
#ifdef DEBUG_PRINT
  unsigned long long int start = allnet_time_us ();
#endif /* DEBUG_PRINT */
  *contact = NULL;
  *kset = -1;
  *text = NULL;
  int ssize = 0;
  if (sig_algo != ALLNET_SIGTYPE_NONE)  /* has signature */
    ssize = readb16 (encrypted + esize - 2) + 2;
  if (ssize > esize)
    return 0;
  int csize = esize - ssize;  /* size of ciphertext to decrypt */
  char * sig = encrypted + csize;  /* only used if ssize != 0 */
  int i, j;
  int count = 0;
  int decrypt_count = 0;
  char ** contacts = NULL;
  int ncontacts = all_individual_contacts (&contacts);
  if ((maxcontacts > 0) && (maxcontacts < ncontacts)) {
    contacts = randomize_contacts (contacts, ncontacts, maxcontacts);
    ncontacts = maxcontacts;
  }
  for (i = 0; ((*contact == NULL) && (i < ncontacts)); i++) {
    keyset * keys = NULL;
    int nkeys = all_keys (contacts [i], &keys);
    for (j = 0; ((*contact == NULL) && (j < nkeys)); j++) {
      int do_decrypt = 1;  /* for now, try to decrypt unsigned messages */
      if ((dest != NULL) && (dbits > 0)) {
        char laddr [ADDRESS_SIZE];
        int lbits = get_local (keys [j], (unsigned char *)laddr);
        if ((lbits > 0) &&  /* if lbits or dbits is zero, we verify */
            (matches ((unsigned char *) dest, dbits,
                      (unsigned char *) laddr, lbits) <= 0))
          do_decrypt = 0;
      }
      if ((sender != NULL) && (sbits > 0)) {
        char raddr [ADDRESS_SIZE];
        int rbits = get_remote (keys [j], (unsigned char *)raddr);
        if ((rbits > 0) &&  /* if lbits or dbits is zero, we verify */
            (matches ((unsigned char *) sender, sbits,
                      (unsigned char *) raddr, rbits) <= 0))
          do_decrypt = 0;
      }
      if (do_decrypt && (sig_algo != ALLNET_SIGTYPE_NONE)) {
        /* verify signature */
        do_decrypt = 0;
        allnet_rsa_pubkey pub_key;
        if (get_contact_pubkey (keys [j], &pub_key)) {
          do_decrypt =
            allnet_verify (encrypted, csize, sig, ssize - 2, pub_key);
          count++;
        }
      }
#ifdef DEBUG_PRINT
      unsigned long long int time_ver = allnet_time_us () - start;
#endif /* DEBUG_PRINT */
      if (do_decrypt) {
#ifdef DEBUG_PRINT
        printf ("signature match for contact %s, key %d\n", contacts [i], j);
#endif /* DEBUG_PRINT */
        allnet_rsa_prvkey prv_key;
        int priv_ksize = get_my_privkey (keys [j], &prv_key);
        int res = 0;
        if (priv_ksize > 0) {
          res = allnet_decrypt (encrypted, csize, prv_key, text);
          decrypt_count++;
        }
        if (res) {
          *contact = strcpy_malloc (contacts [i], "verify contact");
          *kset = keys [j];
#ifdef DEBUG_PRINT
          unsigned long long int time_delta = allnet_time_us () - start;
          printf ("%ssuccess: %d ver (%lld.%06lld s) + %d dec ",
                  (sig_algo != ALLNET_SIGTYPE_NONE) ? "" : "unsigned ", count,
                  time_ver / 1000000, time_ver % 1000000, decrypt_count);
          printf ("%lld.%06lld seconds\n",
                  time_delta / 1000000, time_delta % 1000000);
#endif /* DEBUG_PRINT */
          free (keys);
          if (contacts != NULL) free (contacts);
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
    if ((nkeys > 0) && (keys != NULL))
      free (keys);
  }
  if (contacts != NULL) free (contacts);
#ifdef DEBUG_PRINT
  printf ("unable to decrypt packet, dropping\n");
  unsigned long long int time_delta = allnet_time_us () - start;
  if (count + decrypt_count > 0)
    printf ("%d verifications+%d decryptions took %lld.%06lld seconds\n",
            count, decrypt_count, time_delta / 1000000, time_delta % 1000000);
#endif /* DEBUG_PRINT */
  return 0;
}
