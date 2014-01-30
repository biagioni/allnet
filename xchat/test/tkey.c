/* tkey.c: test key encryption, decryption, and storage */

#include <stdio.h>
#include <stdlib.h>

#include "../key.h"

int main (int argc, char ** argv)
{
  set_application ("tkey");   /* don't pollute key space with our keys */
  printf ("generating my key\n");
  int my_key_id = keys_generate (4096, "test: my key");
  printf ("generating other key\n");
  int oth_key_id = keys_generate (4096, "test: other's key");
  printf ("my key ID %d, other key ID %d\n", my_key_id, oth_key_id);

  int clen;
  char * cipher = sign_encrypt (oth_key_id, my_key_id, "hello world", 11,
                                NULL, NULL, &clen);

  printf ("my key ID %d, other key ID %d, hello world encrypts to %d bytes\n",
          my_key_id, oth_key_id, clen);
  print_buffer (cipher, clen, "cyphertext", 16, 1);

  int ksize;
  char * linearized = key_linearize (oth_key_id, &ksize);
  if (key_remove (oth_key_id) < 1) {
    printf ("unable to remove other key %d\n", oth_key_id);
    return 1;
  }
  /* now we only have the public key part of the other key */
  oth_key_id = key_save (linearized, ksize, "test: other's public key", 0, 0);
  printf ("new key ID for other key %d\n", oth_key_id);
  print_buffer (linearized, ksize, "public key", 18, 1);

  int plen;
  int sig_key = -1;
  int crypt_key = -1;
  char * plaintext = decrypt_verify (cipher, clen, &plen, &sig_key, &crypt_key);
  printf ("got plaintext '%s' (%d bytes), encrypted with %d, signed by %d\n",
          plaintext, plen, crypt_key, sig_key);
  free (plaintext);

  /* now repeat, but sig_key and crypt_key are not -1); */
  plaintext = decrypt_verify (cipher, clen, &plen, &sig_key, &crypt_key);
  printf ("with keys %d and %d, got plaintext '%s' (%d bytes)\n",
          crypt_key, sig_key, plaintext, plen);
}

