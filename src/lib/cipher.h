/* cipher.h: provide enciphering/deciphering and
 *                   authentication/verification operations.
 */

#ifndef ALLNET_APP_CIPHER_H
#define ALLNET_APP_CIPHER_H

#include "crypt_sel.h"
#include "keys.h"

/* first byte of key defines the key format */
#define KEY_RSA4096_E65537	1	/* n for rsa public key, e is 65537 */

#define RSA_E65537_VALUE	65537
#define RSA_E65537_STRING	"65537"

/* returns the number of encrypted bytes if successful, and 0 otherwise */
/* if successful, *res is dynamically allocated and must be free'd */
extern int allnet_encrypt (const char * text, int tsize,
                           allnet_rsa_pubkey key, char ** res);

/* returns the number of decrypted bytes if successful, and 0 otherwise */
/* if successful, *res is dynamically allocated and must be free'd */
extern int allnet_decrypt (const char * cipher, int csize,
                           allnet_rsa_prvkey key, char ** res);

/* returns 1 if it verifies, 0 otherwise */
extern int allnet_verify (const char * text, int tsize, const char * sig,
                          int ssize, allnet_rsa_pubkey key);

/* returns the size of the signature and mallocs the signature into result */
extern int allnet_sign (const char * text, int tsize, allnet_rsa_prvkey key,
                        char ** result);

/* returns the data size > 0, and malloc's and fills in the contact, if able
 * to decrypt and verify the packet.
 * If there is no signature but it is able to decrypt, returns the
 * negative of the data size < 0, and fills in the contact matching
 * the public key used to decrypt.
 * With either of these, malloc's and fills in *text.
 * The contact and keyset always identify an individual contact, never a group
 * if decryption does not work, returns 0 and sets *contact and *text to NULL
 *
 *
 * if maxcontacts > 0, only tries to match up to maxcontacts
 */
extern int decrypt_verify (int sig_algo, char * encrypted, int esize,
                           char ** contact, keyset * key, char ** text,
                           char * sender, int sbits, char * dest, int dbits,
                           int maxcontacts);

#endif /* ALLNET_APP_CIPHER_H */
