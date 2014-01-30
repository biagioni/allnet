/* cipher.h: provide enciphering/deciphering and
 *                   authentication/verification operations.
 */

#ifndef ALLNET_APP_CIPHER_H
#define ALLNET_APP_CIPHER_H

/* first byte of key defines the key format */
#define KEY_RSA_E65537		1	/* n for rsa public key, e is 65537 */

#define RSA_E65537_VALUE	65537
#define RSA_E65537_STRING	"65537"

/* returns the number of encrypted bytes if successful, and 0 otherwise */
/* if successful, *res is dynamically allocated and must be free'd */
extern int encrypt (char * text, int tsize, char * key, int ksize,
                    char ** res);

/* returns the number of decrypted bytes if successful, and 0 otherwise */
/* if successful, *res is dynamically allocated and must be free'd */
extern int decrypt (char * cipher, int csize, char * key, int ksize,
                    char ** res);

/* returns 1 if it verifies, 0 otherwise */
extern int verify (char * text, int tsize, char * sig, int ssize,
                   char * key, int ksize);

/* returns the size of the signature and mallocs the signature into result */
extern int sign (char * text, int tsize, char * key, int ksize, char ** result);

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
extern int decrypt_verify (int sig_algo, char * encrypted, int esize,
                           char ** contact, char ** text,
                           char * sender, int sbits, char * dest, int dbits,
                           int maxcontacts);

#endif /* ALLNET_APP_CIPHER_H */
