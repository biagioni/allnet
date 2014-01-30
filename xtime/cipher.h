/* cipher.h: provide the enciphering/deciphering and authentication
 * and verification operations.
 */

#ifndef XTIME_APP_CIPHER_H
#define XTIME_APP_CIPHER_H


/* returns 1 if it verifies, 0 otherwise */
extern int verify (char * text, int tsize, char * sig, int ssize,
                   char * key, int ksize);

/* returns the size of the signature and mallocs the signature into result */
extern int sign (char * text, int tsize, char * key, int ksize, char ** result);

/* returns 1 if created, 0 otherwise */
extern int create_keys (char * source, char * dest, int overwrite);

/* source and dest must each have ADDRESS_SIZE bytes, or be null */
/* any of the result pointers may be null */
/* if printable is not null, fills it in with a malloc'd printable version
 * of the source and/or destination addresses, if available -- if not
 * available, sets *printable to NULL.
/* returns the key size, or 0 if there is no key or some other error */
extern int get_my_privkey (char ** key, char * source, int * sbits,
                           char * dest, int * dbits, char ** printable);

#endif /* ALLENT_APP_CIPHER_H */
