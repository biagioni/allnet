/* sha.h: sha computations */

#ifndef ALLNET_SHA_H
#define ALLNET_SHA_H

#define SHA1_SIZE	20
#define SHA512_SIZE	64

/* the result array must have size SHA512_SIZE */
extern void sha512 (const char * data, int dsize, char * result);

/* the result array must have size SHA1_SIZE */
extern void sha1 (const char * data, int dsize, char * result);

/* the result array must have size rsize, only the first rsize bytes
 * of the hash are saved (if rsize > SHAx_SIZE, the result is
 * padded with zeros out to rsize) */
extern void sha512_bytes (const char * data, int dsize,
                          char * result, int rsize);
extern void sha1_bytes (const char * data, int dsize,
                        char * result, int rsize);

/* the result array must have size SHA512_SIZE */
extern void sha512hmac (const char * data, int dsize,
                        const char * key, int ksize, char * result);

#endif /* ALLNET_SHA_H */
