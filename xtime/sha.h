/* sha.h: sha computation */

#ifndef ALLNET_SHA_H
#define ALLNET_SHA_H

#define SHA512_SIZE	64

/* the result array must have size SHA512_SIZE */
extern void sha512 (char * data, int dsize, char * result);

/* the result array must have size rsize, only the first rsize bytes
 * of the hash are saved (if rsize > SHA512_SIZE, the result is
 * padded with zeros out to rsize) */
extern void sha512_bytes (char * data, int dsize, char * result, int rsize);

/* the result array must have size SHA512_SIZE */
extern void sha512hmac (char * data, int dsize, char * key, int ksize,
                        char * result);


#endif /* ALLNET_SHA_H */
