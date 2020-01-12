/* dh.h: diffie-hellman elliptic-curve computations, as described in RFC 7748 */
/* the standard in RFC 7748 is little-endian, but allnet uses big-endian */

#ifndef ALLNET_DH_H
#define ALLNET_DH_H

#define DH25519_SIZE	32   /* not used */
#define DH448_SIZE	56

/* all arrays must have size DH448_SIZE.
 * k is the scalar, u is the u-coordinate.
 * given a u5 (the last byte is 5 and the rest are 0) and a random secret r,
 * each party sends to the other side allnet_x448(r, u5).
 * upon receiving from the other side an authenticated s, each side
 * computes the shared secret key as k = allnet_x448(r, s).
 * the call returns 0 if the result is 0, and 1 otherwise */
extern int allnet_x448 (const char * k, const char * u, char * result);

/* turn a randomly-generated string into a value that can be used with x448
 * (decodeScalar448 in RFC 7748) */
extern void allnet_x448_make_valid (char * k);

/* the special value 5 is used in the initial key generation */
extern void allnet_x448_five (char * five);

#endif /* ALLNET_DH_H */
