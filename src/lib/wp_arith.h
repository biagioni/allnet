/* wp_arith.h: long integer arithmetic for rsa implementation */

/* this library is named for W. Wesley Peterson, since this library is
 * loosely based on code he wrote before passing away in 2009 */

/* wp_arith does not do memory management -- the long ints are stored
 * in uint64_t arrays that are passed in to functions.  The caller
 * is responsible for making sure the uint64_t array is long enough
 * for the number of bits needed.
 */

#ifndef WES_ARITH_H
#define WES_ARITH_H

#include <stdint.h>   /* uint64_t */

/* #define NUM_WORDS(nbits)	(((nbits) / 8) / sizeof (uint64_t)) */
#define NUM_WORDS(nbits)	((nbits) >> 6)

#define MAX_WORD_VALUE		(((uint64_t) 0) - 1)

/* prints an integer in hex to a statically allocated string
 * since there is only one string, do not use twice in the same printf!!! */
extern char * wp_itox (int nbits, const uint64_t * n);

/* copies source to destination */
extern void wp_copy (int nbits, uint64_t * dst, const uint64_t * src);

extern void wp_init (int nbits, uint64_t * n, int value);
extern void wp_from_bytes (int nbits, uint64_t * n,
                           int dsize, const char * data);
extern void wp_to_bytes (int nbits, const uint64_t * n,
                         int dsize, char * data);

/* only works if new_bits > old_bits */
extern void wp_extend (int new_bits, uint64_t * new,
                       int old_bits, const uint64_t * old);
/* only works if new_bits < old_bits */
extern void wp_shrink (int new_bits, uint64_t * new,
                       int old_bits, const uint64_t * old);

extern int wp_is_zero (int nbits, const uint64_t * n);
extern int wp_is_even (int nbits, const uint64_t * n);
extern int wp_compare (int nbits, const uint64_t * n1, const uint64_t * n2);
/* returns 1 if n is a multiple of mod, 0 otherwise */
/* temp must have nbits or more */
extern int wp_multiple_of_int (int nbits, const uint64_t * n, uint32_t mod);

/* byte position zero is the least significant.
 * returns -1 in case of error, the byte value (0..255) otherwise */
extern int wp_get_byte (int nbits, const uint64_t * n, int byte_pos);

extern void wp_shift_left (int nbits, uint64_t * n);
extern void wp_shift_right (int nbits, uint64_t * n);

/* returns carry bit, 0 or 1 */
extern int  wp_add (int nbits, uint64_t * res,
                    const uint64_t * a, const uint64_t * b);

extern void wp_add_int (int nbits, uint64_t * res, int value);

/* only works if a and b are already less than mod */
extern void wp_add_mod (int nbits, uint64_t * res, 
                        const uint64_t * a, const uint64_t * b,
                        const uint64_t * mod);

/* returns borrow bit, 0 for no borrow or 1 for borrow */
extern int  wp_sub (int nbits, uint64_t * res,
                    const uint64_t * from, const uint64_t * sub);

extern void wp_sub_int (int nbits, uint64_t * from, int sub);

/* only works if a and b are already less than mod */
extern void wp_sub_mod (int nbits, uint64_t * res, 
                        const uint64_t * a, const uint64_t * b,
                        const uint64_t * mod);

/* rbits must be vbits * 2, and res must be twice the size of v1, v2 */
extern void wp_multiply (int rbits, uint64_t * res,
                         int vbits, const uint64_t * v1, const uint64_t * v2);

/* res cannot be the same as v1 or v2
 * only works if v1 and v2 are already less than mod */
extern void wp_multiply_mod (int nbits, uint64_t * res,
                             const uint64_t * v1, const uint64_t * v2,
                             const uint64_t * mod);

/* the numerator is nbits, and the denominator is dbits = nbits / 2.
 * after the division,
 * the numerator is replaced with the remainder (in the high dbits)
 * and the quotient (in the low dbits).
 * for convenience, q and r (if not null) are set to point to the
 * quotient and the remainder, both inside the numerator_result.
 * it is an error if (denominator <= (numerator >> dbits)) */
extern void wp_div (int nbits, uint64_t * numerator_result,
                    int dbits, const uint64_t * denominator,
                    uint64_t ** q, uint64_t ** r);

/* no argument should be the same pointer as any of the other arguments */
/* temp is a temporary array used internally and must have at least nbits */
extern void wp_exp_mod (int nbits, uint64_t * res, const uint64_t * base,
                        const uint64_t * exp, const uint64_t * mod,
                        uint64_t * temp);

/* same, except temp should have at least nbits * 65 */
extern void wp_exp_mod64 (int nbits, uint64_t * res, const uint64_t * base,
                          const uint64_t * exp, const uint64_t * mod,
                          uint64_t * temp);

/* same, except temp should have at least (nbits + 64) * 70 */
extern void wp_exp_mod_montgomery (int nbits, uint64_t * res,
                                   const uint64_t * base, const uint64_t * exp,
                                   const uint64_t * mod, uint64_t * temp);

#endif /* WES_ARITH_H */
