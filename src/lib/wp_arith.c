/* wp_arith.c: long integer arithmetic */
/* this library is named for W. Wesley Peterson, since this library is
 * loosely based on code he wrote before passing away in 2009 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>

#include "wp_arith.h"

/* #define DEBUG_PRINT_MONT */

static void my_assert (int value, char * desc)
{
  if (value)
    return;
  int zero_divisor = 0;
  printf ("assertion error: %s\n", desc);
  printf ("never printed: %d\n", 1 / zero_divisor);  /* cause core dump */
}

/* prints an integer in hex to a statically allocated string
 * since there is only one string, do not use twice in the same printf!!! */
char * wp_itox (int nbits, const uint64_t * n)
{
  static char result [20000];
  int size = sizeof (result);
  int nwords = NUM_WORDS (nbits);
  if (nbits / 4 + 1 > size) {
    printf ("wp_itox error: %d %d\n", nbits, size);
    my_assert (0, "sizeof result in wp_itox");
  }
  char * to = result;
  int i;
  for (i = 0; i < nwords; i++) {
    int b = snprintf (to, size, "%016" PRIx64, n [i]);
    size -= b;
    to += b;
  }
  return result;
}

/* copies source to destination */
void wp_copy (int nbits, uint64_t * dst, const uint64_t * src)
{
  memcpy (dst, src, nbits / 8);
}

void wp_init (int nbits, uint64_t * n, int value)
{
  if (value < 0) {
    printf ("wp_init error: %d (0x%x) < 0\n", value, value);
    my_assert (0, "value >= 0 in wp_init");
  }
  int nwords = NUM_WORDS (nbits);
  memset (n, 0, nbits / 8 - sizeof (uint64_t));
  n [nwords - 1] = value;
}

static void times_power2 (int nbits, uint64_t * n, int power2)
{
  int i;
  for (i = 0; i < power2; i++)
    wp_shift_left (nbits, n);
}

void wp_from_bytes (int nbits, uint64_t * n, int dsize, const char * data)
{
  int nbytes = nbits / 8;
  wp_init (nbits, n, 0);
  int i;
  for (i = 0; (i < nbytes) && (i < dsize); i++) {
    times_power2 (nbits, n, 8);
    wp_add_int (nbits, n, data [i] & 0xff);
  }
}

void wp_to_bytes (int nbits, const uint64_t * n, int dsize, char * data)
{
  int nbytes = nbits / 8;
  int i;
  for (i = 0; (i < nbytes) && (i < dsize); i++)
    data [i] = (n [i / 8] >> (56 - ((i % 8) * 8))) & 0xff;
}

void wp_from_hex (int nbits, uint64_t * n, int dsize, char * data)
{
  int nbytes = nbits / 8;
  wp_init (nbits, n, 0);
  int i;
  for (i = 0; (i < nbytes * 2) && (i < dsize); i++) {
    char single_digit [2];
    single_digit [0] = data [i];
    single_digit [1] = '\0';
    int value;
    sscanf (single_digit, "%x", &value);
    times_power2 (nbits, n, 4);
    wp_add_int (nbits, n, value);
  }
/* printf ("n from hex is %s / %d\n", wp_itox (nbits, n), nbits); */
}

/* only works if new_bits >= old_bits */
void wp_extend (int new_bits, uint64_t * new,
                int old_bits, const uint64_t * old)
{
  if ((new_bits <= 0) || (new_bits < old_bits) ||
      ((old_bits % 64) != 0) || ((new_bits % 64) != 0)) {
    printf ("wp_extend error: %d < %d\n", new_bits, old_bits);
    my_assert (0, "wp_extend");
  }
  int old_words = NUM_WORDS (old_bits);
  int new_words = NUM_WORDS (new_bits);
  int diff = new_words - old_words;
  memset (new, 0, diff * sizeof (uint64_t));
  memcpy (new + diff, old, old_bits / 8);
}

/* only works if new_bits <= old_bits and the first (old_bits - new_bits + 1)
 * bits are all 0s
 * returns 1 if successful, 0 otherwise. */
void wp_shrink (int new_bits, uint64_t * new,
                int old_bits, const uint64_t * old)
{
  if ((new_bits <= 0) || (new_bits >= old_bits) ||
      ((old_bits % 64) != 0) || ((new_bits % 64) != 0)) {
    printf ("wp_shrink error: %d < %d\n", new_bits, old_bits);
    my_assert (0, "wp_shrink");
  }
  int old_words = NUM_WORDS (old_bits);
  int new_words = NUM_WORDS (new_bits);
  /* check to make sure we only delete all 0s or all 1s*/
  int new_high = (old [old_words - new_words]) >> 63;
  uint64_t expected = 0;
  if (new_high)
    expected = expected - 1;  /* all 1s */
  int i;
  for (i = 0; i < old_words - new_words; i++) {
    if (old [i] != expected) {
      printf ("wp_shrink (%d %d %" PRIx64 " %016" PRIx64 " error: ",
              new_bits, old_bits, expected, old [old_words - new_words]);
      int j;
      for (j = 0; j < old_words; j++)
        printf ("%016" PRIx64 ", ", old [j]);
      printf (")\n");
      my_assert (0, "wp_shrink leading zeros or ones");
    }
  }
/*
*/
  memcpy (new, old + (old_words - new_words), new_bits / 8);
}

int wp_is_zero (int nbits, const uint64_t * n)
{
  int nwords = NUM_WORDS (nbits);
  int i;
  for (i = 0; i < nwords; i++) {
    if (n [i] != 0)
      return 0;
  }
  return 1;
}

int wp_is_even (int nbits, const uint64_t * n)
{
  int nwords = NUM_WORDS (nbits);
  return (1 - ((n [nwords - 1]) & 1));
}

int wp_compare (int nbits, const uint64_t * n1, const uint64_t * n2)
{
  int nwords = NUM_WORDS (nbits);
  int i;
  for (i = 0; i < nwords; i++) {
    if (n1 [i] < n2 [i])
      return -1;
    if (n1 [i] > n2 [i])
      return 1;
  }
  return 0;   /* they are the same */
}

int wp_get_byte (int nbits, const uint64_t * n, int byte_pos)
{
  int nwords = NUM_WORDS (nbits);
  int index = nwords - 1 - byte_pos / sizeof (uint64_t);
  if (index < 0)
    return -1;
  uint64_t value = n [index];
  int shift = (byte_pos % sizeof (uint64_t)) * 8;  /* bit positions to shift */
  return (value >> shift) & 0xff;
}

void wp_shift_left_unrolled (int nwords, uint64_t * n)
{
  int carry = 0;
  int i;
  for (i = nwords - 1; i >= 0; i -= 16) {
    uint64_t word = n [i]; n [i] = (word << 1) | carry; carry = word >> 63;
    word = n [i - 1]; n [i - 1] = (word << 1) | carry; carry = word >> 63;
    word = n [i - 2]; n [i - 2] = (word << 1) | carry; carry = word >> 63;
    word = n [i - 3]; n [i - 3] = (word << 1) | carry; carry = word >> 63;
    word = n [i - 4]; n [i - 4] = (word << 1) | carry; carry = word >> 63;
    word = n [i - 5]; n [i - 5] = (word << 1) | carry; carry = word >> 63;
    word = n [i - 6]; n [i - 6] = (word << 1) | carry; carry = word >> 63;
    word = n [i - 7]; n [i - 7] = (word << 1) | carry; carry = word >> 63;
    word = n [i - 8]; n [i - 8] = (word << 1) | carry; carry = word >> 63;
    word = n [i - 9]; n [i - 9] = (word << 1) | carry; carry = word >> 63;
    word = n [i - 10]; n [i - 10] = (word << 1) | carry; carry = word >> 63;
    word = n [i - 11]; n [i - 11] = (word << 1) | carry; carry = word >> 63;
    word = n [i - 12]; n [i - 12] = (word << 1) | carry; carry = word >> 63;
    word = n [i - 13]; n [i - 13] = (word << 1) | carry; carry = word >> 63;
    word = n [i - 14]; n [i - 14] = (word << 1) | carry; carry = word >> 63;
    word = n [i - 15]; n [i - 15] = (word << 1) | carry; carry = word >> 63;
  }
}

void wp_shift_left (int nbits, uint64_t * n)
{
  int nwords = NUM_WORDS (nbits);
  if (nwords % 16 == 0) {
    wp_shift_left_unrolled (nwords, n);
    return;
  }
  int carry = 0;
  int i;
  for (i = nwords - 1; i >= 0; i--) {
    uint64_t word = n [i];
    n [i] = (word << 1) | carry;
    carry = word >> 63;
  }
}

void wp_shift_left_mod (int nbits, uint64_t * n, const uint64_t * mod)
{
  int nwords = NUM_WORDS (nbits);
  uint64_t carry = 0;
  int i;
  for (i = nwords - 1; i >= 0; i--) {
    uint64_t word = n [i];
    n [i] = (word << 1) | carry;
    carry = word >> 63;
  }
  if ((carry) || wp_compare (nbits, n, mod) >= 0)
    wp_sub (nbits, n, n, mod);
}

void wp_shift_right (int nbits, uint64_t * n)
{
  int nwords = NUM_WORDS (nbits);
  uint64_t carry = 0;
  int i;
  for (i = 0; i < nwords; i++) {
    uint64_t word = n [i];
    n [i] = (word >> 1) | carry;
    carry = word << 63;
  }
}

static int wp_add_unrolled (int nwords, uint64_t * res,
                            const uint64_t * v1, const uint64_t * v2)
{
  int carry = 0;
  int i;
  for (i = nwords - 1; i >= 0; i -= 16) {
    uint64_t raw = v1 [i] + v2 [i]; res [i] = raw + carry;
    carry = ((raw < v2 [i    ]) || ((raw == MAX_WORD_VALUE) && (carry)));
    raw = v1 [i - 1] + v2 [i - 1]; res [i - 1] = raw + carry;
    carry = ((raw < v2 [i - 1]) || ((raw == MAX_WORD_VALUE) && (carry)));
    raw = v1 [i - 2] + v2 [i - 2]; res [i - 2] = raw + carry;
    carry = ((raw < v2 [i - 2]) || ((raw == MAX_WORD_VALUE) && (carry)));
    raw = v1 [i - 3] + v2 [i - 3]; res [i - 3] = raw + carry;
    carry = ((raw < v2 [i - 3]) || ((raw == MAX_WORD_VALUE) && (carry)));
    raw = v1 [i - 4] + v2 [i - 4]; res [i - 4] = raw + carry;
    carry = ((raw < v2 [i - 4]) || ((raw == MAX_WORD_VALUE) && (carry)));
    raw = v1 [i - 5] + v2 [i - 5]; res [i - 5] = raw + carry;
    carry = ((raw < v2 [i - 5]) || ((raw == MAX_WORD_VALUE) && (carry)));
    raw = v1 [i - 6] + v2 [i - 6]; res [i - 6] = raw + carry;
    carry = ((raw < v2 [i - 6]) || ((raw == MAX_WORD_VALUE) && (carry)));
    raw = v1 [i - 7] + v2 [i - 7]; res [i - 7] = raw + carry;
    carry = ((raw < v2 [i - 7]) || ((raw == MAX_WORD_VALUE) && (carry)));
    raw = v1 [i - 8] + v2 [i - 8]; res [i - 8] = raw + carry;
    carry = ((raw < v2 [i - 8]) || ((raw == MAX_WORD_VALUE) && (carry)));
    raw = v1 [i - 9] + v2 [i - 9]; res [i - 9] = raw + carry;
    carry = ((raw < v2 [i - 9]) || ((raw == MAX_WORD_VALUE) && (carry)));
    raw = v1 [i - 10] + v2 [i - 10]; res [i - 10] = raw + carry;
    carry = ((raw < v2 [i - 10]) || ((raw == MAX_WORD_VALUE) && (carry)));
    raw = v1 [i - 11] + v2 [i - 11]; res [i - 11] = raw + carry;
    carry = ((raw < v2 [i - 11]) || ((raw == MAX_WORD_VALUE) && (carry)));
    raw = v1 [i - 12] + v2 [i - 12]; res [i - 12] = raw + carry;
    carry = ((raw < v2 [i - 12]) || ((raw == MAX_WORD_VALUE) && (carry)));
    raw = v1 [i - 13] + v2 [i - 13]; res [i - 13] = raw + carry;
    carry = ((raw < v2 [i - 13]) || ((raw == MAX_WORD_VALUE) && (carry)));
    raw = v1 [i - 14] + v2 [i - 14]; res [i - 14] = raw + carry;
    carry = ((raw < v2 [i - 14]) || ((raw == MAX_WORD_VALUE) && (carry)));
    raw = v1 [i - 15] + v2 [i - 15]; res [i - 15] = raw + carry;
    carry = ((raw < v2 [i - 15]) || ((raw == MAX_WORD_VALUE) && (carry)));
  }
  return carry;
}

#ifdef TEST_AGAINST_OPENSSL_BIGNUMS
#include <openssl/bn.h>
static BIGNUM * make_bn (int nbits, const uint64_t * v)
{
  if (nbits > 4096) {  /* debugging only, up to 4096 */
    printf ("nbits %d > max 4096\n", nbits);
    exit (1);
  }
  static unsigned char bytes [512];
  int i;
  for (i = 0; i < NUM_WORDS (nbits); i++) {
    bytes [i * 8    ] = (v [i] >> 56) & 0xff;
    bytes [i * 8 + 1] = (v [i] >> 48) & 0xff;
    bytes [i * 8 + 2] = (v [i] >> 40) & 0xff;
    bytes [i * 8 + 3] = (v [i] >> 32) & 0xff;
    bytes [i * 8 + 4] = (v [i] >> 24) & 0xff;
    bytes [i * 8 + 5] = (v [i] >> 16) & 0xff;
    bytes [i * 8 + 6] = (v [i] >>  8) & 0xff;
    bytes [i * 8 + 7] = (v [i]      ) & 0xff;
  }
  return BN_bin2bn (bytes, nbits / 8, NULL);
}
static int same_bn (int nbits, const uint64_t * v, BIGNUM * bn)
{
  BIGNUM * bnv = make_bn (nbits, v);
  if (BN_cmp (bnv, bn) != 0) {
    printf ("%s != %s\n", wp_itox (nbits, v), BN_bn2hex (bn));
    return 0;
  }
  return 1;
}
#endif /* TEST_AGAINST_OPENSSL_BIGNUMS */

/* returns carry.  res, v1, and v2 may be the same */
int wp_add (int nbits, uint64_t * res,
            const uint64_t * v1, const uint64_t * v2)
{
#ifdef TEST_AGAINST_OPENSSL_BIGNUMS
BIGNUM * bnv1 = make_bn (nbits, v1);
BIGNUM * bnv2 = make_bn (nbits, v2);
BIGNUM * bnres = BN_new ();
BN_add (bnres, bnv1, bnv2);
#endif /* TEST_AGAINST_OPENSSL_BIGNUMS */
  int nwords = NUM_WORDS (nbits);
  if (nwords % 16 == 0)
    return wp_add_unrolled (nwords, res, v1, v2);
  int carry = 0;
  int i;
  for (i = nwords - 1; i >= 0; i--) {
    uint64_t raw = v1 [i] + v2 [i];
    /* if raw is less than either v1 [i] or v2 [i], we had a carry */
    int new_carry = ((raw < v2 [i]) || ((raw == MAX_WORD_VALUE) && (carry)));
    res [i] = raw + carry;
    carry = new_carry;
  }
#ifdef TEST_AGAINST_OPENSSL_BIGNUMS
if (carry) { BIGNUM * bnc = BN_new (); BN_one (bnc); 
BN_lshift (bnc, bnc, nbits); BN_sub (bnres, bnres, bnc); }
if (! same_bn (nbits, res, bnres)) { printf ("error in wp_add\n");
exit (1); }
#endif /* TEST_AGAINST_OPENSSL_BIGNUMS */
  return carry;
}

void wp_add_mod (int nbits, uint64_t * res,
                 const uint64_t * v1, const uint64_t * v2,
                 const uint64_t * mod)
{
#ifdef TEST_AGAINST_OPENSSL_BIGNUMS
BIGNUM * bnv1 = make_bn (nbits, v1);
BIGNUM * bnv2 = make_bn (nbits, v2);
BIGNUM * bnmod = make_bn (nbits, mod);
BIGNUM * bnres = BN_new ();
BN_CTX * ctx = BN_CTX_new ();
BN_mod_add (bnres, bnv1, bnv2, bnmod, ctx);
#endif /* TEST_AGAINST_OPENSSL_BIGNUMS */

/* printf ("add_mod: %s + ", wp_itox (nbits, v1));
printf ("%s %% ", wp_itox (nbits, v2));
printf ("%s => ", wp_itox (nbits, mod)); */
  int carry = wp_add (nbits, res, v1, v2);
/* printf (" i: %s\n", wp_itox (nbits, res));
if ((carry) || (wp_compare (nbits, res, mod) >= 0))
printf ("(c %d) ", carry); */
  if ((carry) || (wp_compare (nbits, res, mod) >= 0))
    wp_sub (nbits, res, res, mod);
/* printf (" f: %s\n", wp_itox (nbits, res)); */
#ifdef TEST_AGAINST_OPENSSL_BIGNUMS
if (! same_bn (nbits, res, bnres)) {
printf ("error in wp_add_mod, carry %d\n", carry);
exit (1); }
#endif /* TEST_AGAINST_OPENSSL_BIGNUMS */
}

void wp_add_int (int nbits, uint64_t * res, int value)
{
  int nwords = NUM_WORDS (nbits);
  res [nwords - 1] += + value;
  int carry = (res [nwords - 1] < value);
  int i;
  for (i = nwords - 2; (carry && (i >= 0)); i--) {
    res [i] = res [i] + carry;
    carry = (res [i] == 0);
  }
}

static int wp_sub_unrolled (int nwords, uint64_t * res,
                            const uint64_t * from, const uint64_t * sub)
{
  int borrow = 0;
  int i;
  for (i = nwords - 1; i >= 0; i -= 16) {
    uint64_t spb = sub [i] + borrow;   /* spb = sub plus borrow */
    borrow = (((spb == 0) && borrow) || (from [i    ] < spb));
    res [i    ] = from [i    ] - spb;
    spb = sub [i - 1] + borrow;
    borrow = (((spb == 0) && borrow) || (from [i - 1] < spb));
    res [i - 1] = from [i - 1] - spb;
    spb = sub [i - 2] + borrow;
    borrow = (((spb == 0) && borrow) || (from [i - 2] < spb));
    res [i - 2] = from [i - 2] - spb;
    spb = sub [i - 3] + borrow;
    borrow = (((spb == 0) && borrow) || (from [i - 3] < spb));
    res [i - 3] = from [i - 3] - spb;
    spb = sub [i - 4] + borrow;
    borrow = (((spb == 0) && borrow) || (from [i - 4] < spb));
    res [i - 4] = from [i - 4] - spb;
    spb = sub [i - 5] + borrow;
    borrow = (((spb == 0) && borrow) || (from [i - 5] < spb));
    res [i - 5] = from [i - 5] - spb;
    spb = sub [i - 6] + borrow;
    borrow = (((spb == 0) && borrow) || (from [i - 6] < spb));
    res [i - 6] = from [i - 6] - spb;
    spb = sub [i - 7] + borrow;
    borrow = (((spb == 0) && borrow) || (from [i - 7] < spb));
    res [i - 7] = from [i - 7] - spb;
    spb = sub [i - 8] + borrow;
    borrow = (((spb == 0) && borrow) || (from [i - 8] < spb));
    res [i - 8] = from [i - 8] - spb;
    spb = sub [i - 9] + borrow;
    borrow = (((spb == 0) && borrow) || (from [i - 9] < spb));
    res [i - 9] = from [i - 9] - spb;
    spb = sub [i - 10] + borrow;
    borrow = (((spb == 0) && borrow) || (from [i - 10] < spb));
    res [i - 10] = from [i - 10] - spb;
    spb = sub [i - 11] + borrow;
    borrow = (((spb == 0) && borrow) || (from [i - 11] < spb));
    res [i - 11] = from [i - 11] - spb;
    spb = sub [i - 12] + borrow;
    borrow = (((spb == 0) && borrow) || (from [i - 12] < spb));
    res [i - 12] = from [i - 12] - spb;
    spb = sub [i - 13] + borrow;
    borrow = (((spb == 0) && borrow) || (from [i - 13] < spb));
    res [i - 13] = from [i - 13] - spb;
    spb = sub [i - 14] + borrow;
    borrow = (((spb == 0) && borrow) || (from [i - 14] < spb));
    res [i - 14] = from [i - 14] - spb;
    spb = sub [i - 15] + borrow;
    borrow = (((spb == 0) && borrow) || (from [i - 15] < spb));
    res [i - 15] = from [i - 15] - spb;
    spb = sub [i - 1] + borrow;
  }
  return borrow;
}

/* returns borrow.  res, from, and sub may be the same */
int wp_sub (int nbits, uint64_t * res,
            const uint64_t * from, const uint64_t * sub)
{
  int nwords = NUM_WORDS (nbits);
  if (nwords % 16 == 0)
    return wp_sub_unrolled (nwords, res, from, sub);
  int borrow = 0;
  int i;
  for (i = nwords - 1; i >= 0; i--) {
    uint64_t sub_plus_borrow = sub [i] + borrow;
    borrow = (((sub_plus_borrow == 0) && borrow) ||
              (from [i] < sub_plus_borrow));
    res [i] = from [i] - sub_plus_borrow;
  }
  return borrow;
}

void wp_sub_int (int nbits, uint64_t * res, int sub)
{
  int nwords = NUM_WORDS (nbits);
  int borrow = (res [nwords - 1] < sub);
  res [nwords - 1] -= sub;
  int i;
  for (i = nwords - 2; ((borrow) && (i >= 0)); i--) {
    borrow = (res [i] == 0);
    res [i] -= 1;
  }
}

void wp_sub_mod (int nbits, uint64_t * res,
                 const uint64_t * from, const uint64_t * sub,
                 const uint64_t * mod)
{
  int borrow = wp_sub (nbits, res, from, sub);
  if (borrow)
    wp_add (nbits, res, res, mod);
}

/* multiply 0110 * 0101, 6 * 5 = 30 = 1e
   res = 0000 0110   always adding 0101 0000
     res even so res is 0000 0110 => 0000 0011     06 + 00 = 06 >> 03
     res odd  so res is 0101 0011 => 0010 1001     03 + 50 = 53 >> 29
     res odd  so res is 0111 1001 => 0011 1100     29 + 50 = 79 >> 3c
     res even so res is 0011 1100 => 0001 1110     3c + 00 = 3c >> 1e
 * multiply 1001 * 0111, 9 * 7 = 63 = 3f
   res = 0000 1001   always adding 0111 0000       0x70
     res odd  so res is xxxx xxxx => xxxx xxxx     09 + 70 = 79 >> 3c
     res even so res is xxxx xxxx => xxxx xxxx     3c + 00 = 3c >> 1e
     res even so res is xxxx xxxx => xxxx xxxx     1e + 00 = 1e >> 0f
     res odd  so res is xxxx xxxx => xxxx xxxx     0f + 70 = 7f >> 3f
 * multiply 1001 * 1101, 9 * 13 = 117 = 75
   res = 0000 1001   always adding 1101 0000       0xd0
     res odd  so res is xxxx xxxx => xxxx xxxx     09 + d0 = d9 >> 6c
     res even so res is xxxx xxxx => xxxx xxxx     6c + 00 = 6c >> 36
     res even so res is xxxx xxxx => xxxx xxxx     36 + 00 = 36 >> 1b
     res odd  so res is xxxx xxxx => xxxx xxxx     1b + d0 = eb >> 75
 * multiply 0001 * 0001, 1 * 1 = 1 = 1
   res = 0000 0001   always adding 0001 0000       0x10
     res odd  so res is xxxx xxxx => xxxx xxxx     01 + 10 = 11 >> 08
     res even so res is xxxx xxxx => xxxx xxxx     08 + 00 = 08 >> 04
     res even so res is xxxx xxxx => xxxx xxxx     04 + 00 = 04 >> 02
     res even so res is xxxx xxxx => xxxx xxxx     02 + 00 = 02 >> 01
 */
/* rbits must be vbits * 2, and res must be twice the size of v1, v2 */
void wp_multiply (int rbits, uint64_t * res,
                  int vbits, const uint64_t * v1, const uint64_t * v2)
{
  if (rbits != 2 * vbits) {
    printf ("wp_multiply %d %d error\n", rbits, vbits);
    my_assert (0, "wp_multiply");
  }
  int rwords = NUM_WORDS (rbits);
  int vwords = NUM_WORDS (vbits);
  int vbytes = vbits / 8;
  
  my_assert (rwords == 2 * vwords, "wp_multiply rwords != 2 * vwords");
  memset (res, 0, vbytes);
  memcpy (res + vwords, v1, vbytes);
  int i;
  for (i = 0; i < vbits; i++) {
    uint64_t carry = 0;
    if (! wp_is_even (rbits, res))  /* only add in the first vbits */
      carry = ((uint64_t) (wp_add (vbits, res, res, v2))) << 63;
    wp_shift_right (rbits, res);
    res [0] |= carry;
  }
}

static uint64_t add128 (uint64_t * res, uint64_t v, uint64_t carry)
{
  res [1] += v;
  if (res [1] < v)   /* carry into the higher digit */
    carry++;
  res [0] += carry;
  if (res [0] < carry)
    return 1;
  return 0;
}

static const uint64_t mask32 = 0xffffffff;

static void multiply128 (uint64_t * result_high, uint64_t * result_low,
                         uint64_t v1, uint64_t v2)
{
  uint64_t v1_low = v1 & mask32;
  uint64_t v1_high = (v1 >> 32) & mask32;
  uint64_t v2_low = v2 & mask32;
  uint64_t v2_high = (v2 >> 32) & mask32;
  
  uint64_t i1 = v1_low * v2_high + v1_high * v2_low;  /* intermediate value */
  uint64_t i_carry = (i1 < v1_high * v2_low);
  uint64_t i1_low = ((i1 & mask32) << 32);
  uint64_t i1_high = ((i1 >> 32) & mask32);
  uint64_t r1 = v1_low * v2_low + i1_low;
  int carry = (r1 < i1_low);
  uint64_t r2 = v1_high * v2_high + i1_high + (i_carry << 32) + carry;
/*
printf ("%" PRIX64 " * %" PRIX64 " = %" PRIX64 "%" PRIX64 "\n",
v1, v2, r2, r1);
*/
  *result_high = r2;
  *result_low = r1;
}

/* multiply a by b64 and add the result to r, putting the overflow into rhigh.
 * nbits is the number of bits in r and a */
static void add_multiply_int64 (int nbits, uint64_t * rhigh, uint64_t * r,
                                const uint64_t * a, uint64_t b64)
{
  int nwords = NUM_WORDS (nbits);
  int i;
  uint64_t high, low;
  multiply128 (&high, &low, a [nwords - 1], b64);
  r [nwords - 1] += low;
  if (r [nwords - 1] < low)  /* overflow */
    high++;
  for (i = nwords - 2; i >= 0; i--) {
    uint64_t new_high;
    multiply128 (&new_high, &low, a [i], b64);
    r [i] += low;
    if (r [i] < low)  /* carry into the next higher word */
      new_high++;
    /* add in the high part of the result from the previous iteration */
    r [i] += high;
    if (r [i] < high)  /* carry into the next higher word */
      new_high++;
    high = new_high;
  }
  *rhigh = high;
}

/* subtract es <concat> sub from er <concat> res, where es is the high
 * word of sub and er is the high word of res.
 * only subtract if er <concat> res >= es <concat> sub */
static void sub_conditional_extra (int nbits, uint64_t * erp, uint64_t * res,
                                   uint64_t es, const uint64_t * sub)
{
  uint64_t er = *erp;  /* local copy of *erp */
  if ((es > er) || ((es == er) && (wp_compare (nbits, sub, res) > 0))) 
    return;
  int borrow = wp_sub (nbits, res, res, sub);
  (*erp) = er - es - borrow;
}

/* initialize shifted with the shifted mods, of which the 64 high words are
 * in extra.
 * shifted must have room for NUM_WORDS (nbits) * 64 uint64_t's
 * extra must have room for 64 uint64_t's */
/* at the end of this call,
 * extra [0] <concatenated> shifted [0..numwords-1] has mod shifted 64 bits,
 * extra [1] <concatenated> shifted [numwords..numwords*2-1]  "  "  63 bits,
 * extra [2] <concatenated> shifted [numwords*2..numwords*3-1]"  "  62 bits,
 * and so on */
static void init_shifted (int nbits, uint64_t * shifted, uint64_t * extra,
                          const uint64_t * mod)
{
  int nwords = NUM_WORDS (nbits);
  int i;
  /* put mod << 1 into &(shifted [nwords * 63]) */
  int index = nwords * 63;
  uint64_t * old_shift = shifted + index;
  wp_copy (nbits, old_shift, mod);
  int carry = (old_shift [0] >> 63);
  wp_shift_left (nbits, old_shift);
  extra [63] = carry;
  for (i = 62; i >= 0; i--) {
    /* put (extra [i-1] <concatenated> old_shift) << 1 into
            extra [i  ] <concatenated> this_shift */
    uint64_t * this_shift = old_shift - nwords;
    wp_copy (nbits, this_shift, old_shift);
    carry = (this_shift [0] >> 63);
    wp_shift_left (nbits, this_shift);
    extra [i] = ((extra [i + 1]) << 1) + carry;
    old_shift = this_shift;
  }
}

static void mod64_extra_shifted (int nbits, uint64_t extra, uint64_t * n,
                                 const uint64_t * shifted,
                                 const uint64_t * sub_extra,
                                 const uint64_t * mod)
{
  int i;
  int nwords = NUM_WORDS (nbits);
  const uint64_t * this_sub = shifted;   /* what we are subtracting */
  for (i = 0; i < 64; i++) {
    sub_conditional_extra (nbits, &extra, n, sub_extra [i], this_sub);
    this_sub += nwords;
  }
  sub_conditional_extra (nbits, &extra, n, 0, mod);
}

static void shift_left64_mod (int nbits, uint64_t * n,
                              const uint64_t * shifted,
                              const uint64_t * sub_extra,
                              const uint64_t * mod)
{
  uint64_t high = n [0];
  int nwords = NUM_WORDS (nbits);
  int i;
  for (i = 0; i + 1 < nwords; i++)
    n [i] = n [i + 1];
  n [nwords - 1] = 0;
  mod64_extra_shifted (nbits, high, n, shifted, sub_extra, mod);
}

/* temp must have size NUM_WORDS (nbits) * 64, initialized by wp_exp_mod64 */
/* mod_extra must have size 64, likewise initiailized by wp_exp_mod64 */
static void wp_multiply_mod_temp_internal (int nbits, uint64_t * res,
                                           const uint64_t * v1,
                                           const uint64_t * v2,
                                           const uint64_t * mod,
                                           const uint64_t * temp,
                                           const uint64_t * mod_extra)
{
  wp_init (nbits, res, 0);
  int nwords = NUM_WORDS (nbits);
  uint64_t res_high;
  /* first loop does not need an initial shift */
  add_multiply_int64 (nbits, &res_high, res, v1, v2 [0]);
  mod64_extra_shifted (nbits, res_high, res, temp, mod_extra, mod);
  int i;
  for (i = 1; i < nwords; i++) {
    shift_left64_mod (nbits, res, temp, mod_extra, mod);
    add_multiply_int64 (nbits, &res_high, res, v1, v2 [i]);
    mod64_extra_shifted (nbits, res_high, res, temp, mod_extra, mod);
  }
}

static int is65537 (int nbits, const uint64_t * n)
{
  int nwords = NUM_WORDS (nbits);
  int i;
  for (i = 0; i + 1 < nwords; i++)
    if (n [i] != 0)
      return 0;
  if (n [nwords - 1] != 65537)
    return 0;
  return 1;
}

/* res, v1, and v2 can all be the same, as long as temp is different */
static void wp_multiply_mod_temp (int nbits, uint64_t * res,
                                  const uint64_t * v1, const uint64_t * v2,
                                  const uint64_t * mod, uint64_t * temp)
{
  wp_multiply_mod (nbits, temp, v1, v2, mod);
  wp_copy (nbits, res, temp);
}

/* no argument should be the same pointer as any of the other arguments */
/* temp is a temporary array used internally and must have at least nbits */
void wp_exp_mod_65537 (int nbits, uint64_t * res, const uint64_t * base,
                       const uint64_t * mod, uint64_t * temp)
{
  wp_multiply_mod_temp (nbits, res, base, base, mod, temp);
  wp_multiply_mod_temp (nbits, res, res, res, mod, temp);
  wp_multiply_mod_temp (nbits, res, res, res, mod, temp);
  wp_multiply_mod_temp (nbits, res, res, res, mod, temp);
  wp_multiply_mod_temp (nbits, res, res, res, mod, temp);
  wp_multiply_mod_temp (nbits, res, res, res, mod, temp);
  wp_multiply_mod_temp (nbits, res, res, res, mod, temp);
  wp_multiply_mod_temp (nbits, res, res, res, mod, temp);
  wp_multiply_mod_temp (nbits, res, res, res, mod, temp);
  wp_multiply_mod_temp (nbits, res, res, res, mod, temp);
  wp_multiply_mod_temp (nbits, res, res, res, mod, temp);
  wp_multiply_mod_temp (nbits, res, res, res, mod, temp);
  wp_multiply_mod_temp (nbits, res, res, res, mod, temp);
  wp_multiply_mod_temp (nbits, res, res, res, mod, temp);
  wp_multiply_mod_temp (nbits, res, res, res, mod, temp);
  wp_multiply_mod_temp (nbits, res, res, res, mod, temp);
  wp_multiply_mod_temp (nbits, res, res, base, mod, temp);
}

/* same as wp_exp_mod, but temp is a temporary array used internally
 * that must have at least 65 * nbits */
void wp_exp_mod64 (int nbits, uint64_t * res, const uint64_t * base,
                   const uint64_t * exp, const uint64_t * mod,
                   uint64_t * temp)
{
  if (is65537 (nbits, exp)) {
    wp_exp_mod_65537 (nbits, res, base, mod, temp);
    return;
  }
/*
*/
/*
printf ("wp_exp_mod64 (%s ^ ", wp_itox (nbits, base));
printf ("%s %% ", wp_itox (nbits, exp));
printf ("%s)\n", wp_itox (nbits, mod));
*/

  int nwords = NUM_WORDS (nbits);
  uint64_t mod_extra [64];
  init_shifted (nbits, temp, mod_extra, mod);
  uint64_t * square = temp + (nwords * 64);
  wp_init (nbits, res, 1);
  int outer;
  for (outer = 0; outer < nwords; outer++) {
    uint64_t inner = ((uint64_t) 1) << 63;
    uint64_t word = exp [outer];
    while (inner) {
      /* square = res * res % mod */
      wp_multiply_mod_temp_internal (nbits, square, res, res,
                                     mod, temp, mod_extra);
      /* conditionally (if bit is set) res = square * base % mod
                        otherwise, set res = square              */
      if (inner & word)
        wp_multiply_mod_temp_internal (nbits, res, square, base,
                                       mod, temp, mod_extra);
      else
        wp_copy (nbits, res, square);
      inner = inner >> 1;
    }
  }
/*
printf ("  => %s\n", wp_itox (nbits, res));
*/
}

/* res cannot be the same as v1 or v2 */
void wp_multiply_mod (int nbits, uint64_t * res,
                      const uint64_t * v1, const uint64_t * v2,
                      const uint64_t * mod)
{
  int nwords = NUM_WORDS (nbits);
#ifdef DEBUG_PRINT
  printf ("wp_multiply_mod (%s * ", wp_itox (nbits, v1));
  printf ("%s %% ", wp_itox (nbits, v2));
  printf ("%s)\n", wp_itox (nbits, mod));
#endif /* DEBUG_PRINT */
  wp_init (nbits, res, 0);
  int outer;
  for (outer = 0; outer < nwords; outer++) {
    uint64_t inner = ((uint64_t) 1) << 63;
    uint64_t word = v2 [outer];
    while (inner) {
      wp_shift_left_mod (nbits, res, mod);
      if (inner & word)
        wp_add_mod (nbits, res, res, v1, mod);
      inner = inner >> 1;
    }
  }
#ifdef DEBUG_PRINT
  printf ("  => %s\n", wp_itox (nbits, res));
#endif /* DEBUG_PRINT */
}

/* the numerator is nbits, and the denominator is dbits = nbits / 2.
 * after the division,
 * the numerator is replaced with the remainder (in the high dbits)
 * and the quotient (in the low dbits).
 * for convenience, q and r (if not null) are set to point to the
 * quotient and the remainder, both inside the numerator_result.
 * it is an error if (denominator <= (numerator >> dbits)) */
void wp_div (int nbits, uint64_t * numerator_result,
             int dbits, const uint64_t * denominator,
             uint64_t ** q, uint64_t ** r)
{
  if (wp_compare (dbits, numerator_result, denominator) >= 0) {
    printf ("wp_div (%s/%d >= ", wp_itox (dbits, numerator_result), nbits);
    printf ("%s/%d)\n", wp_itox (dbits, denominator), dbits);
  }
  my_assert (wp_compare (dbits, numerator_result, denominator) < 0,
             "wp_div numerator >> dbits must be < denominator");
  int nwords = NUM_WORDS (nbits);
  int dwords = NUM_WORDS (dbits);
  if (q != NULL)
    *q = numerator_result + dwords;
  if (r != NULL)
    *r = numerator_result;
  int i;
/* printf ("denominator %s\n", wp_itox (dbits, denominator)); */
  for (i = 0; i < dbits; i++) {
    uint64_t carry = (numerator_result [0]) >> 63;
    wp_shift_left (nbits, numerator_result);
/* printf ("bit %d, numerator_result %s\n", i,
           wp_itox (nbits, numerator_result)); */
    if (carry || (wp_compare (dbits, numerator_result, denominator) >= 0)) {
/* printf ("bit %d/%d, carry %" PRIx64 ", compare %d\n", i, dbits, carry,
           wp_compare (dbits, numerator_result, denominator)); */
      wp_sub (dbits, numerator_result, numerator_result, denominator);
      numerator_result [nwords - 1] |= 1;   /* set the bit in the quotient */
    }
  }
}

/* returns 1 if n is a multiple of possible_factor, 0 otherwise */
/* for every 32 bits of n (call it nx), computes m = (m<<32 | nx) % mod
 * the final result, in m, is the modulo.  If it is zero, mod divides n */
int wp_multiple_of_int (int nbits, const uint64_t * n, uint32_t mod)
{
  int nwords = NUM_WORDS (nbits);
  uint64_t word = 0;
  int i;
  for (i = 0; i < nwords; i++) {
    word = (word << 32) | ((n [i] >> 32) & 0xffffffff);
    word = word % mod;   /* this should clear the top 32 bits of word */
    word = (word << 32) | (n [i] & 0xffffffff);
    word = word % mod;   /* this should clear the top 32 bits of word */
  }
  /* word has n % mod */
  return (word == 0);
}

/* no argument should be the same pointer as any of the other arguments */
/* temp is a temporary array used internally and must have at least nbits */
void wp_exp_mod (int nbits, uint64_t * res, const uint64_t * base,
                 const uint64_t * exp, const uint64_t * mod,
                 uint64_t * temp)
{
  if (is65537 (nbits, exp)) {
    wp_exp_mod_65537 (nbits, res, base, mod, temp);
    return;
  }
/*
printf ("wp_exp_mod (%s ^ ", wp_itox (nbits, base));
printf ("%s %% ", wp_itox (nbits, exp));
printf ("%s)\n", wp_itox (nbits, mod));
*/

  int nwords = NUM_WORDS (nbits);
  wp_init (nbits, res, 1);
  int outer;
  for (outer = 0; outer < nwords; outer++) {
    uint64_t inner = ((uint64_t) 1) << 63;
    uint64_t word = exp [outer];
    while (inner) {
      wp_multiply_mod (nbits, temp, res, res, mod);  /* square res % mod */
      if (inner & word)
        wp_multiply_mod (nbits, res, base, temp, mod); /*   * base % mod */
      else
        wp_copy (nbits, res, temp);
      inner = inner >> 1;
    }
  }
  /* printf ("  => %s\n", wp_itox (nbits, res)); */
}

/* sources for the montgomery exponentiation:
   http://en.wikipedia.org/wiki/Montgomery_reduction
   http://www.nugae.com/encryption/fap4/montgomery.htm
 */

static void init_shifted_montgomery (int nbits_plus, uint64_t * shifted,
                                     int nbits, const uint64_t * mod)
{
  int nwords = NUM_WORDS (nbits);
  int nwords_plus = NUM_WORDS (nbits_plus);
  memset (shifted, 0, nwords_plus * sizeof (uint64_t));
  memcpy (shifted + 1, mod, nwords * sizeof (uint64_t));
  size_t size = nwords_plus * sizeof (uint64_t);
  uint64_t * prev = shifted;
  int i;
  for (i = 1; i < 64; i++) {
    uint64_t * this = prev + nwords_plus;
    memcpy (this, prev, size);
    wp_shift_left (nbits_plus, this);
    prev = this;
  }
/*
for (i = 0; i < 64; i++)
printf ("shifted [%d] is %s/%p\n", i,
wp_itox (nbits_plus, shifted + nwords_plus * i), shifted + nwords_plus * i);
*/
}

/* r is 2^nbits.  res, mod, and temp[12] are nbits */
static void compute_r_squared (int nbits, uint64_t * res, const uint64_t * mod,
                               uint64_t * temp1, uint64_t * temp2)
{
#ifdef DEBUG_PRINT_MONT
  printf ("computing r squared, mod %s\n", wp_itox (nbits, mod));
#endif /* DEBUG_PRINT_MONT */
  wp_init (nbits, temp1, 0);
  wp_sub (nbits, temp1, temp1, mod);  /* temp1 = 2^nbits - mod */
  wp_copy (nbits, temp2, mod);
  while (((temp2 [0] >> 63) != 1) && (wp_compare (nbits, temp1, temp2) > 0))
    wp_shift_left (nbits, temp2);
#ifdef DEBUG_PRINT_MONT
  printf ("shifted temp2 is %s\n", wp_itox (nbits, temp2));
  printf ("temp1 is %s\n", wp_itox (nbits, temp1));
#endif /* DEBUG_PRINT_MONT */
  /* now subtract temp2 as many times as needed to get temp1
   * to be less than mod.  After each subtraction, shift temp2 to the right */
  while (wp_compare (nbits, temp1, mod) >= 0) {
    if (wp_compare (nbits, temp1, temp2) >= 0)
      wp_sub (nbits, temp1, temp1, temp2);
    wp_shift_right (nbits, temp2);
#ifdef DEBUG_PRINT_MONT
    printf ("subtracted temp1 is %s\n", wp_itox (nbits, temp1));
    printf ("   shifted temp2 is %s\n", wp_itox (nbits, temp2));
#endif /* DEBUG_PRINT_MONT */
  }
  /* now temp1 holds r modulo mod, compute r^2 modulo mod */
  wp_multiply_mod (nbits, res, temp1, temp1, mod);
#ifdef DEBUG_PRINT_MONT
  printf ("r^2 is %s ", wp_itox (nbits, res));
  printf ("modulo %s\n", wp_itox (nbits, mod));
#endif /* DEBUG_PRINT_MONT */
}

/* res = res + a * b, where a is nwords_a and b a single uint64_t */
/* res has one more uint64_t than a. */
static void multiply64_add (int nwords_res, uint64_t * res,
                            int nwords_a, const uint64_t * a, uint64_t b)
{
#ifdef CHECK_AGAINST_PLAIN_OLD_OPS
  uint64_t * old = malloc (nwords_res * 8 * 8);  /* plenty of space, 5 used */
  uint64_t * b_ext = old + nwords_res;
  uint64_t * prod = b_ext + nwords_res;
  uint64_t * prod_half = prod + nwords_a;  /* less significant half of prod */
  uint64_t * prod_half_min1 = prod_half - 1;
  uint64_t * sum = prod + nwords_res + nwords_res;  /* prod is double-sized */
  memcpy (old, res, nwords_res * 8);
  int nbits = nwords_a * 64;
  wp_init (nbits, b_ext, 0);
  b_ext [nwords_a - 1] = b;
  wp_copy (nbits + 64, sum, res);
  if (sum [0] != 0) printf ("sum [0] is %" PRIx64 "\n", sum [0]);
  wp_multiply (nbits + nbits, prod, nbits, a, b_ext);
  wp_add (nbits + 64, sum, sum, prod_half_min1);
  /* wp_copy (nbits + 64, res, sum);  return; -- this is correct */
#endif /* CHECK_AGAINST_PLAIN_OLD_OPS */
        
  my_assert ((nwords_a + 1) == nwords_res, "multiply64_add");
  uint64_t high, low;
  uint64_t carry = 0;
  int i;
  for (i = nwords_a - 1; i >= 0; i--) {
    multiply128 (&high, &low, a [i], b);
    carry = add128 (res + i, low, carry + high);
  }
  if (carry != 0) {
    printf ("multiply64_add (%d, %s, ", nwords_res * 64,
            wp_itox (nwords_res * 64, res));
    printf ("%s, %" PRIx64 ")\n", wp_itox (nwords_a * 64, a), b);
    printf ("unexpected (please check), carry is %" PRIx64 "\n", carry);
    exit (1);
  }
  res [0] += carry;
  /* ignore the most significant carry, if any */
#ifdef DEBUG_PRINT_MONT
  if (res [0] < carry) {  /* overflow from adding carry */
    printf ("multiply64_add (%s (final) ", wp_itox (nwords_res * 64, res));
    printf ("+= %s * %016" PRIx64 "), carry %" PRIx64 ", res [0] %" PRIx64 "\n",
            wp_itox (nwords_a * 64, a), b, carry, res [0]);
exit (1);   /* not happened yet */
  }
#endif /* DEBUG_PRINT_MONT */
#ifdef CHECK_AGAINST_PLAIN_OLD_OPS
  if (wp_compare (nbits + 64, res, sum) != 0) {
    printf ("found error: %s != ", wp_itox (nwords_res * 64, res));
    printf ("%s, carry %" PRIx64 "\n", wp_itox (nbits + 64, sum), carry);
    exit (1);
  }
  free (old);
#endif /* CHECK_AGAINST_PLAIN_OLD_OPS */
}

/* the shifted mod is added or not to make 0 the low word of res
 * each unit of shifted_mod is nwords, as is res */
static void add_multiple_to_make_low_word_zero (int nwords, uint64_t * res,
                                                const uint64_t * shifted_mod)
{
#ifdef DEBUG_PRINT_MONT
  printf ("initial result %s, %d words\n", wp_itox (nwords * 64, res), nwords);
#endif /* DEBUG_PRINT_MONT */
  uint64_t i = 0;
  uint64_t carry = 0;
  for (i = 0; i < 64; i++) {
    if ((((uint64_t) 1) << i) & (res [nwords - 1])) {
uint64_t copy;
copy = res [nwords - 1];
      /* add the i-th temp to res */
      carry += wp_add (nwords * 64, res, res, shifted_mod + (i * nwords));
      /* if there is a carry, should subtract mod until fits -- but cannot
         without changing the invariant that bit i is now 0.  so instead,
         accumulate carries, and do the mod below */
if ((((uint64_t) 1) << i) & (res [nwords - 1])) {
printf ("error: bit %" PRId64 " not cleared from %" PRIx64 "\n",
        i, res [nwords - 1]);
printf ("original %" PRIx64 " + %" PRIx64 " = %" PRIx64 "\n",
        copy, (shifted_mod + (i * nwords)) [nwords - 1], res [nwords - 1]);
printf ("added %s\n", wp_itox (nwords * 64, shifted_mod + (i * nwords)));
exit (1);
}
      my_assert (((((uint64_t) 1) << i) & (res [nwords - 1])) == 0, "cleared");
#ifdef DEBUG_PRINT_MONT
      printf (" result %s\n", wp_itox (nwords * 64, res));
#endif /* DEBUG_PRINT_MONT */
    }
  }
/* here subtract until carry is zero and res < mod (mod is shifted_mod + 1) */
  int nbits_minus = (nwords - 1) * 64;
  while ((carry > 0) ||
         (wp_compare (nbits_minus, res, shifted_mod + 1) >= 0))
    carry -= wp_sub (nbits_minus, res, res, shifted_mod + 1);
}

static void shift_right_64 (int nwords, uint64_t * value)
{
  int i = 0;
  for (i = nwords - 1; i > 0; i--)
    value [i] = value [i - 1];
  value [0] = 0;
}

/* res = a * b / 2^nbits % mod.  a, b, and mod are different from res,
 * a, b, and mod are nbits long, res is nbits+64. shifted_mod has
 * 64 successive locations each nbits+64 long */
static void montgomery_step (int nbits, uint64_t * res,
                             const uint64_t * a, const uint64_t * b,
                             const uint64_t * shifted_mod)
{
  int nlong = nbits + 64;
  wp_init (nlong, res, 0);
  int nwords = NUM_WORDS (nbits);
  int nwords_plus = nwords + 1;
#ifdef DEBUG_PRINT_MONT
  printf ("montgomery_step (%s * ", wp_itox (nbits, a));
  printf ("%s ", wp_itox (nbits, b));
  printf ("%% %s)\n", wp_itox (nbits, shifted_mod + 1));
#endif /* DEBUG_PRINT_MONT */
#ifdef DEBUG_PRINT
#endif /* DEBUG_PRINT */
  int w;
  for (w = nwords - 1; w >= 0; w--) {
    multiply64_add (nwords_plus, res, nwords, a, b [w]);
#ifdef DEBUG_PRINT_MONT
    printf ("a %s * b [%d] ", wp_itox (nwords * 64, a), w);
    printf ("%016" PRIx64 " = %s\n", b [w], wp_itox (nwords_plus * 64, res));
#endif /* DEBUG_PRINT_MONT */
    add_multiple_to_make_low_word_zero (nwords_plus, res, shifted_mod);
    my_assert ((res [nwords_plus - 1] == 0), "low word zero before shift");
    shift_right_64 (nwords_plus, res);
  }
#ifdef DEBUG_PRINT_MONT
  printf ("   ==> %s\n", wp_itox (nbits, res + 1));
#endif /* DEBUG_PRINT_MONT */
}

#ifdef OPTIMIZATION_GIVES_NO_SPEEDUP
/* no argument should be the same pointer as any of the other arguments */
/* temp is a temporary array used internally and must have at least nbits */
void wp_exp_mod_montgomery_65537 (int nbits, uint64_t * res,
                                  const uint64_t * base,
                                  const uint64_t * shifted_mod,
                                  uint64_t * temp)
{
  montgomery_step (nbits, res,  base + 1, base + 1, shifted_mod); /*^2*/
  montgomery_step (nbits, temp, res + 1,  res + 1,  shifted_mod); /*^4 */
  montgomery_step (nbits, res,  temp + 1, temp + 1, shifted_mod); /*^8 */
  montgomery_step (nbits, temp, res + 1,  res + 1,  shifted_mod); /*^16 */

  montgomery_step (nbits, res,  temp + 1, temp + 1, shifted_mod); /*^32 */
  montgomery_step (nbits, temp, res + 1,  res + 1,  shifted_mod); /*^64 */
  montgomery_step (nbits, res,  temp + 1, temp + 1, shifted_mod); /*^128 */
  montgomery_step (nbits, temp, res + 1,  res + 1,  shifted_mod); /*^256 */

  montgomery_step (nbits, res,  temp + 1, temp + 1, shifted_mod); /*^512 */
  montgomery_step (nbits, temp, res + 1,  res + 1,  shifted_mod); /*^1024*/
  montgomery_step (nbits, res,  temp + 1, temp + 1, shifted_mod); /*^2048*/
  montgomery_step (nbits, temp, res + 1,  res + 1,  shifted_mod); /*^4096*/

  montgomery_step (nbits, res,  temp + 1, temp + 1, shifted_mod); /*^8192*/
  montgomery_step (nbits, temp, res + 1,  res + 1,  shifted_mod); /*^16384*/
  montgomery_step (nbits, res,  temp + 1, temp + 1, shifted_mod); /*^32768*/
  montgomery_step (nbits, temp, res + 1,  res + 1,  shifted_mod); /*^65536*/
  montgomery_step (nbits, res,  temp + 1, base + 1, shifted_mod); /*^65537*/
}
#endif /* OPTIMIZATION_GIVES_NO_SPEEDUP */

/* largely based on http://en.wikipedia.org/wiki/Montgomery_reduction */
/* R is 2^nbits */
/* temp must have at least 70 * (nbits + 64) */
void wp_exp_mod_montgomery (int nbits, uint64_t * res, const uint64_t * base,
                            const uint64_t * exp, const uint64_t * mod,
                            uint64_t * temp)
{
  if (wp_is_even (nbits, mod)) { /* mod divides R, so cannot use montgomery */
    printf ("wp_exp_mod_montgomery warning: even modulo %s\n",
            wp_itox (nbits, mod));
    wp_exp_mod (nbits, res, base, exp, mod, temp);
  }
#ifdef DEBUG_PRINT_MONT
  printf ("wp_exp_mod_montgomery (%d, %s ^ ", nbits, wp_itox (nbits, base));
  printf ("%s %% ", wp_itox (nbits, exp));
  printf ("%s)\n", wp_itox (nbits, mod));
#endif /* DEBUG_PRINT_MONT */
  int nwords = NUM_WORDS (nbits);
  int nwords_plus = nwords + 1;
  int nbits_plus = nbits + 64;
  uint64_t * mres = temp;
  uint64_t * mtemp = temp + nwords_plus * 1;
  /* r_squared and one only need nwords, but simpler to have them nwords_plus */
  uint64_t * r_squared = temp + nwords_plus * 2;
  compute_r_squared (nbits, r_squared, mod, mres, mtemp);
  uint64_t * one = temp + nwords_plus * 3;
  wp_init (nbits, one, 1);
  uint64_t * mbase = temp + nwords_plus * 4;
  uint64_t * shifted_mod = temp + nwords_plus * 5;
  init_shifted_montgomery (nbits_plus, shifted_mod, nbits, mod);
  /* convert base to montgomery form by multiplying by r^2 */
  montgomery_step (nbits, mbase, base, r_squared, shifted_mod);
  wp_init (nbits_plus, mres, 0);
#ifdef DEBUG_PRINT_MONT
  printf ("base %s is ", wp_itox (nbits, base));
  printf ("%s\n", wp_itox (nbits_plus, mbase));
#endif /* DEBUG_PRINT_MONT */
#ifdef OPTIMIZATION_GIVES_NO_SPEEDUP
  if (is65537 (nbits, exp)) {
    wp_exp_mod_montgomery_65537 (nbits, mres, mbase, shifted_mod, mtemp);
  } else {   /* do it bit by bit, skipping any high-order zero words */
#endif /* OPTIMIZATION_GIVES_NO_SPEEDUP */
    int outer;
    for (outer = 0; outer < nwords; outer++) {
      if (! ((exp [outer] == 0) && (wp_is_zero (nbits_plus, mres)))) {
/* done with zero high part of exp, so maybe (square and maybe multiply) */
        uint64_t inner = ((uint64_t) 1) << 63;
        uint64_t word = exp [outer];
        while (inner) {
          if (! wp_is_zero (nbits_plus, mres)) {
            /* square res modulo mod*/
            montgomery_step (nbits, mtemp, mres + 1, mres + 1, shifted_mod);
            if (inner & word) /* multiply by base modulo mod */
              montgomery_step (nbits, mres, mtemp + 1, mbase + 1, shifted_mod);
            else
              wp_copy (nbits_plus, mres, mtemp);
          } else {   /* high bit not found yet, test for it now. */
            if (inner & word)   /* res = base (montgomery form) */
              wp_copy (nbits_plus, mres, mbase);
          }
          inner = inner >> 1;
        }
      }
    }
#ifdef OPTIMIZATION_GIVES_NO_SPEEDUP
  }
#endif /* OPTIMIZATION_GIVES_NO_SPEEDUP */
  wp_init (nbits, one, 1);
  montgomery_step (nbits, mtemp, mres + 1, one, shifted_mod);
  wp_copy (nbits, res, mtemp + 1);
#ifdef DEBUG_PRINT_MONT
  printf ("  => %s\n", wp_itox (nbits, res));
#endif /* DEBUG_PRINT_MONT */
}

#ifdef UNIT_TEST

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>

#define get_start_time()  struct timeval start; gettimeofday (&start, NULL)
#define print_time(loops, desc, nbits)  \
{ struct timeval finish; gettimeofday (&finish, NULL);	\
  uint64_t delta = ((uint64_t) (finish.tv_sec - start.tv_sec)) * 1000000 +  \
                   ((uint64_t) (finish.tv_usec - start.tv_usec));  \
  int us = delta % 1000000;  \
  printf ("  %d loop(s) took %" PRId64 ".%06d seconds, %d us/%s (%d bits)\n", \
          loops, delta / 1000000, us, ((int) (delta / loops)), desc, nbits); }

static void my_init (int nbits, uint64_t * n, uint64_t value)
{
  int nwords = NUM_WORDS (nbits);
  memset (n, 0, nbits / 8 - sizeof (uint64_t));
  n [nwords - 1] = value;
}

/* pseudo-random init */
static void my_pr_init (int nbits, uint64_t * n, uint64_t v1, uint64_t v2,
                        uint64_t v3, uint64_t v4)
{
  int nwords = NUM_WORDS (nbits);
  int i;
  for (i = 0; i < nwords; i++) {
    n [i] = 0;
    switch (i % 17) {
    case 0: n [i] = v1 ^ v2 ^ v3 ^ v4 ^ i;
    case 1: n [i] = v2 ^ v3 ^ v4 ^ i;
    case 2: n [i] = v1 ^ v3 ^ v4 ^ i;
    case 3: n [i] = v1 ^ v2 ^ v4 ^ i;
    case 4: n [i] = v1 ^ v2 ^ v3 ^ i;
    case 5: n [i] = v1 ^ v2 ^ i;
    case 6: n [i] = v1 ^ v3 ^ i;
    case 7: n [i] = v1 ^ v4 ^ i;
    case 8: n [i] = v2 ^ v3 ^ i;
    case 10: n [i] = v2 ^ v4 ^ i;
    case 11: n [i] = v3 ^ v4 ^ i;
    case 12: n [i] = v1 ^ i;
    case 13: n [i] = v2 ^ i;
    case 14: n [i] = v3 ^ i;
    case 15: n [i] = v4 ^ i;
    case 16: n [i] = v1 ^ v2 ^ v3 ^ v4;
    }
  }
}

static uint64_t next_i_value (uint64_t i, int inner)
{
  if (i < 5)               return i + 1;
  else if (inner == 2)     return i * 3 + 17;
  else if (inner == 1)     return i * 5 + 13;
  else                     return i * 7 + 11;
}

static uint64_t next_i_value_special (uint64_t i, int inner,
                                      uint64_t max, uint64_t special)
{
  uint64_t possible_next = next_i_value (i, inner);
  if (possible_next >= max) return special;
  return possible_next;
}

static int testb (char * desc, int (*under_test) (int, const uint64_t *),
                  int (*equiv) (uint64_t))
{
  get_start_time ();
  int test_value = 1;
  int total = 0;
  int correct = 0;
  int incorrect = 0;
  uint64_t max = 1LL << 60;
  uint64_t i1 = 0;
  int nbits = 64;
  while (i1 < max) {
    uint64_t v [1];
    my_init (nbits, v, i1);
    int uresult = under_test (nbits, v);
    int eresult = equiv (i1);
    if (uresult != eresult) {
      printf ("error: %s (%016" PRIx64 ")/%d, expected %d, got %d\n",
              desc, i1, nbits, eresult, uresult);
      test_value = 0;
      incorrect++;
    } else {
#ifdef DEBUG_PRINT
      printf ("correct: %s (%016" PRIx64 ")/%d, expected %d, got %d\n",
              desc, i1, nbits, uresult, eresult);
#endif /* DEBUG_PRINT */
      correct++;
    }
    total++;
    /* update i1 */
    i1 = next_i_value (i1, 0);
  }
  printf ("test %s: %d total, %d correct, %d not correct, returning %d\n",
          desc, total, correct, incorrect, test_value);
  print_time(total, desc, nbits);
  return test_value;
}

static int test_is_zero (uint64_t v)
{
  return (v == 0);
}

static int test_is_even (uint64_t v)
{
  return ((v & 1) == 0);
}

static int testb2 (char * desc,
                   int (*under_test) (int, const uint64_t *, const uint64_t *),
                   int (*equiv) (uint64_t, uint64_t))
{
  get_start_time ();
  int test_value = 1;
  int total = 0;
  int correct = 0;
  int incorrect = 0;
  uint64_t max = 1LL << 60;
  int nbits = 64;
  uint64_t i1 = 0;
  while (i1 < max) {
    uint64_t i2 = 0;
    while (i2 < max) {
      uint64_t v1 [1];
      uint64_t v2 [1];
      my_init (nbits, v1, i1);
      my_init (nbits, v2, i2);
      int uresult = under_test (nbits, v1, v2);
      int eresult = equiv (i1, i2);
      if (uresult != eresult) {
        printf ("error: %s (%016" PRIx64 ", %016" PRIx64 ")/%d, e %d, got %d\n",
                desc, i1, i2, nbits, eresult, uresult);
        test_value = 0;
        incorrect++;
      } else {
#ifdef DEBUG_PRINT
        printf ("correct: %s (%016" PRIx64 ", %016" PRIx64 ")/%d, e %d, got %d\n",
                desc, i1, i2, nbits, uresult, eresult);
#endif /* DEBUG_PRINT */
        correct++;
      }
      total++;
      /* update i2 */
      i2 = next_i_value (i2, 1);
    }
    /* update i1 */
    i1 = next_i_value (i1, 0);
  }
  printf ("test %s: %d total, %d correct, %d not correct, returning %d\n",
          desc, total, correct, incorrect, test_value);
  print_time (total, desc, nbits);
  return test_value;
}

static int test_compare (uint64_t v1, uint64_t v2)
{
  if (v1 > v2)
    return 1;
  if (v1 < v2)
    return -1;
  return 0;
}

static int test1 (char * desc, void (*under_test) (int, uint64_t *),
                  uint64_t (*equiv) (uint64_t))
{
  get_start_time ();
  int test_value = 1;
  int total = 0;
  int correct = 0;
  int incorrect = 0;
  uint64_t max = 1LL << 60;
  int nbits = 64;
  uint64_t i1 = 0;
  while (i1 < max) {
    uint64_t v1 [1];
    my_init (nbits, v1, i1);
    under_test (nbits, v1);
    char result [1000];
    snprintf (result, sizeof (result), "%016" PRIx64, equiv (i1));
    if (strcmp (result, wp_itox (nbits, v1)) != 0) {
      printf ("error: %s (%016" PRIx64 ")/%d, expected %s, got %s\n",
              desc, i1, nbits, result, wp_itox (nbits, v1));
      test_value = 0;
      incorrect++;
    } else {
#ifdef DEBUG_PRINT
      printf ("correct: %s (%016" PRIx64 ")/%d, expected %s, got %s\n",
              desc, i1, nbits, result, wp_itox (nbits, v1));
#endif /* DEBUG_PRINT */
      correct++;
    }
    total++;
    /* update i1 */
    i1 = next_i_value (i1, 0);
  }
  printf ("test %s: %d total, %d correct, %d not correct, returning %d\n",
          desc, total, correct, incorrect, test_value);
  print_time (total, desc, nbits);
  return test_value;
}

static uint64_t test_shift_left (uint64_t v1)
{
  return (v1 << 1);
}

static uint64_t test_shift_right (uint64_t v)
{
  return (v >> 1);
}

static int test2 (char * desc,
                  void (*under_test) (int, uint64_t *, const uint64_t *),
                  uint64_t (*equiv) (uint64_t, uint64_t))
{
  get_start_time ();
  int test_value = 1;
  int total = 0;
  int correct = 0;
  int incorrect = 0;
  uint64_t max = 1LL << 60;
  int nbits = 64;
  uint64_t i1 = 0;
  while (i1 < max) {
    uint64_t i2 = 0;
    while (i2 < max) {
      uint64_t v1 [1];
      uint64_t v2 [1];
      my_init (nbits, v1, i1);
      my_init (nbits, v2, i2);
      under_test (nbits, v1, v2);
      char result [1000];
      snprintf (result, sizeof (result), "%016" PRIx64, equiv (i1, i2));
      if (strcmp (result, wp_itox (nbits, v1)) != 0) {
        printf ("error: %s (%016" PRIx64 ", %016" PRIx64 ")/%d, e %s, got %s\n",
                desc, i1, i2, nbits, result, wp_itox (nbits, v1));
        test_value = 0;
        incorrect++;
      } else {
#ifdef DEBUG_PRINT
        printf ("correct: %s (%016" PRIx64 ", %016" PRIx64 ")/%d, e %s, got %s\n",
                desc, i1, i2, nbits, result, wp_itox (nbits, v1));
#endif /* DEBUG_PRINT */
        correct++;
      }
      total++;
      /* update i2 */
      i2 = next_i_value (i2, 1);
    }
    /* update i1 */
    i1 = next_i_value (i1, 0);
  }
  printf ("test %s: %d total, %d correct, %d not correct, returning %d\n",
          desc, total, correct, incorrect, test_value);
  print_time (total, desc, nbits);
  return test_value;
}

static uint64_t test_copy (uint64_t dest, uint64_t source)
{
  return source;
}

static int test3 (char * desc,
                  int (*under_test) (int, uint64_t *,
                                     const uint64_t *, const uint64_t *),
                  uint64_t (*equiv) (uint64_t, uint64_t))
{
  get_start_time ();
  int test_value = 1;
  int total = 0;
  int correct = 0;
  int incorrect = 0;
  uint64_t max = 1LL << 60;
  int nbits = 64;
  uint64_t i1 = 0;
  while (i1 < max) {
    uint64_t i2 = 0;
    while (i2 < max) {
      uint64_t v1 [1];
      uint64_t v2 [1];
      uint64_t v3 [1];
      my_init (nbits, v1, i1);
      my_init (nbits, v2, i2);
      under_test (nbits, v3, v1, v2);
      char result [1000];
      snprintf (result, sizeof (result), "%016" PRIx64, equiv (i1, i2));
      if (strcmp (result, wp_itox (nbits, v3)) != 0) {
        printf ("error: %s (%016" PRIx64 ", %016" PRIx64 ")/%d, e %s, got %s\n",
                desc, i1, i2, nbits, result, wp_itox (nbits, v3));
        test_value = 0;
        incorrect++;
      } else {
#ifdef DEBUG_PRINT
        printf ("correct: %s (%016" PRIx64 ", %016" PRIx64 ")/%d, e %s, got %s\n",
                desc, i1, i2, nbits, result, wp_itox (nbits, v3));
#endif /* DEBUG_PRINT */
        correct++;
      }
      total++;
      /* update i2 */
      i2 = next_i_value (i2, 1);
    }
    /* update i1 */
    i1 = next_i_value (i1, 0);
  }
  printf ("test %s: %d total, %d correct, %d not correct, returning %d\n",
          desc, total, correct, incorrect, test_value);
  print_time (total, desc, nbits);
  return test_value;
}

static uint64_t test_add (uint64_t v1, uint64_t v2)
{
  return v1 + v2;
}

static uint64_t test_sub (uint64_t v1, uint64_t v2)
{
  return v1 - v2;
}

static void multiple_shift_left (int nbits, uint64_t * v, int count)
{
  while (count-- > 0)
    wp_shift_left (nbits, v);
}

/* test with bigger values -- just test internal consistency */
static int test_add_sub ()
{
  get_start_time ();
  int test_value = 1;
  int total = 0;
  int correct = 0;
  int incorrect = 0;
  uint64_t max = 1LL << 63;
  int nbits = 4096;
  uint64_t i1 = 0;
  while (i1 < max) {
    uint64_t i2 = 0;
    while (i2 < max) {
      int i3, i4;
      for (i3 = 0; i3 < 4000; i3 += 1999) {
        for (i4 = 0; i4 < 4000; i4 += 407) {
          uint64_t v1 [64];
          uint64_t v2 [64];
          uint64_t v3 [64];
          uint64_t v4 [64];
          uint64_t v5 [64];
          my_pr_init (nbits, v1, i1, i2, i3, i4);
          /* multiple_shift_left (nbits, v1, i3); */
          my_pr_init (nbits, v2, i2, i1, i4, i3);
          /* multiple_shift_left (nbits, v2, i4); */
          wp_add (nbits, v3, v1, v2);
          wp_sub (nbits, v4, v3, v1);  /* v4 should be equal to v2 */
          wp_sub (nbits, v5, v3, v2);  /* v5 should be equal to v1 */
          if (memcmp (v1, v5, sizeof (v1)) != 0) {
            printf ("add_sub (%" PRIx64 "<<%d, %" PRIx64 "<<%d) error: %s = ",
                    i1, i3, i2, i4, wp_itox (nbits, v5));
            printf ("%s - ", wp_itox (nbits, v3));
            printf ("%s != ", wp_itox (nbits, v2));
            printf ("%s\n", wp_itox (nbits, v1));
            test_value = 0;
            incorrect++;
         } else if (memcmp (v2, v4, sizeof (v2)) != 0) {
            printf ("add_sub (%" PRIx64 "<<%d, %" PRIx64 "<<%d) error: %s = ",
                    i1, i3, i2, i4, wp_itox (nbits, v4));
            printf ("%s - ", wp_itox (nbits, v3));
            printf ("%s != ", wp_itox (nbits, v1));
            printf ("%s\n", wp_itox (nbits, v2));
            test_value = 0;
            incorrect++;
         } else {
#ifdef DEBUG_PRINT
            printf ("add_sub (%" PRIx64 "<<%d, %" PRIx64 "<<%d) correct\n",
                    i1, i3, i2, i4);
#endif /* DEBUG_PRINT */
            correct++;
          }
          total++;
        }
      }
      /* update i2 */
      i2 = next_i_value (i2, 1);
    }
    /* update i1 */
    i1 = next_i_value (i1, 0);
  }
  printf ("test %s: %d total, %d correct, %d not correct, returning %d\n",
          "add_sub", total, correct, incorrect, test_value);
  print_time (total, "add_sub", nbits);
  return test_value;
}

static int testm ()
{
  get_start_time ();
  int test_value = 1;
  int total = 0;
  int correct = 0;
  int incorrect = 0;
  uint64_t max = ((uint64_t) 1) << 31;
  int vbits = 64;  /* all values will be 31 or fewer bits */
  int rbits = 128; /* so the result should be 64 or fewer bits */
  uint64_t i1 = 0;
  while (i1 < max) {
    uint64_t i2 = 0;
    while (i2 < max) {
      uint64_t v1 [1];
      uint64_t v2 [1];
      uint64_t v3 [2];
      my_init (vbits, v1, i1);
      my_init (vbits, v2, i2);
      wp_multiply (rbits, v3, vbits, v1, v2);
      char result [1000];
      snprintf (result, sizeof (result), "%016" PRIx64, i1 * i2);
      if (strcmp (result, wp_itox (vbits, v3 + 1)) != 0) {
        printf ("error: %s (%016" PRIx64 ", %016" PRIx64 ")/%d, e %s, got %s.",
                "mult", i1, i2, vbits, result, wp_itox (vbits, v3));
        printf ("%s\n", wp_itox (vbits, v3 + 1));
        test_value = 0;
        incorrect++;
      } else {
#ifdef DEBUG_PRINT
        printf ("yes: %s (%016" PRIx64 ", %016" PRIx64 ")/%d, e %s, got %s\n",
                "mult", i1, i2, vbits, result, wp_itox (rbits, v3));
#endif /* DEBUG_PRINT */
        correct++;
      }
      total++;
      uint64_t i3 = 1;
      while (i3 < max) {
        uint64_t v4 [1];
        uint64_t v5 [1];
        my_init (vbits, v4, i3);
        if (i1 < i3) {
          wp_multiply_mod (vbits, v5, v1, v2, v4);
          snprintf (result, sizeof (result), "%016" PRIx64, (i1 * i2) % i3);
          if (strcmp (result, wp_itox (vbits, v5)) != 0) {
            printf ("%" PRIx64 " * %" PRIx64 " mod %" PRIx64 "/%d, %s != %s\n",
                    i1, i2, i3, vbits, result, wp_itox (vbits, v5));
            test_value = 0;
            incorrect++;
          } else {
#ifdef DEBUG_PRINT
            printf ("%" PRIx64 " * %" PRIx64 " %% %" PRIx64 " = %s\n",
                    i1, i2, i3, vbits, wp_itox (vbits, v5));
#endif /* DEBUG_PRINT */
            correct++;
          }
          total++;
        }
        /* update i3 */
        i3 = next_i_value (i3, 2);
      }
      /* update i2 */
      i2 = next_i_value (i2, 1);
    }
    /* update i1 */
    i1 = next_i_value (i1, 0);
  }
  printf ("test %s: %d total, %d correct, %d not correct, returning %d\n",
          "mul", total, correct, incorrect, test_value);
  print_time (total, "mul", vbits);
  return test_value;
}

static int testd ()
{
  get_start_time ();
  int test_value = 1;
  int total = 0;
  int correct = 0;
  int incorrect = 0;
  uint64_t max = 1LL << 60;
  uint64_t special = (((uint64_t) 1) << 63) + 31;
  int vbits = 64;  /* dividends will be 63 or fewer bits */
  int rbits = 128; /* so the result should be 32 or fewer bits */
  uint64_t i1 = 0;
  while ((i1 < max) || (i1 == special)) {
    uint64_t i2 = 1;
    while ((i2 < max) || (i2 == special)) {
      if ((i1 >> vbits) < i2) {
        uint64_t v1 [2];
        uint64_t v2 [1];
        uint64_t * q;
        uint64_t * r;
        my_init (rbits, v1, i1);
        my_init (vbits, v2, i2);
        wp_div (rbits, v1, vbits, v2, &q, &r);
        char res_q [1000];
        char res_r [1000];
        snprintf (res_q, sizeof (res_q), "%016" PRIx64, i1 / i2);
        snprintf (res_r, sizeof (res_r), "%016" PRIx64, i1 % i2);
        if (strcmp (res_q, wp_itox (vbits, q)) != 0) {
          printf ("%s %016" PRIx64 " / %016" PRIx64 "(%d), e %s, got %s\n",
                  "error: quotient ", i1, i2, vbits, res_q,
                  wp_itox (vbits, q));
          test_value = 0;
          incorrect++;
        } else if (strcmp (res_r, wp_itox (vbits, r)) != 0) {
          printf ("%s %016" PRIx64 " / %016" PRIx64 "(%d), e %s, got %s\n",
                  "error: remainder ", i1, i2, vbits, res_r,
                  wp_itox (vbits, r));
          test_value = 0;
          incorrect++;
        } else {
#ifdef DEBUG_PRINT
          printf ("%s %016" PRIx64 " / %016" PRIx64 " (/%d), got %s %s\n",
                  "correct: div", i1, i2, vbits, res_q, res_r);
#endif /* DEBUG_PRINT */
          correct++;
        }
        total++;
      }
      /* update i2 */
      if (i2 == special)
        break;
      i2 = next_i_value_special (i2, 1, max, special);
    }
    /* update i1 */
    if (i1 == special)
      break;
    i1 = next_i_value_special (i1, 0, max, special);
  }
  printf ("test %s: %d total, %d correct, %d not correct, returning %d\n",
          "div", total, correct, incorrect, test_value);
  print_time (total, "div", vbits);
  return test_value;
}

static uint64_t test_exp_mod (uint64_t base, int exp, uint64_t mod)
{
  uint64_t result = 1;
  while (exp-- > 0)
    result = ((result * base) % mod);
  return result;
}

static int testem ()  /* test exponentiation modulo x */
{
  get_start_time ();
  int test_value = 1;
  int total = 0;
  int correct = 0;
  int incorrect = 0;
  uint64_t max = 1LL << 30;
  int nbits = 64;
  uint64_t i1 = 1;
  while (i1 < max) {
    int i2 = 1;
    while (i2 < max) {
      uint64_t i3 = 1;
      while (i3 < max) {
        if (((i3 % 2) == 1) && (i1 < i3)) {
          uint64_t v1 [1];
          uint64_t v2 [1];
          uint64_t v3 [1];
          my_init (nbits, v1, i1);
          wp_init (nbits, v2, i2);
          my_init (nbits, v3, i3);
          uint64_t v4 [1];
          uint64_t v5 [1];
          uint64_t v6 [1];
          uint64_t temp [140];
          wp_exp_mod (nbits, v4, v1, v2, v3, temp);
          wp_exp_mod64 (nbits, v5, v1, v2, v3, temp);
          wp_exp_mod_montgomery (nbits, v6, v1, v2, v3, temp);
/* i2 is the exponent, and should not be too big for us to compute
 * using 64-bit arithmetic, so max * 2^i2max < 2^64 */
          char result [1000];
          int i2max = 20;
          if (i2 < i2max)
            snprintf (result, sizeof (result), "%016" PRIx64,
                      test_exp_mod (i1, i2, i3));
          else  /* will always equal v4, but may not equal v5 and v6 */
            snprintf (result, sizeof (result), "%s", wp_itox (nbits, v4));
          if ((strcmp (result, wp_itox (nbits, v4)) != 0) ||
              (strcmp (result, wp_itox (nbits, v5)) != 0) ||
              (strcmp (result, wp_itox (nbits, v6)) != 0)) {
            printf ("error: %016" PRIx64 " ^ %d %% %" PRIx64 ", e %s, got %s ",
                    i1, i2, i3, result, wp_itox (nbits, v4));
            printf ("%s ", wp_itox (nbits, v5));
            printf ("%s\n", wp_itox (nbits, v6));
            test_value = 0;
            incorrect++;
exit (1);
          } else {
#ifdef DEBUG_PRINT
            printf ("correct: %016" PRIx64 " ^ %d %% %" PRIx64 ", e %s, got %s\n",
                    i1, i2, i3, result, wp_itox (nbits, v4));
#endif /* DEBUG_PRINT */
            correct++;
          }
          total++;
        }
        /* update i3 */
        i3 = next_i_value (i3, 2);
      }
      i2 = next_i_value (i2, 1);
      /* i2 is updated by the for loop */
    }
    /* update i1 */
    i1 = next_i_value (i1, 0);
  }
  print_time(total, "b^e mod m", nbits);
  int larger_total = 0;
  gettimeofday (&start, NULL);
  /* now compare wp_exp_mod and wp_exp_mod64 on larger, semi-random values */
  nbits = 512;
  int i;
  for (i = 0; i < 100; i++) {
    char init [] = "123456789abcdef0123456789abcdef0"
                   "123456789abcdef0123456789abcdef0"
                   "123456789abcdef0123456789abcdef0"
                   "123456789abcdef0123456789abcdef0";
    uint64_t base [16];
    uint64_t exp [16];
    uint64_t mod [16];
    wp_from_hex (nbits, base, strlen (init), init);
    wp_add_int (nbits, base, i * 55);
    if (i % 22 == 0)
      base [0] |= ((uint64_t) 0x1) << 63;
    wp_copy (nbits, exp, base);
    exp [i % 16] = 0x0f1e2d3c4b5a6978;
    wp_copy (nbits, mod, base);
    wp_add_int (nbits, mod, i * 7 + 1);
    uint64_t r1 [16];
    uint64_t r2 [16];
    uint64_t r3 [16];
    uint64_t temp [17 * 70];
    wp_exp_mod (nbits, r1, base, exp, mod, temp);
    wp_exp_mod64 (nbits, r2, base, exp, mod, temp);
    wp_exp_mod_montgomery (nbits, r3, base, exp, mod, temp);
    if ((wp_compare (nbits, r1, r2) != 0) ||
        (wp_compare (nbits, r2, r3) != 0)) {
      printf ("error (%d): %s ^ ", i, wp_itox (nbits, base));
      printf ("%s %% ", wp_itox (nbits, exp));
      printf ("%s gives:\n", wp_itox (nbits, mod));
      printf ("%s in wp_exp_mod,\n", wp_itox (nbits, r1));
      printf ("%s in wp_exp_mod64\n", wp_itox (nbits, r2));
      printf ("%s in wp_exp_mod_montgomery\n", wp_itox (nbits, r3));
      test_value = 0;
      incorrect++;
exit (1);
    } else {
      correct++;
    }
    larger_total++;
  }
  print_time (larger_total, "b^e mod m", nbits);
  printf ("test %s: %d total, %d correct, %d not correct, returning %d\n",
          "exp_mod", total + larger_total, correct, incorrect, test_value);
  return test_value;
}

static int testmultiple ()
{
  get_start_time ();
  int test_value = 1;
  int total = 0;
  int correct = 0;
  int incorrect = 0;

  uint64_t n_product_of_primes [64];  /* 4096 bits */
  char * nvalue =
    "d613727d05783d52b01d3c1c8fc8db74e51b2a4ff81b665de593ea844e3b4b0a2"
    "03e24ede65dbecae11817b83c509e1e65ea16a44ab8734a6daea5dc1b3d76db24"
    "f929f71781aebf5a37bb30142a6bde42c900bd222c28ae491b06d442885dcf6e3"
    "90df8397c3d2b1197733dd02e4281eb0e85d158b495b6b80f0b8e87a274c6f09a"
    "fdb2b1e7344c4bea2e358ffbb932983704377b8dd8c237e902bebb071fcc6ca06"
    "8d95bcb72c05c4c457d074fe5263925bf3aa2fd7c064e400adc6de45a5dfc15fe"
    "ed617b6bfbfebcd2fbd5d6fd629e3d100b703cbb642d7eaa2179974fe4184e627"
    "e5364f249e6a5380c42caded41364d9c8254afad7f0cf07dffec4c20234264f29"
    "38e2fe80681ea8f5608766b741821a372fec664a3e1d3d7967279a8a272d59014"
    "82aea8c83702c8563b4f532582ab57e8c4b1135e9b1e7d223299aeace34efb41f"
    "2acdbe38a3a1880e9f56e730c3639b5160fc37af11725eaeea6047462018ac124"
    "dedaebb0b56483b123ae43503b05f6560be76d3e8da82152791e4e67c8dfc6789"
    "8bbfec080f43314dfd16f0fef00948048c93bea70df0cce5c3a9514b477fef104"
    "d23660ce0fdf4b6797b1cb93f1aa33f75415a77148894db49fbd977ef1f929382"
    "e3050089d2f440ab374d7e6aa18aa5f7f7d9d885cd4895f8e7aa67ad1e240bd65"
    "7f316cd8fc785d98e7b3e1e2a8b0b7654d0d1372fdb65185d";
  wp_from_hex (4096, n_product_of_primes, strlen (nvalue), nvalue);
  int i;
  for (i = 2; i < 100000; i++) {
    if (wp_multiple_of_int (4096, n_product_of_primes, i)) {
      incorrect++;
      test_value = 0;
    } else
      correct++;
    total++;
  }
  /* n + 1 should be divisible by 2, 3, and 5 -- check to make sure */
  wp_add_int (4096, n_product_of_primes, 1);
  for (i = 2; i < 6; i++) {
    if (i != 4) {
      if (! wp_multiple_of_int (4096, n_product_of_primes, i)) {
        incorrect++;
        test_value = 0;
      } else
        correct++;
      total++;
    }
  }
  printf ("test %s: %d total, %d correct, %d not correct, returning %d\n",
          "multiple_of", total, correct, incorrect, test_value);
  print_time (total, "multiple_of", 4096);
  return test_value;
}

static int time_sh (int nbits)
/* time shifting left and right */
{
  static uint64_t large_int [1024];
  my_assert (nbits / 8 <= sizeof (large_int), "nbits * 64 <= large_int");
  get_start_time ();
  int total = 0;
  int i;
  for (i = 0; i < nbits / 64; i++)
    large_int [i] = i;
  for (i = 0; i < 10000; i++) {
    wp_shift_left (nbits, large_int);
    wp_shift_right (nbits, large_int);
    total++;
  }
  print_time(total, "shift left-right", nbits);
  return 1;
}

static int time_em (int nbits)
/* time exponentiation modulo x on 4096-bit and larger ints */
{
/* maximum size is LARGE * 64 */
#define LARGE	1024
  my_assert (((1LL << nbits) <= LARGE * 64), "nbits must be 64K or less");
  get_start_time ();
  int total = 0;
  static uint64_t mod [LARGE];
  int i;
  for (i = 0; i < NUM_WORDS (nbits); i++)
    mod [i] = i + 1;
  static uint64_t base [LARGE];
  wp_init (nbits, base, 1);
  base [1] = 33;
  static uint64_t exp [LARGE];
  for (i = 0; i < NUM_WORDS (nbits); i++)
    exp [i] = (((uint64_t) (i * 11) + 1) << 30) - 1;
  int limit = 500;
  int decr = 256;
  while ((limit >= 13) && (decr < nbits)) {
    limit = limit / 6;
    decr *= 2;
  }
  for (i = 0; i < limit; i++) {
    static uint64_t result [LARGE];
    static uint64_t temp [LARGE];
    wp_exp_mod (nbits, result, base, exp, mod, temp);
    wp_copy (nbits, base, result);
    total++;
  }
  print_time(total, "b^e mod m", nbits);
  return 1;
}

/* time m^65537 modulo x on 4096-bit ints */
static int time_encrypt (int nbits)
{
/* maximum size is LARGE * 64 */
#define LARGE	1024
  my_assert (((1LL << nbits) <= LARGE * 64), "nbits must be 64K or less");
  int algorithm;
  for (algorithm = 0; algorithm < 3; algorithm++) {
    get_start_time ();
    int total = 0;
    static uint64_t mod [LARGE];
    int i;
    for (i = 0; i < NUM_WORDS (nbits); i++)
      mod [i] = i + 1;
    mod [NUM_WORDS (nbits) - 1] |= 1;   /* make sure modulo is odd */
    static uint64_t base [LARGE];
    wp_init (nbits, base, 1);
    base [1] = 33;
    static uint64_t exp [LARGE];
    wp_init (nbits, exp, 65537);
    for (i = 0; (i < 100) && ((nbits < 1024) || (i < 20)); i++) {
      static uint64_t result [LARGE];
      static uint64_t temp [(LARGE + 1) * 70];
      switch (algorithm) {
      case 0: wp_exp_mod (nbits, result, base, exp, mod, temp);  break;
      case 1: wp_exp_mod64 (nbits, result, base, exp, mod, temp);  break;
      default: wp_exp_mod_montgomery (nbits, result, base, exp, mod, temp);
               break;
      }
      wp_copy (nbits, base, result);
      total++;
    }
    switch (algorithm) {
    case 0: print_time(total, "b^65537 mod m", nbits); break;
    case 1: print_time(total, "b^65537 mod64 m", nbits); break;
    default: print_time(total, "b^65537 mod_mont m", nbits); break;
    }
  }
  return 1;
}

static int time_em64 (int nbits)
/* time exponentiation modulo x using wp_exp_mod64 */
{
/* maximum size is LARGE * 64 */
#define LARGE	1024
  my_assert (((1LL << nbits) <= LARGE * 64), "nbits must be 64K or less");
  get_start_time ();
  int total = 0;
  static uint64_t mod [LARGE];
  int i;
  for (i = 0; i < NUM_WORDS (nbits); i++)
    mod [i] = i + 0x876543210ffffedc;
  static uint64_t base [LARGE];
  wp_init (nbits, base, 1);
  for (i = 0; i < NUM_WORDS (nbits); i++)
    base [i] = 0x3fff0000ffff0000 + i;
  static uint64_t exp [LARGE];
  for (i = 0; i < NUM_WORDS (nbits); i++)
    exp [i] = (((uint64_t) (i * 11) + 1) << 30) - 1;
  int limit = 500;
  int decr = 256;
  while ((limit >= 13) && (decr < nbits)) {
    limit = limit / 6;
    decr *= 2;
  }
  for (i = 0; i < limit; i++) {
    static uint64_t result [LARGE];
    static uint64_t temp [LARGE * 65];
    wp_exp_mod64 (nbits, result, base, exp, mod, temp);
    wp_copy (nbits, base, result);
    total++;
  }
  print_time(total, "b^e mod64 m", nbits);
  return 1;
}

static int time_em_mont (int nbits)
/* time exponentiation modulo x using wp_exp_mod_montgomery */
{
/* maximum size is LARGE * 64 */
#define LARGE	1024
  my_assert (((1LL << nbits) <= LARGE * 64), "nbits must be 64K or less");
  get_start_time ();
  int total = 0;
  static uint64_t mod [LARGE];
  int i;
  for (i = 0; i < NUM_WORDS (nbits); i++)
    mod [i] = i + 0x876543210ffffedc;
  static uint64_t base [LARGE];
  wp_init (nbits, base, 1);
  for (i = 0; i < NUM_WORDS (nbits); i++)
    base [i] = 0x3fff0000ffff0000 + i;
  static uint64_t exp [LARGE];
  for (i = 0; i < NUM_WORDS (nbits); i++)
    exp [i] = (((uint64_t) (i * 11) + 1) << 30) - 1;
  int limit = 500;
  int decr = 256;
  while ((limit >= 13) && (decr < nbits)) {
    limit = limit / 6;
    decr *= 2;
  }
  for (i = 0; i < limit; i++) {
    static uint64_t result [LARGE];
    static uint64_t temp [LARGE * 70];
    wp_exp_mod_montgomery (nbits, result, base, exp, mod, temp);
    wp_copy (nbits, base, result);
    total++;
  }
  print_time(total, "b^e mod m mont", nbits);
  return 1;
}

/* test with bigger values -- just test internal consistency */
static int test_mul_div ()
{
  get_start_time ();
  int test_value = 1;
  int total = 0;
  int correct = 0;
  int incorrect = 0;
  uint64_t max = 1LL << 63;
  int nbits = 4096;
  int dbits = nbits / 2;
  uint64_t i1 = 1;
  while (i1 < max) {
    uint64_t i2 = 1;
    while (i2 < max) {
      int i3, i4;
      for (i3 = 0; i3 < 1980; i3 += 903) {
        for (i4 = 0; i4 < 1980; i4 += 409) {
          uint64_t v1 [32];
          uint64_t v2 [32];
          uint64_t v3 [64];
          my_init (dbits, v1, i1);
          multiple_shift_left (dbits, v1, i3);
          my_init (dbits, v2, i2);
          multiple_shift_left (dbits, v2, i4);
          wp_multiply (nbits, v3, dbits, v1, v2);

          uint64_t res1 [64];
          wp_copy (nbits, res1, v3);
          uint64_t * q1;
          uint64_t * r1;
          wp_div (nbits, res1, dbits, v2, &q1, &r1);
          if ((memcmp (v1, q1, sizeof (v1)) != 0) ||
              (! wp_is_zero (dbits, r1))) {
            printf ("mul_div (%" PRIx64 "<<%d, %" PRIx64 "<<%d) error: %s + ",
                    i1, i3, i2, i4, wp_itox (dbits, q1));
            printf ("%s != ", wp_itox (dbits, r1));
            printf ("%s / ", wp_itox (nbits, v3));
            printf ("%s\n", wp_itox (dbits, v2));
            test_value = 0;
            incorrect++;
          } else {
#ifdef DEBUG_PRINT
            printf ("mul_div (%" PRIx64 "<<%d, %" PRIx64 "<<%d) correct\n",
                    i1, i3, i2, i4);
#endif /* DEBUG_PRINT */
            correct++;
          }
          total++;
          uint64_t i5 = 0;
          int max5 = (1 << 30);
          while ((i5 < max5) && (i5 < i1)) {
            uint64_t res2 [64];
            uint64_t res2_copy [64];
            uint64_t rem2 [32];
            wp_copy (nbits, res2, v3);
            wp_add_int (nbits, res2, (int) i5);
            wp_copy (nbits, res2_copy, res2);
            wp_init (dbits, rem2, (int) i5);
            wp_div (nbits, res2, dbits, v1, NULL, NULL);
            uint64_t * q2 = res2 + 32;
            uint64_t * r2 = res2;
            if ((memcmp (v2, q2, sizeof (v2)) != 0) ||
                (wp_compare (dbits, r2, rem2) != 0)) {
              printf ("%s (%" PRIx64 "<%d, %" PRIx64 "<%d + %" PRIx64 ") %s + ",
                      "error in mul_div2: ", i1, i3, i2, i4, i5,
                      wp_itox (dbits, q2));
              printf ("%s != ", wp_itox (dbits, r2));
              printf ("%s / ", wp_itox (nbits, res2_copy));
              printf ("%s\n", wp_itox (dbits, v1));
              test_value = 0;
              incorrect++;
            } else {
#ifdef DEBUG_PRINT
              printf ("%s (%" PRIx64 "<<%d, %" PRIx64 "<<%d + %" PRIx64 ")\n",
                      "correct: mul_div", i1, i3, i2, i4, i5);
#endif /* DEBUG_PRINT */
              correct++;
            }
            total++;
            /* update i5 */
            i5 = next_i_value (i5, 2);
          }
        }
      }
      /* update i2 */
      i2 = next_i_value (i2, 1);
    }
    /* update i1 */
    i1 = next_i_value (i1, 0);
  }
  printf ("test %s: %d total, %d correct, %d not correct, returning %d\n",
          "mul_div", total, correct, incorrect, test_value);
  print_time(total, "mul_div", nbits);
  return test_value;
}

/* regression tests: things that have been buggy in the past */
static int test_specific ()
{
  int total = 0;
  int correct = 0;
  int incorrect = 0;
  int test_value = 1;
  uint64_t p [8];
  uint64_t q [8];
  char p_bytes [] = { 0xfe, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0xa7 };
  char q_bytes [] = { 0xdd, 0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x9f };
  wp_from_bytes (64, p, sizeof (p_bytes), p_bytes);
  wp_from_bytes (64, q, sizeof (q_bytes), q_bytes);
  uint64_t n [16];  /* 128 bits */
  wp_multiply (128, n, 64, p, q);
  char expected [] = "dc4fb231cf8c6980f4e877e2264338b9";
  if (strcmp (wp_itox (128, n), expected) != 0) {
    printf ("result of 18343038762207122599 * 15964855580155351967 is:\n");
    printf ("%s, expected\n%s\n", wp_itox (128, n), expected);
    test_value = 0;
    incorrect++;
  } else {
    correct++;
  }
  total++;
  char dividend_string [] = "3089d61745db40dbfbc35ad3439adc5d6988803e828366515b641d7b8bc099662ca62836ab2aa1a7bc53631c1675f90b59c8fe6d1beb6aa90b81a14fc9833c3c329aac0e0640e6e157272eaadbc6b66724bfd77371108f023c3cdc61b4a0ae33b807893202d8281bccef2a27ecfa492144a01c1fc82068628eccc5d17e1e4f877deebde4e2d1395aa9b02395f86f56174e17c26022f6de3761c4efd91e78c89853458e87ee8f466844f059533199b18a45a3fb3d432e860d207eecdd9f547f2eedc75ca46315b7c1efc26560785d5df7d53cdc801e3e69c8967be3813300d0b706c6019029e737293b98336e4c4aaeba56937e5a3c7d1f63639332941ca86e02f6827ea66c797868e03c2a57af1a2a39f13b4be11e6e616ea801d619c28edcf7d1be4ba2147d9c0e64ffc4ab71b6b02905ad4a4b983e790089a202c097552185c816de7731cc04786c48624bee5449ee30372786da8651bbd0daa9e8b1fe3451cb5a097858255fb7b75f91d9c382d99ab21ce1b982abf7abf1be96e1fd810da6354ec2ceb86e576beb9642c5131f23deff1ffd9a8305d282d97474a7c9494e5db7eb356c673a349ba57445e164b5c4a28137f8d92eb1e2847b84d04ef5c352c4b7bd74891e0ec48452aabc0f5559891c9b216f9175ea43d16a336f12d1fcbf85f6154f0de47a0a58e592e17454a474888c579b06151c3a5142ccf9814e01e1e1";
  char divisor_string [] = "f876e820a10ab41832b9f99f9a6b6c0ba6eb8196043c101f1b8f3a80293ac1c05c4927706ddaed733876d895d87fd677871b2789f2e4a45b41c2d2724cdce8a5e17c0d6123cbd4b962b7ef6b9ef2a4e080326e87a5ddc0d3ea3ddaec619aa061fe7c916f3ac813e72e079be24a16bb4cd5303b3fb5263dda6ae4954c044b6ae3d03e641f1c475226c648d6c417f10a4895c8ba85d807f7ee2c81f8fc411751b82e0c13c744daaa43ad86f99f1b4ca4487b5516a03d41a216870ccdeb7c889551b136c9f02ab0d3dedae8d3febaa7f34190e5ea7e0ab22b7daadc6b56ab0604d24d3e636a8c012ee2640b19099b001ff06b47ea46a22662e754f5f13e322c0e97";
  char quotient_string [] = "3202b109248c99f88128e8f7487de5063a2f6e64d6f8dff5129460e7aeebdc9d3aff6509fe90915cf1c02f65cd4aec01801d0088386ee2d19c6f92a3c6cfc14380e53017a6cd366d82924fbee20d4dfa4ba0ea51e44e0aeb1bc9859e2b185bec5d40420dfbe006db8f5863e759ba4cb64b03ee6f62675bba30a27a821eabecfe8bd17c59e4f7cdb275e32c7e7dde35cc0e61536b8b6cf4daa8ff58ef24ce317e24d4d3c3f0436314c3f078de30c73b2fa8ac79ec8fc8cfa064e049ff18ea30ea20cb2b1a8d813e6730027bf89aff22806efe5c74c2b5c039901303b2bb5373860a2324d72cfb550583c3c63a8f09c77d39039724e60ffd978c1d2a369b79a27d";
  char remainder_string [] = "c8926127c3cc1a11c5fb4ab275a928fe99382263bba18f6e4942f638ac19ed9f3e1f4d4a75953e084bae4efdb4b9182200073fd9a29e597fc93a4956918fff99eb232f00bb90fbacdca02143a1ff26394c61dfecb6d0f9a89cf19ab0e61a2c7e9083c0e9682068c9118ad28d087c7f371bddc96d67ff73a360348bce444fd0c52bcb749a7f54d89fbf722eaeeb03d49aa88677a5e52c38a2b11fa2d63a2a2339b3600e15b887d4b8f834a1898e607e5c79f22c6831ab7f1c700f9c17422bd2c8ea992418fb0a1738319b2978aed70590effd1bff2df93c784c476a0d1688ceeaaf3d094980ad924e3280df28cd47b112eba54a2d89cdc5e66a7b94e09ae43426";
  uint64_t dividend [64];
  wp_from_hex (4096, dividend, strlen (dividend_string), dividend_string);
  uint64_t divisor [32];
  wp_from_hex (2048, divisor, strlen (divisor_string), divisor_string);
  uint64_t expected_q [32];
  wp_from_hex (2048, expected_q, strlen (quotient_string), quotient_string);
  uint64_t expected_r [32];
  wp_from_hex (2048, expected_r, strlen (remainder_string), remainder_string);
  uint64_t * quotient;
  uint64_t * rem;
  wp_div (4096, dividend, 2048, divisor, &quotient, &rem);
#ifdef DEBUG_PRINT
  printf ("quotient  %p %s\n", quotient, wp_itox (2048, quotient));
  printf ("remainder %p %s\n", rem, wp_itox (2048, rem));
#endif /* DEBUG_PRINT */
  if (strcmp (wp_itox (2048, quotient), quotient_string) != 0) {
    printf ("%s, expected quotient\n%s\n", wp_itox (2048, quotient),
            quotient_string);
    test_value = 0;
    incorrect++;
  } else {
    correct++;
  }
  total++;
  if (strcmp (wp_itox (2048, rem), remainder_string) != 0) {
    printf ("%s, expected remainder\n%s\n", wp_itox (2048, rem),
            remainder_string);
    test_value = 0;
    incorrect++;
  } else {
    correct++;
  }
  total++;

  /* wp_exp_mod gave the wrong result in this case */
  char wp_exp_mod_base [] = "8e894e79580e6eb5871209b91b3a4621e94f8579a8030b1e2daf7346a55404c2167499951673b597476d9fd67641f22f218bb9e0a321a0f26cba40d9d893243ec81bf7296f84f4a5ab8dcda065dcb819a21f71f7a25941bac75ff1316ae9bfe3da74e2833c437c06e6afa1998f30aec8d3db00385809a773092e4b1e2081fce454915f3fe8901b1f5eda9c0102b2287d4f2c257b8836a913020907e0ee2d89d921279d4ddd9979ab5a1e07d2e7ef5cc827b9cba22e0048d16371fa4ff3e99182aaa2f02f87e6efc3f91eccbd7903a211724263debce832fa533481e22f02f0970e5e8b0fe144e30ac048e6b9d96af6d305dcf617f8fa4cc1b3e1cb1c3364d55bab04506744aa18736f977d74f536f4c61496e22a62d378a88fb1f8dfea36544427ea65e51c472a874f8c2eea3e37b10003e3b2e363a2416be8f205a58cbe9dbce62009ea0b4f2a85442cc83543e31f3c8031bd43833416e093af5d5d3613980477d9fcb44408ea78c127c6e195e46683ef123810629fb9c43a446d55dbbb3c44329a83067b19fac41f9a2463d397bdc854669d3c921e77a7f5938fe385b35372bb4454bbaaec2301daf3a30e47a876b371cdec7a10246b6d849cf4e5b660cb5941fa6e367bd1ff82b4ad3de4f83e61c08c644f024779ea3a39ecab3b1ea8a3469eb857dfe1aa95fae126aacc3ba7bf19eb89f00e9d5e280f8ee195e7780bea13";
  char wp_exp_mod_exp [] = "010001";
  char wp_exp_mod_mod [] = "d7284d5ec6a1854313bf896d0ed1c8f70d1a8fb17e993bc61719866e90f8edf3d693f037e41e2867ef03ea427b4ae3b9c8587226c4aa21de7b15f54a14e1c20844a3c29f23bb20779c31ff02bab5e5ec76e177ce7de3a4e030f905643cce54da05355373980e7012a2641337bc414bbff3b2bc3950899c2c3e3e8dc4492801d7b06b95bda08a24ccfdf750e67713922e6a5cf9201b325945a2a12a550506d0eccb06f095ca3421879a9c7880e15784b089c1a56cff6c26a88fc7f3aa00b0d015b1dc0c204691479738e69ec34cd5dccfab0e63deceb7bb2731f5456d14701469099ad0ae7194c8eb9d03811a59c3d7b2f1d3b17d9a9883205081933b30989e25137dab141b012b21823f5403155a1ea6f251e7f8f0f80799d97aaa469aeee80e4487bda55c044abc7f2e308dab24224a14decf13516115e9b5319fff856e41b2895bc8112f19e65fb5bbebdac5aa90df866e62ce8baa558bee443001a179c5ed961cd98bb93d26ef16a4abd657a2f11d15ae77b27bf4b87b95960f67e584389e7bbfadbc1c741ed46dc6ac21ef70276d67e57735154f805397fe9cc7aa3a62476da1c9f869d586f32611a5aa20c3c4a71cd3f82bc30ab771c98d3f7276d0d06c3cc418e9db33acd17ba901ac625c14c8c9bf7aad6be227b7f3386277a057056a909e8e5599b75971f96a5bde503a83b1133c8bea3fffd58999d44ff017dc47cb";
  char wp_exp_mod_res [] = "0001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff003051300d060960864801650304020305000440c9429b611abc5fc7044370e6cce87b95dcd1a83d508f4dfefafd851abb2aacd8eef017fe050faad9eaaef012656a0709cf60d0ce852bcfa0771518dbb691b1d0";
  uint64_t wp_exp_mod_b [64];
  wp_from_hex (4096, wp_exp_mod_b, strlen (wp_exp_mod_base), wp_exp_mod_base);
  uint64_t wp_exp_mod_e [64];
  wp_from_hex (4096, wp_exp_mod_e, strlen (wp_exp_mod_exp), wp_exp_mod_exp);
  uint64_t wp_exp_mod_m [64];
  wp_from_hex (4096, wp_exp_mod_m, strlen (wp_exp_mod_mod), wp_exp_mod_mod);
  uint64_t wp_exp_mod_r [64];
  wp_from_hex (4096, wp_exp_mod_r, strlen (wp_exp_mod_res), wp_exp_mod_res);
  uint64_t wp_exp_mod_actual [64];
  uint64_t wp_exp_mod_temp [64];
  wp_exp_mod (4096, wp_exp_mod_actual, wp_exp_mod_b, wp_exp_mod_e, wp_exp_mod_m,
              wp_exp_mod_temp);
  if (wp_compare (4096, wp_exp_mod_actual, wp_exp_mod_r) != 0) {
    printf ("wp_exp_mod computed %s\n", wp_itox (4096, wp_exp_mod_actual));
    printf ("         instead of %s\n", wp_itox (4096, wp_exp_mod_r));
    test_value = 0;
    incorrect++;
  } else {
    correct++;
  }
  total++;

  char wp_multiply_mod_f1 [] = "011352987c10cdd62bcb7471c7e9eeed437db197569ea8b00d8c9e4ec50eda29acc077ab995d3a9afa10129d1c36a726308591a677d613dcfbb6a816a921bbba1c807a15febdce1a822aa44117de2d4804ad496255836fbbc147ef40d38800feb953be6b5aa3ab923faae53d7de210c0187e304eae4e6fa689170f754cb5e690458306d58685d19a40597ca19119340e79e221bc66203f572eceb6cafe8efb3338b6b96b41e37275bdbd59bad9ad8ce5ed8c6b12ad392d5d33197f1a964efca6490774b1d38a41a2a3bc6455e82712b10d0da44f8a27f82baee22e7e9959ce4c65a195a3eb4a712599c47ac2350cb78e3d9a896659b03fbefa631173fa3e96d51baa29c53cde43d424c014c464463e42144a9554de84f0162fd2a1f30803d9bdd4b3a29884f152f009974da960404ed2f6b4fe4ef9c1451750eea86b3825f1a5e8233e3627b105e2ce7b42482f93532dfe8861f0a48c263af0d32994b3ffd450e87132e67e227bc84c172b20d4d837e00a55971c5051ea852209a9f9a6da5d5ab19186b0c7bd7104d2637a3f074a3be961307c3653f1d13d3f56bf02314d052981f6ad0eda88b6ef31fd6dd689a0f4989d3d752bbe4a5ef3f53708ae1dc5d40467cb155e92e920de726880da3434e9e0a2e88e71d31c54ff283609f31518a20a97436c1a7f29f838b1ba8ea9f89fbdf042be0b902b5d4d9fa74201ab88d3991e";
  char wp_multiply_mod_f2 [] = "8e894e79580e6eb5871209b91b3a4621e94f8579a8030b1e2daf7346a55404c2167499951673b597476d9fd67641f22f218bb9e0a321a0f26cba40d9d893243ec81bf7296f84f4a5ab8dcda065dcb819a21f71f7a25941bac75ff1316ae9bfe3da74e2833c437c06e6afa1998f30aec8d3db00385809a773092e4b1e2081fce454915f3fe8901b1f5eda9c0102b2287d4f2c257b8836a913020907e0ee2d89d921279d4ddd9979ab5a1e07d2e7ef5cc827b9cba22e0048d16371fa4ff3e99182aaa2f02f87e6efc3f91eccbd7903a211724263debce832fa533481e22f02f0970e5e8b0fe144e30ac048e6b9d96af6d305dcf617f8fa4cc1b3e1cb1c3364d55bab04506744aa18736f977d74f536f4c61496e22a62d378a88fb1f8dfea36544427ea65e51c472a874f8c2eea3e37b10003e3b2e363a2416be8f205a58cbe9dbce62009ea0b4f2a85442cc83543e31f3c8031bd43833416e093af5d5d3613980477d9fcb44408ea78c127c6e195e46683ef123810629fb9c43a446d55dbbb3c44329a83067b19fac41f9a2463d397bdc854669d3c921e77a7f5938fe385b35372bb4454bbaaec2301daf3a30e47a876b371cdec7a10246b6d849cf4e5b660cb5941fa6e367bd1ff82b4ad3de4f83e61c08c644f024779ea3a39ecab3b1ea8a3469eb857dfe1aa95fae126aacc3ba7bf19eb89f00e9d5e280f8ee195e7780bea13";
  uint64_t wp_multiply_mod_a [64];
  wp_from_hex (4096, wp_multiply_mod_a, strlen (wp_multiply_mod_f1),
               wp_multiply_mod_f1);
  uint64_t wp_multiply_mod_b [64];
  wp_from_hex (4096, wp_multiply_mod_b, strlen (wp_multiply_mod_f2),
               wp_multiply_mod_f2);
  /* the result should be the same as for exp_mod */
  wp_multiply_mod (4096, wp_exp_mod_actual,
                   wp_multiply_mod_a, wp_multiply_mod_b, wp_exp_mod_m);
  if (wp_compare (4096, wp_exp_mod_actual, wp_exp_mod_r) != 0) {
    printf ("wp_multiply_mod computed %s\n", wp_itox (4096, wp_exp_mod_actual));
    printf ("              instead of %s\n", wp_itox (4096, wp_exp_mod_r));
    test_value = 0;
    incorrect++;
  } else {
    correct++;
  }
  total++;

  char div_mul_sub_r_string [] = "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000101010101010101020202020202020203030303030303030404040404040402FD92D3D14EC005E8C651AC6B0691528757680DC3B134F03DF3025F7C786430941A435756318D943C77CE2BC0B81309209B4F41EA99C286BED98E6AECEC17F0F467F7187C68C1C53BBA3721EC442D1CD12A1DCE19FA359E528C220B57BF7E4CAA9CA4F42F7D0CA935A086AE9511EFD678DF";
  char div_mul_sub_newr_string [] = "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004A45D3DCDCDCDCDC8DBE18FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE600201010101010779F00101010100FC28";
  uint64_t div_mul_sub_r [32];
  wp_from_hex (2048, div_mul_sub_r,
               strlen (div_mul_sub_r_string), div_mul_sub_r_string);
  uint64_t div_mul_sub_newr [32];
  wp_from_hex (2048, div_mul_sub_newr,
               strlen (div_mul_sub_newr_string), div_mul_sub_newr_string);
  uint64_t div_mul_sub_div_arg [64];
  wp_extend (4096, div_mul_sub_div_arg, 2048, div_mul_sub_r);
  uint64_t * div_mul_sub_q;
  wp_div (4096, div_mul_sub_div_arg, 2048, div_mul_sub_newr,
          &div_mul_sub_q, NULL);
  char div_mul_sub_div_string [] = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000375D458CB6F957F9736146BAD12AD7AC8ADFEBF7B04615CA19AAFA2A8DD64C";
  if (strcasecmp (div_mul_sub_div_string, wp_itox (2048, div_mul_sub_q)) != 0) {
    printf ("initial div gave %s\n", wp_itox (2048, div_mul_sub_q));
    printf ("        expected %s\n", div_mul_sub_div_string);
    test_value = 0;
    incorrect++;
  } else {
    correct++;
  }
  total++;

  int outer;
  for (outer = 1; outer < 3; outer++) {
    int nbits = outer * 64;
    int mont;
    for (mont = 2; mont < 1000; mont = mont * 2 + 1) {
      uint64_t montgomery_base [3];
      wp_init (nbits, montgomery_base, mont);
      uint64_t montgomery_exp [3];
      wp_init (nbits, montgomery_exp, 2 /* 1234 * mont * nbits */ );
      uint64_t montgomery_mod [3] = { 0x1234567809abcdef,
                                      0x1234567809abcdef, 0x1234567809abcdef};
      uint64_t montgomery_res [3];
      uint64_t montgomery_temp [70 * 4];
      wp_exp_mod_montgomery (nbits, montgomery_res, montgomery_base,
                             montgomery_exp, montgomery_mod, montgomery_temp);
      uint64_t regular_res [3];
      wp_exp_mod (nbits, regular_res, montgomery_base,
                  montgomery_exp, montgomery_mod, montgomery_temp);
#ifdef DEBUG_PRINT
      printf ("%s ^ ", wp_itox (nbits, montgomery_base));
      printf ("%s %% ", wp_itox (nbits, montgomery_exp));
      printf ("%s == ", wp_itox (nbits, montgomery_mod));
      printf ("%s =? ", wp_itox (nbits, regular_res));
      printf ("%s\n"  , wp_itox (nbits, montgomery_res));
#endif /* DEBUG_PRINT */
      if (wp_compare (nbits, regular_res, montgomery_res) != 0) {
        test_value = 0;
        incorrect++;
  exit (1);
      } else {
        correct++;
      }
      total++;
    }
  }
  printf ("test specific: %d total, %d correct, %d not correct, returning %d\n",
          total, correct, incorrect, test_value);
  return test_value;
}

static int wp_arith_test ()
{
  int retval = 1;
  get_start_time ();
  if (! testb ("is_zero", &wp_is_zero, &test_is_zero))
    retval = 0;
  if (! testb ("is_even", &wp_is_even, &test_is_even))
    retval = 0;
  if (! testb2 ("compare", &wp_compare, &test_compare))
    retval = 0;
  if (! test1 ("shl", &wp_shift_left, &test_shift_left))
    retval = 0;
  if (! test1 ("shr", &wp_shift_right, &test_shift_right))
    retval = 0;
  if (! test2 ("copy", &wp_copy, &test_copy))
    retval = 0;
  if (! test3 ("add", &wp_add, &test_add))
    retval = 0;
  if (! test3 ("sub", &wp_sub, &test_sub))
    retval = 0;
  if (! testm ())
    retval = 0;
  if (! testd ())
    retval = 0;
  if (! testem ())
    retval = 0;
  if (! testmultiple ())
    retval = 0;
  if (! test_specific ())
    retval = 0;
  int i;
  for (i = 1024; i <= 4096; i *= 2) {
    if (! time_sh (i))
      retval = 0;
    if (! time_em (i))
      retval = 0;
    if (! time_em64 (i))
      retval = 0;
    if (! time_em_mont (i))
      retval = 0;
    if (! time_encrypt (i))
      retval = 0;
  }
  if (! test_add_sub ())
    retval = 0;
  if (! test_mul_div ())
    retval = 0;
  if (retval) {
    print_time (1, "all", 64);
  } else {
    printf ("some test(s) failed\n");
  }
  return retval;
}

int main (int argc, char ** argv)
{
  if (wp_arith_test ())
    return 0;
  return 1;
}

#endif /* UNIT_TEST */


