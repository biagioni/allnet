/* dh.c: diffie-hellman elliptic-curve computations, as described in RFC 7748 */
/* the standard in RFC 7748 is little-endian, but allnet uses big-endian */
/* for testing compile with gcc -DTEST_ALLNET_DH -o dh dh.c wp_arith.c */
/* to follow the (wrong?) standard,
 * gcc -DTEST_ALLNET_DH -o dh -DRFC_7748_STD dh.c wp_arith.c */

#include <stdio.h>
#include <string.h>

#include "dh.h"
#include "wp_arith.h"

/* #define DH448_SIZE	56 */
#define DH448_BITS	(DH448_SIZE * 8)  /* 448 */
#define DH448_WORDS	(DH448_SIZE / 8)  /* 7 */

static int zero_if_all_zeros (const char * data)
{
  int i;
  int r = 0;
  for (i = 0; i < DH448_SIZE; i++)
    r |= data [i];
  return ((r == 0) ? 0 : 1);
}

/* sets a to 2^448 - 2^224 - 1 */
static void prime_p (uint64_t * a)
{
  uint64_t two448minus1 [DH448_WORDS];
  wp_init (DH448_BITS, two448minus1, 0);  /* 0, aka 2^448 */
  wp_sub_int (DH448_BITS, two448minus1, 1);  /* 2^448 - 1 */
  uint64_t two224 [DH448_WORDS];
  wp_init (DH448_BITS, two224, 1);  /* 1 */
  int i;
  for (i = 0; i < 224; i++)  /* sets to 2^224 */
    wp_shift_left (DH448_BITS, two224);
  if (wp_sub (DH448_BITS, a, two448minus1, two224))
    printf ("error: prime initialization borrowed\n");
  /* printf ("prime p is %s\n", wp_itox (DH448_BITS, a)); */
}

static void cswap(int do_swap, uint64_t * a, uint64_t * b)
{
  uint64_t swap_mask = (((uint64_t) 0) - ((uint64_t) do_swap));
  int i;
  for (i = 0; i < DH448_WORDS; i++) {
    uint64_t dummy = swap_mask & (a [i] ^ b [i]);
    a [i] ^= dummy;
    b [i] ^= dummy;
  }
}

/* all arrays must have size DH448_SIZE.
 * k is the scalar, u is the u-coordinate.
 * given a u5 (the last byte is 5 and the rest are 0) and a random secret r,
 * each party sends to the other side allnet_x448(r, u5).
 * upon receiving from the other side an authenticated s, each side
 * computes the shared secret key as k = allnet_x448(r, s).
 * the call returns 0 if the result is 0, and 1 otherwise */
int allnet_x448 (const char * k_bytes, const char * u_bytes, char * result)
{
  uint64_t k [DH448_WORDS];
  wp_from_bytes (DH448_BITS, k, DH448_SIZE, k_bytes);
  uint64_t u [DH448_WORDS];
  wp_from_bytes (DH448_BITS, u, DH448_SIZE, u_bytes);
  uint64_t p [DH448_WORDS];
  prime_p (p);
  memset (result, 0, DH448_SIZE);

  uint64_t x1 [DH448_WORDS];
  wp_copy (DH448_BITS, x1, u);
  uint64_t x2 [DH448_WORDS];
  wp_init (DH448_BITS, x2, 1);
  uint64_t z2 [DH448_WORDS];
  wp_init (DH448_BITS, z2, 0);
  uint64_t x3 [DH448_WORDS];
  wp_copy (DH448_BITS, x3, u);
  uint64_t z3 [DH448_WORDS];
  wp_init (DH448_BITS, z3, 1);
  int swap = 0;

  uint64_t shifted_k [DH448_WORDS];
  wp_copy (DH448_BITS, shifted_k, k);
  uint64_t a24 [DH448_WORDS];
  wp_init (DH448_BITS, a24, 39081);

  int t;
  for (t = DH448_BITS - 1; t >= 0; t--) {
    int k_t = wp_msb (DH448_BITS, shifted_k);
    wp_shift_left (DH448_BITS, shifted_k);
    swap ^= k_t;
    cswap (swap, x2, x3);
    cswap (swap, z2, z3);
    swap = k_t;

    uint64_t A [DH448_WORDS];
    wp_add_mod (DH448_BITS, A, x2, z2, p);
    uint64_t AA [DH448_WORDS];
    wp_multiply_mod (DH448_BITS, AA, A, A, p);  /* A^2 */
    uint64_t B [DH448_WORDS];
    wp_sub_mod (DH448_BITS, B, x2, z2, p);
    uint64_t BB [DH448_WORDS];
    wp_multiply_mod (DH448_BITS, BB, B, B, p);  /* B^2 */
    uint64_t E [DH448_WORDS];
    wp_sub_mod (DH448_BITS, E, AA, BB, p);
    uint64_t C [DH448_WORDS];
    wp_add_mod (DH448_BITS, C, x3, z3, p);
    uint64_t D [DH448_WORDS];
    wp_sub_mod (DH448_BITS, D, x3, z3, p);
    uint64_t DA [DH448_WORDS];
    wp_multiply_mod (DH448_BITS, DA, D, A, p);
    uint64_t CB [DH448_WORDS];
    wp_multiply_mod (DH448_BITS, CB, C, B, p);

    uint64_t DAplusCB [DH448_WORDS];
    wp_add_mod (DH448_BITS, DAplusCB, DA, CB, p);
    wp_multiply_mod (DH448_BITS, x3, DAplusCB, DAplusCB, p); /* (DA+CB)^2 */
    uint64_t DAminusCB [DH448_WORDS];
    wp_sub_mod (DH448_BITS, DAminusCB, DA, CB, p);
    uint64_t DAminusCBsquared [DH448_WORDS];
    wp_multiply_mod (DH448_BITS, DAminusCBsquared, DAminusCB, DAminusCB, p);
    wp_multiply_mod (DH448_BITS, z3, x1, DAminusCBsquared, p);
    wp_multiply_mod (DH448_BITS, x2, AA, BB, p);
    uint64_t a24E [DH448_WORDS];
    wp_multiply_mod (DH448_BITS, a24E, a24, E, p);
    /* 2020/01/04 note: in the errata to RFC 7748, a Pierre Laurent
     * on 2019/03/11 says to use BB instead of AA in the next three
     * lines of code.  The line-by-line analysis of the openssl code
     * (at the bottom of this file) shows openssl doing the same, so I
     * am using BB, although this screws up the RFC 7748 test vectors.
     * https://www.rfc-editor.org/errata_search.php?rfc=7748
     * so define RFC_7748_STD to use AA and have all the RFC 7748 test
     * vectors match, or leave it undefined to use the (presumably better) BB
     */
    uint64_t BBplusa24E [DH448_WORDS];  /* or AA + a24 * E */
#ifdef RFC_7748_STD   /* use AA instead of BB */
    wp_add_mod (DH448_BITS, BBplusa24E, AA, a24E, p);
#else /* use BB instead of AA, as per the errata to the RFC and as in openssl */
    wp_add_mod (DH448_BITS, BBplusa24E, BB, a24E, p);
#endif /* RFC_7748_STD */
    wp_multiply_mod (DH448_BITS, z2, E, BBplusa24E, p);
    
  }
  cswap (swap, x2, x3);
  cswap (swap, z2, z3);
  uint64_t pminus2 [DH448_WORDS];
  wp_copy (DH448_BITS, pminus2, p);
  wp_sub_int (DH448_BITS, pminus2, 2);
  uint64_t temp [(DH448_WORDS + 1) * 70];
  uint64_t z2powerpminus2 [DH448_WORDS];
  wp_exp_mod_montgomery (DH448_BITS, z2powerpminus2, z2, pminus2, p, temp);
  uint64_t r [DH448_WORDS];
  wp_multiply_mod (DH448_BITS, r, x2, z2powerpminus2, p);
  wp_to_bytes (DH448_BITS, r, DH448_SIZE, result);

  return zero_if_all_zeros (result);
}

/* turn a randomly-generated string into a value that can be used with x448
 * (decodeScalar448 in RFC 7748) */
void allnet_x448_make_valid (char * k)
{
  /* reverse the indices from RFC 7748 */
  k [0] |= 128;
  k [DH448_SIZE - 1] &= 252;
}

/* the special value 5 is used in the initial key generation */
void allnet_x448_five (char * five)
{
  memset (five, 0, DH448_SIZE);
  five [DH448_SIZE - 1] = 5;
}

#ifdef TEST_ALLNET_DH

/* from util.c */
void print_buffer (const void * vb, unsigned int count, const char * desc,
                   unsigned int max, int print_eol)
{
  const char * buffer = (const char *) vb;
  unsigned int i;
  if (desc != NULL)
    printf ("%s (%d bytes):", desc, count);
  else
    printf ("%d bytes:", count);
  if (buffer == NULL)
    printf ("(null)");
  else {
    for (i = 0; i < count && i < max; i++)
      printf (" %02x", buffer [i] & 0xff);
    if (i < count)
      printf (" ...");
  }
  if (print_eol)
    printf ("\n");
}

static int from_hex (int c)
{
  switch (c) {
  case '0': return 0;
  case '1': return 1;
  case '2': return 2;
  case '3': return 3;
  case '4': return 4;
  case '5': return 5;
  case '6': return 6;
  case '7': return 7;
  case '8': return 8;
  case '9': return 9;
  case 'a': case 'A': return 10;
  case 'b': case 'B': return 11;
  case 'c': case 'C': return 12;
  case 'd': case 'D': return 13;
  case 'e': case 'E': return 14;
  case 'f': case 'F': return 15;
  default:
    printf ("error: hex digit '%c' (%d)\n", c, c);
    return -1;
  }
}

static void make_big_endian (const char * input, char * result)
{
  const char * p = input + (strlen (input));  /* start from the end */
  if (((p - input) % 2) != 0)
    printf ("error: string has odd number of characters (%d)\n",
            (int)(p - input));
  int index = 0;
  while (p != input) {
    p -= 2;
    result [index++] = from_hex (p [0]) * 16 + from_hex (p [1]);
  }
}

static void test_swap (int s, char * a, char * b)
{
  uint64_t aa [DH448_WORDS];
  uint64_t bb [DH448_WORDS];
  wp_from_bytes (DH448_BITS, aa, DH448_SIZE, a);
  wp_from_bytes (DH448_BITS, bb, DH448_SIZE, b);
  printf ("before swap %d: %s,\n", s, wp_itox (DH448_BITS, aa));
  printf ("%s\n", wp_itox (DH448_BITS, bb));
  cswap (s, aa, bb);
  printf ("after swap %d: %s,\n", s, wp_itox (DH448_BITS, aa));
  printf ("%s\n", wp_itox (DH448_BITS, bb));
}

static void print_as_number_rec (uint64_t * a)
{
  if (wp_is_zero (DH448_BITS, a))
    return;
  uint64_t remainder = 0;
  int i;
  for (i = 0; i < DH448_WORDS; i++) {  /* divide by 10 */
    uint64_t high = (a [i] >> 32);
    uint64_t low = (a [i] & 0xffffffff);
    uint64_t high_remainder = ((remainder << 32) + high) % 10;
    uint64_t    high_result = ((remainder << 32) + high) / 10;
                  remainder = ((high_remainder << 32) + low) % 10;
    uint64_t     low_result = ((high_remainder << 32) + low) / 10;
    a [i] = (high_result << 32) + low_result;
  }
  print_as_number_rec (a);
  printf ("%d", (int)remainder);
}

static void print_as_number (char * n, const char * desc)
{
  uint64_t nn [DH448_WORDS];
  wp_from_bytes (DH448_BITS, nn, DH448_SIZE, n);
  printf ("%s: ", desc);
  print_as_number_rec (nn);
  printf ("\n");
}

int main (int argc, char ** argv)
{
  char test [DH448_SIZE];
  int i;
  for (i = 0; i < sizeof (test); i++)
    test [i] = i;
  print_as_number (test, "test");
  print_buffer (test, sizeof (test), "initial buffer", sizeof (test), 1);
  allnet_x448_make_valid (test);
  print_buffer (test, sizeof (test), "valid buffer", sizeof (test), 1);
  char five [DH448_SIZE];
  allnet_x448_five (five);
  print_buffer (five, sizeof (five), "five", 100, 1);
  print_as_number (five, "five");
  test_swap (1, test, five);
  test_swap (0, test, five);
  char result [DH448_SIZE];
  if (! allnet_x448 (test, five, result))
    printf ("allnet_x4489 (basic test) returned 0\n");
  print_buffer (result, sizeof (result), "result", 100, 1);

  printf ("\nRFC test 1:\n");
  char input_scalar_little_endian1 [] = "3d262fddf9ec8e88495266fea19a34d28882acef045104d0d1aae121700a779c984c24f8cdd78fbff44943eba368f54b29259a4f1c600ad3";
  char input_u_little_endian1 [] = "06fce640fa3487bfda5f6cf2d5263f8aad88334cbd07437f020f08f9814dc031ddbdc38c19c6da2583fa5429db94ada18aa7a7fb4ef8a086";
  char input_scalar1 [DH448_SIZE];
  char input_u1 [DH448_SIZE];
  make_big_endian (input_scalar_little_endian1, input_scalar1);
  allnet_x448_make_valid (input_scalar1);
  make_big_endian (input_u_little_endian1, input_u1);
#ifdef RFC_7748_STD   /* use the test vector from the RFC */
  char result_little_endian1 [] = "ce3e4ff95a60dc6697da1db1d85e6afbdf79b50a2412d7546d5f239fe14fbaadeb445fc66a01b0779d98223961111e21766282f73dd96b6f";
  char result1 [DH448_SIZE];
  make_big_endian (result_little_endian1, result1);
#else /* RFC_7748_STD */
  /* experimentally computed (by me, so only useful for regression) */
  char result1 [DH448_SIZE] =
   { 0x7e, 0xfa, 0x92, 0xd3, 0xee, 0xce, 0x02, 0xde,
     0x13, 0x21, 0xf0, 0x22, 0x9d, 0x18, 0xd9, 0x0f,
     0x08, 0x0c, 0x15, 0x8b, 0x70, 0x65, 0xb9, 0xc9,
     0x2f, 0xc0, 0x1f, 0x0c, 0xbc, 0x13, 0xba, 0xfb,
     0x0f, 0x83, 0xcc, 0x22, 0x6b, 0x3d, 0xe9, 0x5c,
     0x9d, 0x00, 0x8c, 0xfa, 0x5c, 0x86, 0xc2, 0x49,
     0x4b, 0x37, 0x07, 0xef, 0x1e, 0xb1, 0x20, 0x4a };
#endif /* RFC_7748_STD */
  print_buffer (input_scalar1, sizeof (input_scalar1), "input scalar1", 100, 1);
  print_buffer (input_u1, sizeof (input_u1), "input u1", 100, 1);
  print_as_number (input_scalar1, "input scalar1");
  print_as_number (input_u1, "input u1");
  if (! allnet_x448 (input_scalar1, input_u1, result))
    printf ("allnet_x4489 (RFC test 1) returned 0\n");
  print_buffer (result, sizeof (result), "result (RFC test 1)", 100, 1);
  if (memcmp (result, result1, sizeof (result)) != 0) {
    printf ("results do not match, expected\n");
    print_buffer (result1, sizeof (result1), "expect (RFC test 1)", 100, 1);
  }

  printf ("\nRFC test 2:\n");
  char input_scalar_little_endian2 [] = "203d494428b8399352665ddca42f9de8fef600908e0d461cb021f8c538345dd77c3e4806e25f46d3315c44e0a5b4371282dd2c8d5be309df";
  char input_u_little_endian2 [] = "0fbcc2f993cd56d3305b0b7d9e55d4c1a8fb5dbb52f8e9a1e9b6201b165d015894e56c4d3570bee52fe205e28a78b91cdfbde71ce8d157db";
  char input_scalar2 [DH448_SIZE];
  char input_u2 [DH448_SIZE];
  make_big_endian (input_scalar_little_endian2, input_scalar2);
  allnet_x448_make_valid (input_scalar2);
  make_big_endian (input_u_little_endian2, input_u2);
#ifdef RFC_7748_STD   /* use the test vector from the RFC */
  char result_little_endian2 [] = "884a02576239ff7a2f2f63b2db6a9ff37047ac13568e1e30fe63c4a7ad1b3ee3a5700df34321d62077e63633c575c1c954514e99da7c179d";
  char result2 [DH448_SIZE];
  make_big_endian (result_little_endian2, result2);
#else /* RFC_7748_STD */
  /* experimentally computed (by me, so only useful for regression) */
  char result2 [DH448_SIZE] =
   { 0xa5, 0x05, 0x58, 0x9f, 0x61, 0x2c, 0xd8, 0xe5,
     0x03, 0x84, 0xc1, 0x22, 0x58, 0x01, 0xbd, 0x63,
     0x40, 0x79, 0x80, 0x15, 0x64, 0x4b, 0x14, 0xdc,
     0xc0, 0xb4, 0x20, 0x1a, 0xab, 0x4a, 0x36, 0x48,
     0x45, 0x7c, 0x4a, 0xcc, 0x10, 0x7e, 0x8d, 0xb0,
     0x64, 0x33, 0x30, 0x4d, 0x9b, 0x90, 0x91, 0x08,
     0xd4, 0xca, 0x72, 0xd2, 0x6f, 0xac, 0x77, 0xb9 };
#endif /* RFC_7748_STD */
  print_buffer (input_scalar2, sizeof (input_scalar2), "input scalar2", 100, 1);
  print_buffer (input_u2, sizeof (input_u2), "input u2", 100, 1);
  print_as_number (input_scalar2, "input scalar2");
  print_as_number (input_u2, "input u2");
  if (! allnet_x448 (input_scalar2, input_u2, result))
    printf ("allnet_x4489 (RFC test 2) returned 0\n");
  print_buffer (result, sizeof (result), "result (RFC test 2)", 100, 1);
  if (memcmp (result, result2, sizeof (result)) != 0) {
    printf ("results do not match, expected\n");
    print_buffer (result2, sizeof (result2), "expect (RFC test 2)", 100, 1);
  }

  printf ("\nRFC test 3:\n");
  char k3 [DH448_SIZE];
  char u3 [DH448_SIZE];
  allnet_x448_five (k3);
  allnet_x448_five (u3);
  allnet_x448_make_valid (k3);
#ifdef RFC_7748_STD   /* use the test vector from the RFC */
  char result_little_endian3 [] = "3f482c8a9f19b01e6c46ee9711d9dc14fd4bf67af30765c2ae2b846a4d23a8cd0db897086239492caf350b51f833868b9bc2b3bca9cf4113";
  char result3 [DH448_SIZE];
  make_big_endian (result_little_endian3, result3);
#else /* RFC_7748_STD */
  /* experimentally computed (by me, so only useful for regression) */
  char result3 [DH448_SIZE] =
   { 0x83, 0x62, 0xeb, 0xff, 0x83, 0xfe, 0xee, 0x31,
     0x82, 0xfa, 0x0e, 0xc0, 0x1a, 0x6e, 0x18, 0x88,
     0xa7, 0x7e, 0x4a, 0xd0, 0x4d, 0xa9, 0x93, 0x92,
     0x50, 0xac, 0x64, 0x74, 0xaf, 0xe9, 0xa4, 0xd8,
     0xa0, 0xbf, 0x43, 0x3b, 0x31, 0x79, 0x81, 0xf5,
     0xcd, 0x24, 0x99, 0x1e, 0xe1, 0x00, 0xaf, 0xd7,
     0x63, 0x0a, 0x1f, 0x12, 0x25, 0x4e, 0xb7, 0x4c };
#endif /* RFC_7748_STD */
  if (! allnet_x448 (k3, u3, result))
    printf ("allnet_x4489 (RFC test 3) returned 0\n");
  print_buffer (result, sizeof (result), "result (RFC test 3)", 100, 1);
  if (memcmp (result, result3, sizeof (result)) != 0) {
    printf ("results do not match, expected\n");
    print_buffer (result3, sizeof (result3), "expect (RFC test 3)", 100, 1);
  }

  printf ("\nRFC test 4:\n");  /* RFC 7748 section 6.2 */
  char a_a_little_endian [] = "9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b";
  char a_a [DH448_SIZE];
  make_big_endian (a_a_little_endian, a_a);
  allnet_x448_make_valid (a_a);
  char a_b_little_endian [] = "1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d";
  char a_b [DH448_SIZE];
  make_big_endian (a_b_little_endian, a_b);
  allnet_x448_make_valid (a_b);
  char u_five [DH448_SIZE];
  allnet_x448_five (u_five);
#ifdef RFC_7748_STD   /* use the test vectors from the RFC */
  char public_a_little_endian [] = "9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0";
  char public_a [DH448_SIZE];
  make_big_endian (public_a_little_endian, public_a);
  char public_b_little_endian [] = "3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b43027d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609";
  char public_b [DH448_SIZE];
  make_big_endian (public_b_little_endian, public_b);
  char shared_secret_little_endian [] = "07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282bb60c0b56fd2464c335543936521c24403085d59a449a5037514a879d";
  char shared_secret [DH448_SIZE];
  make_big_endian (shared_secret_little_endian, shared_secret);
#else /* RFC_7748_STD */
  /* experimentally computed (by me, so only useful for regression) */
  char public_a [DH448_SIZE] =
   { 0x29, 0xf2, 0x2c, 0xcd, 0x0c, 0x20, 0xd9, 0x40,
     0xaa, 0x27, 0xaf, 0xb3, 0x2e, 0x02, 0x4e, 0xa6,
     0x97, 0xf6, 0xd4, 0xbb, 0x6e, 0x40, 0xbb, 0x2a,
     0x0f, 0xfe, 0x45, 0x34, 0x85, 0xeb, 0x5e, 0xe6,
     0xa2, 0x29, 0x24, 0x1e, 0x78, 0xdf, 0x5e, 0x0a,
     0x81, 0xef, 0x47, 0xd4, 0x82, 0x0f, 0xfb, 0x85,
     0x31, 0xe2, 0xcb, 0x79, 0x80, 0x53, 0x97, 0x6e };
  char public_b [DH448_SIZE] =
   { 0x7a, 0xcd, 0xab, 0xa6, 0x19, 0x48, 0x0a, 0x47,
     0xf0, 0xc0, 0x6e, 0x43, 0x0a, 0x8c, 0x4a, 0x27,
     0xd1, 0x4b, 0xa3, 0x41, 0x12, 0x09, 0x0e, 0x83,
     0xe4, 0x59, 0x01, 0xdc, 0x68, 0x88, 0x20, 0xba,
     0x54, 0x2f, 0x46, 0x09, 0x3c, 0xc5, 0x9e, 0x2f,
     0x89, 0xea, 0x56, 0x31, 0x96, 0x9d, 0xdc, 0x9c,
     0xa8, 0x15, 0x47, 0x04, 0xe2, 0xb0, 0xcc, 0x99 };
  char shared_secret [DH448_SIZE] =
   { 0x95, 0xca, 0x8d, 0x10, 0x39, 0xc2, 0xfd, 0xe4,
     0x40, 0x3f, 0xd0, 0x15, 0x1d, 0xfe, 0xf6, 0x48,
     0x10, 0xd4, 0x61, 0xdd, 0xa3, 0x12, 0x73, 0xe0,
     0x84, 0xe1, 0xfd, 0x82, 0x8d, 0x7a, 0xf2, 0x0a,
     0xdb, 0x1d, 0xef, 0xd2, 0xc8, 0x36, 0x4d, 0xad,
     0xbf, 0x9b, 0xef, 0x8e, 0xa1, 0xad, 0x9a, 0x60,
     0x37, 0xdd, 0x0e, 0x43, 0xf4, 0x92, 0xdc, 0x24 };
#endif /* RFC_7748_STD */
  char pk_a [DH448_SIZE];
  if (! allnet_x448 (a_a, u_five, pk_a))
    printf ("allnet_x4489 (RFC test 4, alice) returned 0\n");
  print_buffer (pk_a, sizeof (pk_a), "pk_a (RFC test 4)", 100, 1);
  if (memcmp (pk_a, public_a, sizeof (public_a)) != 0) {
    printf ("results do not match, expected\n");
    print_buffer (result3, sizeof (result3), "pk_a (RFC test 4)", 100, 1);
  }
  char pk_b [DH448_SIZE];
  if (! allnet_x448 (a_b, u_five, pk_b))
    printf ("allnet_x4489 (RFC test 4, alice) returned 0\n");
  print_buffer (pk_b, sizeof (pk_b), "pk_b (RFC test 4)", 100, 1);
  if (memcmp (pk_b, public_b, sizeof (public_b)) != 0) {
    printf ("results do not match, expected\n");
    print_buffer (result3, sizeof (result3), "pk_b (RFC test 4)", 100, 1);
  }
  char k_a [DH448_SIZE];
  if (! allnet_x448 (a_a, pk_b, k_a))
    printf ("allnet_x4489 (RFC test 4, alice 2) returned 0\n");
  char k_b [DH448_SIZE];
  if (! allnet_x448 (a_b, pk_a, k_b))
    printf ("allnet_x4489 (RFC test 4, bob 2) returned 0\n");
  if ((memcmp (k_a, k_b, sizeof (k_a)) != 0) ||
      (memcmp (k_a, shared_secret, sizeof (k_a)) != 0)) {
    printf ("RFC test 4, shared secrets do not match!\n");
    print_buffer (k_a, sizeof (k_a), "alice's 'shared' secret", 100, 1);
    print_buffer (k_b, sizeof (k_b), "bob's 'shared' secret", 100, 1);
    print_buffer (k_b, sizeof (k_b), "expected shared secret", 100, 1);
  } else {
    printf ("success: alice's and bob's shared secret are both:\n");
    print_buffer (k_a, sizeof (k_a), NULL, 100, 1);
  }

  printf ("\nusage test:\n");  /* RFC 7748 Sections 6.1/6.2, with own values */
  /* non-random a's, ok for testing the code */
  char a_alice [DH448_SIZE] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, };
  char a_bob [DH448_SIZE] = { 255, 254, 253, 252, 251, 250, 249, 248, 247, };
  allnet_x448_make_valid (a_alice);
  allnet_x448_make_valid (a_bob);
  char pk_alice [DH448_SIZE];
  char pk_bob [DH448_SIZE];
  if (! allnet_x448 (a_alice, u_five, pk_alice))
    printf ("allnet_x4489 (usage test, alice) returned 0\n");
  if (! allnet_x448 (a_bob, u_five, pk_bob))
    printf ("allnet_x4489 (usage test, bob) returned 0\n");
  char k_alice [DH448_SIZE];
  if (! allnet_x448 (a_alice, pk_bob, k_alice))
    printf ("allnet_x4489 (usage test, alice 2) returned 0\n");
  char k_bob [DH448_SIZE];
  if (! allnet_x448 (a_bob, pk_alice, k_bob))
    printf ("allnet_x4489 (usage test, bob 2) returned 0\n");
  if (memcmp (k_alice, k_bob, sizeof (k_alice)) != 0) {
    printf ("RFC usage test, shared secrets do not match!\n");
    print_buffer (k_alice, sizeof (k_alice), "alice's 'shared' secret", 100, 1);
    print_buffer (k_bob, sizeof (k_bob), "bob's 'shared' secret", 100, 1);
  } else {
    printf ("success: alice's and bob's shared secret are both:\n");
    print_buffer (k_alice, sizeof (k_alice), NULL, 100, 1);
  }
  
}

#endif /* TEST_ALLNET_DH */

/*
comparison of the loop of
  https://github.com/openssl/openssl/blob/master/crypto/ec/curve25519.c
(x25519_scalar_mult_generic) with the loop from RFC 7748

unsigned b = 1 & (e[pos / 8] >> (pos & 7)); k_t = (k >> t) & 1
swap ^= b;                                  swap ^= k_t
                                            // Conditional swap; see text below.
fe_cswap(x2, x3, swap);                     (x_2, x_3) = cswap(swap, x_2, x_3)
fe_cswap(z2, z3, swap);                     (z_2, z_3) = cswap(swap, z_2, z_3)
swap = b;                                   swap = k_t

fe_sub(tmp0, x3, z3);                       D = x_3 - z_3    tmp0 is D
fe_sub(tmp1, x2, z2);                       B = x_2 - z_2    tmp1 is B
fe_add(x2, x2, z2);                         A = x_2 + z_2    x2 is A
fe_add(z2, x3, z3);                         C = x_3 + z_3    z2 is C
fe_mul(z3, tmp0, x2);                       DA = D * A       z3 is DA
fe_mul(z2, z2, tmp1);                       CB = C * B       z2 is now CB
fe_sq(tmp0, tmp1);                          BB = B^2         tmp0 is now BB
fe_sq(tmp1, x2);                            AA = A^2         tmp1 is now AA
fe_add(x3, z3, z2);                         <int> = DA + CB  x3 is DA+CB
fe_sub(z2, z3, z2);                         <int> = DA - CB  z2 is DA-CB
fe_mul(x2, tmp1, tmp0);                     x_2 = AA * BB
fe_sub(tmp1, tmp1, tmp0);                   E = AA - BB      tmp1 is now E
fe_sq(z2, z2);                              <int> = (DA - CB)^2  z2 is (DA-CB)^2
fe_mul121666(z3, tmp1);                     <int> = a24 * E
fe_sq(x3, x3);                              x3 = (DA + CB)^2
fe_add(tmp0, tmp0, z3);                     AA/BB + a24 * E  *openssl uses BB!*
fe_mul(z3, x1, z2);                         z_3 = x_1 * (DA - CB)^2
fe_mul(z2, tmp1, tmp0);                     z_2 = E * (AA/BB + a24 * E)
*/

