/* wp_rsa.c: rsa encryption and decryption */

/* this library is named for W. Wesley Peterson, since this library is
 * loosely based on code he wrote before passing away in 2009 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <time.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>

#include "wp_rsa.h"
#include "wp_arith.h"
/* for random number generation in the absence of /dev/[u]random may use AES */
#include "wp_aes.h"
#include "sha.h"

typedef uint64_t rsa_int    [WP_RSA_MAX_KEY_WORDS ];
typedef uint64_t rsa_half   [WP_RSA_HALF_KEY_WORDS];
typedef uint64_t rsa_double [WP_RSA_MAX_KEY_WORDS * 2];

/* #define USE_EXP_MOD64 */
#define USE_EXP_MOD_MONTGOMERY

#ifdef USE_EXP_MOD_MONTGOMERY
typedef uint64_t rsa_temp      [(WP_RSA_MAX_KEY_WORDS  + 1) * 70];
typedef uint64_t rsa_temp_half [(WP_RSA_HALF_KEY_WORDS + 1) * 70];
#endif /* USE_EXP_MOD_MONTGOMERY */

#ifdef USE_EXP_MOD64
typedef uint64_t rsa_temp      [WP_RSA_MAX_KEY_WORDS  * 65];
typedef uint64_t rsa_temp_half [WP_RSA_HALF_KEY_WORDS * 65];
#endif /* USE_EXP_MOD64 */

/* get the public key part of the key pair */
wp_rsa_key wp_rsa_get_public_key (wp_rsa_key_pair * key)
{
  wp_rsa_key result;
  result.nbits = key->nbits;
  wp_copy (key->nbits, result.n, key->n);
  result.e = key->e;
  return result;
}

static int is_set_bit (char * a, int bitpos)
{
  int bytepos = bitpos / 8;
  if (a [bytepos] & (1 << (bitpos % 8)))
    return 1;
  return 0;
}

static void set_bit (char * a, int bitpos)
{
  int bytepos = bitpos / 8;
  a [bytepos] |= (1 << (bitpos % 8));
}

static void clear_bit (char * a, int bitpos)
{
  int bytepos = bitpos / 8;
  a [bytepos] &= (~ (1 << (bitpos % 8)));
}

static uint64_t bytes_to_uint64 (const char * data)
{
  return ((((uint64_t) (data [0] & 0xff)) << 56) |
          (((uint64_t) (data [1] & 0xff)) << 48) |
          (((uint64_t) (data [2] & 0xff)) << 40) |
          (((uint64_t) (data [3] & 0xff)) << 32) |
          (((uint64_t) (data [4] & 0xff)) << 24) |
          (((uint64_t) (data [5] & 0xff)) << 16) |
          (((uint64_t) (data [6] & 0xff)) <<  8) |
          (((uint64_t) (data [7] & 0xff))      ));
}

static void uint64_to_bytes (char * result, uint64_t data)
{
  result [0] = (data >> 56) & 0xff;
  result [1] = (data >> 48) & 0xff;
  result [2] = (data >> 40) & 0xff;
  result [3] = (data >> 32) & 0xff;
  result [4] = (data >> 24) & 0xff;
  result [5] = (data >> 16) & 0xff;
  result [6] = (data >>  8) & 0xff;
  result [7] = (data      ) & 0xff;
}

static int is_power_two (int n)
{
  if ((n & (n - 1)) != 0)
    return 0;
  return 1;
}

/* note -- only works for powers of two */
static int root (int n)
{
  if (! is_power_two (n)) {
    printf ("root computation only implemented for powers of two, not %d/%x\n",
            n, n);
    exit (1);
  }
  int result = 1;
  while (result * result < n)
    result += result;
  if (result * result != n) {
    printf ("root computation only implemented for even powers of two, not %d/%x\n",
            n, n);
    exit (1);
  }
  return result;
}

int compute_sieve (int limit, char * sieve,
                   int * results, int rsize)
{
  int outer;
  for (outer = 0; outer < limit; outer++)
    set_bit (sieve, outer);
  clear_bit (sieve, 0);
  clear_bit (sieve, 1);
  int rlimit = root (limit);
#ifdef DEBUG_PRINT
  printf ("root of %d is %d\n", limit, rlimit);
#endif /* DEBUG_PRINT */
  for (outer = 2; outer < rlimit; outer++) {
    int inner;
    for (inner = outer + outer; inner < limit; inner++) {
      if (inner % outer == 0)
        clear_bit (sieve, inner);
    }
  }
  int count = 0;
  int i;
  for (i = 0; i < limit; i++) {
    if (is_set_bit (sieve, i)) {
      if ((results != NULL) && (count < rsize))
        results [count] = i;
      count++;
    }
  }
  return count;
}

static int read_all_or_none (char * fname, char * buffer, int bsize)
{
  int fd = open (fname, O_RDONLY);
  if (fd < 0) {
    if (strcmp (fname, "/dev/random"))
      perror ("open /dev/random");
    else
      perror ("open /dev/urandom");
    return 0;
  }
  ssize_t n;
  int total = 0;
  do {
    n = read (fd, buffer + total, bsize - total);
    if (n < 0)
      return -1;
    total += n;
  } while (total < bsize);
  close (fd);
  return total;
}

#define RANDOM_BANK_AES_KEY_SIZE	32
  /* random_bank may be initialized by caller */
static char random_bank [RANDOM_BANK_AES_KEY_SIZE];
static uint64_t random_init = 0; /* set to 1 if initialized, then incremented */

/* used if and only if /dev/random and /dev/urandom are not available 
 * buffer should contain bsize truly random bytes */
void wp_rsa_randomize (char * buffer, int bsize)
{
  if (bsize >= RANDOM_BANK_AES_KEY_SIZE)
    memcpy (random_bank, buffer, RANDOM_BANK_AES_KEY_SIZE);
  else
    memcpy (random_bank, buffer, bsize);
  random_init++;  /* if it was 0, set to 1, but in any case, increment */
}

/* pure_random is 1 for /dev/random, 0 for /dev/urandom */
/* returns 1 for success, 0 for failure */
static int read_n_random_bytes (char * buffer, int bsize, int pure_random)
{
  int offset = 0;
  if (pure_random) {
/* man 4 random suggests reading at most 32 bytes from /dev/random,
 * which gives 256 truly random bits.  The rest we read from /dev/urandom.
 * This gives much faster key generation in case of limited sources
 * of randomness, hopefully without loss of security */
    if (bsize > 32)
      offset = 32;
    else
      offset = bsize;
    /* printf ("waiting for %d purely random bytes...\n", offset); */
    if (! read_all_or_none ("/dev/random", buffer, offset))
      return 0;
    if (offset >= bsize)
      return 1;
  }
/* if pure_random, we read all but the first 32 bytes from /dev/urandom.
 * otherwise, offset is zero and we read all of the bytes from /dev/urandom */
  if (! read_all_or_none ("/dev/urandom", buffer + offset, bsize - offset))
    return 0;
  return 1;
}

/* #define PREDICTABLE_RANDOM   used for repeatability when debugging */
static void init_random (char * buffer, int bsize, int pure_random,
                         char * rbuffer, int rsize)
{
  if ((rsize > 0) && (rbuffer != NULL)) {   /* note rsize may be < 0 */
    if (rsize > bsize)  /* only need bsize bytes */
      rsize = bsize;
    memcpy (buffer, rbuffer, rsize);
    if (rsize >= bsize)  /* done */
      return;
    bsize -= rsize;  /* still need to generate bsize - rsize bytes */
    buffer += rsize; /* beginning at buffer + rsize */
  }
#ifdef PREDICTABLE_RANDOM
pure_random = 0;
#endif /* PREDICTABLE_RANDOM */
  /* time_t start_time = time (NULL); */
  if (! read_n_random_bytes (buffer, bsize, pure_random)) {
    if (random_init) {   /* use AES in counter mode with random_bank as key */
      printf ("warning: less randomness available, key may be less secure\n");
      int n = 0;
      while (n < bsize) {
        char in [WP_AES_BLOCK_SIZE];
        char out [WP_AES_BLOCK_SIZE];
        uint64_to_bytes (in, random_init++);
        wp_aes_encrypt_block (RANDOM_BANK_AES_KEY_SIZE, random_bank, in, out);
        int byte_count = sizeof (out);
        if (byte_count > bsize - n)
          byte_count = bsize - n;
        memcpy (buffer + n, out, byte_count);
        n += byte_count;
      }
    } else {
      exit (1);
    }
  }
  /* if (pure_random)
    printf ("...done in %ld seconds\n", time (NULL) - start_time); */
#ifdef PREDICTABLE_RANDOM
  printf ("warning: non-random key is very insecure, use only for debugging\n");
  /* debugging */
  static int call_count = 1;
  int i;
  for (i = 0; i < bsize; i++)
    buffer [i] = 150 - i - call_count;
  call_count++;
#endif /* PREDICTABLE_RANDOM */
}

/* http://en.wikipedia.org/wiki/Fermat_primality_test */
static int composite_test_fermat (int nbits, const uint64_t * potential_prime,
                                  const uint64_t * a)
{
  rsa_half potential_prime_minus_one;
  wp_copy (nbits, potential_prime_minus_one, potential_prime);
  wp_sub_int (nbits, potential_prime_minus_one, 1);
  rsa_half em;
#ifdef USE_EXP_MOD_MONTGOMERY
  rsa_temp_half temp;
  wp_exp_mod_montgomery (nbits, em, a, potential_prime_minus_one,
                         potential_prime, temp);
#else /* USE_EXP_MOD_MONTGOMERY */
#ifdef USE_EXP_MOD64
  rsa_temp_half temp;
  wp_exp_mod64 (nbits, em, a, potential_prime_minus_one, potential_prime, temp);
#else /* USE_EXP_MOD64 */
  rsa_half temp;
  wp_exp_mod (nbits, em, a, potential_prime_minus_one, potential_prime, temp);
#endif /* USE_EXP_MOD64 */
#endif /* USE_EXP_MOD_MONTGOMERY */
  rsa_half one;
  wp_init (nbits, one, 1);
  if (wp_compare (nbits, one, em) == 0)
    return 0;   /* potentially prime */
#ifdef DEBUG_PRINT
  printf ("%s^", wp_itox (nbits, a));
  printf ("%s = ", wp_itox (nbits, potential_prime_minus_one));
  printf ("%s mod ", wp_itox (nbits, em));
  printf ("%s (so composite)\n", wp_itox (nbits, potential_prime));
#endif /* DEBUG_PRINT */
  return 1;     /* definitely not prime */
}

/* http://en.wikipedia.org/wiki/Miller-Rabin_primality_test */
static int composite_test_miller_rabin (int nbits,
                                        const uint64_t * potential_prime,
                                        uint64_t * a)
{
  rsa_half potential_prime_minus_one;
  wp_copy (nbits, potential_prime_minus_one, potential_prime);
  wp_sub_int (nbits, potential_prime_minus_one, 1);
  rsa_half d;
  wp_copy (nbits, d, potential_prime_minus_one);
  int shift = 0;
  while ((shift < nbits) && (wp_is_even (nbits, d))) {
    wp_shift_right (nbits, d);
    shift++;
  }
  rsa_half x;
#ifdef USE_EXP_MOD_MONTGOMERY
  rsa_temp_half temp;
  wp_exp_mod_montgomery (nbits, x, a, d, potential_prime, temp);
#else /* USE_EXP_MOD_MONTGOMERY */
#ifdef USE_EXP_MOD64
  rsa_temp_half temp;
  wp_exp_mod64 (nbits, x, a, d, potential_prime, temp);
#else /* USE_EXP_MOD64 */
  rsa_half temp;
  wp_exp_mod (nbits, x, a, d, potential_prime, temp);
#endif /* USE_EXP_MOD64 */
#endif /* USE_EXP_MOD_MONTGOMERY */
  rsa_half one;
  wp_init (nbits, one, 1);
  rsa_half p_minus_one;
  wp_copy (nbits, p_minus_one, potential_prime);
  wp_sub_int (nbits, p_minus_one, 1);
  if ((wp_compare (nbits, x, one) == 0) ||
      (wp_compare (nbits, x, p_minus_one) == 0))
    return 0;    /* possibly prime */
  int i;
  for (i = 1; i < shift; i++) {
    rsa_half res;
    wp_multiply_mod (nbits, res, x, x, potential_prime);
    wp_copy (nbits, x, res);
    if (wp_compare (nbits, x, one) == 0)
      return 1;
    if (wp_compare (nbits, x, p_minus_one) == 0)
      return 0;  /* possibly prime */
  }
  return 0;
}

/* nbits should not exceed rsa_half */
static void rsa_mod (int nbits, uint64_t * n, uint64_t * mod)
{
  if (wp_compare (nbits, n, mod) >= 0) {
    rsa_int result;
    wp_init (nbits * 2, result, 0);
    wp_copy (nbits, result + (nbits / (8 * sizeof (uint64_t))), n);
    uint64_t * remainder;
    wp_div (nbits * 2, result, nbits, mod, NULL, &remainder);
    wp_copy (nbits, n, remainder);
  }
}

/* to and from must both have size nbits, and may be the same array */
static void rsa_int_from_bytes (int nbits, uint64_t * to, const char * from)
{
  int nwords = NUM_WORDS (nbits);
  int i;
  for (i = 0; i < nwords; i++)
    to [i] = bytes_to_uint64 (from + i * 8);
}

static void rsa_int_to_bytes (int nbits, char * to, uint64_t * from)
{
  int nwords = NUM_WORDS (nbits);
  int i;
  for (i = 0; i < nwords; i++)
    uint64_to_bytes (to + i * 8, from [i]);
}

/* http://en.wikipedia.org/wiki/Primality_test#Probabilistic_tests and
 * 2014/09/05 */
static int composite_test (int nbits, const uint64_t * potential_prime)
{
  rsa_half a;
  init_random ((char *) a, nbits / 8, 0, NULL, 0);
  /* a should have a value between 2 and potential_prime - 2); */
  rsa_half two;
  wp_init (nbits, two, 2);
  if (wp_compare (nbits, a, two) < 0)
    wp_add (nbits, a, a, two);
  rsa_half p_minus_two;
  wp_copy (nbits, p_minus_two, potential_prime);
  wp_sub_int (nbits, p_minus_two, 2);
  rsa_mod (nbits, a, p_minus_two);
  if (composite_test_fermat (nbits, potential_prime, a))
    return 1;  /* definitely not prime */
  if (composite_test_miller_rabin (nbits, potential_prime, a))
    return 1;  /* definitely not prime */
  return 0;    /* possibly prime */
}

static int is_prime (int nbits, const uint64_t * n, int iterations)
{
#ifdef DEBUG_PRINT
  printf ("is_prime (%s) ", wp_itox (nbits, n));
#endif /* DEBUG_PRINT */
  static int sieve_size = 0;
  static char * sieve = NULL;
  if ((sieve_size == 0) || (sieve == NULL)) {
    sieve_size = 262144;
    sieve = malloc (sieve_size / 8);
    compute_sieve (sieve_size, sieve, NULL, 0);
  }
  int i;
  for (i = 2; i < sieve_size; i++) {
#define USE_MULTIPLE_FOR_SMALL_PRIMES
#ifdef USE_MULTIPLE_FOR_SMALL_PRIMES
    if ((is_set_bit (sieve, i)) &&
        (wp_multiple_of_int (nbits, n, i)))
      return 0;
#else /* USE_MULTIPLE_FOR_SMALL_PRIMES */
    if (is_set_bit (sieve, i)) {
      rsa_half divisor;
      wp_init (nbits, divisor, i);
      rsa_int dividend;
      wp_extend (nbits * 2, dividend, nbits, n);
      uint64_t * quotient;
      uint64_t * modulo;
      wp_div (nbits * 2, dividend, nbits, divisor, &quotient, &modulo);
#ifdef DEBUG_PRINT
      if (wp_is_zero (nbits, modulo))
        printf (" ==> 0 (%d)\n", i);
#endif /* DEBUG_PRINT */
      if (wp_is_zero (nbits, modulo))
        return 0;
    }
#endif /* USE_MULTIPLE_FOR_SMALL_PRIMES */
  }
  for (i = 0; i < iterations; i++) {
    if (composite_test (nbits, n)) {
#ifdef DEBUG_PRINT
      printf ("composite_test returned true on trial %d of %d\n", i, nbits);
#else /* DEBUG_PRINT */
      if (i > 0)   /* if it is composite, usually trial 0 finds it */
        printf ("composite_test returned true on trial %d of %d\n", i, nbits);
#endif /* DEBUG_PRINT */
      return 0;
    }
  }
#ifdef DEBUG_PRINT
  printf (" ==> 1\n");
#endif /* DEBUG_PRINT */
  return 1;
}

#if 0  /* overly complicated, now we just set the top bits of p and q  */
static void binary_mul (int nbits, uint64_t * n, int power_two)
{
  while (power_two-- > 0)
    wp_shift_left (nbits, n);
}

/* http://en.wikipedia.org/wiki/RSA_%28cryptosystem%29#Faulty_key_generation
    if p − q, for instance is less than 2n^(1/4), solving for p and
    q is trivial.
 * n^1/4 = 2^(nbits/2), so we test for |p - q| < 2^(nbits/2 + 1)
 * if they are too close, result is changed to be farther away.
 */
static void avoid_being_too_close (int nbits, uint64_t * avoid,
                                   uint64_t * result)
{
  if (avoid == NULL)
    return;   /* nothing to avoid */

  rsa_half min;  /* minimum distance is 2^(nbits / 2 + 1) */
  wp_init (nbits, min, 1);
  binary_mul (nbits, min, nbits / 2 + 1);

  if (wp_compare (nbits, avoid, result) > 0) {         /* p > q */
    rsa_half diff;
    wp_sub (nbits, diff, avoid, result);               /* diff = p - q */
    if (wp_compare (nbits, min, diff) >= 0)            /* diff < min   */
      wp_sub (nbits, result, result, min);             /* q -= min     */
  } else if (wp_compare (nbits, avoid, result) < 0) {  /* p < q */
    rsa_half diff;
    wp_sub (nbits, diff, result, avoid);               /* diff = q - p */
    if (wp_compare (nbits, min, diff) >= 0)            /* diff < min   */
      wp_add (nbits, result, result, min);             /* q += min     */
  } 
}
#endif /* 0 */

static void set_top_four_bits (int nbits, uint64_t * n, int value)
{
  uint64_t top = n [0];
  /* set every bit in value */
  top |= (((uint64_t) value) << 60);
  /* clear every bit not in value */
  top &= ((((uint64_t) value) << 60) | (~ (((uint64_t) 0xf) << 60)));
  n [0] = top;
}

/* the first four bits are always set to either 5 or 7, so
 * p and q are at least 2^(nbits/2+1) apart
 * http://en.wikipedia.org/wiki/RSA_%28cryptosystem%29#Faulty_key_generation
    if p − q, for instance is less than 2n^(1/4), solving for p and
    q is trivial.
    Furthermore, if either p − 1 or q − 1 has only small prime factors,
    n can be factored quickly
 * security level is 1 for normal usage -- it defines the maximum number of
 * calls to test compositeness (which is slow)
 */
static void generate_prime (int nbits, uint64_t * bits, int init,
                            int security_level, uint64_t * result)
{
  wp_copy (nbits, result, bits);
  /* set the top 4 bits to 1111 for p, and 1101 for q */
  if (init == 0)
    set_top_four_bits (nbits, result, 0xf);
  else
    set_top_four_bits (nbits, result, 0xd);
#ifdef DEBUG_PRINT
  printf ("prime candidate is %" PRIx64 ".%" PRIx64 "\n",
          result [0], result [1]);
#endif /* DEBUG_PRINT */
  if (wp_is_even (nbits, result))
    wp_add_int (nbits, result, 1);
  while (! is_prime (nbits, result, security_level))
    wp_add_int (nbits, result, 2);
/* should we check whether it is a strong prime? Can we do it without
 * factoring?  https://en.wikipedia.org/wiki/Strong_prime
 * we can easily check whether x = 2q + 1 where q is prime, and also
 * whether q = 2r + 1 and r is prime, but it seems harder to check
 * whether p = a * s - 1 for a large prime s.
 */
/* if ((is_prime (x / 2)) && (is_prime (x / 4)))
    printf ("%d may be a strong prime\n", x);
 */
}

/* 2014/09/01: from
 * https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm#Modular_integers
        function inverse(a, n)
            t := 0;     newt := 1;    
            r := n;     newr := a;    
            while newr ≠ 0
                quotient := r div newr
                (t, newt) := (newt, t - quotient * newt) 
                (r, newr) := (newr, r - quotient * newr)
            if r > 1 then return "a is not invertible"
            if t < 0 then t := t + n
            return t
 */
static int inverse_mod (int nbits, const uint64_t * value,
                        const uint64_t * mod, uint64_t * result)
{
#ifdef DEBUG_PRINT
  printf ("inverse_mod (%d, %s, ", nbits, wp_itox (nbits, value));
  printf ("%s)\n", wp_itox (nbits, mod));
#endif /* DEBUG_PRINT */
  rsa_int t, newt, r, newr;
  wp_init (nbits, t, 0);
  wp_init (nbits, newt, 1);
  wp_copy (nbits, r, mod);
  wp_copy (nbits, newr, value);
  int ndouble = nbits * 2;
  rsa_double moddouble;
  wp_extend (ndouble, moddouble, nbits, mod);
  uint64_t debug_count = 1;
#ifdef DEBUG_PRINT
#endif /* DEBUG_PRINT */
  while (! wp_is_zero (nbits, newr)) {
    if (wp_compare (nbits, r, newr) <= 0) {
      printf ("%" PRId64 ": ", debug_count);
      printf ("t %s -> ", wp_itox (nbits, t));
      printf ("%s, ", wp_itox (nbits, newt));
      printf ("r %s -> ", wp_itox (nbits, r));
      printf ("%s\n", wp_itox (nbits, newr));
    }
    debug_count++;
#ifdef DEBUG_PRINT
#endif /* DEBUG_PRINT */
    rsa_double div_arg;
    wp_extend (ndouble, div_arg, nbits, r);
    uint64_t * qp;
    wp_div (ndouble, div_arg, nbits, newr, &qp, NULL);  /* qp = r / nrewr */

    rsa_double product1;
    wp_multiply (ndouble, product1, nbits, qp, newt);
#ifdef DEBUG_PRINT
    printf ("product1 %s\n", wp_itox (ndouble, product1));
#endif /* DEBUG_PRINT */
    /* the product may be greater than mod, so reduce it modulo mod */
    uint64_t * pm;
    wp_div (ndouble, product1, nbits, mod, NULL, &pm);
#ifdef DEBUG_PRINT
    printf ("productm %s\n", wp_itox (nbits, pm));
#endif /* DEBUG_PRINT */
    rsa_int x;
    wp_sub (nbits, x, t, pm);
    if (wp_compare (nbits, t, pm) < 0)   /* t < pm, add mod to x */
      wp_add (nbits, x, x, mod);
#ifdef DEBUG_PRINT
    if (wp_compare (nbits, x, mod) >= 0) {  /* result is negative */
      printf ("negative result   %s\n", wp_itox (nbits, x));
      printf ("even after adding %s\n", wp_itox (nbits, mod));
    exit (1);
    }
    printf ("  newt mod n %s\n", wp_itox (nbits, x));
#endif /* DEBUG_PRINT */
    wp_copy (nbits, t, newt);
    wp_copy (nbits, newt, x);

    /* since qp is r / newr and r and newr fit in nbits,
     * qp * newr = (r / newr) * newr also fits in nbits,
     * as does r - qp * newr (since r >= newr) */
    rsa_double product2;
    wp_multiply (ndouble, product2, nbits, qp, newr);
#ifdef DEBUG_PRINT
    if (! wp_is_zero (nbits, product2)) { /* check product2 fits in nbits */
      printf ("error: top %d bits of product2 are not all 0\n%s\n",
              nbits, wp_itox (nbits, product2));
      exit (1);
    }
#endif /* DEBUG_PRINT */
    rsa_double rfull;
    wp_extend (ndouble, rfull, nbits, r);
    rsa_double y;
    wp_sub (ndouble, y, rfull, product2);
    wp_copy (nbits, r, newr);
    wp_shrink (nbits, newr, ndouble, y);
  }
  rsa_int one;
  wp_init (nbits, one, 1);
  if (wp_compare (nbits, r, one) > 0) {
    printf ("%s is not invertible\n", wp_itox (nbits, value));
    return 0;
  }
  if (wp_compare (nbits, t, mod) > 0)   /* t is actually negative */
    wp_add (nbits, t, t, mod);

#ifdef DEBUG_PRINT
  printf ("inverse of %s/%d is ", wp_itox (nbits, value), nbits);
  printf ("%s mod ", wp_itox (nbits, t));
  printf ("%s\n", wp_itox (nbits, mod));
  if (wp_compare (nbits, t, mod) >= 0)
    printf ("error, t >= mod\n");
  else if (wp_compare (nbits, value, mod) >= 0)
    printf ("error, value >= mod\n");
  else {
    rsa_int test;
    wp_multiply_mod (nbits, test, t, value, mod);
    printf ("value * inverse mod mod is %s\n", wp_itox (nbits, test));
  }
#endif /* DEBUG_PRINT */
  wp_copy (nbits, result, t);
  return 1;
}

static int mod_is_zero (int nbits, uint64_t * a, int nhalf, uint64_t * b)
{
  rsa_double acopy;
  rsa_int bcopy;
  wp_extend (nbits * 2, acopy, nbits, a);
  wp_extend (nhalf * 2, bcopy, nhalf, b);
  uint64_t * remainder;
  wp_div (nbits * 2, acopy, nhalf * 2, bcopy, NULL, &remainder);
  return wp_is_zero (nhalf * 2, remainder);
}

#ifdef DEBUG_PRINT
#endif /* DEBUG_PRINT */
#define E_VALUE 65537                    /* e is 65537 = 2^16 + 1 */

#if WP_RSA_MAX_KEY_BITS < 32
#undef E_VALUE
#define E_VALUE 3                        /* < 32 bits, use e = 3 */
#endif /* WP_RSA_MAX_KEY_BITS < 32 */

int wp_rsa_generate_key_pair_e (int nbits, wp_rsa_key_pair * key, long int e,
                                int security_level, char * random, int rsize)
{
  if ((nbits > WP_RSA_MAX_KEY_BITS) || (! is_power_two (nbits))) {
    printf ("number of bits %d/0x%x should be a power of two <= %d\n",
            nbits, nbits, WP_RSA_MAX_KEY_BITS);
    return 0;
  }
  int count = 0;
  key->nbits = nbits;
  key->e = e;
#ifdef DEBUG_PRINT
  printf ("generating p and q\n");
#endif /* DEBUG_PRINT */
  /* since the randomness of /dev/urandom may decrease as we get more
   * random bits, generate the p and q candidates first before generating
   * the primes, since generating the primes may use more random bits, but
   * the true randomness of those values is not as essential as the
   * randomness of p and q */
  int half_bytes = (nbits / 2) / 8;
  rsa_half p_candidate;
  rsa_half q_candidate;
  init_random ((char *) p_candidate, half_bytes, 1, random, rsize);
  init_random ((char *) q_candidate, half_bytes, 1, random, rsize - half_bytes);
  rsa_int pfull, qfull;
  int do_over;
  int nhalf = nbits / 2;
  do {
    do_over = 0;
    generate_prime (nhalf, p_candidate, 0, security_level, key->p);
    generate_prime (nhalf, q_candidate, 1, security_level, key->q);
#ifdef DEBUG_PRINT
    printf ("p is %s\n", wp_itox (nbits / 2, key->p));
    printf ("q is %s\n", wp_itox (nbits / 2, key->q));
#endif /* DEBUG_PRINT */
    wp_extend (nbits, pfull, nbits / 2, key->p);
    wp_extend (nbits, qfull, nbits / 2, key->q);
    wp_multiply (nbits, key->n, nhalf, key->p, key->q);
#ifdef DEBUG_PRINT
    printf ("n %s = ", wp_itox (nbits, key->n));
    printf ("p %s * ", wp_itox (nhalf, key->p));
    printf ("q %s\n", wp_itox (nhalf, key->q));
#endif /* DEBUG_PRINT */
#define FASTER_PHI_COMPUTATION
#ifdef FASTER_PHI_COMPUTATION
    rsa_int sum;
    wp_add (nbits, sum, pfull, qfull);
    wp_sub_int (nbits, sum, 1);    /* sum = p + q - 1 */
    rsa_int phi;
    wp_sub (nbits, phi, key->n, sum);      /* phi = n - (p + q - 1) */
#else /* FASTER_PHI_COMPUTATION */
    rsa_half pmin1;
    wp_copy (nhalf, pmin1, key->p); 
    wp_sub_int (nhalf, pmin1, 1);
    rsa_half qmin1;
    wp_copy (nhalf, qmin1, key->q); 
    wp_sub_int (nhalf, qmin1, 1);
    rsa_int phi;
    wp_multiply (nbits, phi, nhalf, qmin1, pmin1);
#endif /* FASTER_PHI_COMPUTATION */
    rsa_half ehalf;
    int eint = (int)e;
    wp_init (nhalf, ehalf, eint);
    rsa_int efull;
    wp_init (nbits, efull, eint);
    if (mod_is_zero (nbits, phi, nhalf, ehalf)) {
      printf ("e %ld is a factor of phi %s, no inverse\n",
              e, wp_itox (nbits, phi));
      do_over = 1;
    } else if (! inverse_mod (nbits, efull, phi, key->d)) {
      printf ("no inverse for e\n");
      do_over = 1;
    }
    if (! do_over) {
      rsa_half pminus1;
      rsa_half qminus1;
      wp_copy (nhalf, pminus1, key->p);
      wp_copy (nhalf, qminus1, key->q);
      wp_sub_int (nhalf, pminus1, 1);
      wp_sub_int (nhalf, qminus1, 1);
      rsa_int dpfull;
      rsa_int dqfull;
      uint64_t * dp_value;
      uint64_t * dq_value;
      wp_copy (nbits, dpfull, key->d);
      wp_copy (nbits, dqfull, key->d);
      wp_div (nbits, dpfull, nhalf, pminus1, NULL, &dp_value);
      wp_div (nbits, dqfull, nhalf, qminus1, NULL, &dq_value);
      wp_copy (nhalf, key->dp, dp_value);
      wp_copy (nhalf, key->dq, dq_value);
      if (! inverse_mod (nhalf, key->q, key->p, key->qinv)) {
        printf ("no inverse for q\n");
        do_over = 1;
      } else if (nbits < 256) {
        printf ("dp %s, ", wp_itox (nhalf, key->dp));
        printf ("dq %s, ", wp_itox (nhalf, key->dq));
        printf ("qinv %s, ", wp_itox (nhalf, key->qinv));
        printf ("e %lx\n", e);
      }
    }
    if (! do_over) {
      char test [WP_RSA_MAX_KEY_BYTES];
      memset (test, 0, sizeof (test));
      test [nbits / 8 - 1] = 99;
      char testc [WP_RSA_MAX_KEY_BYTES];   /* cipher */
      char testp [WP_RSA_MAX_KEY_BYTES];   /* deciphered plaintext */
      wp_rsa_encrypt ((wp_rsa_key *) key, test, nbits / 8, testc, nbits / 8,
                      WP_RSA_PADDING_NONE);
      wp_rsa_decrypt (key, testc, nbits / 8, testp, nbits / 8,
                      WP_RSA_PADDING_NONE);
      if (memcmp (test, testp, nbits / 8) != 0) {
        printf ("found key that doesn't work, will try again:\n");
        printf ("n %s = ", wp_itox (nbits, key->n));
        printf ("p %s * ", wp_itox (nhalf, key->p));
        printf ("q %s\n", wp_itox (nhalf, key->q));
        do_over = 1;
      }
    }
    if (do_over) {  /* restart the search from p+1 and q+1 */
      wp_copy (nhalf, p_candidate, key->p);
      wp_add_int (nhalf, p_candidate, 1);
      wp_copy (nhalf, q_candidate, key->q);
      wp_add_int (nhalf, q_candidate, 1);
    } else {
#ifdef DEBUG_PRINT
      printf ("n %s = ", wp_itox (nbits, key->n));
      printf ("p %s * ", wp_itox (nhalf, key->p));
      printf ("q %s\n", wp_itox (nhalf, key->q));
      printf ("phi %s, ", wp_itox (nbits, phi));
      printf ("e %s, ", wp_itox (nhalf, ehalf));
      printf ("d %s\n", wp_itox (nbits, key->d));
#endif /* DEBUG_PRINT */
    }
    count++;
  } while (do_over);
  return count;
}

/* uses /dev/urandom to generate bits of the key
 * nbits should be a power of two <= WP_RSA_MAX_KEY_BITS
 * returns 1 if successful, and if so, fills in key
 * returns 0 if the number of bits > WP_RSA_MAX_KEY_BITS */
int wp_rsa_generate_key_pair (int nbits, wp_rsa_key_pair * key,
                              int security_level, char * random, int rsize)
{
  return wp_rsa_generate_key_pair_e (nbits, key, E_VALUE, security_level,
                                     random, rsize);
}

/* offset 0 refers to the most significant byte */
static void set_byte (int nbits, uint64_t * dest, int offset, int value)
{
/* printf ("set_byte (%d, %d, x%02x), ", nbits, offset, value); */
  int word = offset / 8;
  if (NUM_WORDS (nbits) <= word) {
    printf ("error in set_byte: %d %d %d\n", offset, word, nbits);
    exit (1);  /* serious error */
  }
  int shift = 56 - ((offset % 8) * 8);
/* printf ("shift %d\n", shift); */
  dest [word] &= (~ (((uint64_t) 0xff) << shift));        /* clear the byte */
  dest [word] |= (((uint64_t) (value & 0xff)) << shift);  /* set the byte */
/* printf ("  => %s\n", wp_itox (nbits, dest)); */
}

/* offset 0 refers to the most significant byte */
static int get_byte (int nbits, uint64_t * dest, int offset)
{
  int word = offset / 8;
  if (NUM_WORDS (nbits) <= word) {
    printf ("error in get_byte: %d %d %d\n", offset, word, nbits);
    exit (1);  /* serious error */
  }
  int shift = 56 - ((offset % 8) * 8);
/* printf ("shift %d\n", shift); */
  return ((dest [word] >> shift) & 0xff);
}

/* documented in appendix B.2.1 of RFC 3447 */
static void mgf1_sha1_mask (char * seed, int ssize, char * result, int rsize)
{
  memset (result, 0, rsize);
  if (ssize > WP_RSA_MAX_KEY_BYTES) {
    printf ("error: seed size %d, max %d\n", ssize, WP_RSA_MAX_KEY_BYTES);
    exit (1);   /* a serious error in the caller */
  }
  /* loop  \ceil (maskLen / hLen) - 1  times*/
  int floor = rsize / SHA1_SIZE;
  int limit = ((rsize % SHA1_SIZE) == 0) ? floor : (floor + 1);
  int i;
  for (i = 0; i < limit; i++) {
    char concat [WP_RSA_MAX_KEY_BYTES + 4 /* 32-bit integer size */ ];
    memset (concat, 0, sizeof (concat));
    memcpy (concat, seed, ssize);
    concat [ssize    ] = (i >> 24) & 0xff;
    concat [ssize + 1] = (i >> 16) & 0xff;
    concat [ssize + 2] = (i >>  8) & 0xff;
    concat [ssize + 3] = (i      ) & 0xff;
    char sha_result [SHA1_SIZE];
    sha1 (concat, ssize + 4, sha_result);
    int copy_size = SHA1_SIZE;
    if (rsize < (i + 1) * SHA1_SIZE) { /* copy less than sha1_size */
      if (rsize > i * SHA1_SIZE) /* copy what fits */
        copy_size = rsize - i * SHA1_SIZE;
      else
        copy_size = 0;
    }
    if (copy_size > 0)
      memcpy (result + i * SHA1_SIZE, sha_result, copy_size);
/* int outsize = i * SHA1_SIZE + copy_size;
printf (" sha1 (");
for (i = 0; i < ssize + 4; i++)
printf ("%02x.", concat [i] & 0xff);
printf (" / %d) ==> \n", ssize + 4);
for (i = 0; i < outsize; i++)
printf ("%02x.", result [i] & 0xff);
printf (" / %d\n", outsize); */
  }
/* printf (" mgf1_sha1 (");
for (i = 0; i < ssize; i++)
printf ("%02x.", seed [i] & 0xff);
printf (" /%d) ==> \n", ssize);
for (i = 0; i < rsize; i++)
printf ("%02x.", result [i] & 0xff);
printf (" /%d\n", rsize); */
}

static char sha1_of_empty_string [] =
{ 0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55,
  0xbf, 0xef, 0x95, 0x60, 0x18, 0x90, 0xaf, 0xd8, 0x07, 0x09 };
static char * default_sha1 = sha1_of_empty_string;

static int rsa_pad (int nbits, uint64_t * result, int rsize,
                    const char * data, int dsize, int padding)
{
  int nbytes = nbits / 8;
  if ((nbytes > rsize) || (dsize < 0))
    return 0;
  if (padding == WP_RSA_PADDING_NONE) {   /* do nothing (but check sizes) */
    if (nbytes != dsize) {
      printf ("error: WP_RSA_PADDING_NONE requires data size %d = key size %d\n",
              dsize, nbytes);
      return 0;
    }
    rsa_int_from_bytes (nbits, result, data);
    return dsize;
  }
  if (padding == WP_RSA_PADDING_VANILLA) {
    /* shift the payload all the way to the right, then precede it by a
     * 1 byte, and as many 0 bytes as needed to fill */
    if (dsize >= nbytes) {
      printf ("error: WP_RSA_PADDING_VANILLA needs at least one byte, %d %d\n",
              dsize, nbytes);
      return 0;
    }
    /* dsize < nbytes <= rsize */
    wp_init (nbits, result, 0);
    /* compute the byte offset within result of the first data byte */
    /* note, can't use char* cast if the machine is not big-endian */
    /* so instead, call set_byte */
    int byte_offset = nbytes - dsize;
    /* write the 1 byte */
    set_byte (nbits, result, byte_offset - 1, 1);
    /* write the data bytes */
    int i;
    for (i = 0; i < dsize; i++)
      set_byte (nbits, result, byte_offset + i, data [i]);
    return nbytes;
  }
  if (padding == WP_RSA_PADDING_PKCS1_OAEP) {   /* based on RFC 3447 sec 7.1.1 */
    if (dsize + WP_RSA_PADDING_PKCS1_OAEP_SIZE > nbytes) {
      printf ("error: WP_RSA_PADDING_PKCS1_OAEP requires %d bytes, %d %d\n",
              WP_RSA_PADDING_PKCS1_OAEP_SIZE, dsize, nbytes);
      return 0;
    }
    if ((WP_RSA_MAX_KEY_BYTES < SHA1_SIZE) || (WP_RSA_MAX_KEY_BYTES < nbytes)) {
      printf ("unable to PKCS1_OAEP pad with key <= %d / %d, requires 20\n",
              WP_RSA_MAX_KEY_BYTES, nbytes);
      return 0;
    }
    /* step 2.c: concatenate lhash, PS, a byte of 1, and the message */
    char * rb = (char *) result;  /* use rb as the buffer for step 2.c */
    memset (rb, 0, nbytes);           /* any uninitialized bytes are set to 0 */
    int db_offset = SHA1_SIZE + 1;   /* db/maskedDB is stored from here */
    int db_size = nbytes - db_offset;
    memcpy (rb + db_offset, default_sha1, SHA1_SIZE);
    /* constant 1 followed by the message is written at the end of rb */
    int data_index = nbytes - dsize;
    rb [data_index - 1] = 1;
    memcpy (rb + data_index, data, dsize);
    char * seed = rb + 1;   /* the seed goes in the 2nd to 11th byte of rb */
    init_random (seed, SHA1_SIZE, 0, NULL, 0);
/*
printf ("padding seed is %02x%02x%02x%02x%02x %02x%02x%02x%02x%02x\n",
seed [0] & 0xff, seed [1] & 0xff, seed [2] & 0xff, seed [3] & 0xff,
seed [4] & 0xff, seed [5] & 0xff, seed [6] & 0xff, seed [7] & 0xff,
seed [8] & 0xff, seed [9] & 0xff);
*/
    char mask [WP_RSA_MAX_KEY_BYTES];
    mgf1_sha1_mask (seed, SHA1_SIZE, mask, db_size);
    int i;
    for (i = db_offset; i < nbytes; i++)
      rb [i] ^= mask [i - db_offset];
/*
printf ("computing pad mask from bytes %d->%d of %02x%02x%02x%02x%02x...\n",
db_offset, db_offset + db_size, rb [0 + db_offset] & 0xff,
rb [1 + db_offset] & 0xff, rb [2 + db_offset] & 0xff,
rb [3 + db_offset] & 0xff, rb [4 + db_offset] & 0xff);
*/
    mgf1_sha1_mask (rb + db_offset, db_size, mask, SHA1_SIZE);
    for (i = 0; i < SHA1_SIZE; i++)
      seed [i] ^= mask [i];
/*
printf ("padding mask is %02x%02x%02x%02x%02x %02x%02x%02x%02x%02x\n",
mask [0] & 0xff, mask [1] & 0xff, mask [2] & 0xff, mask [3] & 0xff,
mask [4] & 0xff, mask [5] & 0xff, mask [6] & 0xff, mask [7] & 0xff,
mask [8] & 0xff, mask [9] & 0xff);
*/
    for (i = 0; i < rsize / sizeof (uint64_t); i++)
      result [i] = bytes_to_uint64 (rb + i * sizeof (uint64_t));
    return nbytes;
  }
  printf ("padding mode %d not implemented\n", padding);
  exit (1);
}

static int rsa_unpad (int nbits, char * result, int rsize,
                      uint64_t * data, int dsize, int padding)
{
  int nbytes = nbits / 8;
  int bytes_in_payload = -1;
  if (dsize != nbytes)
    return -1;
  if (padding == WP_RSA_PADDING_NONE) {
    if (rsize < dsize) {
      printf ("error: WP_RSA_PADDING_NONE requires rsize %d >= dsize %d\n",
              rsize, dsize);
      return -1;
    }
    rsa_int_to_bytes (nbits, result, data);
    return dsize;
  }
  if (padding == WP_RSA_PADDING_VANILLA) {
    if (nbytes > rsize + 1)
      return -1;
    rsa_int_to_bytes (nbits, result, data);
    int i;
    for (i = 0; i < nbytes; i++)
      if (result [i] != 0)
        break;
    if (i == nbytes)
      return 0;  /* empty payload */
    if (result [i] != 1) {
      printf ("result [%d] is %d\n", i, result [i] & 0xff);
      return -1;  /* padding error */
    }
    int data_start = i + 1;
    bytes_in_payload = nbytes - data_start;
    memmove (result, result + data_start, bytes_in_payload);
    memset (result + bytes_in_payload, 0, rsize - bytes_in_payload);
    return bytes_in_payload;
  }
  if (padding == WP_RSA_PADDING_PKCS1_OAEP) { /* based on RFC 3447 sec 7.1.2 */
    if (nbytes > rsize + WP_RSA_PADDING_PKCS1_OAEP_SIZE)
      return -1;
    /* if we get a bad result, we should still do a complete check to
     * avoid giving information to someone who can observe our timings.
     * so don't return right away, just set bad_result to 1 */
    int bad_result = 0;
    memset (result, 0, rsize);
    /* step 3.b: separate Y, seed, and maskedDB */
    char * datab = (char *) data;
    int i;
    for (i = 0; i < rsize / sizeof (uint64_t); i++)
      uint64_to_bytes (datab + i * sizeof (uint64_t), data [i]);
    if (*datab != 0) {  /* step 3.g */
      printf ("unpadding PKCS1_OAEP: byte 0 %d, should be 0\n", *datab);
      printf ("word is %016" PRIx64 "\n", *data);
      bad_result = 1;
    }
    char * seed = datab + 1;  /* the seed is in the 2nd to 21st byte of datab */
    int db_offset = SHA1_SIZE + 1;   /* db/maskedDB is stored from here */
    int db_size = nbytes - db_offset;
    char mask [WP_RSA_MAX_KEY_BYTES];   /* step 3.c and 3.d */
/*
printf ("computing unpad mask from bytes %d->%d of %02x%02x%02x%02x%02x...\n",
db_offset, db_offset + db_size, datab [0 + db_offset] & 0xff,
datab [1 + db_offset] & 0xff, datab [2 + db_offset] & 0xff,
datab [3 + db_offset] & 0xff, datab [4 + db_offset] & 0xff);
*/
    mgf1_sha1_mask (datab + db_offset, db_size, mask, SHA1_SIZE);
/*
printf ("unpad mask is %02x%02x%02x%02x%02x %02x%02x%02x%02x%02x\n",
mask [0] & 0xff, mask [1] & 0xff, mask [2] & 0xff, mask [3] & 0xff,
mask [4] & 0xff, mask [5] & 0xff, mask [6] & 0xff, mask [7] & 0xff,
mask [8] & 0xff, mask [9] & 0xff);
*/
    for (i = 0; i < SHA1_SIZE; i++)
      seed [i] ^= mask [i];
/*
printf ("seed is %02x%02x%02x%02x%02x %02x%02x%02x%02x%02x\n",
seed [0] & 0xff, seed [1] & 0xff, seed [2] & 0xff, seed [3] & 0xff,
seed [4] & 0xff, seed [5] & 0xff, seed [6] & 0xff, seed [7] & 0xff,
seed [8] & 0xff, seed [9] & 0xff);
*/
    mgf1_sha1_mask (seed, SHA1_SIZE, mask, db_size);  /* step 3.e */
    for (i = db_offset; i < nbytes; i++)                     /* step 3.f */
      datab [i] ^= mask [i - db_offset];
    char check_hash [SHA1_SIZE];
    memcpy (check_hash, default_sha1, SHA1_SIZE);
    if (memcmp (check_hash, datab + db_offset, SHA1_SIZE) != 0) {
#ifdef DEBUG_PRINT
      printf ("unpadding PKCS1_OAEP: hash (%d) does not match\n", db_offset);
      for (i = 0; i < SHA1_SIZE; i++)
        printf ("%02x.", datab [db_offset + i] & 0xff);
      printf ("\n");
      for (i = 0; i < SHA1_SIZE; i++)
        printf ("%02x.", check_hash [i] & 0xff);
      printf ("\n");
#endif /* DEBUG_PRINT */
      bad_result = 1;
    }
    int ps = db_offset + SHA1_SIZE;
    while ((ps < nbytes) && (datab [ps] == 0))
      ps++;
    /* datab [ps] should be a byte with value 1 */
    if ((ps > nbytes) || (datab [ps] != 1)) {
#ifdef DEBUG_PRINT
      printf ("unpadding PKCS1_OAEP: ps %d/%d, datab [ps] is %02x\n",
              ps, nbytes, datab [ps] & 0xff);
#endif /* DEBUG_PRINT */
      bad_result = 1;
    }
    ps++;
    for (i = 0; i < nbytes - ps; i++)
      result [i] = get_byte (nbits, data, ps + i);
    memcpy (result, datab + ps, nbytes - ps);
    if (bad_result)
      return -1;
    return (nbytes - ps);
  }
  printf ("unpadding, mode %d not implemented\n", padding);
  exit (1);
  return -1;
}

#ifdef TEST_AGAINST_BN_LIBRARY
/* note: if using this, should link with -lcrypto */
#include <openssl/bn.h>

void print_exp_mod (int nbits, uint64_t * base, uint64_t * exp, uint64_t * mod)
{
  char b [WP_RSA_MAX_KEY_BYTES];
  char e [WP_RSA_MAX_KEY_BYTES];
  char m [WP_RSA_MAX_KEY_BYTES];
  rsa_int_to_bytes (nbits, b, base);
  rsa_int_to_bytes (nbits, e, exp);
  rsa_int_to_bytes (nbits, m, mod);
  BIGNUM * bnb = BN_bin2bn ((unsigned char *) b, nbits / 8, NULL);
  BIGNUM * bne = BN_bin2bn ((unsigned char *) e, nbits / 8, NULL);
  BIGNUM * bnm = BN_bin2bn ((unsigned char *) m, nbits / 8, NULL);
printf ("%s ^\n", BN_bn2hex (bnb));
printf ("%s %%\n", BN_bn2hex (bne));
printf ("%s =\n", BN_bn2hex (bnm));
  BIGNUM * bnr = BN_new ();
  BN_CTX *ctx = BN_CTX_new ();
  if (! BN_mod_exp (bnr, bnb, bne, bnm, ctx))
    printf ("unable to complete the computation\n");
  else
printf ("%s\n", BN_bn2hex (bnr));
}
#endif /* TEST_AGAINST_BN_LIBRARY */

/* data and result must have size at least key->nbits / 8, and
 * key->nbits / 8 should be <= WP_RSA_MAX_KEY_BYTES */
static void rsa_do_encrypt (wp_rsa_key * key, uint64_t * data, char * result)
{
  rsa_int ri;   /* result, as an integer */
  rsa_int efull;
  wp_init (key->nbits, efull, (int) (key->e));
#ifdef DEBUG_PRINT
  printf ("computing %s^", wp_itox (key->nbits, data));
  printf ("%s mod ", wp_itox (key->nbits, efull));
  printf ("%s =\n", wp_itox (key->nbits, key->n));
#endif /* DEBUG_PRINT */
#ifdef TEST_AGAINST_BN_LIBRARY
  print_exp_mod (key->nbits, data, efull, key->n);
#endif /* TEST_AGAINST_BN_LIBRARY */
  /* compute data^e mod key->n and place the result in result */
#ifdef USE_EXP_MOD_MONTGOMERY
  rsa_temp temp;
  wp_exp_mod_montgomery (key->nbits, ri, data, efull, key->n, temp);
#else /* USE_EXP_MOD_MONTGOMERY */
#ifdef USE_EXP_MOD64
  rsa_temp temp;
  wp_exp_mod64 (key->nbits, ri, data, efull, key->n, temp);
#else /* USE_EXP_MOD64 */
  rsa_int temp;
  wp_exp_mod (key->nbits, ri, data, efull, key->n, temp);
#endif /* USE_EXP_MOD64 */
#endif /* USE_EXP_MOD_MONTGOMERY */
#ifdef DEBUG_PRINT
  printf ("  encrypted is %s\n", wp_itox (key->nbits, ri));
#endif /* DEBUG_PRINT */
  rsa_int_to_bytes (key->nbits, result, ri);
}

/* data and result may be the same buffer.
 * dsize <= key->nbits / 8 - padding_size
 * nresult >= key->nbits / 8
 * returns key->nbits / 8 if successful, and if so, fills in result
 * otherwise returns -1 */
int wp_rsa_encrypt (wp_rsa_key * key, const char * data, int dsize,
                    char * result, int nresult, int padding)
{
  int kbytes = key->nbits / 8;
  if (nresult < kbytes)
    return -1;
  rsa_int padded;
  int esize = rsa_pad (key->nbits, padded, sizeof (padded),
                       data, dsize, padding);
  if (esize != kbytes) {
    printf ("rsa_pad returned %d\n", esize);
#ifdef DEBUG_PRINT
#endif /* DEBUG_PRINT */
    return -1;
  }
  rsa_do_encrypt (key, padded, result);
  return kbytes;
}

/* this is the slower version of decryption, computing m^d mod n */
static void rsa_decrypt_slow (wp_rsa_key_pair * key, uint64_t * data,
                              uint64_t * result)
{
  /* compute data^d mod key->n and place the result in result */
#ifdef DEBUG_PRINT
  printf ("decrypting %d %s^", key->nbits, wp_itox (key->nbits, data));
  printf ("%s mod ", wp_itox (key->nbits, key->d));
  printf ("%s = ", wp_itox (key->nbits, key->n));
#endif /* DEBUG_PRINT */
#ifdef USE_EXP_MOD_MONTGOMERY
  rsa_temp temp;
  wp_exp_mod_montgomery (key->nbits, result, data, key->d, key->n, temp);
#else /* USE_EXP_MOD_MONTGOMERY */
#ifdef USE_EXP_MOD64
  rsa_temp temp;
  wp_exp_mod64 (key->nbits, result, data, key->d, key->n, temp);
#else /* USE_EXP_MOD64 */
  rsa_int temp;
  wp_exp_mod (key->nbits, result, data, key->d, key->n, temp);
#endif /* USE_EXP_MOD64 */
#endif /* USE_EXP_MOD_MONTGOMERY */
#ifdef DEBUG_PRINT
  printf ("%s\n", wp_itox (key->nbits, result));
#endif /* DEBUG_PRINT */
}

/* this faster decryption uses nbits/2 arithmetic to compute:
     int m1 = exp_mod (cipher, dp, p);
     int m2 = exp_mod (cipher, dq, q);
     int h = 
       if (m1 >= m2) (qinv * (m1 - m2)) % p;
       else          (qinv * (m1 + p - m2)) % p
     int res = m2 + h * q;
 */
static void rsa_decrypt_fast (wp_rsa_key_pair * key, uint64_t * data,
                              uint64_t * result)
{
  int nbits = key->nbits;
  int nhalf = nbits / 2;
  rsa_int pfull;
  rsa_int qfull;
  wp_extend (nbits, pfull, nhalf, key->p);
  wp_extend (nbits, qfull, nhalf, key->q);

  rsa_int data_copy1;   /* will hold data_mod_p */
  rsa_int data_copy2;   /* will hold data_mod_q */
  wp_copy (nbits, data_copy1, data);
  wp_copy (nbits, data_copy2, data);
  uint64_t * data_mod_p;
  uint64_t * data_mod_q;
  wp_div (nbits, data_copy1, nhalf, key->p, NULL, &data_mod_p);
  wp_div (nbits, data_copy2, nhalf, key->q, NULL, &data_mod_q);

  /* compute m1 and m2 at half size */
  rsa_half m1;
#ifdef USE_EXP_MOD_MONTGOMERY
  rsa_temp_half temp;
  wp_exp_mod_montgomery (nhalf, m1, data_mod_p, key->dp, key->p, temp);
  rsa_half m2;
  wp_exp_mod_montgomery (nhalf, m2, data_mod_q, key->dq, key->q, temp);
#else /* USE_EXP_MOD_MONTGOMERY */
#ifdef USE_EXP_MOD64
  rsa_temp_half temp;
  wp_exp_mod64 (nhalf, m1, data_mod_p, key->dp, key->p, temp);
  rsa_half m2;
  wp_exp_mod64 (nhalf, m2, data_mod_q, key->dq, key->q, temp);
#else /* USE_EXP_MOD64 */
  rsa_half temp;
  wp_exp_mod (nhalf, m1, data_mod_p, key->dp, key->p, temp);
  rsa_half m2;
  wp_exp_mod (nhalf, m2, data_mod_q, key->dq, key->q, temp);
#endif /* USE_EXP_MOD64 */
#endif /* USE_EXP_MOD_MONTGOMERY */

  /* compute at half size h = if (m1 >= m2) (qinv * (m1 - m2)) % p;
                              else          (qinv * (m1 + p - m2)) % p */
  rsa_half diff;
  wp_sub (nhalf, diff, m1, m2);
  if (wp_compare (nhalf, m1, m2) < 0) {
#ifdef DEBUG_PRINT
    printf ("adding p to diff\n");
#endif /* DEBUG_PRINT */
    wp_add (nhalf, diff, diff, key->p);
  }
  rsa_half h;
  wp_multiply_mod (nhalf, h, key->qinv, diff, key->p);
#ifdef DEBUG_PRINT
  printf ("m1 is %s/%d\n", wp_itox (nhalf, m1), nhalf);
  printf ("m2 is %s/%d\n", wp_itox (nhalf, m2), nhalf);
  printf ("h is %s/%d\n", wp_itox (nhalf, h), nhalf);
#endif /* DEBUG_PRINT */

  /* compute the plaintext (at full size) as m2 + h * q */
  rsa_int product;
  wp_multiply (nbits, product, nhalf, h, key->q);
  rsa_int m2full;
  wp_extend (nbits, m2full, nhalf, m2);
  wp_add (nbits, result, m2full, product);
}

static void rsa_choose_decrypt (wp_rsa_key_pair * key,
                                uint64_t * data, uint64_t * result)
{
  int nbits = key->nbits;
  int nhalf = nbits / 2;
  if ((wp_is_zero (nhalf, key->p))  || (wp_is_zero (nhalf, key->q))  ||
      (wp_is_zero (nhalf, key->dp)) || (wp_is_zero (nhalf, key->dq)) ||
      (wp_is_zero (nhalf, key->qinv))) {
#ifdef DEBUG_PRINT
    printf ("using slow version of decrypt, %d %d %d %d %d\n",
            wp_is_zero (nhalf, key->p),  wp_is_zero (nhalf, key->q),
            wp_is_zero (nhalf, key->dp), wp_is_zero (nhalf, key->dq),
            wp_is_zero (nhalf, key->qinv));
#endif /* DEBUG_PRINT */
    rsa_decrypt_slow (key, data, result);
  } else {
    rsa_decrypt_fast (key, data, result);
  }
}

/* data and result may be the same buffer.
 * dsize == key->nbits / 8, nresult >= key->nbits / 8 - padding_size
 * returns the size of the decrypted message if successful
 *   (the size is always key->nbits / 8 for WP_RSA_PADDING_NONE),
 * otherwise returns -1 */
int wp_rsa_decrypt (wp_rsa_key_pair * key, const char * data, int dsize,
                    char * result, int nresult, int padding)
{
  int kbytes = key->nbits / 8;
  if ((dsize != kbytes) || (nresult < kbytes) || (kbytes * 8 != key->nbits))
    return -1;
  rsa_int rdata;
  rsa_int_from_bytes (key->nbits, rdata, data);
  rsa_int decrypted;
  if (sizeof (decrypted) < kbytes) {
    printf ("size of rsa_int is %zd, need %d\n", sizeof (decrypted), kbytes);
    exit (1);  /* serious error in the caller */
  }
  rsa_choose_decrypt (key, rdata, decrypted);
#ifdef DEBUG_PRINT
  printf ("decrypted is: %s\n", wp_itox (key->nbits, decrypted));
#endif /* DEBUG_PRINT */
  int rsize = rsa_unpad (key->nbits, result, nresult, decrypted, kbytes,
                         padding);
  return rsize;
}

/* digest must be rsa_int or have WP_RSA_MAX_KEY_WORDS */
static void sig_digest (int nbits, const char * hash, int hsize,
                        uint64_t * digest, int sig_encoding)
{
  if (sig_encoding == WP_RSA_SIG_ENCODING_NONE) {
    if (hsize != nbits / 8) {
      printf ("error: digest needs exactly %d bytes, %d found\n",
              nbits / 8, hsize);
      exit (1);  /* some error */
    }
    rsa_int_from_bytes (nbits, digest, hash);
  } else if (sig_encoding == WP_RSA_SIG_ENCODING_SHA512) {
    static const char sha512_der_prefix [] = {
        0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
        0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40 };
    int nbytes = nbits / 8;
    int t_size = SHA512_SIZE + sizeof (sha512_der_prefix);
    int needed = t_size + 11;
    if (WP_RSA_MAX_KEY_BYTES < needed) {
      printf ("error: digest needs %d bytes, only %d available\n",
              needed, WP_RSA_MAX_KEY_BYTES);
      exit (1);  /* probably WP_RSA_MAX_KEY_BYTES is too small */
    }
    char * db = (char *) digest;
/*    5. Concatenate PS, the DER encoding T, and other padding to form the
      encoded message EM as
         EM = 0x00 || 0x01 || PS || 0x00 || T. */
    db [0] = 0;
    db [1] = 1;
/* make 0xff every byte that isn't otherwise set -- this is PS */
    memset (db + 2, 0xff, nbytes - 3 - t_size);
    db [nbytes - t_size - 1] = 0;
/* copy the constant string indicating SHA512 encoding */
    memcpy (db + nbytes - t_size, sha512_der_prefix,
            sizeof (sha512_der_prefix));
/* place the sha hash in the last 64 bytes of the digest */
    memcpy (db + nbytes - SHA512_SIZE, hash, hsize);
    rsa_int_from_bytes (nbits, digest, db);
  } else {
    printf ("error: signature encoding %d not implemented", sig_encoding);
    exit (1);   /* cannot continue */
  }
}

/* hash and sig may be the same buffer.
 * hsize <= key->nbits / 8,  nsig >= key->nbits / 8
 * if sig_encoding is WP_RSA_SIG_ENCODING_SHA512, hsize must be 64
 * returns 1 if successful, otherwise returns 0 */
int wp_rsa_sign (wp_rsa_key_pair * key, const char * hash, int hsize,
                 char * sig, int nsig, int sig_encoding)
{
  if ((nsig < key->nbits / 8) || (key->nbits > WP_RSA_MAX_KEY_BITS)) {
    printf ("signature error: %d bytes available, %d needed\n",
            nsig, key->nbits / 8);
    return 0;
  }
  rsa_int to_be_signed;
  sig_digest (key->nbits, hash, hsize, to_be_signed, sig_encoding);
  rsa_int isig;
  rsa_choose_decrypt (key, to_be_signed, isig);
  rsa_int_to_bytes (key->nbits, sig, isig);
  return 1;
}

/* hsize <= key->nbits / 8,  nsig == key->nbits / 8
 * if sig_encoding is WP_RSA_SIG_ENCODING_SHA512, hsize must be 64
 * returns 1 if successful, otherwise returns 0 */
int wp_rsa_verify (wp_rsa_key * key, const char * hash, int hsize,
                   const char * sig, int nsig, int sig_encoding)
{
  if ((nsig != key->nbits / 8) || (key->nbits > WP_RSA_MAX_KEY_BITS))
    return 0;
  rsa_int digest;
  sig_digest (key->nbits, hash, hsize, digest, sig_encoding);
  char digestb [WP_RSA_MAX_KEY_BYTES];
  rsa_int_to_bytes (key->nbits, digestb, digest);
  rsa_int encrypt;
  rsa_int_from_bytes (key->nbits, encrypt, sig);
  char encrypted [WP_RSA_MAX_KEY_BYTES];
  rsa_do_encrypt (key, encrypt, encrypted);
  if (memcmp (encrypted, digestb, nsig) == 0)
    return 1;
/*
int i;
printf ("sig: "); for (i = 0; i < nsig; i++)
printf ("%02x ", sig [i] & 0xff); printf ("\n");
printf ("encrypted: "); for (i = 0; i < nsig; i++)
printf ("%02x ", encrypted [i] & 0xff); printf ("\n");
printf ("digest: "); for (i = 0; i < nsig; i++)
printf ("%02x ", digestb [i] & 0xff); printf ("\n");
printf ("\n");
*/
  return 0;
}

static uint64_t time_usec_since (struct timeval * start)
{
  struct timeval finish;
  gettimeofday (&finish, NULL);
  uint64_t usec = ((uint64_t) (finish.tv_sec - start->tv_sec)) * 1000000 +
                   (finish.tv_usec - start->tv_usec);
  return usec;
}

#ifdef TEST_WITH_OPENSSL

#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/err.h>

static int test_openssl_sign_verify (wp_rsa_key_pair * key, RSA * openssl_key)
{
  char text [WP_RSA_MAX_KEY_BYTES * 2] = "hello world, please sign me today!";
  int tsize = strlen (text);
  char sig [WP_RSA_MAX_KEY_BYTES];
  unsigned int ssize = key->nbits / 8;
  char hash [SHA512_SIZE];
  sha512 (text, tsize, hash);

  /* sign with wp_rsa_sign, verify with openssl */
  struct timeval start;
  if (! wp_rsa_sign (key, hash, SHA512_SIZE, sig, ssize,
                     WP_RSA_SIG_ENCODING_SHA512)) {
    printf ("unable to sign\n");
    return 0;
  }
  gettimeofday (&start, NULL);
  if (! RSA_verify (NID_sha512, (unsigned char *) hash, SHA512_SIZE,
                    (unsigned char *) sig, ssize, openssl_key)) {
    printf ("openssl unable to verify signature\n");
    return 0;
  }
  printf ("wp_rsa signature verified by openssl in %" PRId64 "us\n",
          time_usec_since (&start));

  /* sign with RSA_sign, verify with wp_rsa_verify */
  memset (sig, 0, sizeof (sig));  /* no cheating! */
  if (! RSA_sign (NID_sha512, (unsigned char *) hash, SHA512_SIZE,
                  (unsigned char *) sig, &ssize, openssl_key)) {
    printf ("openssl unable to sign hash\n");
    return 0;
  }
  wp_rsa_key pubkey = wp_rsa_get_public_key (key);
  gettimeofday (&start, NULL);
  if (! wp_rsa_verify (&pubkey, hash, SHA512_SIZE, sig, ssize,
                       WP_RSA_SIG_ENCODING_SHA512)) {
    printf ("wp_rsa_verify unable to verify signature\n");
    return 0;
  }
  printf ("openssl sig of size %d verified by wp_rsa_verify in %" PRId64 "us\n",
          ssize, time_usec_since (&start));
  return 1;
}

static int test_with_openssl (wp_rsa_key_pair * key, int padding)
{
  int rsa_padding = RSA_NO_PADDING;
  if (padding == WP_RSA_PADDING_PKCS1_OAEP)
    rsa_padding = RSA_PKCS1_OAEP_PADDING;   /* equivalent openssl name */
  char text [WP_RSA_MAX_KEY_BYTES + 100] = "hello";
  int tsize = strlen (text);
  if (tsize >= WP_RSA_MAX_KEY_BYTES)
    tsize = WP_RSA_MAX_KEY_BYTES - 1;
  if (padding == WP_RSA_PADDING_NONE)
    tsize = WP_RSA_MAX_KEY_BYTES;

  char encrypted [WP_RSA_MAX_KEY_BYTES + 1];
  char decrypted [WP_RSA_MAX_KEY_BYTES + 1];
  memset (encrypted, 0, sizeof (encrypted));
  memset (decrypted, 0, sizeof (decrypted));

  int nbytes = key->nbits / 8;
  if (((padding == WP_RSA_PADDING_PKCS1_OAEP) && (nbytes < tsize + 42)) ||
      (nbytes != WP_RSA_MAX_KEY_BYTES)) {
    printf ("openssl encryption size error: %d %d %d %d\n",
            nbytes, tsize, tsize + 42, WP_RSA_MAX_KEY_BYTES);
    return 0;
  }
  /* create the openSSL key from my key */
  RSA * rsa = RSA_new ();
  unsigned char binary [WP_RSA_MAX_KEY_BYTES];
  int i;
  for (i = 0; i < WP_RSA_MAX_KEY_WORDS; i++)
    uint64_to_bytes ((char *) (binary + i * sizeof (uint64_t)), key->n [i]);
  rsa->n = BN_bin2bn (binary, nbytes, NULL);
  rsa->e = BN_new ();
  BN_set_word (rsa->e, key->e);
  for (i = 0; i < WP_RSA_MAX_KEY_WORDS; i++)
    uint64_to_bytes ((char *) (binary + i * sizeof (uint64_t)), key->d [i]);
  rsa->d = BN_bin2bn (binary, nbytes, NULL);
  rsa->p = NULL;
  rsa->q = NULL;
  rsa->dmp1 = NULL;
  rsa->dmq1 = NULL;
  rsa->iqmp = NULL;

  /* first, encrypt with openssl and decrypt with my code */
  struct timeval start;
  gettimeofday (&start, NULL);
  int esize = RSA_public_encrypt (tsize, (unsigned char *) text,
                                  (unsigned char *) encrypted, rsa,
                                  rsa_padding);
  if (esize < 0) {
    while (1) {
      unsigned long err = ERR_get_error ();
      if (err == 0)
        return 0;
      printf ("RSA_public_encrypt error %s\n", ERR_error_string (err, NULL));
    }
  }
  printf ("openssl/rsa encrypted %d -> %d bytes in %" PRId64 "us\n",
          tsize, esize, time_usec_since (&start));
  gettimeofday (&start, NULL);
  int psize = wp_rsa_decrypt (key, encrypted, esize,
                              decrypted, sizeof (decrypted), padding);
  printf ("wp_rsa_decrypted %d -> %d bytes in %" PRId64 "us, ",
          esize, psize, time_usec_since (&start));
  printf ("first: %x.%x.%x.%x.%x.%x.%x.%x\n",
          decrypted [0] & 0xff, decrypted [1] & 0xff,
          decrypted [2] & 0xff, decrypted [3] & 0xff, decrypted [4] & 0xff,
          decrypted [5] & 0xff, decrypted [6] & 0xff, decrypted [7] & 0xff);
  if ((psize != tsize) || (strncmp (decrypted, text, tsize) != 0)) {
    printf ("decrypted value %d does not match encrypted value %d!\n",
            psize, tsize);
    printf ("  first 8 of original text are: %x.%x.%x.%x.%x.%x.%x.%x\n",
            text [0] & 0xff, text [1] & 0xff, text [2] & 0xff,
            text [3] & 0xff, text [4] & 0xff,
            text [5] & 0xff, text [6] & 0xff, text [7] & 0xff);
psize = RSA_private_decrypt (esize, (unsigned char *) encrypted,
                             (unsigned char *) decrypted, rsa, rsa_padding);
printf ("openssl decrypted %d bytes: \n", psize);
for (i = 0; i < psize; i++) printf ("%02x.", decrypted [i]); printf ("\n");
    return 0;
  }

  /* now, encrypt with my code and decrypt with openssl */
  wp_rsa_key pubkey = wp_rsa_get_public_key (key);
  gettimeofday (&start, NULL);
  esize = wp_rsa_encrypt (&pubkey, text, tsize,
                          encrypted, sizeof (encrypted), padding);
  printf ("encrypted %d -> %d bytes in %" PRId64 "us\n",
          tsize, esize, time_usec_since (&start));
  gettimeofday (&start, NULL);
  psize = RSA_private_decrypt (esize, (unsigned char *) encrypted,
                               (unsigned char *) decrypted, rsa, rsa_padding);
  printf ("openssl decrypted %d -> %d bytes in %" PRId64 "us, ",
          esize, psize, time_usec_since (&start));
  printf ("first: %x.%x.%x.%x.%x.%x.%x.%x\n",
          decrypted [0] & 0xff, decrypted [1] & 0xff,
          decrypted [2] & 0xff, decrypted [3] & 0xff, decrypted [4] & 0xff,
          decrypted [5] & 0xff, decrypted [6] & 0xff, decrypted [7] & 0xff);
  if ((psize != tsize) || (strncmp (decrypted, text, tsize) != 0)) {
    printf ("decrypted value %d does not match encrypted value %d!\n",
            psize, tsize);
    printf ("  first 8 of original text are: %x.%x.%x.%x.%x.%x.%x.%x\n",
            text [0] & 0xff, text [1] & 0xff, text [2] & 0xff,
            text [3] & 0xff, text [4] & 0xff,
            text [5] & 0xff, text [6] & 0xff, text [7] & 0xff);
for (i = 0; i < psize; i++) printf ("%02x.", decrypted [i] & 0xff);
printf ("\n");
    /* return 0; */
  }
  return test_openssl_sign_verify (key, rsa);
}
#endif /* TEST_WITH_OPENSSL */

static int test_encrypt_decrypt (wp_rsa_key_pair * key, int padding)
{
  char text [WP_RSA_MAX_KEY_BYTES + 100] = "hello";
  int tsize = (int)strlen (text);
  if (tsize >= WP_RSA_MAX_KEY_BYTES)
    tsize = WP_RSA_MAX_KEY_BYTES - 1;
  char cipher [WP_RSA_MAX_KEY_BYTES];
  wp_rsa_key pubkey = wp_rsa_get_public_key (key);
  struct timeval start;
  gettimeofday (&start, NULL);
  int csize =
    wp_rsa_encrypt (&pubkey, text, tsize, cipher, sizeof (cipher), padding);
  printf (" encrypted %d -> %d bytes in %" PRId64 "us, ",
          tsize, csize, time_usec_since (&start));
  if (key->nbits > 128)
    printf ("first 8 are: %02x%02x%02x%02x%02x%02x%02x%02x\n",
            cipher [0] & 0xff, cipher [1] & 0xff,
            cipher [2] & 0xff, cipher [3] & 0xff, cipher [4] & 0xff,
            cipher [5] & 0xff, cipher [6] & 0xff, cipher [7] & 0xff);
  else
    printf ("cipher: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
            cipher [0] & 0xff, cipher [1] & 0xff, cipher [2] & 0xff,
            cipher [3] & 0xff, cipher [4] & 0xff, cipher [5] & 0xff,
            cipher [6] & 0xff, cipher [7] & 0xff,
            cipher [8] & 0xff, cipher [9] & 0xff, cipher [10] & 0xff,
            cipher [11] & 0xff, cipher [12] & 0xff, cipher [13] & 0xff,
            cipher [14] & 0xff, cipher [15] & 0xff);
  char plain [WP_RSA_MAX_KEY_BYTES];
  gettimeofday (&start, NULL);
  int psize = wp_rsa_decrypt (key, cipher, csize,
                              plain, sizeof (plain), padding);
  printf ("fdecrypted %d -> %d bytes in %" PRId64 "us, ",
          csize, psize, time_usec_since (&start));
  printf ("first: %x.%x.%x.%x.%x.%x.%x.%x\n",
          plain [0] & 0xff, plain [1] & 0xff,
          plain [2] & 0xff, plain [3] & 0xff, plain [4] & 0xff,
          plain [5] & 0xff, plain [6] & 0xff, plain [7] & 0xff);
  if ((psize != tsize) || (strncmp (plain, text, tsize) != 0)) {
    printf ("decrypted value %d does not match encrypted value %d!\n",
            psize, tsize);
    printf ("  first 8 of original text are: %x.%x.%x.%x.%x.%x.%x.%x\n",
            text [0] & 0xff, text [1] & 0xff, text [2] & 0xff,
            text [3] & 0xff, text [4] & 0xff,
            text [5] & 0xff, text [6] & 0xff, text [7] & 0xff);
int i; for (i = 0; i < psize; i++) printf ("%02x.", plain [i] & 0xff);
printf ("\n");
    /* return 0; */
  }
  wp_init (key->nbits / 2, key->dp, 0);
  gettimeofday (&start, NULL);
  psize = wp_rsa_decrypt (key, cipher, csize, plain, sizeof (plain), padding);
  printf ("sdecrypted %d -> %d bytes in %" PRId64 "us, ",
          csize, psize, time_usec_since (&start));
  printf ("first: %x.%x.%x.%x.%x.%x.%x.%x\n",
          plain [0] & 0xff, plain [1] & 0xff,
          plain [2] & 0xff, plain [3] & 0xff, plain [4] & 0xff,
          plain [5] & 0xff, plain [6] & 0xff, plain [7] & 0xff);
  if (strncmp (plain, text, tsize) != 0) {
    printf ("decrypted value does not match encrypted value!\n");
    printf ("  first 8 of original text are: %x.%x.%x.%x.%x.%x.%x.%x\n",
            text [0] & 0xff, text [1] & 0xff, text [2] & 0xff,
            text [3] & 0xff, text [4] & 0xff,
            text [5] & 0xff, text [6] & 0xff, text [7] & 0xff);
int i; for (i = 0; i < psize; i++) printf ("%02x.", plain [i] & 0xff);
printf ("\n");
    return 0;
  }
  return 1;
}

static int test_sign_verify (wp_rsa_key_pair * key, int sig_encoding)
{
  char text [WP_RSA_MAX_KEY_BYTES * 2] = "hello world, please sign me today!";
  int tsize = (int)strlen (text);
  char hash [SHA512_SIZE];
  sha512 (text, tsize, hash);
  char sig [WP_RSA_MAX_KEY_BYTES];
  int ssize = key->nbits / 8;

  struct timeval start;
  gettimeofday (&start, NULL);
  if (! wp_rsa_sign (key, hash, SHA512_SIZE, sig, ssize, sig_encoding)) {
    printf ("unable to sign\n");
    return 0;
  }
  printf ("signature: ");
  int i;
  for (i = 0; i < ssize; i++)
    printf ("%02x.", sig [i] & 0xff);
  printf ("\n");
  wp_rsa_key pubkey = wp_rsa_get_public_key (key);
  if (! wp_rsa_verify (&pubkey, hash, SHA512_SIZE, sig, ssize, sig_encoding)) {
    printf ("unable to verify signature\n");
    return 0;
  }
  printf ("signature verifies\n");
  return 1;
}

void rsa_test_padding ()
{
  char data [WP_RSA_MAX_KEY_BYTES + 100] =
    "the quick brown fox jumped over the lazy dog";
  rsa_int padded;
  int padding;
  for (padding = WP_RSA_PADDING_NONE; padding <= WP_RSA_PADDING_PKCS1_OAEP;
       padding++) {
    int dlen = (int)strlen (data);
    int plen = 0;
    if (padding == WP_RSA_PADDING_NONE) {
      dlen = WP_RSA_MAX_KEY_BYTES;
      plen = dlen;
    }
    if ((padding == WP_RSA_PADDING_VANILLA) &&
        (dlen + WP_RSA_PADDING_VANILLA_SIZE > WP_RSA_MAX_KEY_BYTES))
      dlen = WP_RSA_MAX_KEY_BYTES - WP_RSA_PADDING_VANILLA_SIZE;
    if ((padding == WP_RSA_PADDING_PKCS1_OAEP) &&
        (dlen + WP_RSA_PADDING_PKCS1_OAEP_SIZE > WP_RSA_MAX_KEY_BYTES))
      dlen = WP_RSA_MAX_KEY_BYTES - WP_RSA_PADDING_PKCS1_OAEP_SIZE;
    for ( ; plen <= dlen; plen++) {
      int p = rsa_pad (WP_RSA_MAX_KEY_BITS, padded, sizeof (padded),
                       data, plen, padding);
      if (p != WP_RSA_MAX_KEY_BYTES) {
        printf ("padding %d: padded to size %d, but result is %d\n", padding,
                WP_RSA_MAX_KEY_BYTES, p);
        return;
      }
      char result [WP_RSA_MAX_KEY_BYTES];
      int u = rsa_unpad (WP_RSA_MAX_KEY_BITS, result, sizeof (result),
                         padded, sizeof (padded), padding);
      if (u != plen) {
        printf ("padding %d: unpadded should be size %d, but result is %d\n",
                padding, plen, u);
        return;
      }
      if (memcmp (result, data, plen) != 0) {
        printf ("padding/unpadding do not match at size %d:\n", plen);
        int i;
        for (i = 0; i < 20; i++)
          printf ("%d: %02x/%02x\n", i, data [i] & 0xff, result [i] & 0xff);
        return;
      }
    }
    printf ("padding test works for padding %d\n", padding);
  }
}

void run_rsa_test ()
{
  wp_rsa_key_pair k;
  int nbits = 0;
  if (WP_RSA_MAX_KEY_BITS >= 4096) {
    if (! wp_rsa_read_key_from_file ("tssl.pem", &nbits, &k)) {
      printf ("unable to read key from file tssl.pem\n");
    } else {
      printf ("from tssl.pem read %d(%d)-bit key\n", nbits, k.nbits);
/*
      printf ("public key is %s/%d %ld\n", wp_itox (k.nbits, k.n),
              k.nbits, k.e);
      printf ("private d is %s\n", wp_itox (k.nbits, k.d));
      printf ("prime p is %s\n", wp_itox (k.nbits / 2, k.p));
      printf ("prime q is %s\n", wp_itox (k.nbits / 2, k.q));
      printf ("dp is %s\n", wp_itox (k.nbits / 2, k.dp));
      printf ("dq is %s\n", wp_itox (k.nbits / 2, k.dq));
      printf ("qinv is %s\n", wp_itox (k.nbits / 2, k.qinv));
*/
      /* test_encrypt_decrypt (&k, WP_RSA_PADDING_VANILLA); */
#ifdef TEST_WITH_OPENSSL
      test_with_openssl (&k, WP_RSA_PADDING_PKCS1_OAEP);
      return;
#else /* TEST_WITH_OPENSSL */
      test_sign_verify (&k, WP_RSA_SIG_ENCODING_SHA512);
      test_encrypt_decrypt (&k, WP_RSA_PADDING_PKCS1_OAEP);
#endif /* TEST_WITH_OPENSSL */
    }
  }
  rsa_test_padding ();
  printf ("generating %d-bit key\n", WP_RSA_MAX_KEY_BITS);
  struct timeval start;
  gettimeofday (&start, NULL);
  int count = wp_rsa_generate_key_pair (WP_RSA_MAX_KEY_BITS, &k, 5, NULL, 0);
  printf ("generated %d-bit key in %" PRId64 "us\n", k.nbits,
          time_usec_since (&start));
  if (count != 1)
    printf ("generate_key looped %d times\n", count);
  if (k.nbits <= 4096)
    printf ("public key is %s/%d %" PRId64, wp_itox (k.nbits, k.n),
            k.nbits, k.e);
  if (k.nbits <= 512) {
    printf (", secret is %s ", wp_itox (k.nbits, k.d));
    printf ("p %s ", wp_itox (k.nbits, k.p));
    printf ("q %s\n", wp_itox (k.nbits, k.q));
  } else
    printf ("\n");
  /* test_encrypt_decrypt (&k, WP_RSA_PADDING_VANILLA); */
  test_encrypt_decrypt (&k, WP_RSA_PADDING_PKCS1_OAEP);
  test_sign_verify (&k, WP_RSA_SIG_ENCODING_SHA512);
#ifdef TESTING_WIKIPEDIA_EXAMPLE
  /* wikipedia example */
  test = 65;
  cipher = wp_rsa_encrypt (test, 3233, 17);
  int plain = wp_rsa_decrypt (cipher, 3233, 2753);
  printf ("encrypting %d gives %d\n", test, cipher);
  printf ("decrypting %d gives %d\n", cipher, plain);
  sig = rsa_sign (test, 3233, 2753);
  ver = rsa_verify (sig, 3233, 17);
  printf ("signature is %d, verification %d\n", sig, ver);
#endif /* TESTING_WIKIPEDIA_EXAMPLE */
}

#ifdef RSA_UNIT_TEST
int main (int argc, char ** argv)
{
  run_rsa_test ();
  return 0;
}
#endif /* RSA_UNIT_TEST */
