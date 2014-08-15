/* sha.c: compute sha512 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "sha.h"

#define SHA512_BLOCK_SIZE	128	/* 1024 bits or 128 bytes */

static int debugging = 0;

typedef union uint512 {
  unsigned char c [512 / 8];
  unsigned long long int i [512 / (8 * sizeof (unsigned long long int))];
} uint512;

static const unsigned long long int K [] = {
0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
};

static const unsigned long long int init_H [] =
  { 0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1, 
    0x510e527fade682d1, 0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b, 0x5be0cd19137e2179 };

#define shr(n, x) ((x) >> (n))
#define rotr(n, x) (((x) >> (n)) | ((x) << (64 - (n))))

static inline unsigned long long int ch (unsigned long long int x, unsigned long long int y,
                      unsigned long long int z)
{
  return (x & y) ^ ((~x) & z);
}

static inline unsigned long long int maj (unsigned long long int x, unsigned long long int y,
                       unsigned long long int z)
{
  return (x & y) ^ (x & z) ^ (y & z);
}

static inline unsigned long long int SIGMA0 (unsigned long long int x)
{
  return rotr (28, x) ^ rotr (34, x) ^ rotr (39, x);
}

static inline unsigned long long int SIGMA1 (unsigned long long int x)
{
  return rotr (14, x) ^ rotr (18, x) ^ rotr (41, x);
}

static inline unsigned long long int sigma0 (unsigned long long int x)
{
  return rotr (1, x) ^ rotr (8, x) ^ shr (7, x);
}

static inline unsigned long long int sigma1 (unsigned long long int x)
{
  return rotr (19, x) ^ rotr (61, x) ^ shr (6, x);
}

#ifdef DEBUG_PRINT
static void print_data (char * data, int length)
{
  int i;
  for (i = 0; i < length; i++) {
    printf ("%02x", (data [i]) & 0xff);
    if (i % 32 == 31)
      printf ("\n");
    else if (i % 4 == 3)
      printf (" ");
  }
  if (length % 32 != 0)
    printf ("\n");
}
#endif /* DEBUG_PRINT */

static inline unsigned long long int read_int (char * data)
{
  return ((((unsigned long long int) (data [0] & 0xff)) << 56) |
          (((unsigned long long int) (data [1] & 0xff)) << 48) |
          (((unsigned long long int) (data [2] & 0xff)) << 40) |
          (((unsigned long long int) (data [3] & 0xff)) << 32) |
          (((unsigned long long int) (data [4] & 0xff)) << 24) |
          (((unsigned long long int) (data [5] & 0xff)) << 16) |
          (((unsigned long long int) (data [6] & 0xff)) <<  8) |
          (((unsigned long long int) (data [7] & 0xff))      ));
}

static inline void write_int (char * data, unsigned long long int value)
{
  data [7] = value;
  data [6] = value >>  8;
  data [5] = value >> 16;
  data [4] = value >> 24;
  data [3] = value >> 32;
  data [2] = value >> 40;
  data [1] = value >> 48;
  data [0] = value >> 56;
}

static inline void
  init_w_native_byte_order (unsigned long long int * W,
                            const unsigned long long int * block)
{
  W [ 0] = block [ 0];
  W [ 1] = block [ 1];
  W [ 2] = block [ 2];
  W [ 3] = block [ 3];
  W [ 4] = block [ 4];
  W [ 5] = block [ 5];
  W [ 6] = block [ 6];
  W [ 7] = block [ 7];
  W [ 8] = block [ 8];
  W [ 9] = block [ 9];
  W [10] = block [10];
  W [11] = block [11];
  W [12] = block [12];
  W [13] = block [13];
  W [14] = block [14];
  W [15] = block [15];
  int t;
  for (t = 16; t < 80; t++)
    W [t] = sigma1 (W [t - 2]) + W [t - 7] +
            sigma0 (W [t - 15]) + W [t - 16];
}

static inline void init_w (unsigned long long int * W,
                           const unsigned long long int * block)
{
  int t;
  for (t = 0; t < 16; t++)
    W [t] = read_int ((char *) (block + t));
  for (t = 16; t < 80; t++)
    W [t] = sigma1 (W [t - 2]) + W [t - 7] +
            sigma0 (W [t - 15]) + W [t - 16];
}

/* do the basic hash of one block. */
/* block is the 512-bit/64-byte/16-word input block.
 * hash is the 256-bit/32-byte/8-word input and output hash
 * native_in is 1 if we don't have to revert the bytes of the block on
 * a little-endian machine */
static void compute_sha512 (const unsigned long long int * block,
                            uint512 * hash, int native_in) 
{
  unsigned long long int W [80];
  int t;

  /* step 1 */
#if __BYTE_ORDER == __LITTLE_ENDIAN
  if (native_in)
#endif /* __BYTE_ORDER == __LITTLE_ENDIAN */
    init_w_native_byte_order (W, block);
#if __BYTE_ORDER == __LITTLE_ENDIAN
  else
    init_w (W, block);
#endif /* __BYTE_ORDER == __LITTLE_ENDIAN */

  /* step 2 */
  unsigned long long int a = hash->i [0];
  unsigned long long int b = hash->i [1];
  unsigned long long int c = hash->i [2];
  unsigned long long int d = hash->i [3];
  unsigned long long int e = hash->i [4];
  unsigned long long int f = hash->i [5];
  unsigned long long int g = hash->i [6];
  unsigned long long int h = hash->i [7];
#ifdef DEBUG_PRINT
  if (debugging)
    printf ("in: %016llX %016llX %016llX %016llX %016llX %016llX %016llX %016llX\n",
            a, b, c, d, e, f, g, h);

  if (debugging)
    printf ("          A                B                C                D                E                F                G                H\n");
#endif /* DEBUG_PRINT */
  /* step 3 */
  for (t = 0; t < 80; t++) {
    unsigned long long int t1 =
      h + SIGMA1 (e) + ch (e, f, g) + K [t] + W [t];
    unsigned long long int t2 = SIGMA0 (a) + maj (a, b, c);
    h = g;
    g = f;
    f = e;
    e = d + t1;
    d = c;
    c = b;
    b = a;
    a = t1 + t2;
#ifdef DEBUG_PRINT
    if (debugging)
      printf ("t = %d: %016llX %016llX %016llX %016llX %016llX %016llX %016llX %016llX\n",
              t, a, b, c, d, e, f, g, h);
#endif /* DEBUG_PRINT */
  }

  /* step 4 */
  hash->i [0] += a;
  hash->i [1] += b;
  hash->i [2] += c;
  hash->i [3] += d;
  hash->i [4] += e;
  hash->i [5] += f;
  hash->i [6] += g;
  hash->i [7] += h;
  if (debugging)
    printf ("hash = %16llx %16llx %16llx %16llx %16llx %16llx %16llx %16llx\n",
            hash->i [0], hash->i [1], hash->i [2], hash->i [3],
            hash->i [4], hash->i [5], hash->i [6], hash->i [7]);
}

/* the result array must have size SHA512_SIZE */
/* #define SHA512_SIZE	64 */
void sha512 (char * input, int bytes, char * result)
{
  int i;
  if (bytes < 0) {
    printf ("error in sha computation; %d (%x) bytes requested\n",
            bytes, bytes);
    exit (1);
  }
  /* padding */
  unsigned int bits = bytes * 8;
  int input_blocks = ((bytes + 127) / 128) - 1;

  char last1 [SHA512_BLOCK_SIZE];  /* next-to-last block, has data from input */
  char last2 [SHA512_BLOCK_SIZE];  /* last block, may not be needed */
  memset (last1, 0, SHA512_BLOCK_SIZE);
  memset (last2, 0, SHA512_BLOCK_SIZE);
  int last_bytes = bytes % SHA512_BLOCK_SIZE;
  int padding = SHA512_BLOCK_SIZE - last_bytes;
  if (last_bytes > 0)
    memcpy (last1, input + (bytes - last_bytes), last_bytes);
  if (padding > 0)
    last1 [last_bytes] = 0x80;
  else
    last2 [0] = 0x80;
  /* sha512 has 16B for 2^128 bytes, my ints are 64 bits/8B long */
  if (padding < 17)  /* so we extend if padding < 17, but only write 8 bytes */
    write_int (last2 + (SHA512_BLOCK_SIZE - 8), bits);
  else
    write_int (last1 + (SHA512_BLOCK_SIZE - 8), bits);
  uint512 hash;
  memcpy (hash.c, init_H, sizeof (init_H));
  for (i = 0; i < input_blocks; i++) {
    compute_sha512 (((unsigned long long int *) (input + 128 * i)), &hash, 0);
#ifdef DEBUG_PRINT
    printf ("hash is %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx\n",
            hash.i [0], hash.i [1], hash.i [2], hash.i [3],
            hash.i [4], hash.i [5], hash.i [6], hash.i [7]);
    print_data (hash.c, 32);
#endif /* DEBUG_PRINT */
  }
  compute_sha512 (((unsigned long long int *) last1), &hash, 0);
  if (padding < 17)
    compute_sha512 (((unsigned long long int *) last2), &hash, 0);
#ifdef DEBUG_PRINT
  printf ("final hash is %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx\n",
          hash.i [0], hash.i [1], hash.i [2], hash.i [3],
          hash.i [4], hash.i [5], hash.i [6], hash.i [7]);
  print_data (hash.c, 32);
#endif /* DEBUG_PRINT */

#if __BYTE_ORDER == __LITTLE_ENDIAN
  write_int (result     , hash.i [0]);
  write_int (result +  8, hash.i [1]);
  write_int (result + 16, hash.i [2]);
  write_int (result + 24, hash.i [3]);
  write_int (result + 32, hash.i [4]);
  write_int (result + 40, hash.i [5]);
  write_int (result + 48, hash.i [6]);
  write_int (result + 56, hash.i [7]);
#else /* __BYTE_ORDER != __LITTLE_ENDIAN */
  memcpy (result, hash.c, SHA512_SIZE);
#endif /* __BYTE_ORDER == __LITTLE_ENDIAN */
}

/* the result array must have size rsize, only the first rsize bytes
 * of the hash are saved (or the hash is padded with zeros) */
void sha512_bytes (char * data, int dsize, char * result, int rsize)
{
  char sha [SHA512_SIZE];
  sha512 (data, dsize, sha);
  if (rsize <= SHA512_SIZE) {
    memcpy (result, sha, rsize);
  } else {
    memcpy (result, sha, SHA512_SIZE);
    bzero (result + SHA512_SIZE, rsize - SHA512_SIZE);
  }
}

static char * malloc_concat (char * s1, int s1len, char * s2, int s2len)
{
  char * result = malloc (s1len + s2len);
  if (result == NULL) {
    printf ("malloc_concat: unable to allocate %d + %d = %d bytes\n",
            s1len, s2len, s1len + s2len);
    exit (1);
  }
  memcpy (result, s1, s1len);
  memcpy (result + s1len, s2, s2len);
  return result;
}

/* the result array must have size SHA512_SIZE */
void sha512hmac (char * data, int dsize, char * key, int ksize, char * result)
{
  char key_copy [SHA512_BLOCK_SIZE];
  bzero (key_copy, sizeof (key_copy));
  if (ksize <= SHA512_BLOCK_SIZE) {
    memcpy (key_copy, key, ksize);
  } else {
    sha512 (key, ksize, key_copy);  /* only fills half of key_copy */
  }

  char ipad [SHA512_BLOCK_SIZE];
  char opad [SHA512_BLOCK_SIZE];

  int i;
  for (i = 0; i < SHA512_BLOCK_SIZE; i++) {
    ipad [i] = 0x36 ^ key_copy [i];
    opad [i] = 0x5c ^ key_copy [i];
  }

  char * data1 = malloc_concat (ipad, SHA512_BLOCK_SIZE, data, dsize);
  char hash1 [SHA512_SIZE];
  sha512 (data1, SHA512_BLOCK_SIZE + dsize, hash1);
  free (data1);

  char * data2 = malloc_concat (opad, SHA512_BLOCK_SIZE, hash1, SHA512_SIZE);
  sha512 (data2, SHA512_BLOCK_SIZE + SHA512_SIZE, result);
  free (data2);
}

#ifdef TEST_SHA512

#include <sys/time.h>

static char * delta_time (struct timeval * start, struct timeval * finish)
{
  static char result [100];
  int delta_us = finish->tv_usec - start->tv_usec;
  int delta = finish->tv_sec - start->tv_sec;
  if (delta_us < 0) {
    if (delta > 0) {
      delta_us += 1000000;
      delta -= 1;
    } else {
      snprintf (result, sizeof (result), "negative time");
      return result;
    }
  }
  if (delta < 0) {
    snprintf (result, sizeof (result), "negative time");
  } else {
    snprintf (result, sizeof (result), "%d.%06d", delta, delta_us);
  }
  return result;
}

static void run_test (char * text, int tlen, char * expected)
{
  char result [SHA512_SIZE];
  sha512 (text, tlen, result);
  if (memcmp (result, expected, sizeof (result)) != 0) {
    printf ("error (sha512 of %s): expected\n", text);
    print_data (expected, sizeof (result));
  }
  printf ("sha of %s (%d chars) is:\n", text, tlen);
  print_data (result, sizeof (result));
}

static void hmac_test (int tlen)
{
  char key [] = "foo bar";
  char * data = malloc (tlen);
  char result [SHA512_SIZE];
  sha512hmac (data, tlen, key, strlen (key), result);
  printf ("hmac of input of size %d is:\n", tlen);
  print_data (result, sizeof (result));
}

int main ()
{
  char r4 [] = { 0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba,
                 0xcc, 0x41, 0x73, 0x49, 0xae, 0x20, 0x41, 0x31,
                 0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2,
                 0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a,
                 0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8,
                 0x36, 0xba, 0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd,
                 0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e,
                 0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f };
  run_test ("abc", 3, r4);

  char r1 [] = { 0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd,
                 0xf1, 0x54, 0x28, 0x50, 0xd6, 0x6d, 0x80, 0x07,
                 0xd6, 0x20, 0xe4, 0x05, 0x0b, 0x57, 0x15, 0xdc,
                 0x83, 0xf4, 0xa9, 0x21, 0xd3, 0x6c, 0xe9, 0xce,
                 0x47, 0xd0, 0xd1, 0x3c, 0x5d, 0x85, 0xf2, 0xb0,
                 0xff, 0x83, 0x18, 0xd2, 0x87, 0x7e, 0xec, 0x2f,
                 0x63, 0xb9, 0x31, 0xbd, 0x47, 0x41, 0x7a, 0x81,
                 0xa5, 0x38, 0x32, 0x7a, 0xf9, 0x27, 0xda, 0x3e};
  run_test ("", 0, r1);

  char r2 [] = { 0x07, 0xe5, 0x47, 0xd9, 0x58, 0x6f, 0x6a, 0x73,
                 0xf7, 0x3f, 0xba, 0xc0, 0x43, 0x5e, 0xd7, 0x69,
                 0x51, 0x21, 0x8f, 0xb7, 0xd0, 0xc8, 0xd7, 0x88,
                 0xa3, 0x09, 0xd7, 0x85, 0x43, 0x6b, 0xbb, 0x64,
                 0x2e, 0x93, 0xa2, 0x52, 0xa9, 0x54, 0xf2, 0x39,
                 0x12, 0x54, 0x7d, 0x1e, 0x8a, 0x3b, 0x5e, 0xd6,
                 0xe1, 0xbf, 0xd7, 0x09, 0x78, 0x21, 0x23, 0x3f,
                 0xa0, 0x53, 0x8f, 0x3d, 0xb8, 0x54, 0xfe, 0xe6 };
  run_test ("The quick brown fox jumps over the lazy dog", 43, r2);

  char r3 [] = { 0x91, 0xea, 0x12, 0x45, 0xf2, 0x0d, 0x46, 0xae,
                 0x9a, 0x03, 0x7a, 0x98, 0x9f, 0x54, 0xf1, 0xf7,
                 0x90, 0xf0, 0xa4, 0x76, 0x07, 0xee, 0xb8, 0xa1,
                 0x4d, 0x12, 0x89, 0x0c, 0xea, 0x77, 0xa1, 0xbb,
                 0xc6, 0xc7, 0xed, 0x9c, 0xf2, 0x05, 0xe6, 0x7b,
                 0x7f, 0x2b, 0x8f, 0xd4, 0xc7, 0xdf, 0xd3, 0xa7,
                 0xa8, 0x61, 0x7e, 0x45, 0xf3, 0xc4, 0x63, 0xd4,
                 0x81, 0xc7, 0xe5, 0x86, 0xc3, 0x9a, 0xc1, 0xed };
  run_test ("The quick brown fox jumps over the lazy dog.", 44, r3);

  char r5 [] = { 0x8e, 0x95, 0x9b, 0x75, 0xda, 0xe3, 0x13, 0xda,
                 0x8c, 0xf4, 0xf7, 0x28, 0x14, 0xfc, 0x14, 0x3f,
                 0x8f, 0x77, 0x79, 0xc6, 0xeb, 0x9f, 0x7f, 0xa1,
                 0x72, 0x99, 0xae, 0xad, 0xb6, 0x88, 0x90, 0x18,
                 0x50, 0x1d, 0x28, 0x9e, 0x49, 0x00, 0xf7, 0xe4,
                 0x33, 0x1b, 0x99, 0xde, 0xc4, 0xb5, 0x43, 0x3a,
                 0xc7, 0xd3, 0x29, 0xee, 0xb6, 0xdd, 0x26, 0x54,
                 0x5e, 0x96, 0xe5, 0x5b, 0x87, 0x4b, 0xe9, 0x09 };
  run_test ("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", 112, r5);

  char r6 [] = { 0x70, 0x7c, 0xc5, 0x13, 0xaa, 0x52, 0xbd, 0xaa,
                 0xe8, 0xd3, 0xef, 0xd4, 0xf1, 0x75, 0xcf, 0x94,
                 0x27, 0x5e, 0x4e, 0xaf, 0xde, 0xf0, 0x47, 0x17,
                 0x1d, 0x4c, 0x1b, 0x3f, 0x1e, 0xc4, 0x35, 0x62,
                 0x0a, 0x1a, 0xe9, 0xc3, 0x85, 0x91, 0xb1, 0xcb,
                 0xaa, 0xe2, 0x4a, 0x2e, 0x2b, 0x04, 0xf4, 0x0f,
                 0x70, 0x2f, 0xf8, 0x58, 0xe0, 0x89, 0x26, 0x38,
                 0x20, 0xa2, 0x84, 0x1b, 0xdf, 0x84, 0x15, 0xf1 };

  run_test ("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstuabcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstuabcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstuabcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstuabcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoi", 513, r6);

  hmac_test (511);
  hmac_test (512);
  hmac_test (513);
  hmac_test (514);
  hmac_test (515);
}

#endif /* TEST_SHA512 */


