/* sha.c: compute sha512 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <sys/types.h>

#include "sha.h"

#define SHA512_BLOCK_SIZE	128	/* 1024 bits or 128 bytes */
#define SHA1_BLOCK_SIZE		64	/*  512 bits or  64 bytes */

static int debugging = 0;
#ifdef SHA_UNIT_TEST
#define DEBUG_PRINT
#endif /* SHA_UNIT_TEST */

typedef union uint512 {
  unsigned char c [512 / 8];
  uint64_t i [512 / (8 * sizeof (uint64_t))];
} uint512;

typedef union uint160 {
  unsigned char c [160 / 8];   			/* 20 bytes */
  uint32_t i [160 / (8 * sizeof (uint32_t))];  	/* 5 words */
} uint160;

static const uint64_t K512 [] = {
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

static const uint64_t init_H512 [] =
  { 0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1, 
    0x510e527fade682d1, 0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b, 0x5be0cd19137e2179 };

static const uint32_t init_H1 [] =
  { 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0 };

#define shr(n, x) ((x) >> (n))
#define rotr64(n, x) (((x) >> (n)) | ((x) << (64 - (n))))
#define rotl32(n, x) (((x) << (n)) | ((x) >> (32 - (n))))

static inline uint64_t ch (uint64_t x, uint64_t y, uint64_t z)
{
  return (x & y) ^ ((~x) & z);
}

static inline uint64_t maj (uint64_t x, uint64_t y, uint64_t z)
{
  return (x & y) ^ (x & z) ^ (y & z);
}

static inline uint64_t SIGMA0 (uint64_t x)
{
  return rotr64 (28, x) ^ rotr64 (34, x) ^ rotr64 (39, x);
}

static inline uint64_t SIGMA1 (uint64_t x)
{
  return rotr64 (14, x) ^ rotr64 (18, x) ^ rotr64 (41, x);
}

static inline uint64_t sigma0 (uint64_t x)
{
  return rotr64 (1, x) ^ rotr64 (8, x) ^ shr (7, x);
}

static inline uint64_t sigma1 (uint64_t x)
{
  return rotr64 (19, x) ^ rotr64 (61, x) ^ shr (6, x);
}

#ifdef DEBUG_PRINT
static void print_data (unsigned char * data, int length)
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

static inline uint64_t read_int (char * data)
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

static inline uint32_t read_int32 (char * data)
{
  return ((((uint32_t) (data [0] & 0xff)) << 24) |
          (((uint32_t) (data [1] & 0xff)) << 16) |
          (((uint32_t) (data [2] & 0xff)) <<  8) |
          (((uint32_t) (data [3] & 0xff))      ));
}

static inline void write_int32 (char * data, uint32_t value)
{
  data [3] = value;
  data [2] = value >>  8;
  data [1] = value >> 16;
  data [0] = value >> 24;
}

static inline void write_int (char * data, uint64_t value)
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
  init_w_native_byte_order (uint64_t * W, const uint64_t * block)
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

static inline void init_w (uint64_t * W, const uint64_t * block)
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
 * hash is the 160-bit/20-byte/5-word input and output hash
 * native_in is 1 if we don't have to revert the bytes of the block on
 * a little-endian machine */
static void compute_sha512 (const uint64_t * block,
                            uint512 * hash, int native_in) 
{
  uint64_t W [80];
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
  uint64_t a = hash->i [0];
  uint64_t b = hash->i [1];
  uint64_t c = hash->i [2];
  uint64_t d = hash->i [3];
  uint64_t e = hash->i [4];
  uint64_t f = hash->i [5];
  uint64_t g = hash->i [6];
  uint64_t h = hash->i [7];
#ifdef DEBUG_PRINT
  if (debugging)
    printf ("in: %016" PRIx64 " %016" PRIx64 " %016" PRIx64 " %016" PRIx64 " %016" PRIx64 " %016" PRIx64 " %016" PRIx64 " %016" PRIx64 "\n",
            a, b, c, d, e, f, g, h);

  if (debugging)
    printf ("          A                B                C                D                E                F                G                H\n");
#endif /* DEBUG_PRINT */
  /* step 3 */
  for (t = 0; t < 80; t++) {
    uint64_t t1 =
      h + SIGMA1 (e) + ch (e, f, g) + K512 [t] + W [t];
    uint64_t t2 = SIGMA0 (a) + maj (a, b, c);
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
      printf ("t = %2d: %016" PRIx64 " %016" PRIx64 " %016" PRIx64 " %016" PRIx64 " %016" PRIx64 " %016" PRIx64 " %016" PRIx64 " %016" PRIx64 "\n",
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
    printf ("hash = %16" PRIx64 " %16" PRIx64 " %16" PRIx64 " %16" PRIx64 " %16" PRIx64 " %16" PRIx64 " %16" PRIx64 " %16" PRIx64 "\n",
            hash->i [0], hash->i [1], hash->i [2], hash->i [3],
            hash->i [4], hash->i [5], hash->i [6], hash->i [7]);
}

/* the result array must have size SHA512_SIZE */
/* #define SHA512_SIZE	64 */
void sha512 (const char * input, int bytes, char * result)
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
  memcpy (hash.c, init_H512, sizeof (init_H512));
  for (i = 0; i < input_blocks; i++) {
    compute_sha512 (((uint64_t *) (input + 128 * i)), &hash, 0);
#ifdef DEBUG_PRINT
    printf ("hash is %016" PRIx64 " %016" PRIx64 " %016" PRIx64 " %016" PRIx64 " %016" PRIx64 " %016" PRIx64 " %016" PRIx64 " %016" PRIx64 "\n",
            hash.i [0], hash.i [1], hash.i [2], hash.i [3],
            hash.i [4], hash.i [5], hash.i [6], hash.i [7]);
    print_data (hash.c, 64);
#endif /* DEBUG_PRINT */
  }
  compute_sha512 (((uint64_t *) last1), &hash, 0);
  if (padding < 17)
    compute_sha512 (((uint64_t *) last2), &hash, 0);
#ifdef DEBUG_PRINT
  if (debugging) {
    printf ("final hash is %016" PRIx64 " %016" PRIx64 " %016" PRIx64 " %016" PRIx64 " %016" PRIx64 " %016" PRIx64 " %016" PRIx64 " %016" PRIx64 "\n",
            hash.i [0], hash.i [1], hash.i [2], hash.i [3],
            hash.i [4], hash.i [5], hash.i [6], hash.i [7]);
    print_data (hash.c, 64);
  }
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
void sha512_bytes (const char * data, int dsize, char * result, int rsize)
{
  char sha [SHA512_SIZE];
  sha512 (data, dsize, sha);
  if (rsize <= SHA512_SIZE) {
    memcpy (result, sha, rsize);
  } else {
    memcpy (result, sha, SHA512_SIZE);
    memset (result + SHA512_SIZE, 0, rsize - SHA512_SIZE);
  }
}

static inline void
  init_w32_native_byte_order (uint32_t * W, const uint32_t * block)
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
    W [t] = rotl32 (1, W [t - 3] ^ W [t - 8] ^ W [t - 14] ^ W [t - 16]);
}

static inline void init_w32 (uint32_t * W, const uint32_t * block)
{
  int t;
  for (t = 0; t < 16; t++)
    W [t] = read_int32 ((char *) (block + t));
  for (t = 16; t < 80; t++)
    W [t] = rotl32 (1, W [t - 3] ^ W [t - 8] ^ W [t - 14] ^ W [t - 16]);
}

/* do the basic hash of one block. */
/* block is the 512-bit/64-byte/16-word input block.
 * hash is the 256-bit/32-byte/8-word input and output hash
 * native_in is 1 if we don't have to revert the bytes of the block on
 * a little-endian machine */
static void compute_sha1 (const uint32_t * block,
                          uint160 * hash, int native_in) 
{
  uint32_t W [80];
  int t;

  /* step 1 */
#if __BYTE_ORDER == __LITTLE_ENDIAN
  if (native_in)
#endif /* __BYTE_ORDER == __LITTLE_ENDIAN */
    init_w32_native_byte_order (W, block);
#if __BYTE_ORDER == __LITTLE_ENDIAN
  else
    init_w32 (W, block);
#endif /* __BYTE_ORDER == __LITTLE_ENDIAN */

  /* step 2 */
  uint32_t a = hash->i [0];
  uint32_t b = hash->i [1];
  uint32_t c = hash->i [2];
  uint32_t d = hash->i [3];
  uint32_t e = hash->i [4];
#ifdef DEBUG_PRINT
  if (debugging)
    printf ("in: %08" PRIx32 " %08" PRIx32 " %08" PRIx32 " %08" PRIx32 " %08" PRIx32 "\n",
            a, b, c, d, e);

  if (debugging)
    printf ("        A        B        C        D        E\n");
#endif /* DEBUG_PRINT */
  /* step 3 */
  uint32_t f;
  uint32_t k;
  for (t = 0; t < 80; t++) {
    if (t < 20) {
      f = (b & c) | ((~ b) & d);
      k = 0x5A827999;
    } else if (t < 40) {
      f = b ^ c ^ d;
      k = 0x6ED9EBA1;
    } else if (t < 60) {
      f = (b & c) | (b & d) | (c & d);
      k = 0x8F1BBCDC;
    } else {
      f = b ^ c ^ d;
      k = 0xCA62C1D6;
    }
    uint32_t T = rotl32 (5, a) + f + e + k + W [t];
    e = d;
    d = c;
    c = rotl32 (30, b);
    b = a;
    a = T;
#ifdef DEBUG_PRINT
    if (debugging)
      printf ("t = %2d: %08" PRIx32 " %08" PRIx32 " %08" PRIx32 " %08" PRIx32 " %08" PRIx32 "\n",
              t, a, b, c, d, e);
#endif /* DEBUG_PRINT */
  }

  /* step 4 */
  hash->i [0] += a;
  hash->i [1] += b;
  hash->i [2] += c;
  hash->i [3] += d;
  hash->i [4] += e;
  if (debugging)
    printf ("hash = %8" PRIx32 " %8" PRIx32 " %8" PRIx32 " %8" PRIx32 " %8" PRIx32 "\n",
            hash->i [0], hash->i [1], hash->i [2], hash->i [3], hash->i [4]);
}

/* the result array must have size SHA1_SIZE */
void sha1 (const char * data, int dsize, char * result)
{
  int i;
  if (dsize < 0) {
    printf ("error in sha1 computation; %d (%x) bytes requested\n",
            dsize, dsize);
    exit (1);
  }
  /* padding */
  unsigned int bits = dsize * 8;
  /* number of full input blocks */
  /* int input_blocks = ((dsize + SHA1_BLOCK_SIZE - 1) / SHA1_BLOCK_SIZE) - 1;*/
  int input_blocks = dsize / SHA1_BLOCK_SIZE;

  char last1 [SHA1_BLOCK_SIZE];  /* next-to-last block, has data from input */
  char last2 [SHA1_BLOCK_SIZE];  /* last block, may not be needed */
  memset (last1, 0, sizeof (last1));
  memset (last2, 0, sizeof (last2));
  /* number of bytes in last1 (< SHA1_BLOCK_SIZE), and also index of byte
   * of last1 into which to write the 0x80 which ends the data */
  int last_bytes = dsize % SHA1_BLOCK_SIZE;
  /* number of bytes left in last1 after writing any odd bytes into last1 */
  int padding = SHA1_BLOCK_SIZE - last_bytes;
  /* number of bytes processed in the main loop */
  int full_blocks_bytes = input_blocks * SHA1_BLOCK_SIZE;
  if (dsize > full_blocks_bytes)
    memcpy (last1, data + full_blocks_bytes, dsize - full_blocks_bytes);
  last1 [last_bytes] = 0x80;
  if (padding < 9)  /* we extend if padding < 9 */
    write_int (last2 + (SHA1_BLOCK_SIZE - 8), bits);
  else
    write_int (last1 + (SHA1_BLOCK_SIZE - 8), bits);
  uint160 hash;
  memcpy (hash.c, init_H1, sizeof (init_H1));
  for (i = 0; i < input_blocks; i++) {
    compute_sha1 (((uint32_t *) (data + SHA1_BLOCK_SIZE * i)), &hash, 0);
#ifdef DEBUG_PRINT
    if (debugging) {
      printf ("sha1 is %08" PRIx32 " %08" PRIx32 " %08" PRIx32 " %08" PRIx32 " %08" PRIx32 "\n", hash.i [0], hash.i [1], hash.i [2], hash.i [3], hash.i [4]);
      print_data (hash.c, 20);
    }
#endif /* DEBUG_PRINT */
  }
  compute_sha1 (((uint32_t *) last1), &hash, 0);
  if (padding < 9)
    compute_sha1 (((uint32_t *) last2), &hash, 0);
#ifdef DEBUG_PRINT
    if (debugging) {
      printf ("final sha1 is %08" PRIx32 " %08" PRIx32 " %08" PRIx32 " %08" PRIx32 " %08" PRIx32 "\n", hash.i [0], hash.i [1], hash.i [2], hash.i [3], hash.i [4]);
      print_data (hash.c, 20);
    }
#endif /* DEBUG_PRINT */

#if __BYTE_ORDER == __LITTLE_ENDIAN
  write_int32 (result     , hash.i [0]);
  write_int32 (result +  4, hash.i [1]);
  write_int32 (result +  8, hash.i [2]);
  write_int32 (result + 12, hash.i [3]);
  write_int32 (result + 16, hash.i [4]);
#else /* __BYTE_ORDER != __LITTLE_ENDIAN */
  memcpy (result, hash.c, SHA1_SIZE);
#endif /* __BYTE_ORDER == __LITTLE_ENDIAN */
}

/* the result array must have size rsize, only the first rsize bytes
 * of the hash are saved (or the hash is padded with zeros) */
void sha1_bytes (const char * data, int dsize, char * result, int rsize)
{
  char sha [SHA1_SIZE];
  sha512 (data, dsize, sha);
  if (rsize <= SHA1_SIZE) {
    memcpy (result, sha, rsize);
  } else {
    memcpy (result, sha, SHA1_SIZE);
    memset (result + SHA1_SIZE, 0, rsize - SHA1_SIZE);
  }
}

static char * malloc_concat (const char * s1, int s1len,
                             const char * s2, int s2len)
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
void sha512hmac (const char * data, int dsize, const char * key, int ksize,
                 char * result)
{
  char key_copy [SHA512_BLOCK_SIZE];
  memset (key_copy, 0, sizeof (key_copy));
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

#ifdef SHA_UNIT_TEST

#include <sys/time.h>

#if 0
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
#endif /* 0 */

static void run_test (char * text, int tlen, char * expected)
{
  char result [SHA512_SIZE];
  sha512 (text, tlen, result);
  if (memcmp (result, expected, sizeof (result)) != 0) {
    printf ("error (sha512 of %s): expected\n", text);
    print_data ((unsigned char *) expected, sizeof (result));
  }
  printf ("sha of %s (%d chars) is:\n", text, tlen);
  print_data ((unsigned char *) result, sizeof (result));
}

static void run_test_sha1 (char * text, int tlen, char * expected)
{
  char result [SHA1_SIZE];
  sha1 (text, tlen, result);
  if (memcmp (result, expected, sizeof (result)) != 0) {
    if (tlen != 495)
      printf ("error (sha1 of %s): expected\n", text);
    else
      printf ("error (sha1 of <unprintable>): expected\n");
    print_data ((unsigned char *) expected, sizeof (result));
  }
  if (tlen != 495)
    printf ("sha1 of %s (%d chars) is:\n", text, tlen);
  else
    printf ("sha1 of <unprintable> (%d chars) is:\n", tlen);
  print_data ((unsigned char *) result, sizeof (result));
}

static void hmac_test (int tlen)
{
  char key [] = "foo bar";
  char * data = malloc (tlen);
  char result [SHA512_SIZE];
  sha512hmac (data, tlen, key, strlen (key), result);
  printf ("hmac of input of size %d is:\n", tlen);
  print_data ((unsigned char *) result, sizeof (result));
}

static void sha_given_array (char * array)
{
  debugging = 0;
#define DATA_SIZE	10000
  unsigned char data [DATA_SIZE];
  int i;
  for (i = 0; (i < DATA_SIZE) && (i * 2 < strlen (array)); i++) {
    char two_bytes [3];
    two_bytes [0] = array [2 * i];
    two_bytes [1] = array [2 * i + 1];
    two_bytes [2] = '\0';
    unsigned int value;
    if (sscanf (two_bytes, "%2x", &value) != 1) {
      printf ("unable to parse hex %s at index %d\n", two_bytes, 2 * i);
      return;
    }
    data [i] = value;
  }
  char result [SHA512_SIZE];
  sha512 (data, strlen (array) / 2, result);
  for (i = 0; (i < DATA_SIZE) && (i * 2 < strlen (array)); i++)
    printf ("%02x", (data [i] & 0xff));
  printf ("  ==> \n");
  for (i = 0; i < SHA512_SIZE; i++)
    printf ("%02x", (result [i] & 0xff));
  printf ("\n");
#undef DATA_SIZE
}

int main (int argc, char ** argv)
{
  if (argc > 1) {
    int i;
    for (i = 1; i < argc ; i++)
      sha_given_array (argv [i]);
    return 0;
  }
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

  char sha1_r1 [] = { 0xA9, 0x99, 0x3E, 0x36, 0x47, 0x06, 0x81, 0x6A,
                      0xBA, 0x3E, 0x25, 0x71, 0x78, 0x50, 0xC2, 0x6C,
                      0x9C, 0xD0, 0xD8, 0x9D };

  run_test_sha1 ("abc", 3, sha1_r1);

  char sha1_r2 [] = { 0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d,
                      0x32, 0x55, 0xbf, 0xef, 0x95, 0x60, 0x18, 0x90,
                      0xaf, 0xd8, 0x07, 0x09 };
  run_test_sha1 ("", 0, sha1_r2);

  char sha1_r3 [] = { 0x84, 0x98, 0x3E, 0x44, 0x1C, 0x3B, 0xD2, 0x6E,
                      0xBA, 0xAE, 0x4A, 0xA1, 0xF9, 0x51, 0x29, 0xE5,
                      0xE5, 0x46, 0x70, 0xF1 };
  run_test_sha1 ("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                 56, sha1_r3);

  /* test patterns from RFC 3174, skipping the first two which are r1, r3 */
  /* note that the results shown in RFC 3174 do not match sha1sum nor
   * http://www.hashemall.com/, which match each other */
/* :s/\(..\)/, 0x\1/g */

  char sha1_r4 [] = {
      0x86, 0xf7, 0xe4, 0x37, 0xfa, 0xa5, 0xa7, 0xfc, 0xe1, 0x5d,
      0x1d, 0xdc, 0xb9, 0xea, 0xea, 0xea, 0x37, 0x76, 0x67, 0xb8 };
  run_test_sha1 ("a", 1, sha1_r4);

  char sha1_r5 [] = {
      0xe0, 0xc0, 0x94, 0xe8, 0x67, 0xef, 0x46, 0xc3, 0x50, 0xef,
      0x54, 0xa7, 0xf5, 0x9d, 0xd6, 0x0b, 0xed, 0x92, 0xae, 0x83 };
  run_test_sha1 ("0123456701234567012345670123456701234567012345670123456701234567", 64, sha1_r5);

  char sha1_r6 [] = {
      0xec, 0x2d, 0x31, 0xe3, 0x62, 0x57, 0x43, 0x69, 0x67, 0xeb,
      0xa4, 0xc0, 0x14, 0xfb, 0xe7, 0x19, 0xa1, 0x30, 0x1a, 0x38 };
/* openssl gets ec.2d.31.e3.62.57.43.69.67.eb.a4.c0.14.fb.e7.19.a1.30.1a.38 */
/* length should be 495 */
  char sha1_t6 [] = { 0x98, 0xfe, 0x89, 0xb4, 0x4b, 0xc4, 0x9c, 0x08,
                      0xba, 0x67, 0x86, 0x4a, 0xf8, 0xef, 0x27, 0x20,
                      0xa3, 0x0f, 0x65, 0xe6, 0xf2, 0x4e, 0x64, 0x1a,
                      0x32, 0xe1, 0x06, 0x56, 0x9a, 0x5d, 0x75, 0x53,
                      0xea, 0x8d, 0xb1, 0x4d, 0x41, 0xaa, 0xeb, 0x0a,
                      0x7d, 0x9f, 0xc4, 0x4a, 0x50, 0x56, 0x47, 0x56,
                      0xd9, 0x3f, 0x70, 0xc0, 0xf0, 0xe2, 0x4e, 0xba,
                      0xb5, 0xb2, 0x4d, 0x75, 0xe0, 0x1a, 0x90, 0x83,
                      0x17, 0x0b, 0x1e, 0xf8, 0xdb, 0xa3, 0x2d, 0x3c,
                      0xf1, 0x1c, 0xe8, 0xa1, 0x22, 0x5f, 0x84, 0x0b,
                      0x6b, 0x98, 0x39, 0x02, 0x11, 0x3a, 0xaa, 0xca,
                      0x82, 0x5c, 0x36, 0xba, 0x28, 0x8b, 0xe6, 0xa7,
                      0x2c, 0x42, 0x99, 0x9b, 0x01, 0xe0, 0x78, 0x16,
                      0x68, 0xb8, 0xe2, 0x9d, 0xcc, 0x75, 0xbb, 0x2e,
                      0x7b, 0x46, 0x3e, 0x98, 0x7d, 0x91, 0x48, 0xc9,
                      0x3c, 0x85, 0xd3, 0xea, 0x3b, 0x38, 0x2a, 0x50,
                      0x2f, 0x6c, 0x44, 0x21, 0x79, 0x60, 0xa9, 0x9a,
                      0x0f, 0xd2, 0x3a, 0xe4, 0xb9, 0xe4, 0x4d, 0xb1,
                      0xbb, 0x5a, 0xbd, 0x3c, 0x02, 0x9a, 0xf2, 0x14,
                      0x71, 0xbe, 0x93, 0x31, 0xd6, 0xc7, 0xe5, 0x3d,
                      0xdf, 0x11, 0xd5, 0x71, 0xb8, 0x64, 0xe9, 0x2a,
                      0x5d, 0x19, 0x17, 0x0f, 0xac, 0x74, 0x7e, 0x87,
                      0x72, 0x8d, 0x2c, 0x6e, 0xba, 0x2b, 0x48, 0xb1,
                      0x21, 0xbc, 0xbc, 0x22, 0xd4, 0x06, 0x8f, 0x91,
                      0x35, 0x45, 0x87, 0xe2, 0xaa, 0x4b, 0xa6, 0xae,
                      0xf0, 0x75, 0xee, 0xea, 0xdb, 0xd9, 0x19, 0x57,
                      0xf4, 0x22, 0x56, 0x1c, 0x56, 0xf2, 0x94, 0x15,
                      0x69, 0x73, 0xe1, 0xb0, 0xec, 0x0a, 0xbd, 0x25,
                      0x04, 0xfb, 0xa0, 0xae, 0x63, 0xd7, 0x3d, 0x16,
                      0x67, 0xbf, 0xcc, 0x4a, 0xf6, 0x19, 0x86, 0xb5,
                      0xe0, 0x1b, 0xf3, 0xd5, 0xcf, 0xdb, 0x3c, 0x97,
                      0x7d, 0x6d, 0x4a, 0xff, 0x05, 0x0d, 0x81, 0x01,
                      0x2b, 0xcd, 0xe4, 0xf4, 0xea, 0x76, 0xbc, 0xb0,
                      0x84, 0x1e, 0x17, 0x59, 0x8f, 0xa3, 0x40, 0x6c,
                      0x90, 0xcc, 0x43, 0x30, 0xe7, 0xbd, 0xb5, 0xb2,
                      0x07, 0x83, 0x6f, 0xce, 0x27, 0x6e, 0xc7, 0x46,
                      0xef, 0x6a, 0x39, 0x58, 0xac, 0x4e, 0xcd, 0xb7,
                      0xfe, 0x32, 0x84, 0xe9, 0x52, 0xfe, 0x48, 0x73,
                      0xde, 0xfd, 0x14, 0x13, 0x98, 0x20, 0x52, 0x09,
                      0xa4, 0x34, 0xf1, 0x82, 0xb8, 0xc2, 0xc8, 0x67,
                      0xca, 0x62, 0x63, 0x5a, 0x97, 0xe2, 0x20, 0xd5,
                      0x03, 0xf8, 0x07, 0x3c, 0x42, 0xdf, 0xca, 0x4c,
                      0xa7, 0xd4, 0xc1, 0xe0, 0x30, 0xb5, 0x1e, 0x6c, 
                      0x5d, 0xf1, 0x60, 0x5a, 0xa6, 0xee, 0xca, 0xcf, 
                      0xc1, 0x01, 0x54, 0x99, 0xaf, 0x2a, 0xd8, 0x80,
                      0xe4, 0x75, 0xc9, 0xc5, 0xa9, 0x93, 0xad, 0xae,
                      0xb3, 0x3b, 0x05, 0x55, 0xa7, 0xcf, 0x88, 0x05,
                      0x1c, 0x34, 0xa7, 0xcf, 0xee, 0xf5, 0x64, 0x28,
                      0x8b, 0x65, 0xf6, 0x16, 0x7c, 0x94, 0x7a, 0x2a,
                      0xc2, 0x1d, 0x6c, 0xc8, 0xf8, 0x32, 0xba, 0x7c,
                      0x58, 0xd6, 0xbf, 0xb9, 0x39, 0x13, 0x1f, 0xdd,
                      0x9b, 0xac, 0xd3, 0x99, 0x68, 0x45, 0x79, 0x83,
                      0xb9, 0xca, 0xf8, 0xae, 0xc8, 0x6c, 0xf7, 0x77,
                      0x70, 0xaa, 0x25, 0xe2, 0xb5, 0x7c, 0x7e, 0x49,
                      0x78, 0x74, 0xa7, 0x51, 0x97, 0x19, 0x20, 0x40,
                      0x7a, 0xcb, 0xc3, 0x65, 0xa2, 0x0b, 0x3d, 0x80,
                      0x4c, 0x34, 0x80, 0x64, 0x4b, 0xd8, 0xe5, 0xcc,
                      0x49, 0x7c, 0x98, 0x0f, 0xf2, 0x19, 0x3d, 0xb0,
                      0x0d, 0xda, 0x4f, 0x8a, 0xc6, 0x12, 0x69, 0x36,
                      0x0c, 0xb6, 0xc4, 0x48, 0x39, 0x7c, 0xaa, 0x75,
                      0x77, 0x8e, 0x93, 0xcc, 0x4c, 0xed, 0x5b, 0xa1,
                      0xad, 0xbc, 0xde, 0x00, 0x00, 0x00, 0x00 };
  if (sizeof (sha1_t6) != 495)
    printf ("size of sha1_t6 is %zd, should be 495\n", sizeof (sha1_t6));
  run_test_sha1 (sha1_t6, 495, sha1_r6);

  return 0;
}

#endif /* SHA_UNIT_TEST */


