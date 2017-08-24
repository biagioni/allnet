/* asn1.c: read and write values in ans.1 format */

/* each function returns 0 if it fails, and the byte count > 0 otherwise
 * functions called with a NULL result just return the size */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>

#include "wp_rsa.h"
#include "wp_arith.h"

static const char * debug_data = NULL;

static int read_byte (const char * data, int dsize, int * read_error)
{
  if (dsize <= 0) {
    *read_error = 1;
    return 0;
  }
/*
if (debug_data != NULL)
printf ("returning data [%ld] %02x\n", data - debug_data, data [0] & 0xff);
else printf ("returning data %02x\n", data [0] & 0xff);
*/
  return data [0] & 0xff;
}

/* only handles the definite form */
static int read_length (const char * data, int dsize, int * length)
{
  if (length != NULL)
    * length = -1;
  int read_error = 0;
  int first = read_byte (data++, dsize--, &read_error);
  if (read_error)
    return 0;
  if ((first & 0x80) == 0) {  /* short form */
    if (length != NULL)
      * length = (first & 0x7f);
/* printf ("returning lengths 1 %d\n", (first & 0x7f)); */
    return 1;
  }
  int nbytes = (first & 0x7f);
  if (nbytes >= 4) {
    printf ("input error: unable to read size %d > 3 bytes\n", nbytes);
    return 0;
  }
  int result = nbytes + 1;
  int rlength = 0;
  while (nbytes-- > 0)
    rlength = rlength * 256 + read_byte (data++, dsize--, &read_error);
  if (read_error)
    return 0;
  if (length != NULL)
    *length = rlength;
/* printf ("returning lengths x%x x%x\n", result, rlength); */
  return result;
}

/* returns in num_elements the number of elements in the sequence */
/* if specific_element >= 0, returns in specific_pos the position of
 * the given element, as long as the sequence has that many elements. */
int asn1_read_seq (const char * data, int dsize, int * num_elements,
                   int specific_element, int * specific_pos)
{
debug_data = data;
  if (num_elements != NULL)
    *num_elements = 0;
  int read_error = 0;
  int id = read_byte (data, dsize, &read_error);
  if (read_error || ((id & 0x1f) != 0x10))
    return 0;
  int length, length_bytes;
  length_bytes = read_length (data + 1, dsize - 1, &length);
  if (length_bytes <= 0)
    return 0;
/*printf ("sequence length is %d (%d)\n", length, dsize - 1 - length_bytes); */
  int seq_len = 1 + length_bytes + length;  /* number of bytes in sequence */
  if (seq_len > dsize) {
    printf ("input error: seq length %d (1 + %d + %d) out of %d\n",
            seq_len, length_bytes, length, dsize);
    return 0;
  }
  
  if ((specific_element >= 0) && (specific_pos != NULL))
    * specific_pos = 0;
  int pos = 1 + length_bytes;
  int i = 0;
  while (1) {
    int ebytes;
    int elbytes = read_length (data + pos + 1, seq_len - pos - 1, &ebytes);
    if ((ebytes < 0) || (elbytes <= 0) ||
        (pos + ebytes + elbytes + 1 > seq_len)) {
      printf ("input error reading element %d at position %d\n", i, pos);
      printf ("    %d %d %d\n", ebytes, elbytes, seq_len);
      return 0;
    }
    if ((specific_element == i) && (specific_pos != NULL))
      * specific_pos = pos;
    pos += ebytes + elbytes + 1;
    i++;
    if (pos == seq_len) {
      if (num_elements != NULL)
        *num_elements = i;
      return seq_len;
    }
  }
}

/* returns 0 for error, 1 for success */
static int read_int (const char * data, int dsize, uint64_t * result)
{
  int re = 0;
  int id = read_byte (data, dsize, &re) & 0x1f;
  if (re || (id != 2)) {
    printf ("read_int error: read_error %d, id %d (wanted 2)\n", re, id);
    return 0;
  }
  int length;
  int length_bytes = read_length (data + 1, dsize - 1, &length);
  if ((length_bytes <= 0) || (length > 4)) {
    printf ("read_int error: %d bytes encoding length %d (max 4)\n",
            length_bytes, length);
    return 0;
  }
  data  += 1 + length_bytes;
  dsize -= 1 + length_bytes;
  long int value = 0;
  while ((! re) && (length-- > 0))
    value = value * 256 + read_byte (data++, dsize--, &re);
  if (re) {
    printf ("read_int error: %d bytes left\n", length);
    return 0;
  }
  *result = value;
  return 1;
}

static void print_indent (int indent)
{
  while (indent-- > 0)
    printf (" ");
}

static void print_sequence (const char * data, int dsize, int indent)
{
  int num_elements;
  /* get the number of elements */
  int size = asn1_read_seq (data, dsize, &num_elements, -1, NULL);
  print_indent (indent);
  printf ("sequence has %d elements in %d/%d bytes\n",
          num_elements, size, dsize);
  if (size <= 0) {
    print_indent (indent);
    int length;
    read_length (data + 1, dsize - 1, &length);
    printf ("not a sequence, first byte %02x, length %d\n",
            data [0] & 0xff, length);
    return;
  }
  int e;
  for (e = 0; e < num_elements; e++) {
    int epos;
    asn1_read_seq (data, dsize, &num_elements, e, &epos);
    print_indent (indent);
    printf ("element %d is at position %d\n", e, epos);
    print_sequence (data + epos, dsize - epos, indent + 3);
  }
}

static int check_int (const char * data, int dsize, int expected)
{
  uint64_t found;
  if (read_int (data, dsize, &found))
    if (found == expected)
      return 1;
  return 0;
}

static char rsa_object_id [] =
 { 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
   0x01, 0x01, 0x01, 0x05, 0x00 };

static int check_rsa_id (const char * data, int dsize)
{
  if (dsize < sizeof (rsa_object_id)) {
    printf ("check_rsa_id failed, size %d, wanted %zd\n",
            dsize, sizeof (rsa_object_id));
    return 0;
  }
  if (memcmp (data, rsa_object_id, sizeof (rsa_object_id)) != 0) {
    printf ("check_rsa_id failed, data does not match\n");
    return 0;
  }
  return 1;
}

/* returns 0 for error, 1 for success */
static int read_key (const char * data, int dsize, int nbits,
                     uint64_t * result, int * bits_read)
{
  int re = 0;
  int id = read_byte (data, dsize, &re) & 0x1f;
  if (re || (id != 2)) {
    printf ("read_key error: read_error %d, id %d (wanted 2)\n", re, id);
    return 0;
  }
  int length;
  int length_bytes = read_length (data + 1, dsize - 1, &length);
  if (length_bytes <= 0) {
    printf ("read_key error: %d bytes encoding length %d (max %d)\n",
            length_bytes, length, nbits / 8);
    return 0;
  }
  data  += 1 + length_bytes;
  dsize -= 1 + length_bytes;
  if ((read_byte (data, dsize, &re) == 0) && (! re)) {
    data++;    /* ignore an initial zero byte */
    dsize--;
    length--;
  }
  if (length * 8 > nbits) {
    printf ("integer length is %d (%d bits), max %d\n",
            length, length * 8, nbits);
    return 0;
  }
  wp_from_bytes (nbits, result, dsize, data);
  if (bits_read != NULL)
    *bits_read = length * 8;
  return 1;
}

/* returns 1 if read a private key, returns 2 if read a public key,
 * and zero in case of errors (including extra bytes at the end). */
static int wp_rsa_read (const char * data, int dsize,
                        int * nbits, wp_rsa_key_pair * key)
{
debug_data = data;
int debug_dsize = dsize;
  memset (key, 0, sizeof (wp_rsa_key_pair));  /* set all unused keys to 0 */
  int num_elements;
  int length = asn1_read_seq (data, dsize, &num_elements, -1, NULL);
  if (length != dsize) {
    printf ("error: reading sequence gives length %d, data %d bytes\n",
            length, dsize);
    return 0;
  }
  int epos [9];    /* positions of up to 9 elements in the sequence */
  int e;
  if (num_elements == 3) {
    /* determine whether this is a public key (0, n, e) or an encapsulated
     * key preceded by the RSA ID */
    for (e = 0; e < num_elements; e++)
      asn1_read_seq (data, dsize, NULL, e, epos + e);
    int re = 0;
    /* if this is an encapsulated key, this is an octet string/os = 4 */
    int os_byte = read_byte (data + epos [2], dsize - epos [2], &re) & 0x1f;
    if (re)   /* error reading the byte */
      os_byte = -1;
    if ((check_int (data + epos [0], dsize - epos [0], 0)) &&
        (check_rsa_id (data + epos [1], dsize - epos [1])) &&
        (os_byte == 4)) {
       /* encapsulated key, open the octet string to find the key integers */
      data  += epos [2];
      dsize -= epos [2];
      int os_length;
      int length_bytes = read_length (data + 1, dsize - 2, &os_length);
      if (length_bytes <= 0) {
        printf ("error: no octet stream length\n");
        return 0;
      }
      data  += 1 + length_bytes;
      dsize -= 1 + length_bytes;
      int seq_length = asn1_read_seq (data, dsize, &num_elements, -1, NULL);
      if (seq_length != dsize) {
        printf ("error: inner sequence gives length %d, data %d bytes\n",
                seq_length, dsize);
        return 0;
      }
    }
  }
  if ((num_elements != 2) &&   /* public key only: n, e */
      (num_elements != 3) &&   /* public key only: 0, n, e */
      (num_elements != 4) &&   /* public + secret key: 0, n, e, d */
      (num_elements != 9)) {   /* pub+sec: 0, n, e, d, p, q, dp, dq, qinv */
    printf ("error: expected 2, 3, 4, or 9 elements in key seq, got %d %d\n",
            num_elements, debug_dsize);
    print_sequence (debug_data, debug_dsize, 0);
    return 0;
  }
  for (e = 0; e < num_elements; e++)
    asn1_read_seq (data, dsize, NULL, e, epos + e);
  if (num_elements > 2) {
    /* make sure the first element is a zero int, then ignore it */
    if (! check_int (data + epos [0], dsize - epos [0], 0))
      return 0;
    for (e = 1; e < num_elements; e++)  /* delete that element */
      epos [e - 1] = epos [e];
    num_elements--;
  }
  if (! read_key (data + epos [0], dsize - epos [0],  /* read n */
                  WP_RSA_MAX_KEY_BITS, key->n, &(key->nbits)))
    return 0;
  while ((key->nbits % 8) != 0) 
    (key->nbits)++;
  if (nbits != NULL)
    *nbits = key->nbits;
  int nhalf = key->nbits / 2;
  if (! read_int (data + epos [1], dsize - epos [1], &(key->e)))  /* e */
    return 0;
/* printf ("read %d-bit public key\n", key->nbits); */
  if ((num_elements > 2) &&
      (! read_key (data + epos [2], dsize - epos [2], key->nbits,
                   key->d, NULL)))
    return 0;
  if ((num_elements > 7) &&
      (! (read_key (data + epos [3], dsize - epos [3], nhalf, key->p, NULL) &&
          read_key (data + epos [4], dsize - epos [4], nhalf, key->q, NULL) &&
          read_key (data + epos [5], dsize - epos [5], nhalf, key->dp, NULL) &&
          read_key (data + epos [6], dsize - epos [6], nhalf, key->dq, NULL) &&
          read_key (data + epos [7], dsize - epos [7], nhalf, key->qinv,
                    NULL))))
    return 0;
  if (num_elements > 2)
    return 1;
  return 2;
}

/* all the write operations write back from the end of the buffer, and
 * return the number n of bytes written.  The content will be found
 * at buffer [dsize - n].. buffer [dsize -1].
 * 0 is returned in case of error */

static int write_id_len (char * buffer, int bsize, int id, int seqsize, int c)
{
  if (c)
    id |= 0x20;
  if ((seqsize < 0) || (bsize < 2))
    return 0;
  int written = 0;
  if (seqsize <= 127) {
    buffer [bsize - 1] = seqsize;
    written++;
  } else {
    int shifted_size = seqsize;
    while ((written + 1 < bsize) && (shifted_size >= 256)) {
      if ((written >= 4) || (written + 2 >= bsize))
        return 0;
      buffer [bsize - 1 - written] = shifted_size & 0xff;
      written++;
      shifted_size >>= 8;
    }
    buffer [bsize - 1 - written] = shifted_size & 0xff;
    written++;
    buffer [bsize - 1 - written] = written | 0x80;
    written++;
  }
  buffer [bsize - 1 - written] = id;
  written++;
  return written;
}

static int write_int (char * buffer, int bsize, const uint64_t * n, int nbits)
{
  int written = 0;
  int nbytes =  nbits / 8;
  int wbytes =  nbytes;
  while ((wbytes > 0) && (wp_get_byte (nbits, n, wbytes - 1) == 0))
    wbytes--;
  if (wbytes == 0)
    wbytes++;
  if (wp_get_byte (nbits, n, wbytes - 1) & 0x80)
    wbytes++;
  if (wbytes + 4 >= bsize)
    return 0;
  int i;
  for (i = 0; (i < wbytes) && (i < nbytes); i++) {
    buffer [bsize - 1 - written] = wp_get_byte (nbits, n, i);
    written++;
  }
  if (wbytes > nbytes) {
    buffer [bsize - 1 - written] = 0;
    written++;
  }
  written += write_id_len (buffer, bsize - written, 0x02, written, 0);
#ifdef DEBUG_PRINT
  printf ("write_int (%d, %d) => %d, %d returning %d\n", bsize, nbits,
          wbytes, nbytes, written);
#endif /* DEBUG_PRINT */
  return written;
}

static int wp_rsa_write_key_to_bytes (char * buffer, int bsize,
                                      const wp_rsa_key_pair * key)
{
  int write_zero = 0;
#ifdef ENCAPSULATE_KEY
  write_zero = 1;
#endif /* ENCAPSULATE_KEY */
  int written = 0;
  if (! wp_is_zero (key->nbits, key->d)) {  /* has private key */
    write_zero = 1;
    if ((! wp_is_zero (key->nbits / 2, key->p)) &&
        (! wp_is_zero (key->nbits / 2, key->q)) &&
        (! wp_is_zero (key->nbits / 2, key->dp)) &&
        (! wp_is_zero (key->nbits / 2, key->dq)) &&
        (! wp_is_zero (key->nbits / 2, key->qinv))) {
      /* private key with primes and exponentes */
      written += write_int (buffer, bsize - written, key->qinv, key->nbits / 2);
      written += write_int (buffer, bsize - written, key->dq, key->nbits / 2);
      written += write_int (buffer, bsize - written, key->dp, key->nbits / 2);
      written += write_int (buffer, bsize - written, key->q, key->nbits / 2);
      written += write_int (buffer, bsize - written, key->p, key->nbits / 2);
    }
    written += write_int (buffer, bsize - written, key->d, key->nbits);
  }
  uint64_t elong;
  wp_init (64, &elong, (int) (key->e));
  written += write_int (buffer, bsize - written, &elong, 64);
  written += write_int (buffer, bsize - written, key->n, key->nbits);
  if (write_zero) {    /* write zero if encapsulated or has private key */
    uint64_t zero;
    wp_init (64, &zero, 0);
    written += write_int (buffer, bsize - written, &zero, 64);
  }
  /* write the header for the sequence of ints */
  written += write_id_len (buffer, bsize - written, 0x10, written, 1);
#ifdef ENCAPSULATE_KEY
  /* write the header for the octet string */
  written += write_id_len (buffer, bsize - written, 0x04, written, 0);
  /* write the object ID identifying RSA */
  int osize = sizeof (rsa_object_id);
  if (bsize - written > osize) {
    memcpy (buffer + bsize - written - osize, rsa_object_id, osize);
    written += osize;
  }
  /* write zero */
  written += write_int (buffer, bsize - written, &zero, 64);
  /* write the header for the overall sequence */
  written += write_id_len (buffer, bsize - written, 0x10, written, 1);
#endif /* ENCAPSULATE_KEY */
  return written;
}

#define B64_PADDING	64
#define B64_IGNORE	65
#define B64_DONE	66

static int b64_next (int c)
{
  if ((c >= 'A') && (c <= 'Z'))
    return (c - 'A');
  if ((c >= 'a') && (c <= 'z'))
    return (c - 'a') + 26;
  if ((c >= '0') && (c <= '9'))
    return (c - '0') + 52;
  if (c == '+') return 62;
  if (c == '/') return 63;
  if (c == '=') return B64_PADDING;
  if (c == '-') return B64_DONE;
  return B64_IGNORE;
}

static int b64_encode_bits (int bits)
{
  if ((bits < 0) || (bits >= 64)) {
    printf ("error: b64_encode_bits (%d), must be 0..63\n", bits);
    return -1;
  }
  if (bits < 26)
    return bits + 'A';
  bits -= 26;
  if (bits < 26)
    return bits + 'a';
  bits -= 26;
  if (bits < 10)
    return bits + '0';
  bits -= 10;
  if (bits == 0)
    return '+';
  return '/';
}

/* data and result may be the same buffer -- we only write to result
 * after reading from data */
int b64_decode (const char * data, int dsize, char * result, int rsize)
{
  int written = 0;
  int state = 0;
  int old_char = B64_IGNORE;
  int i;
  for (i = 0; (i < dsize) && (written < rsize); i++) {
    int v = b64_next (data [i]);
    if (v < B64_PADDING) {
      if (state == 0) {
        old_char = (v << 2);
      } else if (state == 1) {
        result [written++] = old_char | (v >> 4);
        old_char = (v << 4) & 0xff;
      } else if (state == 2) {
        result [written++] = old_char | (v >> 2);
        old_char = (v << 6) & 0xff;
      } else if (state == 3) {
        result [written++] = old_char | v;
      } else {
        printf ("error in b64decode, state %d, only 0..3 allowed\n", state);
        return 0;  /* programming error */
      }
      state = (state + 1) % 4;
    } else if (v == B64_PADDING) {
      if (state == 0)
        printf ("b64 error: there should be no padding in state 0\n");
      state = (state + 1) % 4;
    }
  }

  if (state != 0)
    printf ("b64_decode warning: final state %d is nonzero, %d/%d, %d/%d\n",
            state, i, dsize, written, rsize);
  if (i < dsize)
    printf ("warning in b64_decode: decoded %d, but %d offered\n", i, dsize);
  return written;
}

/* chars to encode are in  buffer [bsize - dsize].. buffer [bsize - 1] */
static int b64_encode (char * buffer, int dsize, int bsize)
{
  /* 4 chars for every 3 bytes */
  /* a \n, and possibly a \r\n per 64 chars */
  /* up to 5 misc characters at the end: ==\r\n\0 */
  int wanted = (dsize + 2) * 4 / 3 + dsize / 32 + 5 > bsize;
  if (wanted > bsize) {
    printf ("b64_encode, need %d bytes for %d data, only have %d bytes\n",
            wanted, dsize, bsize);
    return 0;
  }
  int space = bsize - dsize;
  char * from = buffer + space;

  int written = 0;
  int wline = 0;
  int i;
  for (i = 0; (i < dsize) && (written < bsize); i++) {
    int bits = -1;
    if (i % 3 == 0) {
      bits = (from [i] >> 2) & 0x3f;
    } else if (i % 3 == 1) {
      bits = ((from [i - 1] & 0x3) << 4) | ((from [i] >> 4) & 0xf);
    } else if (i % 3 == 2) {  /* write two bytes */
      int first = ((from [i - 1] & 0xf) << 2) | ((from [i] >> 6) & 0x3);
      buffer [written++] = b64_encode_bits (first);
      bits = (from [i] & 0x3f);
      wline++;
    }
    buffer [written++] = b64_encode_bits (bits);
    wline++;
    if (wline >= 64) {
      buffer [written++] = '\n';
      wline = 0;
    }
  }
  switch (i % 3) {
    case 1:                   
      buffer [written++] = b64_encode_bits ((from [i - 1] & 0x3) << 4);
      buffer [written++] = '='; /* add 2 = signs */;
      buffer [written++] = '=';
      break;
    case 2:
      buffer [written++] = b64_encode_bits ((from [i - 1] & 0xf) << 2);
      buffer [written++] = '=';  /* add 1 = sign */;
    default:  /* do nothing for i % 3 == 0 */
      break;
  }
  if (wline != 0)     /* write a final newline */
    buffer [written++] = '\n';
  buffer [written] = '\0';  /* do not count the null character, so no '++' */
  return written;
}

/* haystack need not be NULL terminated */
static const char * find_in_string (const char * haystack, int hsize,
                                    const char * needle)
{
  size_t nsize = strlen (needle);
  int i;
  for (i = 0; i + nsize <= hsize; i++)
    if (strncmp (haystack + i, needle, nsize) == 0) 
      return haystack + i;
  return NULL;
}

/* read the key from the given bytes, returning 1 for success or 0 for error
 * if this is a public key, key->d will be set to zero */
int wp_rsa_read_key_from_bytes (const char * bytes, int bsize,
                                int * nbits, wp_rsa_key_pair * key)
{
  char wp_buffer [50000];
  if (bsize >= sizeof (wp_buffer)) {
    printf ("wp_rsa_read_key_from_bytes: bsize %d > max %zd\n",
            bsize, sizeof (wp_buffer));
    return 0;
  }
  const char * start = find_in_string (bytes, bsize, "-----BEGIN");
  if (start != NULL)
    start = find_in_string (start, bsize - (int)(start - bytes), "\n");
  if (start != NULL)
    start++;  /* point to the first char after the BEGIN line */
  const char * end = find_in_string (bytes, bsize, "-----END");
  while ((end != NULL) && (end > start + 3) &&  /* go back over \n or \r */
         ((* (end - 1) == '\n') || (* (end - 1) == '\r')))
    end--;
  if ((start == NULL) || (end == NULL))
    return 0;
  int b64bytes = (int)(end - start) + 1;
  int dbytes = b64_decode (start, b64bytes, wp_buffer, sizeof (wp_buffer));
  if (dbytes > 0)
    return wp_rsa_read (wp_buffer, dbytes, nbits, key);
  return 0;
}

int wp_rsa_read_key_from_file (const char * fname, int * nbits,
                               wp_rsa_key_pair * key)
{
  char wp_buffer [50000];
  int fd = open (fname, O_RDONLY);
  if (fd < 0) {
    perror ("open key file");
    printf ("wp_rsa_read_key_from_file unable to open file %s\n", fname);
    return 0;
  }
  ssize_t nread = read (fd, wp_buffer, sizeof (wp_buffer));
  if (nread < 0) {
    perror ("read key file");
    return 0;
  }
  close (fd);
  if (nread >= sizeof (wp_buffer)) {
    printf ("ans1.c: file %s too large\n", fname);
    return 0;
  }
#ifdef DEBUG_PRINT
  printf ("wp_rsa_read_key_from_file read %d bytes\n", nread);
#endif /* DEBUG_PRINT */
  return wp_rsa_read_key_from_bytes (wp_buffer, (int)nread, nbits, key);
}

int wp_rsa_write_key_to_file (const char * fname, const wp_rsa_key_pair * key)
{
  char wp_buffer [50000];

  int has_private = 0;
  int i;
  for (i = 0; i < NUM_WORDS (key->nbits); i++)
    if (key->d [i] != 0)
      has_private = 1;

  int bsize = wp_rsa_write_key_to_bytes (wp_buffer, sizeof (wp_buffer), key);
  int dbytes = b64_encode (wp_buffer, bsize, sizeof (wp_buffer));
  int fd = open (fname, O_WRONLY | O_CREAT | O_TRUNC, 0666);
  if (fd < 0) {
    perror ("create key file");
    return 0;
  }
  char * prefix  = "-----BEGIN RSA PUBLIC KEY-----\n";
  char * postfix = "-----END RSA PUBLIC KEY-----\n";
  if (has_private) {
    prefix  = "-----BEGIN RSA PRIVATE KEY-----\n";
    postfix = "-----END RSA PRIVATE KEY-----\n";
  }
  ssize_t nwrite = write (fd, prefix, strlen (prefix));
  if (nwrite != strlen (prefix)) {
    perror ("write");
    return 0;
  }
  nwrite = write (fd, wp_buffer, dbytes);
  if (nwrite != dbytes) {
    perror ("write 2");
    return 0;
  }
  nwrite = write (fd, postfix, strlen (postfix));
  if (nwrite != strlen (postfix)) {
    perror ("write 3");
    return 0;
  }
  close (fd);
  return 1;
}

#ifdef UNIT_TEST

#ifdef SHOW_KEY_BUFFER
static void print_buffer (const char * buffer, int count)
{
  printf ("%d bytes\n", count);
  int i;
  for (i = 0; i < count; i++) {
    if (i % 16 == 0)
      printf ("%07o", i);
    printf (" %02x", buffer [i] & 0xff);
    if (i % 16 == 15)
      printf ("\n");
  }
  if (count % 16 != 15)
    printf ("\n");
}
#endif /* SHOW_KEY_BUFFER */

static void print_element (char * data, int dsize, int indent)
{
  int read_error = 0;
  int id = read_byte (data, dsize, &read_error);
  int id_bits = id & 0x1f;
  int length, length_bytes;
  length_bytes = read_length (data + 1, dsize - 1, &length);
  char id_name [1000];
  int next = -1;
  if ((! read_error) && (id_bits == 0x02))
    next = read_byte (data + length_bytes + 1, dsize - length_bytes - 1,
                      &read_error);
  if (read_error) {
    printf ("read_error in print_element");
    next = -1;
  }
  switch (id_bits) {
  case 0x02:  snprintf (id_name, sizeof (id_name), "integer %d", next); break;
  case 0x04:  snprintf (id_name, sizeof (id_name), "octetString"); break;
  case 0x05:  snprintf (id_name, sizeof (id_name), "null"); break;
  case 0x06:  snprintf (id_name, sizeof (id_name), "objectID"); break;
  case 0x10:  snprintf (id_name, sizeof (id_name), "sequence"); break;
  default:    snprintf (id_name, sizeof (id_name), "id x%x", id_bits); break;
  }
  print_indent (indent);
  printf ("len %5d, %s\n", length, id_name);
  if (id_bits == 0x10) {
    int num_elements;
    /* get the number of elements */
    int size = asn1_read_seq (data, dsize, &num_elements, -1, NULL);
    print_indent (indent);
    printf ("sequence has %d elements in %d/%d bytes\n",
            num_elements, size, dsize);
    if (size <= 0) {
      printf ("not a sequence, first byte is x%02x\n", data [0] & 0xff);
      return;
    }
    int e;
    for (e = 0; e < num_elements; e++) {
      int epos;
      asn1_read_seq (data, dsize, &num_elements, e, &epos);
      print_indent (indent + 2);
      printf ("element %d is at position %d\n", e, epos);
      print_element (data + epos, dsize - epos, indent + 2);
    }
  } else if (id_bits == 0x04) {  /* octet stream contains other objects */
    int offset = length_bytes + 1;
    print_element (data + offset, dsize - offset, indent + 3);
  }
}

static void testb64_encode ()
{
  int i;
  char buffer [164];
  int offset = 100;
  for (i = 0; i < sizeof (buffer) - offset; i++) {
    int j;
    for (j = sizeof (buffer) - i; j < sizeof (buffer); j++)
      buffer [j] = j + i;
    int encoded = b64_encode (buffer, i, sizeof (buffer));
    printf ("buffer encoding of %d bytes takes %d bytes: %s\n", i, encoded,
            buffer);
    int decoded = b64_decode (buffer, encoded, buffer, sizeof (buffer));
    if (decoded != i) {
      printf ("error: encoded %d bytes via %d bytes, decoded %d bytes\n",
              i, encoded, decoded);
    }
    for (j = sizeof (buffer) - i; j < sizeof (buffer); j++) {
      if ((buffer [j - (sizeof (buffer) - i)] & 0xff) != ((j + i) & 0xff)) {
        printf ("error: byte %zd of %d should be %02x but is %02x\n",
                j - (sizeof (buffer) - i), decoded, (j + i) & 0xff,
                buffer [j - (sizeof (buffer) - i)] & 0xff);
      }
    }
  }
}

int run_asn1_test ()
{
  testb64_encode ();
  static char buffer [20000];
  /* read a binary file, to make sure the asn stuff works */
  int fd = open ("testasn1.bin", O_RDONLY);
  if (fd >= 0) {
    int nread = read (fd, buffer, sizeof (buffer));
    if (nread < 0) {
      perror ("read testasn1.bin");
      return 0;
    }
    close (fd);
    printf ("read %d bytes\n", nread);
    print_element (buffer, nread, 0);
  }
  /* read a file written by openssh */
  wp_rsa_key_pair key;
  int nbits;
  if (! wp_rsa_read_key_from_file ("tssl.pem", &nbits, &key)) {
    printf ("unable to read key from file tssl.pem, creating fake key\n");
    nbits = 4096;
    key.nbits = nbits;
    wp_init (nbits, key.n, 1);
    key.e = 2;
    wp_init (nbits, key.d, 3);
    wp_init (nbits / 2, key.p, 4);
    wp_init (nbits / 2, key.q, 5);
    wp_init (nbits / 2, key.dp, 6);
    wp_init (nbits / 2, key.dq, 7);
    wp_init (nbits / 2, key.qinv, 8);
    key.n [0] = key.d [0] = key.p [0] = key.q [0] = key.dp [0] =
      key.dq [0] = key.qinv [0] = ((uint64_t) 1) << 63;
  } else {
    printf ("from tssl.pem read %d(%d)-bit key\n", nbits, key.nbits);
/*
    printf ("n = %s\n", wp_itox (nbits, key.n));
    printf ("e = %ld\n", key.e);
    printf ("d = %s\n", wp_itox (nbits, key.d));
    printf ("p = %s\n", wp_itox (nbits / 2, key.p));
    printf ("q = %s\n", wp_itox (nbits / 2, key.q));
    printf ("dp = %s\n", wp_itox (nbits / 2, key.dp));
    printf ("dq = %s\n", wp_itox (nbits / 2, key.dq));
    printf ("qinv = %s\n", wp_itox (nbits / 2, key.qinv));
*/
  }
  int w = wp_rsa_write_key_to_bytes (buffer, sizeof (buffer), &key);
  printf ("saving key to buffer takes %d bytes\n", w);
#ifdef SHOW_KEY_BUFFER
  print_buffer (buffer + (sizeof (buffer) - w), w);
#endif /* SHOW_KEY_BUFFER */

  if (wp_rsa_write_key_to_file ("tssl.asn1.pem", &key))
    printf ("successfully saved key in tssl.asn1.pem\n");
  else
    printf ("did not succeed in saving key to tssl.asn1.pem\n");
  return 1;
}

int main (int argc, char ** argv)
{
  if (run_asn1_test ())
    return 0;
  return 1;
}

#endif /* UNIT_TEST */
