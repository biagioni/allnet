/* cypher.c: provide the encyphering/decyphering and authentication
 * and verification operations.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <openssl/rsa.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/pem.h>

#include "packet.h"
#include "sha.h"
#include "config.h"
#include "cipher.h"

/* first byte of key defines the key format */
#define KEY_RSA4096_E65537	1	/* n for rsa public key, e is 65537 */
#define KEY_RSA8192_E65537	2	/* n for rsa public key, e is 65537 */

#define RSA_E65537_VALUE	65537
#define RSA_E65537_STRING	"65537"

#define FINGERPRINT_SIZE	15    /* 15-byte fingerprint */
#define PRINTABLE_FINGERPRINT_SIZE	60    /* 60 chars to print 12 bytes */

static void write_big_endian64 (char * array, long long int value)
{
  array [0] = (value >> 56) & 0xff; array [1] = (value >> 48) & 0xff;
  array [2] = (value >> 40) & 0xff; array [3] = (value >> 32) & 0xff;
  array [4] = (value >> 24) & 0xff; array [5] = (value >> 16) & 0xff;
  array [6] = (value >>  8) & 0xff; array [7] =  value        & 0xff;
}

static int check_valid_chars (char * string, int n)
{
  int i;
  for (i = 0; i < n; i++) {
    if ((string [i] == '=') ||
        (string [i] == '\n') ||
        (string [i] == '\0'))
      return 0;
  }
  return 1;
}

static void make_fingerprint (char * key_buffer, unsigned char * fp)
{
  int i;
  for (i = 0; i < FINGERPRINT_SIZE; i++)
    fp [i] = i;
  if (key_buffer == NULL)
    return;

  /* convert key into internal format */
  BIO * mbio = BIO_new_mem_buf (key_buffer, strlen (key_buffer));
  RSA * rsa = PEM_read_bio_RSAPublicKey (mbio, NULL, NULL, NULL);
  BIO_free (mbio);

  if (rsa == NULL) {
    printf ("make_fingerprint unable get RSA public key\n");
    return;
  }

  int bn_size = BN_num_bytes (rsa->n);
  char * key_copy = malloc (bn_size);
  if (key_copy == NULL) {
    printf ("make_fingerprint unable to allocate %d for key copy\n", bn_size);
    return;
  }
  BN_bn2bin (rsa->n, key_copy);
  RSA_free (rsa);
  /* print_buffer (key_copy, bn_size, "key copy", 16, 1); */
  sha512_bytes (key_copy, bn_size, fp, FINGERPRINT_SIZE);
}

/* print out the addresses in human-readable format */
static void print_addresses (char * string, char * key, int ksize,
                             char ** printable)
{
  if ((printable != NULL) && (*printable != NULL))
    printf ("%s\n", *printable);

  char * start_source = index (string, '=');
  if (start_source == NULL)
    return;
  start_source++;    /* character after the equal sign */
  char * after_source = index (start_source, '=');
  if (after_source == NULL)
    return;
  if (! check_valid_chars (start_source, after_source - start_source))
    return;

  char * start_dest = index (after_source + 1, '=');
  if (start_dest == NULL)
    return;
  start_dest++;      /* character after the equal sign */
  char * after_dest = index (start_dest + 2, '=');
  if (after_dest == NULL)
    return;
  if (! check_valid_chars (start_dest, after_dest - start_dest))
    return;
}

static char * last_line (char * buffer) /* buffer must be null terminated */
{
  char * result = buffer;
  char * old_result = buffer - 1;
  while (*buffer != '\0') {
    if (*buffer == '\n') {
      old_result = result;
      result = buffer;
    }
    buffer++;
  }
  if (result == old_result + 1)  /* at start, no newline found */
    return result;
  if (result + 1 == buffer)  /* ignore final newline */
    return old_result + 1;
  return result + 1;         /* return the character after the last newline */
}

static int get_from_file (char * fname, int fsize, char ** key,
                          char * source, int * sbits,
                          char * dest, int * dbits,
                          char ** printable)
{
  int fd = open (fname, O_RDONLY);
  if (fd < 0) {
    perror ("open");
    printf ("unable to open file %s\n", fname);
    return 0;
  }
  char * buffer = malloc (fsize + 1);  /* + 1 for '\0' at end */
  if (buffer == NULL) {
    perror ("malloc");
    printf ("get_from_file: unable to malloc %d bytes\n", fsize + 1);
    close (fd);
    return 0;
  }
  int r = read (fd, buffer, fsize);
  if (r != fsize) {
    perror ("get_from_file/read");
    printf ("unable to read %d bytes from file %s, only read %d\n",
            fsize, fname, r);
    close (fd);
    free (buffer);
    return 0;
  }
  close (fd);
  buffer [r] = '\0';   /* usually text, so null terminate */
  if (key != NULL)
    *key = buffer;
  /* the last line of the file should have source (in hex), sbits (decimal),
   * dest, dbits, followed by a newline.  If this is not the case, we
   * set sbits and dbits to zero */
  /* the dbits may optionally be followed by the pre-hashed source and
   * destination addresses, enclosed in "=" signs */
  if (source != NULL)
    memset (source, 0, ADDRESS_SIZE);
  if (dest   != NULL)
    memset (dest  , 0, ADDRESS_SIZE);
  if (sbits  != NULL)
    *sbits = 0;
  if (dbits  != NULL)
    *dbits = 0;
  char * last = last_line (buffer);
  if (last != NULL) {
    /* printf ("last line is '%s'\n", last); */
    unsigned long long int s = 0, d = 0;  /* for reading hex input */
    int mysb = 0, mydb = 0;
    int matches = sscanf (last, "%llx %d %llx %d", &s, &mysb, &d, &mydb);
    /* printf ("last line is '%s', source %llx, dest %llx, %d matches\n", last,
            s, d, matches); */
    if (matches == 4) {
      if (source != NULL)
        write_big_endian64 (source, s);
      if (dest   != NULL)
        write_big_endian64 (dest  , d);
      if (sbits  != NULL)
        *sbits = mysb;
      if (dbits  != NULL)
        *dbits = mydb;
      r = last - buffer;
      if (printable != NULL) {
        unsigned char fp [FINGERPRINT_SIZE];
        make_fingerprint (*key, fp);
        int size = PRINTABLE_FINGERPRINT_SIZE;
        char * eq = index (last, '=');
        if (eq != NULL)
          size += strlen (eq) + 4;  /* should be enough */
        char * s = calloc (size, 1);
        *printable = s;
        if (s == NULL) {
          printf ("unable to allocate %d bytes for printable addrs\n", size);
        } else {
          if (eq != NULL) {
            char * psrc = eq + 1;
            char * end = index (psrc, '=');
            char * pdst = NULL;
            if (end != NULL) {
              *end = '\0';
              pdst = index (end + 1, '=');
            }
            if (pdst != NULL) {
              pdst++;
              end = index (pdst, '=');
              if (end != NULL)
                *end = '\0';
#define FORMAT_F "==%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x"
#define FORMAT_SF "=%s=%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x"
#define FORMAT_SFD "=%s=%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x to %s"
              snprintf (s, size, FORMAT_SFD, psrc,
                        fp [0], fp [1], fp [2], fp [3], fp [4],
                        fp [5], fp [6], fp [7], fp [8], fp [9],
                        fp [10], fp [11], fp [12], fp [13], fp [14],
                        pdst);
            } else {
              snprintf (s, size, FORMAT_SF, psrc,
                        fp [0], fp [1], fp [2], fp [3], fp [4],
                        fp [5], fp [6], fp [7], fp [8], fp [9],
                        fp [10], fp [11], fp [12], fp [13], fp [14]);
            }
          } else {
            snprintf (s, size, FORMAT_F,
                      fp [0], fp [1], fp [2], fp [3], fp [4],
                      fp [5], fp [6], fp [7], fp [8], fp [9],
                      fp [10], fp [11], fp [12], fp [13], fp [14]);
#undef FORMAT_F
#undef FORMAT_SF
#undef FORMAT_SFD
          }
        }
      }
      if (key != NULL)
        print_addresses (last, *key, r, printable);
      else
        print_addresses (last, NULL, r, printable);
    }
  }
  return r;
}

static void set_if_valid (char * dir, char * fname,
                          char ** full, char ** tail, int * size)
{
  int length = strlen (dir) + 1 + strlen (fname) + 1;
  char * path = malloc (length);
  if (path == NULL) {
      perror ("malloc");
      printf ("set_if_valid: unable to malloc %d bytes\n", length);
      return;
  }
  snprintf (path, length, "%s/%s", dir, fname);
  struct stat st;
  if ((stat (path, &st) == 0) && (S_ISREG (st.st_mode)) && (st.st_size > 0)) {
    *full = path;
    *tail = fname;
    *size = st.st_size;
  } else {
    free (path);
  }
}

/* source and dest must each have ADDRESS_SIZE bytes, or be null */
int get_my_privkey (char ** key, char * source, int * sbits,
                    char * dest, int * dbits, char ** printable)
{
  char * dirname;
  int dirnamesize = config_file_name ("xtime", "keys", &dirname);
  /* printf ("directory name is %s (%d)\n", dirname, dirnamesize); */
  if (! create_dir (dirname)) {
    printf ("directory %s does not exist, and unable to create it\n", dirname);
    free (dirname);
    return 0;
  }
  DIR * dir = opendir (dirname);
  if (dir == NULL) {
    perror ("opendir");
    printf ("unable to open directory %s\n", dirname);
    free (dirname);
    return 0;
  }
  struct dirent * dep;
  char * latest = NULL;
  char * key_dirname = NULL;
  int lsize = -1;
  int ksize = 0;
  while ((dep = readdir (dir)) != NULL)
    if ((latest == NULL) || (strcoll (latest, dep->d_name) < 0))
      set_if_valid (dirname, dep->d_name, &key_dirname, &latest, &lsize);

  if ((latest != NULL) && (lsize > 0) && (key_dirname != NULL)) {
    ksize = get_from_file (key_dirname, lsize,
                           key, source, sbits, dest, dbits, printable);
  } else {
    if (source != NULL)
      memset (source, 0, ADDRESS_SIZE);
    if (dest != NULL)
      memset (dest, 0, ADDRESS_SIZE);
    if (sbits != NULL)
      *sbits = 0;
    if (dbits != NULL)
      *dbits = 0;
    if (key != NULL)
      *key = NULL;
  }
  if (key_dirname != NULL)
    free (key_dirname);
  closedir (dir);
  free (dirname);
  return ksize;
}

static void callback (int type, int count, void * arg)
{
  if (type == 0)
    printf (".");
  else if (type == 1)
    printf (",");
  else if (type == 2)
    printf ("!");
  else if (type == 3)
    printf (":");
  else
    printf ("?");
  fflush (stdout);
}

static int write_to_file (char * fname, char * key, int len, int append)
{
  int flags = O_WRONLY;
  if (append)
    flags |= O_APPEND;
  else
    flags |= O_CREAT;
  int fd = open (fname, flags, S_IRUSR | S_IWUSR);
  if (fd < 0) {
    perror ("open");
    printf ("error opening/creating %s\n", fname);
    return 0;
  }
  int w = write (fd, key, len);
  if (w != len) {
    perror ("write");
    printf ("error writing %d bytes to file %s\n", len, fname);
    close (fd);
    return 0;
  }
  close (fd);
  return 1;
}

/* source and destination are strings, hashed to give the actual
 * source and destination addresses */
/* if a key already exists, does nothing unless "overwrite" is nonzero */
int create_keys (char * source, char * dest, int overwrite)
{
  if ((! overwrite) && (get_my_privkey (NULL, NULL, 0, NULL, 0, NULL))) {
    /* printf ("key found\n"); */
    return 0;
  }
  char * dirname;
  int dirnamesize = config_file_name ("xtime", "keys", &dirname);
  printf ("directory name is %s (%d)\n", dirname, dirnamesize);
  if (! create_dir (dirname)) {
    printf ("directory %s does not exist, and unable to create it\n", dirname);
    free (dirname);
    return 0;
  }
  int size = dirnamesize + 1 + strlen ("20131217193050") + 1;
  char * fname = malloc (size);
  if (fname == NULL) {
    perror ("malloc");
    printf ("unable to malloc %d bytes for filename\n", size);
    free (dirname);
    return 0;
  }
  time_t now = time (NULL);
  struct tm t;
  gmtime_r (&now, &t);
  snprintf (fname, size, "%s/%04d%02d%02d%02d%02d%02d",
            dirname, t.tm_year + 1900, t.tm_mon + 1, t.tm_mday,
            t.tm_hour, t.tm_min, t.tm_sec);
  free (dirname);
  /* create the keys */
  int bits = 8192;
  printf ("generating %d-bit private key", bits);
  RSA * key = RSA_generate_key (bits, RSA_E65537_VALUE, callback, NULL);
  printf ("\n");
  BIO * mbio = BIO_new (BIO_s_mem ());
  PEM_write_bio_RSAPrivateKey (mbio, key, NULL, NULL, 0, NULL, NULL);
  printf ("private key takes %zd bytes\n", BIO_ctrl_pending (mbio));
  PEM_write_bio_RSAPublicKey (mbio, key);
  char * keystore;
  long int ksize = BIO_get_mem_data (mbio, &keystore);
  printf ("private + public key take %ld bytes, saving to file %s\n",
          ksize, fname);
  if (! write_to_file (fname, keystore, ksize, 0)) {
    free (fname);
    return 0;
  }
  BIO_free (mbio);
  RSA_free (key);   /* saved in file */
  int bsize = strlen ("0123456789abcdef 64 0123456789abcdef 64 == ==\n") + 1;
  if (source != NULL)
    bsize += strlen (source);
  if (dest != NULL)
    bsize += strlen (dest);
  char * buffer = malloc (bsize);
  if (buffer == NULL) {
    perror ("malloc");
    printf ("unable to malloc %d bytes for last line of file\n", bsize);
    free (fname);
    return 0;
  }
  char s [8];
  char d [8];
  memset (s, 0, sizeof (s));
  memset (d, 0, sizeof (d));
  if (source != NULL)
    sha512_bytes (source, strlen (source), s, sizeof (s));
  if (dest != NULL)
    sha512_bytes (dest  , strlen (dest  ), d, sizeof (d));
  if (source == NULL) source = "";
  if (dest   == NULL) dest   = "";
  int n =
    snprintf (buffer, bsize,
              "%02x%02x%02x%02x%02x%02x%02x%02x %d %02x%02x%02x%02x%02x%02x%02x%02x %d =%s= =%s=\n",
              s [0] & 0xff, s [1] & 0xff, s [2] & 0xff, s [3] & 0xff,
              s [4] & 0xff, s [5] & 0xff, s [6] & 0xff, s [7] & 0xff, 64,
              d [0] & 0xff, d [1] & 0xff, d [2] & 0xff, d [3] & 0xff,
              d [4] & 0xff, d [5] & 0xff, d [6] & 0xff, d [7] & 0xff, 64,
              source, dest);
  if (! write_to_file (fname, buffer, n, 1)) {
    free (fname);
    free (buffer);
    return 0;
  }
  free (fname);
  return ksize;
}

/* returns 1 if it verifies, 0 otherwise */
int verify (char * text, int tsize, char * sig, int ssize,
            char * key, int ksize)
{
  /* convert key into internal format */
  if ((*key != KEY_RSA4096_E65537) && (*key != KEY_RSA8192_E65537)) {
    printf ("key with unknown format %d, unable to verify\n", (*key) & 0xff);
    return 0;
  }
  RSA * rsa = RSA_new ();
  rsa->n = BN_bin2bn (key + 1, ksize - 1, NULL);
  rsa->e = NULL;
  BN_dec2bn (&(rsa->e), RSA_E65537_STRING);
  int rsa_size = RSA_size (rsa);
  if (rsa_size > ssize) {
    printf ("public key has %d-byte signature, only %d bytes given\n",
            RSA_size (rsa), ssize);
    RSA_free (rsa);
    return 0;
  }
  if (ssize != rsa_size)
    printf ("notice: public key has %d-byte signature, %d bytes given\n",
            RSA_size (rsa), ssize);

  /* hash the contents, verify that the signature matches the hash */
  char hash [SHA512_SIZE];
  int hsize = rsa_size - 12;
  if (hsize > SHA512_SIZE)
    hsize = SHA512_SIZE;
  sha512_bytes (text, tsize, hash, hsize);

  int verifies = RSA_verify (NID_md5, hash, hsize, sig, ssize, rsa);
  RSA_free (rsa);
#ifdef DEBUG_PRINT
  printf ("RSA_verify returned %d\n", verifies);
#endif /* DEBUG_PRINT */
  
  return verifies;
}

/* returns the size of the signature and mallocs the signature into result */
int sign (char * text, int tsize, char * key, int ksize, char ** result)
{
  /* convert key into internal format */
  BIO * mbio = BIO_new_mem_buf (key, ksize);
  RSA * rsa = PEM_read_bio_RSAPrivateKey (mbio, NULL, NULL, NULL);
  BIO_free (mbio);

  if (rsa == NULL) {
    printf ("unable get RSA private key, unable to decrypt\n");
    return 0;
  }

  int rsa_size = RSA_size (rsa);
  *result = malloc (rsa_size);;
  if (*result == NULL) {
    printf ("unable to malloc %d bytes for signature\n", rsa_size);
    return 0;
  }
  int siglen;

  /* hash the contents, sign the hash */
  char hash [SHA512_SIZE];
  int hsize = rsa_size - 12;
  if (hsize > SHA512_SIZE)
    hsize = SHA512_SIZE;
  sha512_bytes (text, tsize, hash, hsize);

  if (! RSA_sign (NID_md5, hash, hsize, *result, &siglen, rsa)) {
    unsigned long e = ERR_get_error ();
    printf ("RSA signature (%d) failed %ld: %s\n", rsa_size, e,
            ERR_error_string (e, NULL));
    siglen = 0;
    free (*result);
    *result = NULL;
  }
  RSA_free (rsa);
  return siglen;
}
