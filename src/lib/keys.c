/* keys.c: manage keys on disk */

/* keys are stored under ~/.allnet/contacts/yyyymmddhhmmss/ */
/* each such directory has a file "name", a file "my_key", and possibly
 * a file "contact_public_key".  It is an error (and the contact is not
 * usable) if either of the first two files is missing */
/* if ~/.allnet/contacts does not exist, it is created */

/* to do: should be able to have multiple public keys for the contact */
/*        also some mechanism to get new private keys for a contact */

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/types.h>

#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#include "packet.h"
#include "keys.h"
#include "util.h"
#include "log.h"
#include "cipher.h"
#include "config.h"
#include "sha.h"
#include "mapchar.h"

/* a key set consists of the contact name, my private and public keys,
 * the contact's public key, and possibly a local address and/or
 * a remote address */
/* each contact name is associated with 0 or more key sets */

struct key_address {
  int nbits;
  char address [ADDRESS_SIZE];
};

/* typedef int keyset;  refers to a key_info */
struct key_info {
  char * contact_name;
  RSA * contact_pubkey;
  RSA * my_key;
  struct key_address local;
  struct key_address remote;
  char * dir_name;
};

struct key_info * kip = NULL;
int num_key_infos = 0;

/* contact names is set to the same size as kip, although if a contact
 * has multiple keys, in practice the number of contacts will be less
 * than the number of keysets */
char * * cp = NULL;
int cp_used = 0;

/* return 0 if the contact does not exist, otherwise one more than the
 * contact's intex in cp */
static int contact_exists (char * contact)
{
  int i;
  for (i = 0; i < cp_used; i++) {
    if (strcmp (cp [i], contact) == 0)
      return i + 1;
    /* else
      printf ("%d: %s does not match %s\n", i, contact, cp [i]); */
  }
  return 0;
}

static int valid_keyset (keyset k)
{
  return ((k >= 0) && (k < num_key_infos));
}

static void generate_contacts ()
{
  int ki = 0;
  cp_used = 0;
  for (ki = 0; ki < num_key_infos; ki++) {
    if ((kip [ki].contact_name != NULL) &&
        (! contact_exists (kip [ki].contact_name)))
      cp [cp_used++] = kip [ki].contact_name;
  }
}

static void set_kip_size (int size)
{
  struct key_info * new_kip = NULL;
  char * * new_cp = NULL;
  if (size > 0) {
    new_kip = malloc_or_fail (sizeof (struct key_info) * size, "key info");
    new_cp = malloc_or_fail (sizeof (char *) * size, "contact names");
  }
  /* if kip/cp is NULL, num_key_infos should be 0 */
  /* if new_kip/new_cp is NULL, size should be 0 */

  int i;
  /* copy any keys from the old array to the new array */
  for (i = 0; (i < num_key_infos) && (i < size); i++)
    new_kip [i] = kip [i];
  /* free any keys from the old array that don't fit in the new array */
  for (i = size; i < num_key_infos; i++) {
    free (kip [i].contact_name);
    RSA_free (kip [i].contact_pubkey);
    RSA_free (kip [i].my_key);
    if (kip [i].dir_name != NULL)
      free (kip [i].dir_name);
  }
  /* zero out the new entries (if any) in kip */
  for (i = num_key_infos; i < size; i++) {
    new_kip [i].contact_name = NULL;
    new_kip [i].contact_pubkey = NULL;
    new_kip [i].my_key = NULL;
    new_kip [i].local.nbits = 0;
    bzero (new_kip [i].local.address, ADDRESS_SIZE);
    new_kip [i].remote.nbits = 0;
    bzero (new_kip [i].remote.address, ADDRESS_SIZE);
    new_kip [i].dir_name = NULL;
  }
  /* clear the new entries in cp/cip, generate_contacts will init them */
  for (i = 0; i < size; i++)
    new_cp [i] = NULL;
  /* set kip, cp, cip to point to the new arrays */
  if (kip != NULL)
    free (kip);
  if (cp != NULL)
    free (cp);
  num_key_infos = size;
  kip = new_kip;
  cp = new_cp;
  cp_used = 0;
  generate_contacts ();
}

#define DATE_TIME_LEN           14      /* strlen("20130101120102") */

/* if it is the kind of name we want, it should end in a string of n digits */
static int is_ndigits (char * path, int ndigits)
{
  char * slash = rindex (path, '/');
  char * name = path;
  if (slash != NULL)
    name = slash + 1;
  if (strlen (name) != ndigits)
    return 0;
  int i;
  for (i = 0; i < ndigits; i++)
    if ((name [i] < '0') || (name [i] > '9'))
      return 0;
  return 1;
}

#if 0
static void debug_read_public_RSA_file (char * fname, RSA * * key)
{
  *key = NULL;
  char * bytes;
  int size = read_file_malloc (fname, &bytes, 0);
  if (size > 0) {
    BIO * mbio = BIO_new_mem_buf (bytes, size);
    *key = PEM_read_bio_RSAPublicKey (mbio, NULL, NULL, NULL);
    BIO_free (mbio);
    free (bytes);
/*
    mbio = BIO_new (BIO_s_mem ());
    PEM_write_bio_RSAPublicKey (mbio, *key);
    printf ("public key takes %zd bytes\n", BIO_ctrl_pending (mbio));
    BIO_free (mbio);
*/
  }
}
#endif /* 0 */

static void read_RSA_file (char * fname, RSA * * key, int expect_private)
{
  *key = NULL;
  char * bytes;
  int size = read_file_malloc (fname, &bytes, 0);
  if (size > 0) {
    BIO * mbio = BIO_new_mem_buf (bytes, size);
    if (expect_private)
      *key = PEM_read_bio_RSAPrivateKey (mbio, NULL, NULL, NULL);
    else
      *key = PEM_read_bio_RSAPublicKey (mbio, NULL, NULL, NULL);
    if (*key == NULL) {
      ERR_load_crypto_strings ();
      ERR_print_errors_fp (stdout);
      printf ("unable to read RSA from file %s\n", fname);
    }
    BIO_free (mbio);
    free (bytes);
  }
}

static void read_address_file (char * fname, char * address, int * nbits)
{
  bzero (address, ADDRESS_SIZE);
  *nbits = 0;
  char * bytes;
  int size = read_file_malloc (fname, &bytes, 0);
  if (size > 0) {
    char * p;
    int n = strtol (bytes, &p, 10);
    if (p != bytes) {
      int count = (n + 7) / 8;
      int i;
      for (i = 0; (p != NULL) && (i < count) && (i < ADDRESS_SIZE); i++) {
        int value;
        sscanf (p, " %x", &value);
        address [i] = value;
        p = index (p, ':');
        if (p != NULL)  /* p points to ':' */
          p++;
      }
      *nbits = n;
    }
  }
}

/* returns 0 if the contact does not exist, 1 otherwise */
static int read_key_info (char * path, char * file, char ** contact,
                          RSA ** my_key, RSA ** contact_pubkey,
                          char * local, int * loc_nbits,
                          char * remote, int * rem_nbits,
                          char ** dir_name)
{
  char * basename = strcat3_malloc (path, "/", file, "basename");

  char * contact_name = strcat_malloc (basename, "/name", "name-name");
  int found = read_file_malloc (contact_name, contact, 0);
  free (contact_name);
  if (found <= 0) {
    free (basename);
    return 0;
  }
  if (contact != NULL) {  /* null-terminate contact */
    char * result = malloc_or_fail (found + 1, "result of read_key_info");
    memcpy (result, *contact, found);
    result [found] = '\0';
    free (*contact);
    *contact = result;
  }

  if (my_key != NULL) {
    char * name = strcat_malloc (basename, "/my_key", "my key name");
    read_RSA_file (name, my_key, 1);
    free (name);
  }
  if (contact_pubkey != NULL) {
    char * name = strcat_malloc (basename, "/contact_pubkey", "pub name");
    read_RSA_file (name, contact_pubkey, 0);
    free (name);
  }
  if ((local != NULL) && (loc_nbits != NULL)) {
    char * name = strcat_malloc (basename, "/local", "local name");
    read_address_file (name, local, loc_nbits);
    free (name);
  }
  if ((remote != NULL) && (rem_nbits != NULL)) {
    char * name = strcat_malloc (basename, "/remote", "remote name");
    read_address_file (name, remote, rem_nbits);
    free (name);
  }
  if (dir_name != NULL) {
    *dir_name = basename;
    /* printf ("dir name for %s set to %s\n", *contact, *dir_name); */
  } else
    free (basename);
  return 1;
}

static void init_from_file ()
{
  static int initialized = 0;
  if (initialized)
    return;
  initialized = 1;
  /* first count the number of keys */
  char * dirname;
  int dirnamesize = config_file_name ("contacts", "", &dirname);
  char * last = dirname + dirnamesize - 2;
  if (*last == '/')
    *last = '\0';
  DIR * dir = opendir (dirname);
  if (dir == NULL) {
    perror ("opendir in init_from_file");
    printf ("unable to open directory %s\n", dirname);
    return;
  }
  int num_keys = 0;
  struct dirent * dep;
  while ((dep = readdir (dir)) != NULL) {
    if ((is_ndigits (dep->d_name, DATE_TIME_LEN)) && /* key directory */
        (read_key_info (dirname, dep->d_name, NULL, NULL, NULL,
                        NULL, NULL, NULL, NULL, NULL)))
      num_keys++;
  }
  closedir (dir);

  set_kip_size (0);  /* get rid of anything that was previously there */
  set_kip_size (num_keys);  /* create new array */

  /* now load the keys */
  dir = opendir (dirname);
  if (dir == NULL) {
    printf ("directory %s no longer accessible\n", dirname);
    exit (1);
  }
  int i = 0;
  while ((dep = readdir (dir)) != NULL) {
    if ((is_ndigits (dep->d_name, DATE_TIME_LEN)) && /* key directory */
        (read_key_info (dirname, dep->d_name, &(kip [i].contact_name),
                        &(kip [i].my_key), &(kip [i].contact_pubkey),
                        kip [i].local.address, &(kip [i].local.nbits),
                        kip [i].remote.address, &(kip [i].remote.nbits),
                        &(kip [i].dir_name))))
      i++;
  }
  closedir (dir);
  free (dirname);
  generate_contacts ();
/* int debug = 0;
printf ("time for div0 %d\n", 5 / debug) */
}

/*************** operations on contacts ********************/

/* returns 0 or more */
int num_contacts ()
{
  init_from_file ();
  return cp_used;
}

/* returns the number of contacts, and has contacts point to a statically
 * allocated array of pointers to statically allocated null-terminated
 * contact names (do not modify in any way). */
int all_contacts (char *** contacts)
{
  init_from_file ();
  *contacts = cp;
  return cp_used;
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

static void no_feedback (int type, int count, void * arg)
{
}

static void write_file (char * fname, char * contents, int len)
{
  int fd = open (fname, O_WRONLY | O_CREAT | O_TRUNC, 0600);
  if (fd < 0) {
    perror ("open in write_file");
    return;
  }
  int n = write (fd, contents, len);
  if (n < 0) {
    perror ("write in write_file");
    printf ("attempted to write %d bytes, wrote %d\n", len, n);
    return;
  }
  close (fd);
}

static void write_RSA_file (char * fname, RSA * key, int write_priv)
{
  BIO * mbio = BIO_new (BIO_s_mem ());
  PEM_write_bio_RSAPublicKey (mbio, key);
  if (write_priv)
    PEM_write_bio_RSAPrivateKey (mbio, key, NULL, NULL, 0, NULL, NULL);
  char * keystore;
  long ksize = BIO_get_mem_data (mbio, &keystore);
  write_file (fname, keystore, ksize);
  BIO_free (mbio);
}

static void write_address_file (char * fname, char * address, int nbits)
{
  if (nbits <= 0)
    return;
  char buf [4 + ADDRESS_SIZE * 3 + 4];
  int bytes = (nbits + 7) / 8;
  int offset = snprintf (buf, sizeof (buf), "%d %02x",
                         nbits, address [0] & 0xff);
  int i;
  for (i = 1; i < bytes; i++) {
    offset += snprintf (buf + offset, sizeof (buf) - offset,
                        ":%02x", address [i] & 0xff);
  }
  offset += snprintf (buf + offset, sizeof (buf) - offset, "\n");
  write_file (fname, buf, offset);
}

static void save_contact (struct key_info * k)
{
  char * dirname = k->dir_name;
#ifdef DEBUG_PRINT
  printf ("save_contact dirname is %s\n", dirname);
#endif /* DEBUG_PRINT */
  if (dirname == NULL) {
    char fname [DATE_TIME_LEN + 1];
    time_t now = time (NULL);
    struct tm t;
    gmtime_r (&now, &t);
    snprintf (fname, sizeof (fname), "%04d%02d%02d%02d%02d%02d",
              t.tm_year + 1900, t.tm_mon + 1, t.tm_mday,
              t.tm_hour, t.tm_min, t.tm_sec);
 
    int dirnamesize = config_file_name ("contacts", fname, &dirname);
    if (dirnamesize < 0) {
      snprintf (log_buf, LOG_SIZE, "unable to get config file name");
      log_print ();
      return;
    }
    k->dir_name = dirname;
  }
  create_dir (dirname);
  if (k->contact_name != NULL) {
    char * name_fname = strcat3_malloc (dirname, "/", "name", "name file");
    write_file (name_fname, k->contact_name, strlen (k->contact_name));
    free (name_fname);
  }
  if (k->my_key != NULL) {
    char * my_key_fname = strcat3_malloc (dirname, "/", "my_key", "key file");
    write_RSA_file (my_key_fname, k->my_key, 1);
    free (my_key_fname);
  }
  if (k->contact_pubkey != NULL) {
    char * key_fname = strcat3_malloc (dirname, "/", "contact_pubkey", "kf");
    write_RSA_file (key_fname, k->contact_pubkey, 0);
    free (key_fname);
  }
  if (k->local.nbits != 0) {
    char * local_fname = strcat3_malloc (dirname, "/", "local", "lfile");
    write_address_file (local_fname, k->local.address, k->local.nbits);
    free (local_fname);
  }
  if (k->remote.nbits != 0) {
    char * remote_fname = strcat3_malloc (dirname, "/", "remote", "rfile");
    write_address_file (remote_fname, k->remote.address, k->remote.nbits);
    free (remote_fname);
  }
#ifdef DEBUG_PRINT
  printf ("save_contact %d file name is %s\n", ((int) (k - kip)), dirname);
#endif /* DEBUG_PRINT */
}

static int do_set_contact_pubkey (struct key_info * k,
                                  char * contact_key, int ksize)
{
  if ((ksize != 513) || (contact_key == NULL) ||
      (*contact_key != KEY_RSA4096_E65537)) {
    printf ("do_set_contact_pubkey, key size %d, key %p (%d)\n",
            ksize, contact_key, ((contact_key == NULL) ? 0 : *contact_key));
    return 0;
  }
  RSA * rsa = RSA_new ();
  rsa->n = BN_bin2bn ((unsigned char *) (contact_key + 1), ksize - 1, NULL);
  rsa->e = NULL;
  BN_dec2bn (&(rsa->e), RSA_E65537_STRING);
  k->contact_pubkey = rsa;
  return 1;
/*
  BIO * mbio = BIO_new_mem_buf (contact_key, ksize);
  kip [k].contact_pubkey = PEM_read_bio_RSAPublicKey (mbio, NULL, NULL, NULL);
  BIO_free (mbio);
*/
}

int set_contact_pubkey (keyset k, char * contact_key, int contact_ksize)
{
  init_from_file ();
  if ((! valid_keyset (k)) || (kip [k].contact_pubkey != NULL) ||
      (contact_key == NULL) || (contact_ksize == 0))
    return 0;
  if (do_set_contact_pubkey (kip + k, contact_key, contact_ksize) == 0)
    return 0;
  save_contact (kip + k);
  return 1;
}

int set_contact_local_addr (keyset k, int nbits, unsigned char * address)
{
  init_from_file ();
  if (! valid_keyset (k))
    return 0;
  kip [k].local.nbits = nbits;
  memcpy (kip [k].local.address, address, ADDRESS_SIZE);
  save_contact (kip + k);
  return 1;
}

int set_contact_remote_addr (keyset k, int nbits, unsigned char * address)
{
  init_from_file ();
  if (! valid_keyset (k))
    return 0;
  kip [k].remote.nbits = nbits;
  memcpy (kip [k].remote.address, address, ADDRESS_SIZE);
  save_contact (kip + k);
  return 1;
}

/* returns the keyset if successful, -1 if the contact already existed */
/* creates a new private/public key pair, and if not NULL, also 
 * the contact public key, source and destination addresses */
/* if feedback is nonzero, gives feedback while creating the key */
keyset create_contact (char * contact, int keybits, int feedback,
                       char * contact_key, int contact_ksize,
                       unsigned char * local, int loc_nbits,
                       unsigned char * remote, int rem_nbits)
{
  init_from_file ();
  if (contact_exists (contact))
    return -1;

  RSA * my_key = NULL;
  if (feedback) {
    my_key = RSA_generate_key (keybits, RSA_E65537_VALUE, callback, NULL);
    printf ("\n");
  } else {
    my_key = RSA_generate_key (keybits, RSA_E65537_VALUE, no_feedback, NULL);
  }

  struct key_info new;
  new.contact_name = strcpy_malloc (contact, "create_contact");
  new.my_key = my_key;
  /* set defaults for the remaining values, then override them later if given */
  new.contact_pubkey = NULL;
  new.local.nbits = 0;
  bzero (new.local.address, ADDRESS_SIZE);
  new.remote.nbits = 0;
  bzero (new.remote.address, ADDRESS_SIZE);
  new.dir_name = NULL;

  if ((contact_key != NULL) && (contact_ksize > 0) &&
      (do_set_contact_pubkey (&new, contact_key, contact_ksize) == 0)) {
    free (new.contact_name);
    printf ("do_set_contact_pubkey failed for contact %s\n", contact);
    return -1;
  }
  if ((local != NULL) && (loc_nbits > 0)) {
    new.local.nbits = loc_nbits;
    memcpy (new.local.address, local, ADDRESS_SIZE);
  }
  if ((remote != NULL) && (rem_nbits > 0)) {
    new.remote.nbits = rem_nbits;
    memcpy (new.remote.address, remote, ADDRESS_SIZE);
  }

  /* save into the kip data structure */
  int new_contact = num_key_infos;
  set_kip_size (new_contact + 1);   /* make room for the new entry */
  kip [new_contact] = new;
  generate_contacts ();

#ifdef DEBUG_PRINT
  printf ("for %s new.keys are %p %p, kip keys are %p %p\n",
  kip [new_contact].contact_name, new.contact_pubkey, new.my_key,
  kip [new_contact].contact_pubkey, kip [new_contact].my_key);
#endif /* DEBUG_PRINT */

  /* now save to disk */
  save_contact (kip + new_contact);
  return new_contact;
}

/*************** operations on keysets and keys ********************/

/* returns -1 if the contact does not exist, and 0 or more otherwise */
int num_keysets (char * contact)
{
  init_from_file ();
  if (! contact_exists (contact))
    return -1;
  int i;
  int count = 0;
  for (i = 0; i < cp_used; i++) {
    if (strcmp (cp [i], contact) == 0)
      count++;
  }
  return count;
}

/* returns the number of keysets, and has keysets point to a statically
 * allocated array of pointers to statically allocated keysets
 * (do not modify in any way). */
int all_keys (char * contact, keyset ** keysets)
{
#define DEFAULT_KEYSETS		10
  static int buf [DEFAULT_KEYSETS];
  static int * all_keysets = buf;
  static int num_keysets = DEFAULT_KEYSETS;
  init_from_file ();

  if (! contact_exists (contact))
    return -1;
  int i;
  int count = 0;
  for (i = 0; i < num_key_infos; i++) {
    if (strcmp (kip [i].contact_name, contact) == 0)
      count++;
  }
  if (keysets == NULL)
    return count;
  
  if (count > num_keysets) {   /* reallocate */
    if (all_keysets != buf)
      free (all_keysets);
    all_keysets = malloc_or_fail (count * sizeof(int), "all keysets");
    num_keysets = count;
  }
  count = 0;
  for (i = 0; i < num_key_infos; i++) {
    if (strcmp (kip [i].contact_name, contact) == 0)
      all_keysets [count++] = i;
  }
  *keysets = all_keysets;
  return count;
}

/* returns a pointer to a statically allocated (do not modify in any way).
 * name for the directory corresponding to this key. */
/* in case of error, returns NULL */
char * key_dir (keyset key)
{
  init_from_file ();
  if (! valid_keyset (key))
    return NULL;
  return kip [key].dir_name;
}

static unsigned int get_pubkey (RSA * rsa, char ** bytes,
                                char * storage, int ssize)
{
  *bytes = NULL;
  if (rsa == NULL)
    return 0;
  int size = BN_num_bytes (rsa->n);
  if (bytes != NULL) {
    if (size + 1 > ssize)
      return 0;
    BN_bn2bin (rsa->n, (unsigned char *) (storage + 1));
    storage [0] = KEY_RSA4096_E65537;
    *bytes = storage;
  }
  return size + 1;
}

#define KEY_STATIC_STORAGE	4099   /* up to 32Kbit key size */
/* if successful returns the key length and sets *key to point to
 * statically allocated storage for the key (do not modify in any way)
 * if not successful, returns 0 */
unsigned int get_contact_pubkey (keyset k, char ** key)
{
  init_from_file ();
  if (! valid_keyset (k))
    return 0;
  static char storage [KEY_STATIC_STORAGE];
  return get_pubkey (kip [k].contact_pubkey, key, storage, KEY_STATIC_STORAGE);
}

unsigned int get_my_pubkey (keyset k, char ** key)
{
  init_from_file ();
  if (! valid_keyset (k))
    return 0;
  static char storage [KEY_STATIC_STORAGE];
  return get_pubkey (kip [k].my_key, key, storage, KEY_STATIC_STORAGE);
}

unsigned int get_my_privkey (keyset k, char ** key)
{
int debug_n = 0;
/* printf ("get_my_privkey (%d, %p)\n", k, key); */
  init_from_file ();
  if (! valid_keyset (k))
    printf ("division by zero is %d\n", k / debug_n);
  if (! valid_keyset (k))
    return 0;
  if (kip [k].my_key == NULL)
    return 0;
  static char storage [KEY_STATIC_STORAGE * 8];
  BIO * mbio = BIO_new (BIO_s_mem ());
  PEM_write_bio_RSAPrivateKey (mbio, kip [k].my_key,
                               NULL, NULL, 0, NULL, NULL);
#ifdef DEBUG_PRINT
  printf ("private key takes %zd bytes, %zd available\n",
          BIO_ctrl_pending (mbio), sizeof (storage));
#endif /* DEBUG_PRINT */
  char * keystore;
  long ksize = BIO_get_mem_data (mbio, &keystore);
  if (ksize + 1 > sizeof (storage))
    return 0;
  memcpy (storage, keystore, ksize);
  storage [ksize] = '\0';   /* null terminate */
  BIO_free (mbio);
  *key = storage;
  return ksize;
}

/* returns the number of bits in the address, 0 if none */
/* address must have length at least ADDRESS_SIZE */
unsigned int get_local (keyset k, unsigned char * address)
{
  init_from_file ();
  if (! valid_keyset (k))
    return 0;
  if (kip [k].local.nbits == 0)
    return 0;
  memcpy (address, kip [k].local.address, ADDRESS_SIZE);
  return kip [k].local.nbits;
}

unsigned int get_remote (keyset k, unsigned char * address)
{
  init_from_file ();
  if (! valid_keyset (k))
    return 0;
  if (kip [k].remote.nbits == 0)
    return 0;
  memcpy (address, kip [k].remote.address, ADDRESS_SIZE);
  return kip [k].remote.nbits;
}

/* a keyset may be marked as invalid.  The keys are not deleted, but can no
 * longer be accessed unless the marked as valid again */
int mark_invalid (keyset k)
{
  init_from_file ();
  printf ("mark_invalid not implemented\n");
  return 0;
}
int invalid_keys (char * contact, keyset ** keysets)
{
  init_from_file ();
  printf ("invalid_keys not implemented\n");
  return 0;
}
int mark_valid (keyset k)
{
  init_from_file ();
  printf ("mark_valid not implemented\n");
  return 0;
}

/*************** operations on broadcast keys ********************/

/* each broadcast key matches an AllNet address, which is of the form
   "some phrase"@word_pair.word_pair.word_pair
   Optionally the address may be followed by a language code and a
   bitstring size,
   e.g.  "some phrase"@word_pair.word_pair.word_pair.en.16 or
         "some phrase"@word_pair.word_pair.24

   The phrase is hashed.  The first ADDRESS_SIZE bytes of the hash are the
   broadcast address.  The last BITSTRING_* sets of bits (or bitstrings,
   if specified in the address) of the hash are matched to words from
   the files pre-list.* and post-list.* to give the word_pairs ("word"
   from the pre-list, and "pairs" from the post-list).

   The address may be written in many different ways, e.g. with '-' instead
   of '_', with '' instead of "" or no quotes at all (as long as the phrase
   is correctly identified)
 */

/* #define BITSTRING_BITS	16
 * #define BITSTRING_BYTES	2 */

struct bc_key_info * own_bc_keys = NULL;
int num_own_bc_keys = -1;    /* not initialized */
struct bc_key_info * other_bc_keys = NULL;
int num_other_bc_keys = -1;  /* not initialized */

extern void ** keyd_debug;

static int count_keys (char * path)
{
  DIR * dir = opendir (path);
  if (dir == NULL) {
    perror ("opendir");
    printf ("unable to open %s\n", path);
    return 0;
  }
  int result = 0;
  struct dirent * ent = readdir (dir);
  while (ent != NULL) {
    if (parse_ahra (ent->d_name, NULL, NULL, NULL, NULL, NULL, NULL)) {
      /* printf ("counting %s\n", ent->d_name); */
      result++;
    }
    ent = readdir (dir);
  }
  closedir (dir);
  return result;
}

static void rsa_to_external_pubkey (RSA * rsa, char ** key, int * klen)
{
  /* the public key in external format */
  int size = BN_num_bytes (rsa->n) + 1;
  char * p = malloc_or_fail (size, "external public key");
  BN_bn2bin (rsa->n, (unsigned char *) (p + 1));
  p [0] = KEY_RSA4096_E65537;
  *key = p;
  *klen = size;
/* printf ("external, key set to %p, length %d\n", *key, *klen); */
}

static void rsa_to_internal_key (RSA * rsa, char ** key, int * klen)
{
  BIO * mbio = BIO_new (BIO_s_mem ());
  PEM_write_bio_RSAPublicKey (mbio, rsa);
  PEM_write_bio_RSAPrivateKey (mbio, rsa, NULL, NULL, 0, NULL, NULL);
  char * keystore;
  *klen = BIO_get_mem_data (mbio, &keystore);
  *key = memcpy_malloc (keystore, *klen, "internal key");
/* printf ("internal, key set to %p, length %d\n", *key, *klen); */
  BIO_free (mbio);
}

static void init_key_info (char * config_dir, char * file,
                           struct bc_key_info * key, char * phrase,
                           int expect_private)
{
  bzero (key, sizeof (struct bc_key_info));  /* in case of error return */

  char * mapped;
  int mlen = map_string (phrase, &mapped);
  sha512_bytes (mapped, mlen, (char *) (key->address), ADDRESS_SIZE);
  free (mapped);

  key->identifier = strcpy_malloc (file, "keys.c init_key_info");

  char * fname = strcat3_malloc (config_dir, "/", file, "init_key_info fname");
  RSA * rsa = NULL;
  read_RSA_file (fname, &rsa, expect_private);
  free (fname);
  if (rsa == NULL) {
    printf ("unable to read RSA file %s/%s\n", config_dir, file);
    return;
  }

  rsa_to_external_pubkey (rsa, &(key->pub_key), &(key->pub_klen));
  key->priv_klen = 0;
  key->priv_key = NULL;
  if (expect_private)
    rsa_to_internal_key (rsa, &(key->priv_key), &(key->priv_klen));

  RSA_free (rsa);
}

static void init_bc_from_files (char * config_dir, struct bc_key_info * keys,
                                int num_keys, int expect_private)
{
  DIR * dir = opendir (config_dir);
  if (dir == NULL) {
    perror ("opendir");
    printf ("unable to open %s\n", config_dir);
    return;
  }
  int i = 0;
  struct dirent * ent = readdir (dir);
  while ((i < num_keys) && (ent != NULL)) {
    char * phrase;
    if (parse_ahra (ent->d_name, &phrase, NULL, NULL, NULL, NULL, NULL)) {
      init_key_info (config_dir, ent->d_name, keys + i, phrase, expect_private);
      free (phrase);
      i++;
    }
    ent = readdir (dir);
  }
  closedir (dir);
}

static void init_bc_key_set (char * dirname, struct bc_key_info ** keys,
                             int * num_keys, int expect_private)
{
  if (*num_keys < 0) {
/* printf ("init_bc_key_set 1, debug %p\n", *keyd_debug); */
    *num_keys = 0;    /* initialized */
    char * config_dir;
    if (config_file_name (dirname, "", &config_dir) < 0) {
      printf ("unable to open key directory ~/.allnet/%s\n", dirname);
    } else {
/* printf ("init_bc_key_set 2, debug %p\n", *keyd_debug); */
      char * slash = rindex (config_dir, '/');
      if (slash != NULL)
        *slash = '\0';
/* printf ("init_bc_key_set 3, debug %p\n", *keyd_debug); */
      *num_keys = count_keys (config_dir);
/* printf ("init_bc_key_set 4, debug %p\n", *keyd_debug); */
/*    printf ("config_dir is %s, %d keys found\n", config_dir, *num_keys); */
      *keys = malloc_or_fail (sizeof (struct key_info) * (*num_keys),
                              "broadcast keys");
/* printf ("init_bc_key_set 5, debug %p\n", *keyd_debug); */
      init_bc_from_files (config_dir, *keys, *num_keys, expect_private);
/* printf ("init_bc_key_set 6, debug %p\n", *keyd_debug); */
    }
  }
}

static void init_bc_keys ()
{
  init_bc_key_set ("own_bc_keys", &own_bc_keys, &num_own_bc_keys, 1);
  init_bc_key_set ("other_bc_keys", &other_bc_keys, &num_other_bc_keys, 0);
}

static void assign_lang_bits (char * p, int length,
                              char ** language, int * matching_bits)
{
  if (isalpha (*p)) {
    if (language != NULL) {
      *language = memcpy_malloc (p, length + 1, "parse_ahra language");
      (*language) [length] = '\0';
    }
  } else if (isdigit (*p)) {
    char * end;
    int value = strtol (p, &end, 10);
    if ((matching_bits != NULL) && (end != p))
      *matching_bits = value;
  }
}

/* returns the number of characters parsed */
static int parse_position (char * p, int * result)
{
  int length = strlen (p);
  char * end = index (p, '.');
  if (end != NULL) {
    end++;   /* point after the '.' */
    length = end - p;
  } else {
    end = index (p, ',');
    if (end != NULL)
      length = end - p;
  }
  int value = aaddr_decode_value (p, length);
  if ((value >= 0) && (result != NULL))
    *result = value;
  return length;
}

/* returns 1 for a successful parse, 0 otherwise */
int parse_ahra (char * ahra,
                char ** phrase, int ** positions, int * num_positions,
                char ** language, int * matching_bits, char ** reason)
{
  if (ahra == NULL) {
    if (reason != NULL) *reason = "AHRA is NULL";
    return 0;
  }
  char * middle = index (ahra, '@');
  if (middle == NULL) {
    if (reason != NULL) *reason = "AHRA lacks '@'";
    return 0;
  }
  if (phrase != NULL) {
    int len = (middle - ahra) + 1;
    *phrase = memcpy_malloc (ahra, len, "parse_ahra phrase");
    (*phrase) [len - 1] = '\0';
  }
  char * p = middle + 1;
  if ((*p) == '\0') {
    if (positions != NULL) *positions = NULL;
    if (num_positions != NULL) *num_positions = 0;
    return 1;
  }
  int np = 1;
  if (*p == ',')   /* no positions at all */
    np = 0;
  while (((*p) != '\0') && ((*p) != ',')) {
    if (*p == '.')
      np++;
    p++;
  }
  if (num_positions != NULL) *num_positions = np;
  if (positions != NULL) {
    if (np == 0) {
      *positions = NULL;
    } else {
      *positions = malloc_or_fail (sizeof (int) * np, "parse_ahra positions");
      char * q = middle + 1;
      int i;
      for (i = 0; i < np; i++)
        q += parse_position (q, (*positions) + i);
    }
  }
  if (*p != ',')
    return 1;
  p++;
  char * next_comma = index (p, ',');
  if (next_comma == NULL) {
    assign_lang_bits (p, strlen (p), language, matching_bits);
  } else {
    assign_lang_bits (p, next_comma - p, language, matching_bits);
    p = next_comma + 1;
    assign_lang_bits (p, strlen (p), language, matching_bits);
  }
  return 1;
}

static char * make_address (RSA * key, int key_bits,
                            char * phrase, char * lang, int bitstring_bits,
                            int min_bitstrings)
{
  int rsa_size = RSA_size (key);
  int max_rsa = rsa_size - 42;  /* PKCS #1 v2 requires 42 bytes */

  char * mapped;
  int msize = map_string (phrase, &mapped);
  char hash [SHA512_SIZE];
  sha512 (mapped, msize, hash);

  if (msize > max_rsa) {
    printf ("keys.c: too many bytes %d to encrypt, max %d\n", msize, max_rsa);
    exit (1);
  }

  /* get the bits of the ciphertext */
  unsigned char * encrypted =
     malloc_or_fail (rsa_size, "keys.c: encrypted phrase");

/* in general, RSA_NO_PADDING is not secure for RSA encryptions.  However,
 * in this application we want the remote system to be able to perform the
 * same encryption and give the same result, so no padding is appropriate */
  unsigned char * padded = malloc_or_fail (rsa_size, "make_address padded");
  bzero (padded, rsa_size);
  memcpy (padded + (rsa_size - msize), mapped, msize);
  int esize = RSA_public_encrypt (rsa_size, padded, encrypted, key,
                                  RSA_NO_PADDING);
  free (padded);
  if (esize != rsa_size) {
    ERR_load_crypto_strings ();
    ERR_print_errors_fp (stdout);
    printf ("make_address RSA encryption failed\n");
    exit (1);
  }
  free (mapped);


  /* assuming each bitstring is at least 1 bit long, the maximum number of
   * matching positions would be 512 */
#define SHA512_BITS	(SHA512_SIZE * 8)
#define MAX_MATCHES	SHA512_BITS
  int match_pos [MAX_MATCHES];
  int i, j;
  int nmatches = 0;
  for (i = 0; i < MAX_MATCHES / bitstring_bits; i++) {
    int hashpos = SHA512_BITS - ((i + 1) * bitstring_bits);
    int found = 0;  /* if no match, cannot continue the outer loop */
    for (j = 0; j <= esize * 8 - bitstring_bits; j++) {
      if (bitstring_matches (encrypted, j, (unsigned char *) hash, hashpos,
                             bitstring_bits)) {
        match_pos [nmatches++] = j;
/*
        printf ("match %d found at encr bit %d hash bit %d, bitstring: ",
                i, j, hashpos);
        print_buffer (hash + (hashpos / 8), (bitstring_bits + 7) / 8, NULL,
                      10, 1);
        print_buffer (encrypted + (j / 8), 10, "encrypted buffer:", 10, 1);
        printf ("%d matches\n", nmatches);
*/
        found = 1;
        break;   /* end the inner loop */
      }
    }
    if (! found)
      break;     /* not found, end the outer loop */
  }
/*
  if (nmatches >= min_bitstrings) {
    print_buffer (encrypted, esize, "encrypted", esize, 1);
    printf ("matched %d bitstrings, %d needed\n", nmatches, min_bitstrings);
  }
*/
  free (encrypted);
  if (nmatches < min_bitstrings)
    return NULL;

  int rsize = strlen (phrase) + 50 /* @.lang.bits\0 + margin */ +
              max_pair_len (lang) * nmatches;
  char * result = malloc_or_fail (rsize, "make_address result");
  char * p = result;
  char * next;
/* we use map_char to decide whether to copy a char, replace it with _, or
 * consider it the end of the phrase */
  int map = map_char (phrase, &next);
/* convert the blanks and other unprintables in the phrase to underscores */
  while ((map != MAPCHAR_EOS) && (map != MAPCHAR_UNKNOWN_CHAR)) {
    int clen = next - phrase;    /* length of a character */
    /* printf ("clen is %d\n", clen); */
    if (map == MAPCHAR_IGNORE_CHAR)
      *p = '_';
    else
      memcpy (p, phrase, clen);
    p += clen;
    phrase = next;
    map = map_char (phrase, &next);
  }
/*  *p = '\0';  printf ("phrase is '%s'\n", result); */
  int off = (p - result);
  off += snprintf (result + off, rsize - off, "@");
  for (i = 0; i < nmatches; i++) {
    if (i > 0)
      off += snprintf (result + off, rsize - off, ".");
    char * encoded_position = aaddr_encode_value (match_pos [i], lang);
    off += snprintf (result + off, rsize - off, "%s", encoded_position);
    free (encoded_position);
  }
  off += snprintf (result + off, rsize - off, ",%s,%d", lang, bitstring_bits);

  printf ("make_address ==> %s\n", result);
char * pkey;
int pklen;
rsa_to_external_pubkey (key, &pkey, &pklen);
print_buffer (pkey, pklen, "public key", 12, 1);
printf ("make_address verify_bc_key (%s) = %d\n", result,
verify_bc_key (result, pkey, pklen, "en", 16, 0));

  return result;
}

static char * generate_one_key (int key_bits, char * phrase, char * lang,
                                int bitstring_bits, int min_bitstrings)
{
  RSA * key = RSA_generate_key (key_bits, RSA_E65537_VALUE, no_feedback, NULL);

  char * aaddr = make_address (key, key_bits, phrase, lang, bitstring_bits,
                               min_bitstrings);
  if (aaddr != NULL) {
    char * fname;
    if (config_file_name ("own_bc_keys", aaddr, &fname) < 0) {
      printf ("unable to save key to ~/.allnet/own_bc_keys/%s\n", aaddr);
    } else {
      write_RSA_file (fname, key, 1);
      free (fname);
    }
  }

  RSA_free (key);
  return aaddr;
}

/* returns a malloc'd string with the address.  The key is saved and may
 * be retrieved using the complete address.  May be called multiple times
 * to generate different keys. */
char * generate_key (int key_bits, char * phrase, char * lang,
                     int bitstring_bits, int min_bitstrings, int give_feedback)
{
  char * result = NULL;
  do {
    if (give_feedback) {
      printf (".");
      fflush (stdout);
    }
    result = generate_one_key (key_bits, phrase, lang, bitstring_bits,
                               min_bitstrings);
  } while (result == NULL);
  return result;
}

/* these give the "normal" version of the broadcast address, without the
 * language, bits, or both.  The existing string is modified in place */
void delete_lang (char * ahra)
{
  char * comma = index (ahra, ',');
  if (comma == NULL)
    return;
  char * second = index (comma + 1, ',');
  if (isalpha (comma [1])) {
    if (second != NULL) {
      int lsize = strlen (second + 1);
      /* move lsize + 1 to copy the null character at the end */
      memmove (comma + 1, second + 1, lsize + 1);
    } else {  /* no second, just remove */
      *comma = '\0';
    }
  } else if ((second != NULL) && (isalpha (second [1]))) {  /* just delete */
    *second = '\0';
  }
}

void delete_bits (char * ahra)
{
  char * comma = index (ahra, ',');
  if (comma == NULL)
    return;
  char * second = index (comma + 1, ',');
  if (isdigit (comma [1])) {
    if (second != NULL) {
      int lsize = strlen (second + 1);
      /* move lsize + 1 to copy the null character at the end */
      memmove (comma + 1, second + 1, lsize + 1);
    } else {  /* no second, just remove */
      *comma = '\0';
    }
  } else if ((second != NULL) && (isdigit (second [1]))) {  /* just delete */
    *second = '\0';
  }
}

void delete_lang_bits (char * ahra)
{
  char * comma = index (ahra, ',');
  if (comma != NULL)
    *comma = '\0';
}

/* useful, e.g. for requesting a key.  Returns the public key size. */
/* pubkey and privkey should be free'd when done */
int get_temporary_key (char ** pubkey, char ** privkey, int * privksize)
{
  RSA * key = RSA_generate_key (4096, RSA_E65537_VALUE, no_feedback, NULL);

  int result = 0;
  rsa_to_external_pubkey (key, pubkey, &result);
  rsa_to_internal_key (key, privkey, privksize);
  RSA_free (key);   /* copied into the buffers, no longer needed */

  /* printf ("get_temporary_key returns %d, %d\n", result, *privksize); */
  return result;
}

/* verifies that a key obtained by a key exchange matches the address */
/* the default lang and bits are used if they are not part of the address */
unsigned int verify_bc_key (char * ahra, char * key, int key_bytes,
                            char * default_lang, int bitstring_bits,
                            int save_if_correct)
{
  if (((key != NULL) && (key_bytes > 0)) &&
      ((key_bytes != 513) || (*key != KEY_RSA4096_E65537))) {
    printf ("verify_bc_key: bad key, size %d, code %d\n", key_bytes, *key);
    return 0;
  }
  RSA * rsa = RSA_new ();
  rsa->n = BN_bin2bn ((unsigned char *) (key + 1), key_bytes - 1, NULL);
  rsa->e = NULL;
  BN_dec2bn (&(rsa->e), RSA_E65537_STRING);
  int rsa_size = RSA_size (rsa);
  int max_rsa = rsa_size - 42;  /* PKCS #1 v2 requires 42 bytes */

  char * phrase;
  int * positions;
  int num_positions;
  char * reason;
  if (! parse_ahra (ahra, &phrase, &positions, &num_positions,
                    &default_lang, &bitstring_bits, &reason)) {
    printf ("unable to parse allnet human-readable address '%s', %s\n",
            ahra, reason);
    return 0;
  }

  char * mapped;
  int mlen = map_string (phrase, &mapped);
  free (phrase);
  char hash [SHA512_SIZE];
  sha512 (mapped, mlen, hash);

  /* get the bits of the ciphertext */
  if (mlen > max_rsa)
    mlen = max_rsa;
  unsigned char * encrypted =
    malloc_or_fail (rsa_size, "keys.c: encrypted phrase");
/* in general, RSA_NO_PADDING is not secure for RSA encryptions.  However,
 * in this application we want the remote system to be able to perform the
 * same encryption and give the same result, so no padding is appropriate */
  unsigned char * padded = malloc_or_fail (rsa_size, "verify_bc_key padded");
  bzero (padded, rsa_size);
  memcpy (padded + (rsa_size - mlen), mapped, mlen);
  int esize = RSA_public_encrypt (rsa_size, padded, encrypted, rsa,
                                  RSA_NO_PADDING);
  free (padded);
  if (esize != rsa_size) {
    ERR_load_crypto_strings ();
    ERR_print_errors_fp (stdout);
    printf ("RSA failed to encrypt %d bytes, result %d\n", mlen, esize);
    exit (1);
  }
  free (mapped);

  int i;
  for (i = 0; i < num_positions; i++) {
    int hashpos = SHA512_BITS - ((i + 1) * bitstring_bits);
    if (! bitstring_matches (encrypted, positions [i],
                             (unsigned char *) hash, hashpos,
                             bitstring_bits)) {

      printf ("%d: no %d-bit match at positions %d/%d\n", i,
              bitstring_bits, positions [i], hashpos);
      print_bitstring (encrypted, positions [i], bitstring_bits, 1);
      print_bitstring ((unsigned char *) hash, hashpos, bitstring_bits, 1);

      free (encrypted);
      free (positions);
      return 0;
    }
  }
  char * fname;
  if (config_file_name ("other_bc_keys", ahra, &fname) < 0) {
    printf ("unable to save key to ~/.allnet/other_bc_keys/%s\n", ahra);
  } else {
    write_RSA_file (fname, rsa, 0);
    free (fname);
  }
  
  free (positions);
  free (encrypted);
  RSA_free (rsa);
  return 1;
}

/* if successful returns the number of keys and sets *keys to point to
 * statically allocated storage for the keys (do not modify in any way)
 * if not successful, returns 0 */
unsigned int get_own_keys (struct bc_key_info ** keys)
{
  init_bc_keys ();
  *keys = own_bc_keys;
  return num_own_bc_keys;
}

/* if successful returns the number of keys and sets *keys to point to
 * statically allocated storage for the keys (do not modify in any way)
 * if not successful, returns 0 */
unsigned int get_other_keys (struct bc_key_info ** keys)
{
  init_bc_keys ();
  *keys = other_bc_keys;
  return num_other_bc_keys;
}

static struct bc_key_info * find_bc_key (char * address,
                                         struct bc_key_info * keys, int nkeys)
{
  int i;
  for (i = 0; i < nkeys; i++) {
    if (verify_bc_key (address, keys [i].pub_key, keys [i].pub_klen,
                       NULL, 0, 0))
      return keys + i;
  }
  return NULL;
}

/* return the specified key (statically allocated, do not modify), or NULL */
struct bc_key_info * get_own_bc_key (char * ahra)
{
  init_bc_keys ();
  return find_bc_key (ahra, own_bc_keys, num_own_bc_keys);
}

struct bc_key_info * get_other_bc_key (char * ahra)
{
  init_bc_keys ();
  return find_bc_key (ahra, other_bc_keys, num_other_bc_keys);
}

#ifdef TEST_KEYS

int main ()
{
  init_from_file ();
  char addr [ADDRESS_SIZE];
  addr [0] = 0x01;
  addr [1] = 0x02;
  addr [2] = 0xAF;
  printf ("create_contact (edo) returns %d\n",
          create_contact ("edo", 8192, 1, NULL, 0, NULL, 0, addr, 18));
  printf ("create_contact (foo) returns %d\n",
          create_contact ("foo", 8192, 1, NULL, 0, NULL, 0, addr, 18));
  keyset * ks;
  int nk = all_keys ("edo", &ks);
  char * key;
  int ksize = get_my_privkey (ks [0], &key);
  printf ("private key (edo/%d/%d) is '%s'/%d\n", nk, ks [0], key, ksize);
}
#endif /* TEST_KEYS */
