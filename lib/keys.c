/* keys.c: manage keys on disk */

/* keys are stored under ~/.allnet/contacts/yyyymmddhhmmss/ */
/* each such directory has a file "name", a file "my_key", and possibly
 * a file "contact_public_key".  It is an error (and the contact is not
 * usable) if either of the first two files is missing */
/* if ~/.allnet/contacts does not exist, it is created */

/* to do: should be able to have multiple public keys for the contact */
/*        also some mechanism to get new private keys for a contact */

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/types.h>

#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

#include "keys.h"
#include "../packet.h"
#include "util.h"
#include "log.h"
#include "cipher.h"
#include "config.h"

/* a key set consists of the contact name, my private and public keys,
 * the contact's public key, and possibly a source address and/or
 * a destination address */
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
  struct key_address source;
  struct key_address dest;
};

struct key_info * kip = NULL;
int num_key_infos = 0;
/* contact names is set to the same size as kip, although if a contact
 * has multiple keys, in practice the number of contacts will be less
 * than the number of keysets */
char * * cp = NULL;
int cp_used = 0;

static int contact_exists (char * contact)
{
  int i;
  for (i = 0; i < cp_used; i++) {
    if (strcmp (cp [i], contact) == 0)
      return 1;
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
  for (ki = 0; ki < num_key_infos; ki++)
    if ((kip [ki].contact_name != NULL) &&
        (! contact_exists (kip [ki].contact_name)))
      cp [cp_used++] = kip [ki].contact_name;
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
  }
  /* zero out any new entries */
  for (i = num_key_infos; i < size; i++) {
    new_kip [i].contact_name = NULL;
    new_kip [i].contact_pubkey = NULL;
    new_kip [i].my_key = NULL;
    new_kip [i].source.nbits = 0;
    bzero (new_kip [i].source.address, ADDRESS_SIZE);
    new_kip [i].dest.nbits = 0;
    bzero (new_kip [i].dest.address, ADDRESS_SIZE);
  }
  /* set kip to point to the new array */
  if (kip != NULL)
    free (kip);
  if (cp != NULL)
    free (cp);
  num_key_infos = size;
  kip = new_kip;
  cp = new_cp;
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

static void read_RSA_file (char * fname, RSA * * key)
{
  *key = NULL;
  char * bytes;
  int size = read_file_malloc (fname, &bytes, 0);
  if (size > 0) {
    BIO * mbio = BIO_new_mem_buf (bytes, size);
    *key = PEM_read_bio_RSAPrivateKey (mbio, NULL, NULL, NULL);
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
      }
      *nbits = n;
    }
  }
}

/* returns 0 if the contact does not exist, 1 otherwise */
static int read_key_info (char * path, char * file, char ** contact,
                          RSA ** my_key, RSA ** contact_pubkey,
                          char * source, int * src_nbits,
                          char * destination, int * dst_nbits)
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
    read_RSA_file (name, my_key);
    free (name);
  }
  if (contact_pubkey != NULL) {
    char * name = strcat_malloc (basename, "/contact_pubkey", "pub name");
    read_RSA_file (name, contact_pubkey);
    free (name);
  }
  if ((source != NULL) && (src_nbits != NULL)) {
    char * name = strcat_malloc (basename, "/source", "source name");
    read_address_file (name, source, src_nbits);
    free (name);
  }
  if ((destination != NULL) && (dst_nbits != NULL)) {
    char * name = strcat_malloc (basename, "/destination", "dest name");
    read_address_file (name, destination, dst_nbits);
    free (name);
  }

  free (basename);
  return 1;
}

static void init_from_file ()
{
  static int initialized = 0;
  if (initialized)
    return;
  initialized = 1;
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
                        NULL, NULL, NULL, NULL)))
      num_keys++;
  }
  closedir (dir);

  set_kip_size (0);  /* get rid of anything that was previously there */
  set_kip_size (num_keys);  /* create new array */

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
                        kip [i].source.address, &(kip [i].source.nbits),
                        kip [i].dest.address, &(kip [i].dest.nbits))))
      i++;
  }
  closedir (dir);
  free (dirname);
  generate_contacts ();
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

static void write_RSA_file (char * fname, RSA * key)
{
  BIO * mbio = BIO_new (BIO_s_mem ());
  PEM_write_bio_RSAPublicKey (mbio, key);
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
  char fname [DATE_TIME_LEN + 1];
  time_t now = time (NULL);
  struct tm t;
  gmtime_r (&now, &t);
  snprintf (fname, sizeof (fname), "%04d%02d%02d%02d%02d%02d",
            t.tm_year + 1900, t.tm_mon + 1, t.tm_mday,
            t.tm_hour, t.tm_min, t.tm_sec);
 
  char * dirname;
  int dirnamesize = config_file_name ("contacts", fname, &dirname);
  create_dir (dirname);
  if (k->contact_name != NULL) {
    char * name_fname = strcat3_malloc (dirname, "/", "name", "name file");
    write_file (name_fname, k->contact_name, strlen (k->contact_name));
    free (name_fname);
  }
  if (k->my_key != NULL) {
    char * my_key_fname = strcat3_malloc (dirname, "/", "my_key", "key file");
    write_RSA_file (my_key_fname, k->my_key);
    free (my_key_fname);
  }
  if (k->contact_pubkey != NULL) {
    char * key_fname = strcat3_malloc (dirname, "/", "contact_pubkey", "kfile");
    write_RSA_file (key_fname, k->contact_pubkey);
    free (key_fname);
  }
  if (k->source.nbits != 0) {
    char * source_fname = strcat3_malloc (dirname, "/", "source", "sfile");
    write_address_file (source_fname, k->source.address, k->source.nbits);
    free (source_fname);
  }
  if (k->dest.nbits != 0) {
    char * dest_fname = strcat3_malloc (dirname, "/", "destination", "dfile");
    write_address_file (dest_fname, k->dest.address, k->dest.nbits);
    free (dest_fname);
  }
  printf ("save_contact file name is %s\n", dirname);
}

static int do_set_contact_pubkey (keyset k, char * contact_key, int ksize)
{
  BIO * mbio = BIO_new_mem_buf (contact_key, ksize);
  kip [k].contact_pubkey = PEM_read_bio_RSAPublicKey (mbio, NULL, NULL, NULL);
  BIO_free (mbio);
}

int set_contact_pubkey (keyset k, char * contact_key, int contact_ksize)
{
  init_from_file ();
  if ((! valid_keyset (k)) || (kip [k].contact_pubkey != NULL) ||
      (contact_key == NULL) || (contact_ksize = 0))
    return 0;
  do_set_contact_pubkey (k, contact_key, contact_ksize);
  save_contact (kip + k);
  return 1;
}

int set_contact_source_addr (keyset k, int nbits, char * address)
{
  init_from_file ();
  if (! valid_keyset (k))
    return 0;
  kip [k].source.nbits = nbits;
  memcpy (kip [k].source.address, address, ADDRESS_SIZE);
  save_contact (kip + k);
  return 1;
}

int set_contact_dest_addr (keyset k, int nbits, char * address)
{
  init_from_file ();
  if (! valid_keyset (k))
    return 0;
  kip [k].dest.nbits = nbits;
  memcpy (kip [k].dest.address, address, ADDRESS_SIZE);
  save_contact (kip + k);
  return 1;
}

/* returns the keyset if successful, -1 if the contact already existed */
/* creates a new private/public key pair, and if not NULL, also 
 * the contact public key, source and destination addresses */
/* if feedback is nonzero, gives feedback while creating the key */
keyset create_contact (char * contact, int keybits, int feedback,
                       char * contact_key, int contact_ksize,
                       char * source, int src_nbits,
                       char * destination, int dst_nbits)
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

  int new_contact = num_key_infos;
  set_kip_size (new_contact + 1);   /* make room for the new entry */
  kip [new_contact].contact_name = strcpy_malloc (contact, "create_contact");
  generate_contacts ();
  kip [new_contact].my_key = my_key;

  /* set defaults for the remaining values, then override them later if given */
  kip [new_contact].contact_pubkey = NULL;
  kip [new_contact].source.nbits = 0;
  bzero (kip [new_contact].source.address, ADDRESS_SIZE);
  kip [new_contact].dest.nbits = 0;
  bzero (kip [new_contact].dest.address, ADDRESS_SIZE);

  if ((contact_key != NULL) && (contact_ksize > 0))
    do_set_contact_pubkey (new_contact, contact_key, contact_ksize);
  if ((source != NULL) && (src_nbits > 0)) {
    kip [new_contact].source.nbits = src_nbits;
    memcpy (kip [new_contact].source.address, source, ADDRESS_SIZE);
  }
  if ((destination != NULL) && (dst_nbits > 0)) {
    kip [new_contact].dest.nbits = dst_nbits;
    memcpy (kip [new_contact].dest.address, destination, ADDRESS_SIZE);
  }

  /* now save to disk */
  save_contact (kip + new_contact);
  return new_contact;
}

/*************** operations on keysets and keys ********************/

/* returns -1 if the contact does not exist, and 0 or more otherwise */
int num_key_sets (char * contact)
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

static unsigned int get_pubkey (RSA * rsa, char ** bytes,
                                char * storage, int ssize)
{
  if (rsa == NULL)
    return 0;
  int size = BN_num_bytes (rsa->n);
  if (bytes != NULL) {
    if (size + 1 > ssize)
      return 0;
    BN_bn2bin (rsa->n, storage + 1);
    storage [0] = KEY_RSA_E65537;
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
  init_from_file ();
  if (! valid_keyset (k))
    return 0;
  if (kip [k].my_key == NULL)
    return 0;
  static char storage [KEY_STATIC_STORAGE * 8];
  BIO * mbio = BIO_new (BIO_s_mem ());
  PEM_write_bio_RSAPrivateKey (mbio, kip [k].my_key,
                               NULL, NULL, 0, NULL, NULL);
  printf ("private key takes %zd bytes, %zd available\n",
          BIO_ctrl_pending (mbio), sizeof (storage));
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
unsigned int get_source (keyset k, char * address)
{
  init_from_file ();
  if (! valid_keyset (k))
    return 0;
  if (kip [k].source.nbits == 0)
    return 0;
  memcpy (address, kip [k].source.address, ADDRESS_SIZE);
  return kip [k].source.nbits;
}

unsigned int get_destination (keyset k, char * address)
{
  init_from_file ();
  if (! valid_keyset (k))
    return 0;
  if (kip [k].dest.nbits == 0)
    return 0;
  memcpy (address, kip [k].dest.address, ADDRESS_SIZE);
  return kip [k].dest.nbits;
}

/* a keyset may be marked as invalid.  The keys are not deleted, but can no
 * longer be accessed unless the marked as valid again */
unsigned int mark_invalid (keyset k)
{
  init_from_file ();
}
int invalid_keys (char * contact, keyset ** keysets)
{
  init_from_file ();
}
unsigned int mark_valid (keyset k)
{
  init_from_file ();
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
