/* keys.c: manage keys on disk */

/* keys are stored under ~/.allnet/contacts/yyyymmddhhmmss/ */
/* each such directory has a file "name", a file "my_key", and possibly
 * a file "contact_public_key".  It is an error (and the contact is not
 * usable) if either of the first two files is missing */
/* if ~/.allnet/contacts does not exist, it is created */

/* to do: should be able to have multiple public keys for the contact */
/*        also some mechanism to get new private keys for a contact */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <inttypes.h>
#include <pthread.h>
#include <fcntl.h>
#include <dirent.h>
#include <assert.h>
#include <sys/types.h>

#include "crypt_sel.h"

#include "packet.h"
#include "cipher.h"
#include "keys.h"
#include "util.h"
#include "configfiles.h"
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

/* typedef int keyset;  refers to a key_info or a group_info */
struct key_info {
  char * contact_name;
  int is_group;
  int is_visible;         /* hidden contacts can still send or receive */
  int is_deleted;         /* deleted contacts can no longer send or receive */
  int has_pub_key;                   /* always 0 for groups */
  allnet_rsa_pubkey contact_pubkey;  /* only defined if not a group */
  allnet_rsa_prvkey my_key;          /* only defined if not a group */
  struct key_address local;          /* only defined if not a group */
  struct key_address remote;         /* only defined if not a group */
  char * dir_name;
  int num_group_members;             /* >= 0, only defined if is_group */
  char ** members;                   /* only defined if num_members > 0 */
/* symmetric keys are useful for encrypting larger amounts of data,
 * and for sending to larger groups */
  int has_symmetric_key;
#ifndef SYMMETRIC_KEY_SIZE
#define SYMMETRIC_KEY_SIZE AES256_SIZE
#endif /* SYMMETRIC_KEY_SIZE */
  char symmetric_key [SYMMETRIC_KEY_SIZE];
/* state includes a key, which may or may not be the same as symmetric_key,
 * but usually will be. */
  int has_state;
  struct allnet_stream_encryption_state state;
};
static struct key_info * kip = NULL;
static int num_key_infos = 0;

/* contact names is set to the same size as kip, although if a contact
 * has multiple keys, in practice the number of contacts will be less
 * than the number of keysets */
static char * * cpx = NULL;
static int cp_used = 0;

#ifdef DEBUG_PRINT
static void print_contacts (char * desc, int individual_only)
{
  int i;
  printf ("%s: %d contacts (%p)%s\n", desc, cp_used, cpx,
          ((individual_only) ? ", printing only individual contacts" : ""));
  for (i = 0; i < cp_used; i++)
    if ((! individual_only) || (! (kip [i].is_group)))
      printf ("   [%d]: %p %s\n", i, cpx [i], cpx [i]);
}
#endif /* DEBUG_PRINT */

/* return 0 if the contact does not exist, otherwise one more than the
 * contact's index in cp */
static int contact_exists (const char * contact)
{
  int i;
  for (i = 0; i < cp_used; i++) {
    if (strcmp (cpx [i], contact) == 0)
      return i + 1;
    /* else
      printf ("%d: %s does not match %s\n", i, contact, cp [i]); */
  }
  return 0;
}

static int valid_keyset (keyset k)
{
  return ((k >= 0) && (k < num_key_infos) && (! kip [k].is_deleted));
}

static void generate_contacts ()
{
  int ki = 0;
  cp_used = 0;
  for (ki = 0; ki < num_key_infos; ki++) {
    if ((kip [ki].contact_name != NULL) &&
        (! contact_exists (kip [ki].contact_name)))
      cpx [cp_used++] = kip [ki].contact_name;
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
    if (! kip [i].is_group) {  /* not a group */
      allnet_rsa_free_pubkey (kip [i].contact_pubkey);
      allnet_rsa_free_prvkey (kip [i].my_key);
    }
    if (kip [i].dir_name != NULL)
      free (kip [i].dir_name);
    if (kip [i].members != NULL)
      free (kip [i].members);
  }
  /* zero out the new entries (if any) in kip */
  for (i = num_key_infos; i < size; i++) {
    memset (new_kip + i, 0, sizeof (new_kip [i]));
    allnet_rsa_null_pubkey (&(new_kip [i].contact_pubkey));
    allnet_rsa_null_prvkey (&(new_kip [i].my_key));
  }
  /* clear the new entries in cp/cpx, generate_contacts will init them */
  for (i = 0; i < size; i++)
    new_cp [i] = NULL;
  /* set kip, cp, cpx to point to the new arrays */
  if (kip != NULL)
    free (kip);
  if (cpx != NULL)
    free (cpx);
  num_key_infos = size;
  kip = new_kip;
  cpx = new_cp;
  cp_used = 0;
  generate_contacts ();
}

#define DATE_TIME_LEN           14      /* strlen("20130101120102") */

/* if it is the kind of name we want, it should end in a string of n digits */
static int is_ndigits (char * path, int ndigits)
{
  char * slash = strrchr (path, '/');
  char * name = path;
  if (slash != NULL)
    name = slash + 1;
  if (((int) strlen (name)) != ndigits)
    return 0;
  int i;
  for (i = 0; i < ndigits; i++)
    if ((name [i] < '0') || (name [i] > '9'))
      return 0;
  return 1;
}

static int write_bytes_file (char * fname, char * bytes, int nbytes)
{
  /* two hex digits for each byte, a separator (: or \n) after each byte,
   * and a null char at the end. */
  int size = nbytes * 3 + 1;
  char * print_buffer = malloc_or_fail (size, "write_bytes_file");
  print_buffer [0] = '\0';
  int i;
  for (i = 0; i < nbytes; i++) {
    int slen = (int)strlen (print_buffer);  /* print after the current string */
    char * p = print_buffer + slen;
    char * post = ":";
    if (i + 1 == nbytes)
      post = "\n";
    snprintf (p, size - slen, "%02x%s", bytes [i] & 0xff, post);
  }
  int result = 0;
  if (write_file (fname, print_buffer, (int)strlen (print_buffer), 1))
    result = 1;
  else
    printf ("write_bytes_file: unable to write %d bytes to %s\n", size, fname);
  free (print_buffer);
  return result;
}

/* hex must be a C string, i.e. null terminated.
 * the return value is NULL in case of failure, or the next bytes to read
 * otherwise */
static char * s_to_bytes (char * hex, char * result, int rbytes)
{
  if (rbytes <= 0)
    return hex;
  int i;
  char * p = hex;
  for (i = 0; i < rbytes; i++) {
    int value;
    int num_chars = 0;
    int found = sscanf (p, " %x%n", &value, &num_chars);
    if (found == 0)
      found = sscanf (p, " : %x%n", &value, &num_chars);
    if ((found >= 1) && (num_chars > 0)) {
      result [i] = value;
      p += num_chars;
    } else {
      printf ("s_to_bytes (%s, %d) returning NULL at pos %d\n", hex, rbytes, i);
      return NULL;
    }
  }
  return p;
}

static int read_bytes_file (char * fname, char * bytes, int nbytes)
{
  memset (bytes, 0, nbytes);
  char * data;
  int size = read_file_malloc (fname, &data, 0);
  if (size <= 0)
    return 0;
  char * next = s_to_bytes (data, bytes, nbytes);
  if (next == NULL)
    return 0;
#ifdef DEBUG_PRINT
  print_buffer (bytes, nbytes, " read_bytes_file returns", 64, 1);
#endif /* DEBUG_PRINT */
  return nbytes;
}

/* returns 1 for success, 0 for failure */
static int read_address_file (const char * basename, const char * name,
                              struct key_address * addr)
{
  char * path = strcat3_malloc (basename, "/", name, "read_address_file name");
  memset (addr->address, 0, ADDRESS_SIZE);
  addr->nbits = 0;
  char * bytes = NULL;
  int size = read_file_malloc (path, &bytes, 0);
  if (size <= 0) {
    free (path);
    return 0;
  }
  char * p;
  int n = (int)strtol (bytes, &p, 10);
  if (p != bytes) {
    int count = (n + 7) / 8;
    int i;
    for (i = 0; (p != NULL) && (i < count) && (i < ADDRESS_SIZE); i++) {
      int value;
      sscanf (p, " %x", &value);
      addr->address [i] = value;
      p = strchr (p, ':');
      if (p != NULL)  /* p points to ':' */
        p++;
    }
    addr->nbits = n;
  }
  free (path);
  if (bytes != NULL)
    free (bytes);
  return 1;
}

/* return 1 for success, 0 for failure */
static int read_symmetric_state (char * fname,
                                 struct allnet_stream_encryption_state * state)
{
  memset (state, 0, sizeof (struct allnet_stream_encryption_state));
  char * data;
  int size = read_file_malloc (fname, &data, 0);
  if (size <= 0) return 0;
  char * next = s_to_bytes (data, state->key, ALLNET_STREAM_KEY_SIZE);
  if (next == NULL) return 0;
  next = s_to_bytes (next, state->secret, ALLNET_STREAM_SECRET_SIZE);
  if (next == NULL) return 0;
  int read = sscanf (next, "%d %d %" SCNu64 " %d", &(state->counter_size),
                     &(state->hash_size), &(state->counter),
                     &(state->block_offset));
#ifdef DEBUG_PRINT
  printf ("read state: ");
  print_buffer (state->key, ALLNET_STREAM_KEY_SIZE, "symmetric key", 32, 0);
  print_buffer (state->secret, ALLNET_STREAM_SECRET_SIZE, ", secret", 64, 0);
  printf (", %d %d %" PRIu64 " %d\n", state->counter_size, state->hash_size,
          state->counter, state->block_offset);
#endif /* DEBUG_PRINT */
  if (read < 4)
    return 0;
  return 1;
}

static void remove_unprintable (char * s)
{
  int offset = 0;
  int i = 0;
  do {
/* the way ASCII works, remove all characters less than space except '\0'
 * this preserves all UTF characters and the null terminator */
    if ((s [i] < ' ') && (s [i] != '\0'))
      offset++;
    else
      s [i - offset] = s [i];
    i++;
  } while (s [i - 1] != '\0');
}

static int get_members (const char * members_content, int mlen,
                        char *** members_list)
{
  int i;
  int num_members = 0;
  for (i = 0; i < mlen; i++)
    if (members_content [i] == '\n')
      num_members++;
  int extra = 0;
  if (members_content [mlen - 1] != '\n') {
    num_members++;   /* last member name not \n-terminated */
    extra = 1;       /* need room for a null character, not in mlen */
  }
  int ptr_size = num_members * sizeof (char *);
  int size = ptr_size + mlen + extra;
  char ** result = malloc_or_fail (size, "get_members");
  const char * p = members_content;
  int plen = mlen;
  char * s = ((char *) result) + ptr_size;
#ifdef DEBUG_GROUP
  printf ("num_members %d, result %p, ptr_size %d, size %d(%d)\n", num_members,
          result, ptr_size, size, extra);
#endif /* DEBUG_GROUP */
#ifdef DEBUG_PRINT
#endif /* DEBUG_PRINT */
  for (i = 0; i < num_members; i++) {
#ifdef DEBUG_GROUP
    printf ("i %d, p %p/%d, s %p/%d\n", i, p, plen, s, mlen);
#endif /* DEBUG_GROUP */
#ifdef DEBUG_PRINT
#endif /* DEBUG_PRINT */
    if (p + plen != members_content + mlen) {
      printf ("group members error: %p + %d != %p + %d\n",
              p, plen, members_content, mlen);
      exit (1);
    }
    int slen = plen;
    char * nl = strchr (p, '\n');
    if (nl != NULL)
      slen = (int)(nl - p);
    if (s + slen > ((char *) result) + size) {
      printf ("group members error: %p + %d > %p + %d\n",
              s, slen, result, size);
      exit (1);
    }
    memcpy (s, p, slen);
    s [slen] = '\0';
    result [i] = s;  /* save ptr to the newly copied/null-terminated string */
    slen++;  /* now count the null character (for p/plen, the newline if any) */
    p += slen;
    plen -= slen;
    s += slen;
  }
  if (members_list != NULL)
    *members_list = result;
  else
    free (result);
#ifdef DEBUG_GROUP
  for (i = 0; i < num_members; i++)
    printf ("member [%d] = %s\n", i, result [i]);
#ifdef DEBUG_PRINT
#endif /* DEBUG_PRINT */
#endif /* DEBUG_GROUP */
  return num_members;
}

/* returns 0 if the contact does not exist, 1 if it does, 2 if it is a group.
 * if num_members is not NULL, it is set to -1 for a plain contact, or otherwise
 * the number of members. */
static int read_key_info (const char * path, const char * file,
                          struct key_info * info)
{
/* initialize all the results to NULL/zero defaults, in case we return */
  if (info != NULL) {
    memset (info, 0, sizeof (struct key_info));
    allnet_rsa_null_prvkey (&(info->my_key));
    allnet_rsa_null_pubkey (&(info->contact_pubkey));
  }
  int result = 1;   /* found individual contact */

  /* basename is the name of the directory for the contact information files */
  char * basename = strcat3_malloc (path, "/", file, "basename");

  /* contact name is the path to the file containing the contact name */
  if (info != NULL) {
    char * contact_name = strcat_malloc (basename, "/name", "name-path");
    char * contact_value = NULL;
    int found = read_file_malloc (contact_name, &contact_value, 0);
    free (contact_name);
    if ((found <= 0) || (contact_value == NULL)) {
      free (basename);
      return 0;
    } /* read_file_malloc allocates 1 extra byte and null terminates */
    remove_unprintable (contact_value);
#ifdef DEBUG_PRINT
    printf ("contact name is now %s\n", contact_value);
#endif /* DEBUG_PRINT */
    info->contact_name = contact_value;
    char * hidden_name = strcat_malloc (basename, "/hidden", "hidden-path");
    if (file_size (hidden_name) < 0)
      info->is_visible = 1;  /* no "/hidden" file in the directory */
    free (hidden_name);
  }
  /* check to see if this is a group */
  char * members_name = strcat_malloc (basename, "/members", "members-name");
  /* the file may be empty, but as long as it exists, it is a group */
  int found_members = (file_size (members_name) >= 0);
  char * members_content = NULL;
  int mlen = 0;  /* some things we only do if the group has members */
  if (file_size (members_name) > 0)
    mlen = read_file_malloc (members_name, &members_content, 0);
  if (mlen < 0)
    mlen = 0;
#ifdef DEBUG_GROUP
  if (found_members && (contact != NULL))
    printf ("found group %s in %s, mlen %d\n", *contact, members_name, mlen);
#endif /* DEBUG_GROUP */
  free (members_name);
  if (found_members) {  /* it's a group */
    char ** members_list = NULL;
    int mcount = 0;
    if (members_content != NULL) {
      mcount = get_members (members_content, mlen, &members_list);
      free (members_content);
    }
#ifdef DEBUG_GROUP
    int i;
    for (i = 0; i < mcount; i++)
      printf ("  %s\n", members_list [i]);
#endif /* DEBUG_GROUP */
    if (info != NULL) {
      info->is_group = 1;
      info->members = members_list;
      info->num_group_members = mcount;
    } else {
      free (members_list);
    }
    result = 2;  /* found a group */
  } else {  /* it's not a group */
    if (info != NULL) {
      char * kname = strcat_malloc (basename, "/my_key", "my key name");
      if (allnet_rsa_read_prvkey (kname, &(info->my_key))) {
        char * pname = strcat_malloc (basename, "/contact_pubkey", "pub name");
        info->has_pub_key =
          allnet_rsa_read_pubkey (pname, &(info->contact_pubkey));
        free (pname);
        read_address_file (basename, "local", &(info->local));
        read_address_file (basename, "remote", &(info->remote));
      }
      free (kname);
    }
  }
  if (info != NULL) {
    char * name = strcat_malloc (basename, "/symmetric_key", "symmetric name");
    int n = read_bytes_file (name, info->symmetric_key, SYMMETRIC_KEY_SIZE);
    if (n >= SYMMETRIC_KEY_SIZE) {
      info->has_symmetric_key = 1;
    } else if (n < SYMMETRIC_KEY_SIZE) {
      memset (info->symmetric_key, 0, SYMMETRIC_KEY_SIZE);
      if ((n < SYMMETRIC_KEY_SIZE) && (n > 0))
        printf ("found symmetric key in %s, but lenght %d < minimum %d\n",
                name, n, SYMMETRIC_KEY_SIZE);
    }
    free (name);
#ifdef DEBUG_PRINT
    printf ("symmetric key for %s has size %d/%d\n",
            basename, n, SYMMETRIC_KEY_SIZE);
    if (info->has_symmetric_key)
      printf ("%d: %02x:%02x:%02x...\n", info->has_symmetric_key,
              info->symmetric_key [0], info->symmetric_key [1],
              info->symmetric_key [2]);
#endif /* DEBUG_PRINT */
    if (info->has_symmetric_key) {
      char * sname = strcat_malloc (basename, "/send_state", "symm state");
      if (read_symmetric_state (sname, &(info->state)))
        info->has_state = 1;
      free (sname);
    }
  }
  if (info != NULL)
    info->dir_name = basename;
  else
    free (basename);
  return result;
}

static void init_from_file (const char * debug)
{
  static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
  static int initialized = 0;
  /* quick check -- if not initialized, check again after getting mutex */
  if (initialized)
    return;
  /* all but one thread blocks here until initialized is set to 1 */
  pthread_mutex_lock (&mutex);
  if (initialized) {
  /* all the threads that get the lock, except the first, return here */
    pthread_mutex_unlock (&mutex);
    return;
  }
  /* first count the number of keys */
  char * dirname = NULL;
  int dirnamesize = config_file_name ("contacts", "", &dirname);
  if (dirnamesize < 0) {  /* no config file names */
    printf ("init_from_file unable to access config files\n");
    initialized = 1; /* don't try again on the next call */
    pthread_mutex_unlock (&mutex);
    return;
  }
  char * last = dirname + dirnamesize - 2;
  if (*last == '/')
    *last = '\0';
  DIR * dir = opendir (dirname);
  if (dir == NULL) {
    perror ("opendir in init_from_file");
    printf ("unable to open directory %s (called by %s)\n", dirname, debug);
    initialized = 1; /* don't try again on the next call */
    pthread_mutex_unlock (&mutex);
    return;
  }
  int num_keys = 0;
  struct dirent * dep;
  while ((dep = readdir (dir)) != NULL) {
    if (is_ndigits (dep->d_name, DATE_TIME_LEN)) { /* key directory */
      if (read_key_info (dirname, dep->d_name, NULL)) {
        num_keys++;
      } else {
        printf ("error: unable to load key from .allnet/contacts/%s/\n",
                dep->d_name);
      }
    }
  }

  set_kip_size (0);  /* get rid of anything that was previously there */
  if (num_keys > 0) {
    set_kip_size (num_keys);  /* create new array */

    /* now load the keys */
    rewinddir (dir);
    int i = 0;
    while ((i < num_keys) && ((dep = readdir (dir)) != NULL)) {
      /* this is only legal as long as i < num_keys */
      kip [i].local.nbits = ADDRESS_SIZE * 8;
      kip [i].remote.nbits = ADDRESS_SIZE * 8;
      if ((is_ndigits (dep->d_name, DATE_TIME_LEN)) && /* is a key directory */
          (read_key_info (dirname, dep->d_name, kip + i))) {
        i++;
      }
    }
  }
  closedir (dir);
  free (dirname);
  generate_contacts ();
#ifdef TEST_GROUP_MEMBERSHIP
  char ** contacts;   /* do not free or modify */
  int nc = all_contacts (&contacts);
  int ic;
  for (ic = 0; ic < nc; ic++) {
    char ** simple_groups = NULL;
    char ** rec_groups = NULL;
printf ("querying contact %s\n", contacts [ic]);
    int ngs = member_of_groups (contacts [ic], &simple_groups);
    int ngr = member_of_groups_recursive (contacts [ic], &rec_groups);
    printf ("contact %s is in %d groups, recursively %d (%p %p)\n",
            contacts [ic], ngs, ngr, simple_groups, rec_groups);
    int ig;
    for (ig = 0; ig < ngs; ig++)
      printf ("   %s member of %s\n", contacts [ic], simple_groups [ig]);
    for (ig = 0; ig < ngr; ig++)
      printf ("   %s recursive member of %s\n", contacts [ic], rec_groups [ig]);
    if (ngs > 0)
      free (simple_groups);
    if (ngr > 0)
      free (rec_groups);
  }
  if ((nc > 0) && (contacts != NULL))
    free (contacts);
#endif /* TEST_GROUP_MEMBERSHIP */
  initialized = 1;
  pthread_mutex_unlock (&mutex);
}

/*************** operations on contacts ********************/

/* returns 0 or more */
int num_contacts ()
{
  init_from_file ("num_contacts");
  return cp_used;
}

static char ** malloc_copy_array_of_strings (char ** array, int count)
{
  if ((array == NULL) || (count <= 0))
    return NULL;
  int i;
  size_t size = 0;
  for (i = 0; i < count; i++) /* room for char * and the string including \0 */
    size += sizeof (char *) + strlen (array [i]) + 1;
  char * mem = malloc_or_fail (size, "malloc_copy_array_of_strings");
  char ** result = (char **) mem;
  mem += count * sizeof (char *);  /* copy the strings after the pointers */
  for (i = 0; i < count; i++) {
    strcpy (mem, array [i]);
    result [i] = mem;
    mem += strlen (result [i]) + 1;
  }
  return result;
}

static int all_contacts_implementation (char *** contacts, int individual_only)
{
  init_from_file ("all_contacts_implementation");
#ifdef DEBUG_PRINT
  print_contacts ("entering all_contacts_implementation (%d)", individual_only);
#endif /* DEBUG_PRINT */
  int i;
  int delta = 0;
  char ** p = NULL;
/* allocate enough room for all the contacts, then only return the ones
 * we actually want to return: the ones that are not deleted,
 * and if individual_only, that are not groups
 * otherwise, that are visible
 * we do waste of some space, but the amount of wasted space should
 * be small, and simplifying the code is worth it */
  if (contacts != NULL) {
    p = malloc_copy_array_of_strings (cpx, cp_used);
    *contacts = p;
  }
  for (i = 0; i < cp_used; i++) {
    int include = (! kip [i].is_deleted);
    if (individual_only)  /* only include if it is not a group */
      include = include && (! kip [i].is_group);
    else                  /* only include if it is visible */
      include = include && (kip [i].is_visible);
    if (include) {
      if ((delta > 0) && (p != NULL))
        /* delta > 0, so at least some with index < i have been ignored */
        p [i - delta] = p [i];  /* make p[i-delta] valid */
         /* note: delta increases at most once per loop,
            so i >= delta >= 0 and i >= i - delta >= 0 */
    } else {
      delta++;
    }
  }
  return cp_used - delta;
}

/* returns the number of contacts, and (if not NULL) has contacts point
 * to a dynamically allocated array of pointers to null-terminated
 * contact names (to free, call free (*contacts)). */
int all_contacts (char *** contacts)
{
  return all_contacts_implementation (contacts, 0);
}

/* same, but only individual contacts, not groups */
int all_individual_contacts (char *** contacts)
{
  return all_contacts_implementation (contacts, 1);
}

#if 0
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
#endif /* 0 */

#if 0
static void write_RSA_file (char * fname, RSA * key, int write_priv)
{
  BIO * mbio = BIO_new (BIO_s_mem ());
  if (write_priv)
    PEM_write_bio_RSAPrivateKey (mbio, key, NULL, NULL, 0, NULL, NULL);
  else
    PEM_write_bio_RSAPublicKey (mbio, key);
  char * keystore;
  long ksize = BIO_get_mem_data (mbio, &keystore);
  write_file (fname, keystore, ksize, 1);
  BIO_free (mbio);
}
#endif /* 0 */

static void write_address_file (const char * fname,
                                const char * address, int nbits)
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
  write_file (fname, buf, offset, 1);
}

/* only access members if num_members > 0 */
static void write_member_file (const char * fname, char ** members,
                               int num_members)
{
  int size = 1;  /* allocate at least one for the null character at the end */
  if (num_members > 0) {
    int i;
    for (i = 0; i < num_members; i++)
      size += strlen (members [i]) + 1;
  }
  char * buffer = malloc_or_fail (size, "write_member_file");
  buffer [0] = '\0';  /* if there are no members */
  if (num_members > 0) {
    char * p = buffer;
    int i;
    for (i = 0; i < num_members; i++) {
      snprintf (p, size - (p - buffer), "%s\n", members [i]);
      p += strlen (members [i]) + 1;
    }
  }
  write_file (fname, buffer, (int)strlen (buffer), 1);
}

static void save_contact (struct key_info * k)
{
  if (k->is_deleted) {
    printf ("not saving deleted contact %s\n", k->contact_name);
    return;
  }
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
      printf ("unable to get config file name");
      return;
    }
    k->dir_name = dirname;
  }
  create_dir (dirname);
  if (k->contact_name != NULL) {
    char * name_fname = strcat3_malloc (dirname, "/", "name", "name file");
    write_file (name_fname, k->contact_name, (int)strlen (k->contact_name), 1);
    free (name_fname);
  }
  if (! allnet_rsa_prvkey_is_null (k->my_key)) {
    char * my_key_fname = strcat3_malloc (dirname, "/", "my_key", "key file");
    if (! allnet_rsa_write_prvkey (my_key_fname, k->my_key))
      printf ("unable to write private key to file %s\n", my_key_fname);
    free (my_key_fname);
  }
  if (! allnet_rsa_pubkey_is_null (k->contact_pubkey)) {
    char * key_fname = strcat3_malloc (dirname, "/", "contact_pubkey", "kf");
    if (! allnet_rsa_write_pubkey (key_fname, k->contact_pubkey))
      printf ("unable to write public key to file %s\n", key_fname);
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
  if (k->is_group) {  /* it's a group even if it has no members */
    char * member_fname = strcat3_malloc (dirname, "/", "members", "mfile");
    write_member_file (member_fname, k->members, k->num_group_members);
    free (member_fname);
  }
  if (k->has_symmetric_key) {
    char * fname = strcat3_malloc (dirname, "/", "symmetric_key", "mfile");
    write_bytes_file (fname, k->symmetric_key, SYMMETRIC_KEY_SIZE);
    free (fname);
  }
  /* create or delete the hidden file */
  char * hidden_fname = strcat3_malloc (dirname, "/", "hidden", "mfile");
  if (k->is_visible) {
    unlink (hidden_fname);  /* delete the file, if any */
  } else {
    write_file (hidden_fname, "", 0, 0);  /* create the file */
  }
  free (hidden_fname);
#ifdef DEBUG_PRINT
  printf ("save_contact %d file name is %s\n", ((int) (k - kip)), dirname);
#endif /* DEBUG_PRINT */
}

static int count_spare_key_files ()
{
  char * dirname;
  int dirnamesize = config_file_name ("own_spare_keys", "", &dirname);
  if (dirnamesize < 0)
    return 0;
  DIR * dir = opendir (dirname);
  if (dir == NULL) {
    free (dirname);
    return 0;
  }
  struct dirent * de;
  int result = 0;
  while ((de = readdir (dir)) != NULL) {
  /* count it as long as it has the right length and doesn't begin with . */
    if ((de->d_name [0] != '.') &&
        (strlen (de->d_name) == DATE_TIME_LEN))
      result++;
  }
  closedir (dir);
#ifdef DEBUG_PRINT
  printf ("directory %s has %d spare key files\n", dirname, result);
#endif /* DEBUG_PRINT */
  free (dirname);
  return result;
}

static int save_spare_key (allnet_rsa_prvkey key)
{
  if (allnet_rsa_prvkey_is_null (key))
    return 0;
  char now_printed [DATE_TIME_LEN + 1];
  time_t now = time (NULL);
  struct tm t;
  gmtime_r (&now, &t);
  snprintf (now_printed, sizeof (now_printed), "%04d%02d%02d%02d%02d%02d",
            t.tm_year + 1900, t.tm_mon + 1, t.tm_mday,
            t.tm_hour, t.tm_min, t.tm_sec);

  char * fname;
  int fnamesize = config_file_name ("own_spare_keys", now_printed, &fname);
  if (fnamesize < 0) {
    printf ("unable to get config file name for spare");
    return 0;
  }
  if (! allnet_rsa_write_prvkey (fname, key)) {
    printf ("unable to write spare private key to file %s\n", fname);
    free (fname);
    return 0;
  }
  free (fname);
  return 1;
}

static allnet_rsa_prvkey get_spare_key (int keybits)
{
  allnet_rsa_prvkey result;
  allnet_rsa_null_prvkey (&result);
  if (count_spare_key_files () <= 0)
    return result;
  char * dirname;
  int dirnamesize = config_file_name ("own_spare_keys", "", &dirname);
  if (dirnamesize < 0)
    return result;
  DIR * dir = opendir (dirname);
  free (dirname);
  if (dir == NULL)
    return result;
  struct dirent * de;
  while ((de = readdir (dir)) != NULL) {
  /* try to read it if it has the right length and doesn't begin with . */
    if ((de->d_name [0] != '.') &&
        (strlen (de->d_name) == DATE_TIME_LEN)) {
      char * fname;
      int fnamesize = config_file_name ("own_spare_keys", de->d_name, &fname);
      if (fnamesize >= 0) {
        int success = allnet_rsa_read_prvkey (fname, &result);
        if ((success) && (allnet_rsa_prvkey_size (result) == keybits / 8)) {
          unlink (fname);   /* remove the file, don't reuse it in the future */
          printf ("found spare key with %d bits\n", keybits);
          free (fname);
          closedir (dir);
          return result;
        }
        free (fname);
      }
    }
  }
  closedir (dir);
  allnet_rsa_null_prvkey (&result);
  return result;
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
  if (allnet_get_pubkey (contact_key + 1, ksize - 1, &(k->contact_pubkey)))
    return 1;
  return 0;
}

int set_contact_pubkey (keyset k, char * contact_key, int contact_ksize)
{
  init_from_file ("set_contact_pubkey");
  if ((! valid_keyset (k)) ||
      (! allnet_rsa_pubkey_is_null (kip [k].contact_pubkey)) ||
      (contact_key == NULL) || (contact_ksize == 0))
    return 0;
  if (do_set_contact_pubkey (kip + k, contact_key, contact_ksize) == 0)
    return 0;
  save_contact (kip + k);
  return 1;
}

int set_contact_local_addr (keyset k, int nbits, unsigned char * address)
{
  init_from_file ("set_contact_local_addr");
  if (! valid_keyset (k))
    return 0;
  kip [k].local.nbits = nbits;
  memcpy (kip [k].local.address, address, ADDRESS_SIZE);
  save_contact (kip + k);
  return 1;
}

int set_contact_remote_addr (keyset k, int nbits, unsigned char * address)
{
  init_from_file ("set_contact_remote_addr");
  if (! valid_keyset (k))
    return 0;
  kip [k].remote.nbits = nbits;
  memcpy (kip [k].remote.address, address, ADDRESS_SIZE);
  save_contact (kip + k);
  return 1;
}

/* returns the keyset if successful, -1 if the contact already existed
 * creates a new private/public key pair, and if not NULL, also 
 * the contact public key, source and destination addresses
 * if a spare key of the requested size already exists, uses the spare key 
 * if feedback is nonzero, gives feedback while creating the key.
 * If the contact was already created, but does not have the peer's
 * info, returns as if it were a newly created contact after replacing
 * the contents of local (as long as loc_nbits matches the original nbits) 
 * if there is no contact public key, marks the contact hidden */
keyset create_contact (const char * contact, int keybits, int feedback,
                       char * contact_key, int contact_ksize,
                       unsigned char * local, int loc_nbits,
                       unsigned char * remote, int rem_nbits)
{
  int preselected_index = -1;   /* no preselected index, yet */
  init_from_file ("create_contact");
  keyset index_plus_one = contact_exists (contact);
  if (index_plus_one > 0) {  /* contact exists */
    keyset k = index_plus_one - 1;
    struct key_info * ki = kip + k;
    if (! ki->is_deleted) {  /* contact exists */
      if (allnet_rsa_pubkey_is_null (ki->contact_pubkey) &&
          ((ki->local.nbits == 0) || (loc_nbits == ki->local.nbits))) {
        if (local != NULL)
          memcpy (local, ki->local.address, ADDRESS_SIZE);
        return k;  /* found an incomplete entry, use that */
      }
      return -1;   /* conflicts with a live entry */
    } else {                 /* contact has been deleted, continue */
      preselected_index = k;
      /* free the memory used to store the previous contact */
      if (ki->contact_name != NULL)
        free (ki->contact_name);
      ki->contact_name = NULL;
      if (ki->dir_name != NULL)
        free (ki->dir_name);
      ki->dir_name = NULL;
      if (ki->members != NULL)
        free (ki->members);
      ki->members = NULL;
    }
  }

  allnet_rsa_prvkey my_key = get_spare_key (keybits);
  if (allnet_rsa_prvkey_is_null (my_key))
    my_key = allnet_rsa_generate_key (keybits, NULL, 0);
  if (allnet_rsa_prvkey_is_null (my_key)) {
    printf ("unable to generate RSA key\n");
    return -1;
  }

  struct key_info new;
  memset (&new, 0, sizeof (new));  /* for most fields 0 is a good default */
  new.contact_name = strcpy_malloc (contact, "create_contact");
  new.is_visible = ((contact_key != NULL) && (contact_ksize > 0));
  new.has_pub_key = 1;
  new.my_key = my_key;
  /* set defaults for the remaining values, then override them later if given */
  allnet_rsa_null_pubkey (&(new.contact_pubkey));

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
  if (preselected_index >= 0)         /* overwrite existing entry */
    new_contact = preselected_index;
  else
    set_kip_size (new_contact + 1);   /* make room for the new entry */
  kip [new_contact] = new;
  if (preselected_index < 0)          /* re-initialize the list */
    generate_contacts ();

#ifdef DEBUG_PRINT
#ifdef HAVE_OPENSSL
  printf ("for %s new.keys are %p %p, kip keys are %p %p\n",
          kip [new_contact].contact_name, new.contact_pubkey, new.my_key,
          kip [new_contact].contact_pubkey, kip [new_contact].my_key);
#else /* ! HAVE_OPENSSL */
  /* this code only works if HAVE_OPENSSL is not defined */
  printf ("for %s new.keys are %d %d, kip keys are %d %d\n",
          kip [new_contact].contact_name, new.contact_pubkey.nbits,
          new.my_key.nbits, kip [new_contact].contact_pubkey.nbits,
          kip [new_contact].my_key.nbits);
#endif /* HAVE_OPENSSL */
#endif /* DEBUG_PRINT */

  /* now save to disk */
  save_contact (kip + new_contact);
  return new_contact;
}

/* change the name associated with a contact.  Fails and returns 0
 * if the old name does not exist, or if the new one does, and of
 * course for other reasons too.
 * returns 1 for success */
int rename_contact (const char * old, const char * new)
{
  init_from_file ("rename_contact");
  int key;
  for (key = 0; key < cp_used; key++) {
    if ((! kip [key].is_deleted) && (kip [key].is_visible) &&
        (strcmp (cpx [key], new) == 0)) {
      printf ("cannot rename %s to existing contact %s\n", old, new);
      return 0;
    }
  }
  int renamed = 0;
  for (key = 0; key < cp_used; key++) {
    if ((! kip [key].is_deleted) && (strcmp (cpx [key], old) == 0)) {
      char * name_file_name = strcat_malloc (kip [key].dir_name, "/name",
                                             "rename_contact");
      size_t newlen = strlen (new);
      if (write_file (name_file_name, new, (int)newlen, 1)) {
        char * p = realloc (kip [key].contact_name, newlen + 1);
        if (p != NULL) {
          strcpy (p, new);
          kip [key].contact_name = p;
          cpx [key] = p;
          renamed = 1;
        } else {
          printf ("unable to realloc %s for %s\n", old, new);
        }
      } else {
        printf ("unable to write to file %s\n", name_file_name);
      }
      free (name_file_name);
    }
  }
  return renamed;
}

/* sort of the complement of all_contacts */
/* a contact may be marked as not visible.  Nothing is deleted,
 * but the contact can no longer be accessed unless made visible again.
 * invisible_contacts returns the number of hidden contacts, or 0.
 * if not 0 and contacts is not NULL, the contacts array is malloc'd,
 * should be free'd. */
int invisible_contacts (char *** contacts)
{
  init_from_file ("hidden_contacts");
#ifdef DEBUG_PRINT
  print_contacts ("entering hidden_contacts", 0);
#endif /* DEBUG_PRINT */
  int i;
  int delta = 0;
  char ** p = NULL;
  if (contacts != NULL) {
    p = malloc_copy_array_of_strings (cpx, cp_used);
    *contacts = p;
  }
  for (i = 0; i < cp_used; i++) {
    if ((kip [i].is_deleted) || (kip [i].is_visible)) {  /* skip */
      delta++;
    } else {
      if ((delta > 0) && (p != NULL))  /* make p[i-delta] valid */
        p [i - delta] = p [i];
         /* note: delta increases at most once per loop,
            so i >= delta >= 0 and i >= i - delta >= 0 */
    }
  }
  return cp_used - delta;
}

/* make_in/visible return 1 for success, 0 if not successful */
int make_invisible (const char * contact)
{
  init_from_file ("make_invisible");
  int key;
  int hidden = 0;
  for (key = 0; key < cp_used; key++) {
    if ((! kip [key].is_deleted) && (kip [key].is_visible) &&
        (strcmp (cpx [key], contact) == 0)) {
      char * file_name =
        strcat_malloc (kip [key].dir_name, "/hidden", "make_invisible");
      write_file (file_name, "", 0, 0);  /* create the file */
      free (file_name);
 /* now hide in the data structure */
      kip [key].is_visible = 0;
 /* record success */
      hidden = 1;
    }
  }
  return hidden;
}

int make_visible (const char * contact)
{
  init_from_file ("make_visible");
  int key;
  for (key = 0; key < cp_used; key++) {
    if ((! kip [key].is_deleted) && (kip [key].is_visible) &&
        (strcmp (cpx [key], contact) == 0)) {
#ifdef DEBUG_PRINT
      printf ("unable to unhide contact %s, already visible\n", contact);
#endif /* DEBUG_PRINT */
      return 0;
    }
  }
  int success = 0;
  for (key = 0; key < cp_used; key++) {
    if ((! kip [key].is_visible) && (! kip [key].is_deleted) &&
        (strcmp (cpx [key], contact) == 0)) {
      char * file_name =
        strcat_malloc (kip [key].dir_name, "/hidden", "make_visible");
 /* remove .allnet/contacts/x/hidden, if any */
      if (unlink (file_name) != 0)  /* not really an error */
        /* printf ("failed to remove '%s'\n", file_name) */
        ;
 /* now un-hide in the data structure */
      kip [key].is_visible = 1;
 /* record success */
      success = 1;
      free (file_name);
    }
  }
  return success;
}

/* returns 1 if the contact exists and is visible */
int is_visible (const char * contact)
{
  init_from_file ("is_visible");
  int key;
  for (key = 0; key < cp_used; key++) {
    if ((! kip [key].is_deleted) && (kip [key].is_visible) &&
        (strcmp (cpx [key], contact) == 0)) {
      return 1;
    }
  }
  return 0;  /* is invisible, or deleted, or does not exist */
}

/* returns 1 if the contact exists and is not visible */
int is_invisible (const char * contact)
{
  init_from_file ("is_invisible");
  int key;
  for (key = 0; key < cp_used; key++) {
    if ((! kip [key].is_deleted) && (! kip [key].is_visible) &&
        (strcmp (cpx [key], contact) == 0)) {
      return 1;
    }
  }
  return 0;  /* is visible, or deleted, or does not exist */
}

/* notice -- moving keys around causes existing keysets to be invalidated
 * if we were to actually delete contacts, this would cause a race
 * condition if free_key_info is called in one thread while another
 * thread is working through the keyset for a contact
 * so instead, just mark a key info as invalid */

/* this is the actual deletion. return 1 for success, 0 otherwise */
int delete_contact (const char * contact)
{
  init_from_file ("delete_contact");
  int result = 0;
  int key;
  for (key = 0; key < cp_used; key++) {
    if ((! kip [key].is_deleted) && (strcmp (cpx [key], contact) == 0)) {
      /* for now, only actually delete contacts that are hidden */
      if (! kip [key].is_visible) {
        rmdir_and_all_files (kip [key].dir_name);
        kip [key].is_deleted = 1;
        result = 1;
      } else {
        return 0;
      }
    }
  }
  return result;
}

/* return -1 if the file does not exist, the size otherwise.
 * if content is not NULL, malloc's enough space to hold the 
 * content (with null termination), and returns it */
int contact_file_get (const char * contact, const char * fname, char ** content)
{
  init_from_file ("contact_file_get");
  int key;
  for (key = 0; key < cp_used; key++) {
    if ((! kip [key].is_deleted) && (strcmp (cpx [key], contact) == 0)) {
      char * path = strcat3_malloc (kip [key].dir_name, "/", fname,
                                    "contact_file_get");
      int result = read_file_malloc (path, content, 0);
      free (path);
      return result;
    }
  }
  if (content != NULL)
    *content = NULL;
  return -1;
}

/* write the content to the file, returning 0 in case of error, 1 otherwise */
int contact_file_write (const char * contact, const char * fname,
                        const char * content, int clength)
{
  init_from_file ("contact_file_write");
  int key;
  for (key = 0; key < cp_used; key++) {
    if ((! kip [key].is_deleted) && (strcmp (cpx [key], contact) == 0)) {
      char * path = strcat3_malloc (kip [key].dir_name, "/", fname,
                                    "contact_file_write");
      int result = write_file (path, content, clength, 0);
      free (path);
      return result;
    }
  }
  return 0;  /* contact not found */
}

/* return 1 if the file was deleted, 0 otherwise */
int contact_file_delete (const char * contact, const char * fname)
{
  init_from_file ("contact_file_delete");
  int key;
  for (key = 0; key < cp_used; key++) {
    if ((! kip [key].is_deleted) && (strcmp (cpx [key], contact) == 0)) {
      char * path = strcat3_malloc (kip [key].dir_name, "/", fname,
                                    "contact_file_delete");
      int result = unlink (path);
      free (path);
      if (result < 0)
        return 0;
      return 1;  /* success */
    }
  }
  return 0;  /* contact not found */
}

/* create a spare key of the given size, returning the number of spare keys.
 * if random is not NULL and rsize >= keybits / 8, uses the bytes from
 * random to randomize the generated key
 * if keybits < 0, returns the number of spare keys without generating
 * any new key (and ignoring random/rsize)
 * returns 0 in case of error
 * should normally only be called after calling
 *    setpriority (PRIO_PROCESS, 0, n), with n >= 15 */
int create_spare_key (int keybits, char * random, int rsize)
{
  if (keybits < 0)
    return count_spare_key_files ();
  allnet_rsa_prvkey spare = allnet_rsa_generate_key (keybits, random, rsize);
  if (allnet_rsa_prvkey_is_null (spare)) {
    printf ("unable to generate spare RSA key\n");
    return 0;
  }
  if (save_spare_key (spare))
    return count_spare_key_files ();
  return 0;
}

/*************** operations on groups of contacts ******************/

/* a contact may actually be a group of contacts. */
/* the members of a group may themselves be groups. */
/* deleting a group does not delete the members of the group. */
int is_group (const char * contact)   
{
  int ki;
  for (ki = 0; ki < num_key_infos; ki++) {
    if ((! kip [ki].is_deleted) &&
        (kip [ki].is_group) &&
        (strcmp (kip [ki].contact_name, contact) == 0))
      return 1;
  }
  return 0;
}

/* group creation succeeds iff there is no prior contact or group
 * with the same name
 * returns 1 for success, 0 for failure */
int create_group (const char * group)
{
  init_from_file ("create_group");
  int index_plus_one = contact_exists (group);
  if (index_plus_one) {  /* found an existing entry */
    printf ("create_group failed, %s already exists\n", group);
    return 0;
  }

  struct key_info new;
  memset (&new, 0, sizeof (new));  /* for most fields 0 is a good default */
  new.contact_name = strcpy_malloc (group, "create_group");
  new.is_group = 1;
  new.is_visible = 1;
  allnet_rsa_null_prvkey (&(new.my_key));
  allnet_rsa_null_pubkey (&(new.contact_pubkey));
  /* save into the kip data structure */
  int new_contact = num_key_infos;
  set_kip_size (new_contact + 1);   /* make room for the new entry */
  kip [new_contact] = new;
  generate_contacts ();

  /* now save to disk */
  save_contact (kip + new_contact);
  return 1;
}

/* returns the number of members of the group, and the names listed
 * in a dynamically allocated array (if not NULL, must be free'd) */
int group_membership (const char * group, char *** members)   
{
  init_from_file ("group_membership");
  if (members != NULL)
    *members = NULL;
  if (! is_group (group))
    return 0;
  int index_plus_one = contact_exists (group);
  if (index_plus_one <= 0)
    return 0;
  int index = index_plus_one - 1;
  if ((members != NULL) && (kip [index].is_group) &&
      (kip [index].members != NULL) && (kip [index].num_group_members > 0)) {
    int size = kip [index].num_group_members * sizeof (char *);
    int ptr_size = size;
    int i;
    for (i = 0; i < kip [index].num_group_members; i++)
      size += strlen (kip [index].members [i]) + 1;
    char ** result = malloc_or_fail (size, "group_membership");
    char * p = ((char *) result) + ptr_size;
    for (i = 0; i < kip [index].num_group_members; i++) {
      result [i] = p;
      int len = (int)strlen (kip [index].members [i]) + 1;
      memcpy (p, kip [index].members [i], len);
      p += len;
    }
    *members = result;
  }
  return kip [index].num_group_members;
}

static int reload_members_from_file (int ki)
{
  int result = 0;
  char * fname = strcat_malloc (kip [ki].dir_name, "/members",
                                "reload_members_from_file");
  char * members_content = NULL;
  int mlen = 0;
  if (file_size (fname) >= 0) /* file exists, even if empty we succeed */
    result = 1;
  if (file_size (fname) > 0)  /* file has some content, read it */
    mlen = read_file_malloc (fname, &members_content, 0);
  if (mlen < 0)
    mlen = 0;
  free (fname);
  if (result) {
    if ((kip [ki].num_group_members > 0) && (kip [ki].members != NULL))
      free (kip [ki].members); /* throw away the in-memory info */
    char ** members_list = NULL;
    int mcount = 0;
    if (mlen > 0)
      mcount = get_members (members_content, mlen, &members_list);
    kip [ki].num_group_members = mcount;
    kip [ki].members = members_list;
  }
  if (members_content != NULL)
    free (members_content);
  return result;
}

/* these return 0 for failure, 1 for success.  Reason for failures
 * include non-existence of the group or contact, or the group being
 * an individual contact rather than a group */
int add_to_group (const char * group, const char * contact)
{
  init_from_file ("add_to_group");
  if (! is_group (group))
    return 0;
  int index_plus_one = contact_exists (group);
  if (index_plus_one <= 0)
    return 0;
  int index = index_plus_one - 1;
  if ((kip [index].is_group) && (kip [index].num_group_members > 0) &&
      (kip [index].members != NULL)) {
    int i;
    for (i = 0; i < kip [index].num_group_members; i++)
      if (strcmp (kip [index].members [i], contact) == 0)
        return 0;  /* already in the group */
  }
  int result = 0;
  char * fname = strcat_malloc (kip [index].dir_name, "/members",
                                "add_to_group members-name");
  char * copy = strcat_malloc (contact, "\n", "add_to_group");
  if (append_file (fname, copy, (int)strlen (copy), 1))
    result = 1;
  free (copy);
  free (fname);
  if (result)
    return reload_members_from_file (index);
  else
    return 0;
}

int remove_from_group (const char * group, const char * contact)
{
  init_from_file ("remove_from_group");
  if (! is_group (group))
    return 0;
  int index_plus_one = contact_exists (group);
  if (index_plus_one <= 0)
    return 0;
  int index = index_plus_one - 1;
  if ((! kip [index].is_group) || (kip [index].num_group_members <= 0) ||
      (kip [index].members == NULL))
    return 0;  /* cannot remove if the group has no members */
  char * fname = strcat_malloc (kip [index].dir_name, "/members",
                                "remove_from_group members-name");
  char * members_content;
  int mlen = read_file_malloc (fname, &members_content, 0);
  if ((members_content == NULL) || (mlen <= 0)) {
    free (fname);
    return 0;
  }
  char * match = members_content;
  int clen = (int)strlen (contact);
  int found = 0;
  while ((! found) && ((match = strstr (match, contact)) != NULL)) {
    int remlen = mlen - (int)(match - members_content);  /* remaining length */
    /* check for newline at beginning (or at start of file) */
    /* it is safe to use the -1 index iff match != members_content */
    if (((match == members_content) || (match [-1] == '\n')) &&
        (match [clen] == '\n')) {  /* also check for match at end */
      /* real match, delete the string (with memmove) and write back */
      memmove (match, match + (clen + 1), remlen - (clen + 1));
      mlen -= clen + 1;
      found = 1;
      break;   /* removed */
    }
    match++;  /* so it no longer matches at the same spot */
  }
  if (found) {
    int written = write_file (fname, members_content, mlen, 1);
    if (! written) {
      printf ("unable to write %d bytes to %s, wrote %d\n", mlen, fname, written);
      found = 0;
    }
  }
  free (fname);
  free (members_content);
  if (found)
    return reload_members_from_file (index);
  return 0;
}

static int groups_for_contact (const char * contact, int * groups, int ngroups)
{
  int i;
  int count = 0;
  for (i = 0; i < num_key_infos; i++) {
    if (kip [i].contact_name != NULL) {
#ifdef DEBUG_GROUPS
printf ("searching for contact %s in kip [%d].contact_name: %s, %d, %d\n", contact, i, kip [i].contact_name, kip [i].is_group, kip [i].num_group_members);
#endif /* DEBUG_GROUPS */
      if ((kip [i].is_group) && (kip [i].num_group_members > 0)) {
        int m;
        for (m = 0; m < kip [i].num_group_members; m++) {
#ifdef DEBUG_GROUPS
printf ("comparing contact %s to kip [%d].members [%d]: %s\n", contact, i, m, kip [i].members [m]);
#endif /* DEBUG_GROUPS */
          if (strcmp (contact, kip [i].members [m]) == 0) {
#ifdef DEBUG_GROUPS
printf ("succcess comparing contact %s to kip [%d].members [%d]: %s\n", contact, i, m, kip [i].members [m]);
#endif /* DEBUG_GROUPS */
            if ((groups != NULL) && (count < ngroups))
              groups [count] = i;
            count++;
          }
        }
      }
    }
  }
#ifdef DEBUG_GROUPS
printf ("%d groups for contact %s\n", count, contact);
#endif /* DEBUG_GROUPS */
  return (count);
}

/* return the count of groups of which this contact or group is a member
 * 0 if not a member of any group, -1 for errors
 * if groups is not NULL, also allocates and returns the list of groups */
int member_of_groups (const char * contact, char *** groups)
{
  int count = groups_for_contact (contact, NULL, 0);
  if ((groups == NULL) || (count <= 0))
    return count;
  int * keys = malloc_or_fail (sizeof (int) * count, "member_of_group keys");
  int recount = groups_for_contact (contact, keys, count);
  assert (count == recount);
  int i;
  size_t size = 0;
  for (i = 0; i < count; i++)
    size += strlen (kip [keys [i]].contact_name) + 1 + sizeof (char *);
  char * memory = malloc_or_fail (size, "member_of_group");
  char ** names = (char **) memory;
  memory += (count * sizeof (char *));
  for (i = 0; i < count; i++) {
    strcpy (memory, kip [keys [i]].contact_name);
    names [i] = memory;
    memory += strlen (memory) + 1;
  }
  *groups = names;
  free (keys);
  return count;
}

/* identical to string_in_array, except for the order of parameters
static int is_in_group (const char * contact, char ** group, int n_group)
{
  int i;
  for (i = 0; i < n_group; i++)
    if (strcmp (contact, group [i]) == 0)
      return 1;
  return 0;
}
*/

static int string_in_array (char ** array, int count, const char * string)
{
  int i;
  for (i = 0; i < count; i++)
    if (strcmp (string, array [i]) == 0)
      return 1;
  return 0;
}

/* doesn't change the allocated memory, but returns the new count */
static int remove_from_array (char ** array, int count, const char * string)
{
  int i = 0;
  while (i < count) {
    if (strcmp (string, array [i]) == 0) {
      count--;
      array [i] = array [count];  /* replace with the last element */
    } else {
      i++;
    }
  }
  return count;
}

#if 0 /* not used */
/* doesn't change the allocated memory, but returns the new count */
static int remove_groups (char ** array, int count)
{
  int i = 0;
  while (i < count) {
    if (is_group (array [i])) {
      count--;
      array [i] = array [count];  /* replace with the last element */
    } else {
      i++;
    }
  }
  return count;
}
#endif /* 0 */

/* assumes it's OK to reorder */
static int eliminate_duplicates (char ** from, int fcount)
{
  int i = 0;
  while (i < fcount) {             /* each loop, incr i or decr fcount */
    int j;
    int increment = 1;             /* increment i if no match found */
    for (j = i + 1; j < fcount; j++) {
      if (strcmp (from [i], from [j]) == 0) {
        increment = 0;
        fcount--;
        from [j] = from [fcount];  /* put the last one in position j */
        break;                     /* and start over with fcount less by 1 */
      }
    }
    i += increment;                /* i++ or no change to i */
  }
  return fcount;
}

/* assumes it's OK to reorder */
static int merge_no_duplicates (char ** a, int acount, char ** b, int bcount,
                                char *** result)
{
  int i;
  size_t needed = 0;  /* allocate for the duplicates too -- simpler */
  int count = acount + bcount;
  for (i = 0; i < acount; i++)
    needed += sizeof (char *) + strlen (a [i]) + 1;
  for (i = 0; i < bcount; i++)
    needed += sizeof (char *) + strlen (b [i]) + 1;
  char * memory = malloc_or_fail (needed, "merge_no_duplicates");
  char ** res = (char **) memory;
  *result = res;
  char * strings = memory + (count * sizeof (char *));
  count = 0;
  for (i = 0; i < acount; i++) {
    if (! string_in_array (res, count, a [i])) {
      strcpy (strings, a [i]);
      res [count] = strings;
      strings += (strlen (res [count]) + 1);
      count++;
    }
  }
  for (i = 0; i < bcount; i++) {
    if (! string_in_array (res, count, b [i])) {
      strcpy (strings, b [i]);
      res [count] = strings;
      strings += (strlen (res [count]) + 1);
      count++;
    }
  }
  return count;
}

/* same as member_of_groups, but also lists the groups of this
 * contact's groups, and so on recursively */
int member_of_groups_recursive (const char * contact, char *** groups)
{
  char ** first_groups = NULL;
  if (groups != NULL)
    *groups = NULL;
  int first_count = member_of_groups (contact, &first_groups);
  if ((first_count <= 0) || (first_groups == NULL)) {
    if (first_groups != NULL)
      free (first_groups);
    if (first_count > 0)
      first_count = -1;   /* first_groups is null, so there was some error */
    return first_count;
  }
  /* if self is in group, remove */
  first_count = remove_from_array (first_groups, first_count, contact);
  int count = eliminate_duplicates (first_groups, first_count);
  char ** current_groups = first_groups;
  int i = 0;
  while (i < count) {  /* add any supergroup, but at most once */
    char ** local_groups = NULL;
    int local_count = member_of_groups (current_groups [i], &local_groups);
    if ((local_count > 0) && (local_groups != NULL)) {
      char ** new_groups = NULL;
      int new_count = merge_no_duplicates (current_groups, count,
                                           local_groups, local_count,
                                           &new_groups);
      if (new_count > count) {
        free (current_groups);
        current_groups = new_groups;
        count = new_count;
/* note - relying on groups not disappearing from current_groups.
   Otherwise should change i and start over again */
      } else {
        free (new_groups);
      }
      free (local_groups);
    }
    i++;
  }
  if (groups != NULL)
    *groups = current_groups;
  else
    free (current_groups);
  return count;
}

static int add_to_array (char *** array, int count, const char * value)
{
  int i;
  char ** strings = *array;
  size_t size = sizeof (char *) + strlen (value) + 1;
  if (*array != NULL) {
    for (i = 0; i < count; i++)
      size += sizeof (char *) + strlen (strings [i]) + 1;
  }
  char * mem = malloc_or_fail (size, "add_to_array");
  char ** res = (char **) mem;
  mem += (count + 1) * sizeof (char *);
  for (i = 0; i < count; i++) {
    strcpy (mem, strings [i]);
    res [i] = mem;
    mem += strlen (strings [i]) + 1;
  }
  strcpy (mem, value);
  res [count] = mem;
  *array = res;
  return count + 1;
}

/* same as group_membership, but (a) recursively examines all groups
 * and subgroups, and (b) includes one each of all non-group members
 * of all (sub)groups */
int group_contacts (const char * group, char *** members)   
{
  if (members != NULL)
    *members = NULL;
  if (! is_group (group))
    return 0;
  char ** all_members = NULL;
  int nmembers = 0;
  /* track the groups we add in case they refer to each other recursively */
  /* begin with ourselves */
  char ** subgroups = NULL;
  int ngroups = add_to_array (&subgroups, 0, group);
  int i = 0;
  while (i < ngroups) {  /* add the members of each subgroup, at most once */
    char ** local_members = NULL;
    int local_count = group_membership (subgroups [i], &local_members);
    /* add each member to subgroups or all_members, unless already there */
    int j;
    for (j = 0; j < local_count; j++) {
      const char * member = local_members [j];
      if (is_group (member)) {
        if (! string_in_array (subgroups, ngroups, member)) {
          /* increases ngroups, loops longer */
          ngroups = add_to_array (&subgroups, ngroups, member);
        }
      } else {  /* not a group */
        if (! string_in_array (all_members, nmembers, member)) {
          nmembers = add_to_array (&all_members, nmembers, member);
        }
      }
    }
    i++;  /* process next subgroup */
  }
  free (subgroups);
  if (members != NULL)
    *members = all_members;
  else
    free (all_members);
#ifdef DEBUG_PRINT
  printf ("end of group_contacts, returning %d members:\n", nmembers);
  for (i = 0; i < nmembers; i++)
    printf ("   [%d] %s\n", i, all_members [i]);
#endif /* DEBUG_PRINT */
  return nmembers;
}

/*************** operations on keysets and keys ********************/

#define RECURSIVELY_INCLUDE_GROUP_KEYS
#ifdef RECURSIVELY_INCLUDE_GROUP_KEYS
/* recursively (up to max depth) count keysets for groups */
/* return -1 if a recursive loop is detected, as indicated by max_depth <= 0 */
/* if keysets is not null, assign up to the first num_keysets */
static int recursive_num_keysets (const char * contact, int max_depth,
                                  keyset * keysets, int num_keysets)
{
  if (max_depth <= 0)
    return -1;
  int i;
  int count = 0;
  for (i = 0; i < num_key_infos; i++) {
    if ((kip [i].contact_name != NULL) &&
        (strcmp (kip [i].contact_name, contact) == 0)) {
      if ((! kip [i].is_group) || (kip [i].num_group_members < 0)) {
        /* not a group */
        if ((keysets != NULL) && (num_keysets > count))
          keysets [count] = i;
        count++;
      } else {  /* recursively count each member's keys */
        int m;
        for (m = 0; m < kip [i].num_group_members; m++) {
          int result =
            recursive_num_keysets (kip [i].members [m], max_depth - 1,
                                   keysets + count, num_keysets - count);
          if (result < 0)
            return result;
          count += result;
        }
      }
    }
  }
#ifdef DEBUG_PRINT
  printf ("recursive_num_keysets (%s) returning %d, pointer %p %d\n",
          contact, count, keysets, num_keysets);
#endif /* DEBUG_PRINT */
  return count;
}

#else /* ! RECURSIVELY_INCLUDE_GROUP_KEYS */

/* count keysets -- same as above, but returns 0 for groups */
/* if keysets is not null, assign up to the first num_keysets */
static int plain_num_keysets (const char * contact,
                              keyset * keysets, int num_keysets)
{
  int i;
  int count = 0;
  for (i = 0; i < num_key_infos; i++) {
    if ((kip [i].contact_name != NULL) &&
        (strcmp (kip [i].contact_name, contact) == 0) &&
        (! kip [i].is_group)) {
      if ((keysets != NULL) && (num_keysets > count))
        keysets [count] = i;
      count++;
    }
  }
  return count;
}
#endif /* RECURSIVELY_INCLUDE_GROUP_KEYS */

/* returns -1 if the contact does not exist, and 0 or more otherwise */
int num_keysets (const char * contact)
{
  init_from_file ("num_keysets");
  keyset k_plus_one = contact_exists (contact);
  if (k_plus_one <= 0)
    return -1;
  keyset k = k_plus_one - 1;
  if (! valid_keyset (k))
    return -1;
#ifdef RECURSIVELY_INCLUDE_GROUP_KEYS
  return recursive_num_keysets (contact, num_key_infos + 1, NULL, 0);
#else /* ! RECURSIVELY_INCLUDE_GROUP_KEYS */
  return plain_num_keysets (contact, NULL, 0);
#endif /* RECURSIVELY_INCLUDE_GROUP_KEYS */
}

/* returns the number of keysets.
 * malloc's a new keysets (must be free'd) and fills it with the keysets. */
/* returns -1 if the contact does not exist */
int all_keys (const char * contact, keyset ** keysets)
{
  init_from_file ("all_keys");
#ifdef DEBUG_PRINT
  print_contacts ("entering all_keys", 0);
#endif /* DEBUG_PRINT */

  if (! contact_exists (contact))
    return -1;
#ifdef RECURSIVELY_INCLUDE_GROUP_KEYS
  int count = recursive_num_keysets (contact, num_key_infos + 1, NULL, 0);
#else /* ! RECURSIVELY_INCLUDE_GROUP_KEYS */
  int count = plain_num_keysets (contact, NULL, 0);
#endif /* RECURSIVELY_INCLUDE_GROUP_KEYS */

  if ((keysets == NULL) || (count <= 0)) {
    *keysets = NULL;
    return count;
  }

  *keysets = malloc_or_fail (count * sizeof (keyset), "all_keys");
#ifdef RECURSIVELY_INCLUDE_GROUP_KEYS
  int copied = recursive_num_keysets (contact, num_key_infos + 1,
                                      *keysets, count);
#else /* ! RECURSIVELY_INCLUDE_GROUP_KEYS */
  int copied = plain_num_keysets (contact, *keysets, count);
#endif /* RECURSIVELY_INCLUDE_GROUP_KEYS */
  assert (copied == count);
  return count;
}

/* returns a pointer to a dynamically allocated (must be free'd).
 * name for the directory corresponding to this key. */
/* in case of error, returns NULL */
char * key_dir (keyset key)
{
  init_from_file ("key_dir");
  if (! valid_keyset (key))
    return NULL;
  return strcpy_malloc (kip [key].dir_name, "key_dir");
}

#if 0
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
#endif /* 0 */

/* if successful returns the key length and sets *key to point to
 * statically allocated storage for the key (do not modify in any way)
 * if not successful, returns 0 */
unsigned int get_contact_pubkey (keyset k, allnet_rsa_pubkey * key)
{
  init_from_file ("get_contact_pubkey");
  if (! valid_keyset (k))
    return 0;
  *key = kip [k].contact_pubkey;
  return allnet_rsa_pubkey_size (*key);
}

unsigned int get_my_pubkey (keyset k, allnet_rsa_pubkey * key)
{
  init_from_file ("get_my_pubkey");
  if (! valid_keyset (k))
    return 0;
  *key = allnet_rsa_private_to_public (kip [k].my_key);
  return allnet_rsa_pubkey_size (*key);
}

unsigned int get_my_privkey (keyset k, allnet_rsa_prvkey * key)
{
  init_from_file ("get_my_privkey");
  if (! valid_keyset (k))
    return 0;
  *key = kip [k].my_key;
  return allnet_rsa_prvkey_size (*key);
}

/* returns the number of bits in the address, 0 if none */
/* address must have length at least ADDRESS_SIZE */
unsigned int get_local (keyset k, unsigned char * address)
{
  init_from_file ("get_local");
  if (! valid_keyset (k))
    return 0;
  if (kip [k].local.nbits == 0)
    return 0;
  memcpy (address, kip [k].local.address, ADDRESS_SIZE);
  return kip [k].local.nbits;
}

unsigned int get_remote (keyset k, unsigned char * address)
{
  init_from_file ("get_remote");
  if (! valid_keyset (k))
    return 0;
  if (kip [k].remote.nbits == 0)
    return 0;
  memcpy (address, kip [k].remote.address, ADDRESS_SIZE);
  return kip [k].remote.nbits;
}

/* returnes a malloc'd copy of the contact name, or NULL for errors */
char * get_contact_name (keyset k)
{
  init_from_file ("get_contact_name");
  if (! valid_keyset (k))
    return NULL;
  if (kip [k].contact_name == NULL)
    return NULL;
  if (strlen (kip [k].contact_name) <= 0)
    return NULL;
  return strcpy_malloc (kip [k].contact_name, "get_contact_name");
}

/* a keyset may be marked as invalid.  The keys are not deleted, but can no
 * longer be accessed unless marked as valid again
 * invalid_keys returns the number of invalid keys, or 0.
 * mark_* return 1 for success, 0 if not successful */
/* a keyset is marked as invalid by renaming the my_key to my_key_invalidated */
int mark_invalid (const char * contact, keyset k)
{
  init_from_file ("mark_invalid");
  if (! valid_keyset (k))
    return 0;
  char * fname = strcat_malloc (kip [k].dir_name, "/my_key",
                                "invalidate_symmetric_key-1");
  char * new_fname = strcat_malloc (fname, "_invalidated",
                                    "invalidate_symmetric_key-2");
  int result = 0;
  if (rename (fname, new_fname) == 0)
    result = 1;
  else {
    perror ("rename in mark_invalid");
    printf ("unable to rename %s to %s\n", fname, new_fname);
  }
  free (fname);
  free (new_fname);
  /* delete from data structure */
  allnet_rsa_null_prvkey (&(kip [k].my_key));
  return result;
}

int invalid_keys (const char * contact, keyset ** keysets)
{
  init_from_file ("invalid_keys");
  int ki;
  int count = 0;
  for (ki = 0; ki < num_key_infos; ki++)
    if ((strcmp (kip [ki].contact_name, contact) == 0) &&
        (allnet_rsa_prvkey_is_null (kip [ki].my_key)))
      count++;
  if ((keysets != NULL) && (count > 0)) {
    *keysets = malloc_or_fail (sizeof (keyset *) * count, "invalid_keys");
    int index = 0;
    for (ki = 0; ki < num_key_infos; ki++)
      if ((strcmp (kip [ki].contact_name, contact) == 0) &&
          (allnet_rsa_prvkey_is_null (kip [ki].my_key)))
        (*keysets) [index++] = ki;
  }
  return count;
}

/* mirror image of mark_invalid */
int mark_valid (const char * contact, keyset k)
{
  init_from_file ("mark_valid");
  if (! valid_keyset (k))
    return 0;
  char * fname = strcat_malloc (kip [k].dir_name, "/my_key",
                                "invalidate_symmetric_key-1");
  char * old_fname = strcat_malloc (fname, "_invalidated",
                                    "invalidate_symmetric_key-2");
  int result = 0;
  if (rename (old_fname, fname) == 0) {
    /* read the key into the kip data structure */
    if (allnet_rsa_read_prvkey (fname, &(kip [k].my_key)))
      result = 1;
    else
      printf ("unable to read private key from %s\n", fname);
  } else {
    perror ("rename in mark_valid");
    printf ("unable to rename %s to %s\n", old_fname, fname);
  }
  free (old_fname);
  free (fname);
  return result;
}

/* returns the number of contacts with incomplete key exchanges,
 * defined as contacts that have no contact public key, or have
 * an exchange file, or both.
 * if the number is greater than 0 and contacts is not NULL, fills contacts
 * with the names of those contacts (must be free'd)
 * likewise for keys -- exactly one key is returned per contact 
 * likewise for status, which is the OR (|) of one or more constants below
#define KEYS_INCOMPLETE_NO_CONTACT_PUBKEY
#define KEYS_INCOMPLETE_HAS_EXCHANGE_FILE */
int incomplete_key_exchanges (char *** result_contacts, keyset ** result_keys,
                              int ** result_status)
{
  int result = 0;
  if (result_contacts != NULL)
    *result_contacts = NULL;
  if (result_keys != NULL)
    *result_keys = NULL;
  if (result_status != NULL)
    *result_status = NULL;
  char ** local_contacts = NULL;
  /* only individual contacts can have incomplete key exchanges */
  int nc = all_individual_contacts (&local_contacts);
  if ((nc <= 0) || (local_contacts == NULL))
    return 0;
  keyset * local_keys = malloc_or_fail (sizeof (keyset) * nc, "incomplete ks");
  int * local_status = malloc_or_fail (sizeof (int) * nc, "incomplete status");
  int ic;
  for (ic = 0; ic < nc; ic++) {
    keyset * keys = NULL;
    int nk = all_keys (local_contacts [ic], &keys);
    int ik;
    for (ik = 0; ik < nk; ik++) {
      keyset k = keys [ik];
      int status = 0;
      allnet_rsa_pubkey pubkey; /* test for incomplete key exchange */
      if (! get_contact_pubkey (k, &pubkey)) /* incomplete */
        status |= KEYS_INCOMPLETE_NO_CONTACT_PUBKEY;
      /* test for existence of the exchange file */
      char * dir = key_dir (k);
      if (dir != NULL) {
        char * fname = strcat_malloc (dir, "/exchange", "exchange file name");
        if (fname != NULL) {
          if (file_size (fname) >= 0)  /* file exists */
            status |= KEYS_INCOMPLETE_HAS_EXCHANGE_FILE;
          free (fname);
        }
        free (dir);
      }
      if (status) {   /* found an incomplete key exchange or exchange file */
        /* invariant: result <= ic, so it's safe to overwrite the first
         * result entries of local_contacts */
        local_contacts [result] = local_contacts [ic];
        local_keys [result] = keys [ik];
        local_status [result] = status;
        result++;
        /* break out of inner (keys) loop, continue outer (contacts) loop */
        break;
        /* i.e. ignore any other keys, do not add this contact again */
        /* (otherwise the invariant might not hold) */
      }
    }
    if (keys != NULL)
      free (keys);
  }
  if ((result_contacts != NULL) && (result > 0))
    *result_contacts = local_contacts;
  else
    free (local_contacts);
  if ((result_keys != NULL) && (result > 0))
    *result_keys = local_keys;
  else
    free (local_keys);
  if ((result_status != NULL) && (result > 0))
    *result_status = local_status;
  else
    free (local_status);
  return result;
}

/* manipulate the exchange file:
 * if both old_content and new_content are NULL, deletes the file if any
 * if old_content is not NULL, fills it in with the malloc'd contents of
 *   the file (must be free'd) if any, or NULL if the file does not exist
 * if new_content is not NULL, saves it as the new contents of the file,
 *   or if it is NULL, leaves the file unchanged.
 * except as described, always does what it can, without reporting errors */
void incomplete_exchange_file (const char * contact, keyset k,
                               char ** old_content,
                               const char * new_content)
{
  if (old_content != NULL)
    *old_content = NULL;
  char * dir = key_dir (k);
  if (dir != NULL) {
    char * fname = strcat_malloc (dir, "/exchange", "incomplete exchange file");
    if (fname != NULL) {
      if ((old_content == NULL) && (new_content == NULL)) { /* delete */
        unlink (fname);   /* ignore return value, only delete if it exists */
      } else {
        if (old_content != NULL) {   /* read the contents of the file */
          int bytes = read_file_malloc (fname, old_content, 0);
          if (bytes <= 0)
            *old_content = NULL;
        }
        if (new_content != NULL) {   /* create or replace file */
          write_file (fname, new_content, (int)strlen (new_content), 1);
        }
      }
      free (fname);
    }
    free (dir);
  }
}

/*************** operations on symmetric keys ********************/

/* returns the index of the kip that has the symmetric key for this contact,
 * if any.  If the contact exists but has no symmetric key, it returns
 * -1 - (the index of the contact).
 * If the contact is not found, returns num_key_infos */
static int find_symmetric_key (const char * contact)
{
  int ki = 0;
  int found = num_key_infos;
  for (ki = 0; ki < num_key_infos; ki++) {
    if ((kip [ki].contact_name != NULL) &&
        (strcmp (kip [ki].contact_name, contact) == 0)) {
      if (kip [ki].has_symmetric_key) {
        return ki;
      }
      found = -1 - ki;
    }
  }
  return found;
}

/* returns the symmetric key size if any, or 0 otherwise */
/* if there is a symmetric key && key != NULL && ksize >= key size,
 * copies the key value into key */
int has_symmetric_key (const char * contact, char * key, int ksize)
{
  init_from_file ("has_symmetric_key");
  int found = find_symmetric_key (contact);
  if ((found >= 0) && (found < num_key_infos)) {  /* found */
    if ((key != NULL) && (ksize >= SYMMETRIC_KEY_SIZE))
      memcpy (key, kip [found].symmetric_key, SYMMETRIC_KEY_SIZE);
    return SYMMETRIC_KEY_SIZE;
  }  /* else not found */
  return 0;
}

/* returns 1 if the contact is valid and there was no prior symmetric key
 * for this contact and the ksize is adequate for a symmetric key,
 * returns 0 otherwise */
int set_symmetric_key (const char * contact, char * key, int ksize)
{
  init_from_file ("set_symmetric_key");
  if ((ksize < SYMMETRIC_KEY_SIZE) || (key == NULL))
    return 0;
  int ki = find_symmetric_key (contact);
  if (ki == num_key_infos)  /* contact not found */
    return 0;
  /* else found contact, with or without symmetric key */
  if (ki < 0)  /* no symmetric key, but the code is the same */
    ki = -ki;
  memcpy (kip [ki].symmetric_key, key, SYMMETRIC_KEY_SIZE);
  kip [ki].has_symmetric_key = 1;
  char * fname = strcat_malloc (kip [ki].dir_name, "/symmetric_key",
                                "set_symmetric_key");
  int result = write_bytes_file (fname, key, SYMMETRIC_KEY_SIZE);
  free (fname);
  return result;
}

/* returns the index of the kip that has the state for this contact,
 * if any.  If the contact exists but has no state, it returns
 * -1 - (the index of the contact).
 * If the contact is not found, returns num_key_infos */
static int find_state (const char * contact)
{
  int ki = 0;
  int found = num_key_infos;
  for (ki = 0; ki < num_key_infos; ki++) {
    if ((kip [ki].contact_name != NULL) &&
        (strcmp (kip [ki].contact_name, contact) == 0)) {
      if (kip [ki].has_state) {
        return ki;
      }
      found = -1 - ki;
    }
  }
  return found;
}

/* for use with allnet_stream_encrypt and decrypt.  You MUST save the state
 * after successfully encrypting or decrypting
 *
 * returns 1 if the state is available, 0 otherwise.
 * if state is not null, copies the state if available
 *
 * to initialize the state correctly, always call allnet_stream_init with
 * the key given by has_symmetric_key */
int symmetric_key_state (const char * contact,
                         struct allnet_stream_encryption_state * state)
{
  init_from_file ("symmetric_key_state");
  if (state == NULL)
    return 0;
  int found = find_state (contact);
  if ((found >= 0) && (found < num_key_infos)) {  /* found */
    if (state != NULL)
      memcpy (state, &(kip [found].state),
              sizeof (struct allnet_stream_encryption_state));
    return 1;
  }  /* else not found */
  return 0;
}

static char * array_to_buf (const char * array, int abytes,
                            char * buf, int * bbytes)
{
  char * p = buf;
  int psize = *bbytes;
  int i;
  for (i = 0; ((i < abytes) && (psize > 0)); i++) {
    int printed = 0;
    if (i + 1 < abytes)  /* not the last */
      printed = snprintf (p, psize, "%02x:", (array [i]) & 0xff);
    else                 /* the last byte printed */
      printed = snprintf (p, psize, "%02x\n", (array [i]) & 0xff);
    p += printed;
    psize = minz (psize, printed);
  }
  *bbytes = psize;
  return p;
}

/* returns 1 if the state was saved, 0 otherwise. */
int save_key_state (const char * contact,
                    struct allnet_stream_encryption_state * state)
{
  init_from_file ("save_key_state");
  if (state == NULL)
    return 0;
  int ki = find_state (contact);
  if (ki == num_key_infos)  /* contact not found */
    return 0;
  /* else found contact, with or without state */
  if (ki < 0)  /* no state, but the code is the same */
    ki = -ki;
  memcpy (&(kip [ki].state), state,
          sizeof (struct allnet_stream_encryption_state));
  kip [ki].has_state = 1;
  char print_buffer [sizeof (struct allnet_stream_encryption_state) * 10];
  int psize = sizeof (print_buffer);
  char * next = array_to_buf (state->key, ALLNET_STREAM_KEY_SIZE,
                              print_buffer, &psize);
  next = array_to_buf (state->secret, ALLNET_STREAM_SECRET_SIZE, next, &psize);
  snprintf (next, psize, "%d %d %" PRIu64 " %d\n", state->counter_size,
            state->hash_size, state->counter, state->block_offset);
  char * fname = strcat_malloc (kip [ki].dir_name, "/send_state",
                                "save_key_state");
  int result = write_file (fname, print_buffer, (int)strlen (print_buffer), 1);
  free (fname);
  return result;

}

/* after invalidating, can set a new symmetric key, and then the old
 * one can no longer be revalidated.  Until then, revalidation is an option 
 * return 1 for success, 0 if the operation was not done for any reason */
int invalidate_symmetric_key (const char * contact)
{
  init_from_file ("invalidate_symmetric_key");
  int ki = find_symmetric_key (contact);
  if ((ki < 0) || (ki >= num_key_infos))  /* not found */
    return 0;
  char * fname = strcat_malloc (kip [ki].dir_name, "/symmetric_key",
                                "invalidate_symmetric_key-1");
  char * new_fname = strcat_malloc (fname, "_invalidated",
                                    "invalidate_symmetric_key-2");
  int result = 0;
  if (rename (fname, new_fname) == 0)
    result = 1;
  else {
    perror ("rename");
    printf ("unable to rename %s to %s\n", fname, new_fname);
  }
  free (fname);
  free (new_fname);
  /* delete from data structure */
  kip [ki].has_symmetric_key = 0;
  return result;
}

int revalidate_symmetric_key (const char * contact)
{
  init_from_file ("revalidate_symmetric_key");
  int ki = find_symmetric_key (contact);
  if (ki >= 0)   /* no contact, or contact already has a symmetric key */
    return 0;
  ki = -ki;   /* turn it into a valid index */
  char * fname = strcat_malloc (kip [ki].dir_name, "/symmetric_key",
                                "invalidate_symmetric_key-1");
  char * old_fname = strcat_malloc (fname, "_invalidated",
                                    "invalidate_symmetric_key-2");
  int result = 0;
  if (rename (old_fname, fname) == 0) {
    int n = read_bytes_file (fname, kip [ki].symmetric_key, SYMMETRIC_KEY_SIZE);
    if (n >= SYMMETRIC_KEY_SIZE) {
      kip [ki].has_symmetric_key = 1; /* mark in data structure */
      result = 1;
    } else {
      printf ("renamed %s to %s, but found %d < %d bytes\n", old_fname, fname,
              n, SYMMETRIC_KEY_SIZE);
    }
  } else {
    perror ("rename");
    printf ("unable to rename %s to %s\n", old_fname, fname);
  }
  free (old_fname);
  free (fname);
  return result;
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

static int count_keys (const char * path)
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

static void rsa_to_external_pubkey (allnet_rsa_pubkey rsa,
                                    char ** key, int * klen)
{
  /* the public key in external format */
  int size = allnet_rsa_pubkey_size (rsa) + 1;
  char * p = malloc_or_fail (size, "external public key");
  int res = allnet_pubkey_to_raw (rsa, p, size);
  if (res != size)
    printf ("allnet_pubkey_to_raw should give %d, gave %d\n", size - 1, res);
  p [0] = KEY_RSA4096_E65537;
  *key = p;
  *klen = size;
/* printf ("external, key set to %p, length %d\n", *key, *klen); */
}

#if 0
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
#endif /* 0 */

static void init_key_info (char * config_dir, char * file,
                           struct bc_key_info * key, char * phrase,
                           int expect_private)
{
  memset (key, 0, sizeof (struct bc_key_info));  /* in case of error return */

  char * mapped;
  int mlen = map_string (phrase, &mapped);
  sha512_bytes (mapped, mlen, (char *) (key->address), ADDRESS_SIZE);
  free (mapped);

  key->identifier = strcpy_malloc (file, "keys.c init_key_info");

  char * fname = strcat3_malloc (config_dir, "/", file, "init_key_info fname");
  int success = 0;
  char * key_type = "public";
  if (expect_private) {
    key_type = "private";
    success = allnet_rsa_read_prvkey (fname, &(key->prv_key));
    if (success)
      key->pub_key = allnet_rsa_private_to_public (key->prv_key);
  } else {
    success = allnet_rsa_read_pubkey (fname, &(key->pub_key));
  }
  free (fname);
  if (! success) {
    printf ("unable to read %s RSA file %s/%s\n", key_type, config_dir, file);
    printf ("init_key_info (%s, %s, %s, %d\n", config_dir, file, phrase, expect_private);
    return;
  }
  key->has_private = expect_private;
}

static void free_bc_keys (struct bc_key_info * keys, int num_keys)
{
  if ((keys != NULL) && (num_keys > 0)) {
    int i;
    for (i = 0; i < num_keys; i++) {
      if (keys [i].identifier != NULL)
        free (keys [i].identifier);
    }
    free (keys);
  }
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
    *num_keys = 0;    /* initialized */
    char * config_dir;
    if (config_file_name (dirname, "", &config_dir) < 0) {
      printf ("unable to open key directory ~/.allnet/%s\n", dirname);
    } else {
      char * slash = strrchr (config_dir, '/');
      if (slash != NULL)
        *slash = '\0';
      *num_keys = count_keys (config_dir);
      *keys = malloc_or_fail (sizeof (struct key_info) * (*num_keys),
                              "broadcast keys");
      init_bc_from_files (config_dir, *keys, *num_keys, expect_private);
      free (config_dir);
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
    int value = (int)strtol (p, &end, 10);
    if ((matching_bits != NULL) && (end != p))
      *matching_bits = value;
  }
}

/* returns the number of characters parsed */
static int parse_position (char * p, int * result)
{
  int length = (int)strlen (p);
  char * end = strchr (p, '.');
  if (end != NULL) {
    end++;   /* point after the '.' */
    length = (int)(end - p);
  } else {
    end = strchr (p, ',');
    if (end != NULL)
      length = (int)(end - p);
  }
  int value = aaddr_decode_value (p, length);
  if ((value >= 0) && (result != NULL))
    *result = value;
  return length;
}

/* returns 1 for a successful parse, 0 otherwise */
int parse_ahra (const char * ahra,
                char ** phrase, int ** positions, int * num_positions,
                char ** language, int * matching_bits, char ** reason)
{
  if (matching_bits != NULL)
    *matching_bits = BITSTRING_BITS;
  if (ahra == NULL) {
    if (reason != NULL) *reason = "AHRA is NULL";
    return 0;
  }
  char * middle = strchr (ahra, '@');
  if (middle == NULL) {
    if (reason != NULL) *reason = "AHRA lacks '@'";
    return 0;
  }
  if (phrase != NULL) {
    int len = (int)(middle - ahra) + 1;
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
  if (*p != ',')  /* no language or bits specified */
    return 1;
  p++;
  char * next_comma = strchr (p, ',');
  if (next_comma == NULL) {    /* no bits or no language specified */
    assign_lang_bits (p, (int)strlen (p), language, matching_bits);
  } else {                     /* both bits and language are specified */
    assign_lang_bits (p, (int)(next_comma - p), language, matching_bits);
    p = next_comma + 1;
    assign_lang_bits (p, (int)strlen (p), language, matching_bits);
  }
  return 1;
}

static char * make_address (allnet_rsa_pubkey key, int key_bits,
                            const char * phrase, const char * lang,
                            int bitstring_bits, int min_bitstrings)
{
  int rsa_size = allnet_rsa_pubkey_size (key);

  char * mapped;
  int msize = map_string (phrase, &mapped);
  char hash [SHA512_SIZE];
  sha512 (mapped, msize, hash);

  if (msize > rsa_size) {
    printf ("keys.c: too many bytes %d to encrypt, max %d\n", msize, rsa_size);
    exit (1);
  }

  /* get the bits of the ciphertext */
  char * encrypted = malloc_or_fail (rsa_size, "keys.c: encrypted phrase");

/* in general, no padding is not secure for RSA encryptions.  However,
 * in this application we want the remote system to be able to perform the
 * same encryption and give the same result, so no padding is appropriate */
  char * padded = malloc_or_fail (rsa_size, "make_address padded");
  memset (padded, 0, rsa_size);
  memcpy (padded + (rsa_size - msize), mapped, msize);
  free (mapped);
  int esize = allnet_rsa_encrypt (key, padded, rsa_size, encrypted, rsa_size,
                                  0 /* no padding */  );
  free (padded);
  if (esize != rsa_size) {
    printf ("make_address RSA encryption failed\n");
    exit (1);
  }

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
      if (bitstring_matches ((unsigned char *) encrypted, j,
                             (unsigned char *) hash, hashpos, bitstring_bits)) {
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

  int rsize = (int)strlen (phrase) + 50 /* @.lang.bits\0 + margin */ +
              max_pair_len (lang) * nmatches;
  char * result = malloc_or_fail (rsize, "make_address result");
  char * p = result;
  const char * next;
/* we use map_char to decide whether to copy a char, replace it with _, or
 * consider it the end of the phrase */
  int map = map_char (phrase, &next);
/* convert the blanks and other unprintables in the phrase to underscores */
  while ((map != MAPCHAR_EOS) && (map != MAPCHAR_UNKNOWN_CHAR)) {
    int clen = (int)(next - phrase);    /* length of a character */
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
  int off = (int)(p - result);
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
  allnet_rsa_prvkey key = allnet_rsa_generate_key (key_bits, NULL, 0);
  allnet_rsa_pubkey pubkey = allnet_rsa_private_to_public (key);

  char * aaddr = make_address (pubkey, key_bits, phrase, lang, bitstring_bits,
                               min_bitstrings);
  if (aaddr != NULL) {
    char * fname;
    if (config_file_name ("own_bc_keys", aaddr, &fname) < 0) {
      printf ("unable to save key to ~/.allnet/own_bc_keys/%s\n", aaddr);
    } else {
      if (! allnet_rsa_write_prvkey (fname, key))
        printf ("unable to write new key to file %s\n", fname);
      free (fname);
    }
  }

  allnet_rsa_free_prvkey (key);
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
  char * comma = strchr (ahra, ',');
  if (comma == NULL)
    return;
  char * second = strchr (comma + 1, ',');
  if (isalpha (comma [1])) {
    if (second != NULL) {
      int lsize = (int)strlen (second + 1);
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
  char * comma = strchr (ahra, ',');
  if (comma == NULL)
    return;
  char * second = strchr (comma + 1, ',');
  if (isdigit (comma [1])) {
    if (second != NULL) {
      int lsize = (int)strlen (second + 1);
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
  char * comma = strchr (ahra, ',');
  if (comma != NULL)
    *comma = '\0';
}

/* useful, e.g. for requesting a key.  Returns the public key size. */
/* pubkey and privkey should be free'd when done */
int get_temporary_key (char ** pubkey, allnet_rsa_prvkey * prvkey)
{
  *prvkey = allnet_rsa_generate_key (4096, NULL, 0);
  if (allnet_rsa_prvkey_is_null (*prvkey))
    return 0;

  allnet_rsa_pubkey pub = allnet_rsa_private_to_public (*prvkey);
  int result = 0;
  rsa_to_external_pubkey (pub, pubkey, &result);
  /* printf ("get_temporary_key returns %d, %d\n", result, *privksize); */
  return result;
}

/* verifies that a key obtained by a key exchange matches the address */
/* the default lang and bits are used if they are not part of the address */
/* if save_if_correct != 0, also saves it to a file using the given address */
unsigned int verify_bc_key (const char * ahra, const char * key, int key_bytes,
                            const char * default_lang, int bitstring_bits,
                            int save_if_correct)
{
  if (((key != NULL) && (key_bytes > 0)) &&
      ((key_bytes != 513) || (*key != KEY_RSA4096_E65537))) {
    printf ("verify_bc_key: bad key, size %d, code %d\n", key_bytes, *key);
    return 0;
  }
  allnet_rsa_pubkey rsa;
  if (! allnet_pubkey_from_raw (&rsa, key, key_bytes)) {
    /* probably should be silent, but good for debugging */
    printf ("unable to convert received bytes to public key\n");
    return 0;
  }
  int rsa_size = allnet_rsa_pubkey_size (rsa);

  char * phrase;
  int * positions;
  int num_positions;
  char * reason;
  if (! parse_ahra (ahra, &phrase, &positions, &num_positions,
                    NULL, &bitstring_bits, &reason)) {
    printf ("unable to parse allnet human-readable address '%s', %s\n",
            ahra, reason);
    allnet_rsa_free_pubkey (rsa);
    return 0;
  }

  char * mapped;
  int msize = map_string (phrase, &mapped);
  free (phrase);
  char hash [SHA512_SIZE];
  sha512 (mapped, msize, hash);

  /* get the bits of the ciphertext */
  if (msize > rsa_size)
    msize = rsa_size;
  char * encrypted = malloc_or_fail (rsa_size, "keys.c: encrypted phrase");
/* in general, padding is required for RSA encryptions.  However,
 * in this application we want the remote system to be able to perform the
 * same encryption and give the same result, so no padding is appropriate */
  char * padded = malloc_or_fail (rsa_size, "verify_bc_key padded");
  memset (padded, 0, rsa_size);
  memcpy (padded + (rsa_size - msize), mapped, msize);
  free (mapped);
  int esize = allnet_rsa_encrypt (rsa, padded, rsa_size, encrypted, rsa_size,
                                  0 /* no padding */  );
  free (padded);
  if (esize != rsa_size) {
    printf ("verify_bc_key RSA encryption failed: %d %d\n", esize, rsa_size);
    allnet_rsa_free_pubkey (rsa);
    return 0;
  }

  int i;
  for (i = 0; i < num_positions; i++) {
    int hashpos = SHA512_BITS - ((i + 1) * bitstring_bits);
    if (! bitstring_matches ((unsigned char *) encrypted, positions [i],
                             (unsigned char *) hash, hashpos,
                             bitstring_bits)) {

      printf ("%s %d: no %d-bit match at positions %d/%d\n", ahra, i,
              bitstring_bits, positions [i], hashpos);
      print_bitstring ((unsigned char *) encrypted, positions [i],
                       bitstring_bits, 1);
      print_bitstring ((unsigned char *) hash, hashpos, bitstring_bits, 1);

      free (encrypted);
      free (positions);
      return 0;
    }
  }
  char * fname;
  if (save_if_correct) {
    if (config_file_name ("other_bc_keys", ahra, &fname) < 0) {
      printf ("unable to save key to ~/.allnet/other_bc_keys/%s\n", ahra);
    } else {
      if (! allnet_rsa_write_pubkey (fname, rsa)) {
        printf ("unable to write broadcast key to file %s\n", fname);
      } else {
        free_bc_keys (other_bc_keys, num_other_bc_keys);
        other_bc_keys = NULL;
        num_other_bc_keys = -1;  /* so init actually reads the keys */
        init_bc_key_set ("other_bc_keys",
                         &other_bc_keys, &num_other_bc_keys, 0);
      }
      free (fname);
    }
  }
  allnet_rsa_free_pubkey (rsa);
  free (positions);
  free (encrypted);
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

static struct bc_key_info * find_bc_key (const char * address,
                                         struct bc_key_info * keys, int nkeys)
{
  char * outer_index = strchr (address, '@');
  if (outer_index == NULL)
    return NULL;
  size_t alen = outer_index - address;
  int i;
  for (i = 0; i < nkeys; i++) {
    char * loop_index = strchr (keys [i].identifier, '@');
    if (loop_index == NULL)
      continue;  /* skip the rest of the loop; */
    size_t idlen = loop_index - keys [i].identifier;
    if ((alen != idlen) ||
        (strncmp (address, keys [i].identifier, alen) != 0)) {
      /* not the same ID */
#ifdef DEBUG_PRINT
      printf ("alen %zd, idlen %zd, for '%s' and '%s'\n", alen, idlen,
              address, keys [i].identifier);
#endif /* DEBUG_PRINT */
      continue;  /* skip the rest of the loop; */
    }
    char * key;
    int klen;
    rsa_to_external_pubkey (keys [i].pub_key, &key, &klen);
    int num_bits;
    int success = 0;
    if (parse_ahra (address, NULL, NULL, NULL, NULL, &num_bits, NULL))
      success = verify_bc_key (address, key, klen, NULL, num_bits, 0);
    free (key);
#ifdef DEBUG_PRINT
    if (success)
      printf ("address %s matches key %s\n", address, keys [i].identifier);
#endif /* DEBUG_PRINT */
    if (success)
      return keys + i;
  }
  return NULL;
}

/* return the specified key (statically allocated, do not modify), or NULL */
struct bc_key_info * get_own_bc_key (const char * ahra)
{
  init_bc_keys ();
  return find_bc_key (ahra, own_bc_keys, num_own_bc_keys);
}

struct bc_key_info * get_other_bc_key (const char * ahra)
{
  init_bc_keys ();
  return find_bc_key (ahra, other_bc_keys, num_other_bc_keys);
}

/* record that we are requesting a broadcast key */
void requesting_bc_key (const char * ahra)
{
  char * fname = NULL;
  if (config_file_name ("requested_bc_keys", ahra, &fname) < 0) {
    printf ("unable to save key request to ~/.allnet/requested_bc_keys/%s\n",
            ahra);
  } else {
    char content [10];
    write_file (fname, content, 0, 1);
    free (fname);
  }
}

/* return the number of requested broadcast keys.  For each, if the
 * variables is not NULL, return the AHRA -- dynamically allocated, 
 * must be free'd (with a single free operation) */
int requested_bc_keys (char *** ahras)
{
  if (ahras != NULL)
    *ahras = NULL;
  char * config_dir;
  if (config_file_name ("requested_bc_keys", "", &config_dir) < 0) {
    /* this is OK -- no requests
       printf ("unable to open key directory ~/.allnet/requested_bc_keys\n"); */
    return 0;
  }
  DIR * dir = opendir (config_dir);
  if (dir == NULL) {
    perror ("requested_bc_keys opendir");
    printf ("unable to open %s\n", config_dir);
    return 0;
  }
  int count = 0;
  size_t size = 0;
  struct dirent * ent = readdir (dir);
  while (ent != NULL) {
    if (parse_ahra (ent->d_name, NULL, NULL, NULL, NULL, NULL, NULL)) {
      /* printf ("counting %s\n", ent->d_name); */
      count++;
      size += (sizeof (char *)) + strlen (ent->d_name) + 1;
    }
    ent = readdir (dir);
  }
  closedir (dir);
  if ((count == 0) || (ahras == NULL)) {  /* done */
    free (config_dir);
    return count;
  }
  dir = opendir (config_dir);  /* repeat the search */
  if (dir == NULL) {
    perror ("requested_bc_keys opendir2");
    printf ("unable to open %s (2)\n", config_dir);
    return 0;
  }
  char * ahra_storage = malloc_or_fail (size, "requested_bc_keys");
  *ahras = (char **) ahra_storage;
  char * string_storage = ahra_storage + sizeof (char *) * count;
  ent = readdir (dir);
  int new_count = 0;
  while ((ent != NULL) && (new_count < count)) {
    if (parse_ahra (ent->d_name, NULL, NULL, NULL, NULL, NULL, NULL)) {
      strcpy (string_storage, ent->d_name);
      (*ahras) [new_count] = string_storage;
      string_storage += strlen ((*ahras) [new_count]) + 1;
      new_count++;
    }
    ent = readdir (dir);
  }
  closedir (dir);
  return new_count;
}

/* record that the broadcast key request is no longer active */
void finished_bc_key_request (const char * ahra)
{
  char * fname = NULL;
  if (config_file_name ("requested_bc_keys", ahra, &fname) < 0) {
    printf ("unable to save key request to ~/.allnet/requested_bc_keys/%s\n",
            ahra);
  } else {
    unlink (fname);
    free (fname);
  }
}

#ifdef TEST_KEYS

int main ()
{
  init_from_file ("test_keys main");
  char addr [ADDRESS_SIZE];
  addr [0] = 0x01;
  addr [1] = 0x02;
  addr [2] = 0xAF;
  printf ("create_contact (edo) returns %d\n",
          create_contact ("edo", 8192, 1, NULL, 0, NULL, 0, addr, 18));
  printf ("create_contact (foo) returns %d\n",
          create_contact ("foo", 8192, 1, NULL, 0, NULL, 0, addr, 18));
  const keyset * ks = NULL;
  int nk = all_keys ("edo", &ks);
  char * key;
  int ksize = get_my_privkey (ks [0], &key);
  printf ("private key (edo/%d/%d) is '%s'/%d\n", nk, ks [0], key, ksize);
  if (nk > 0)
    free (ks);
}
#endif /* TEST_KEYS */
