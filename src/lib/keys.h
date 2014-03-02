/* keys.h: manage keys on disk */

/* a key set consists of the contact name, my private and public keys,
 * the contact's public key, and possibly a local address and/or
 * a remote address */
/* each contact name is associated with 0 or more key sets */

/* broadcast keys are not associated with any specific contact. */

#ifndef ALLNET_KEYS_H
#define ALLNET_KEYS_H

#include "../packet.h"		/* ADDRESS_SIZE */

typedef int keyset;  /* opaque type, do not access directly */

/*************** operations on contacts ********************/

/* returns 0 or more */
extern int num_contacts ();

/* returns the number of contacts, and has contacts point to a statically
 * allocated array of pointers to statically allocated null-terminated
 * contact names (do not modify in any way). */
extern int all_contacts (char *** contacts);

/* returns the number of directories for this contact, and
 * sets dirs to point to a statically allocated array of
 * pointers to directory names (do not modify in any way). */
/* if the contact is not found, returns 0 and sets dirs to NULL */
extern int contact_dirs (char * contact, char * * * dirs);

/* returns the keyset if successful, -1 if the contact already existed */
/* creates a new private/public key pair, and if not NULL, also 
 * the contact public key, local and remote addresses */
/* if feedback is nonzero, gives feedback while creating the key */
extern keyset create_contact (char * contact, int keybits, int feedback,
                              char * contact_key, int contact_ksize,
                              char * local, int loc_nbits,
                              char * remote, int rem_nbits);

/*************** operations on keysets and keys ********************/

/* returns -1 if the contact does not exist, and 0 or more otherwise */
extern int num_key_sets (char * contact);

/* returns the number of keysets, and has keysets point to a statically
 * allocated array of pointers to statically allocated keysets
 * (do not modify in any way). */
/* returns -1 if the contact does not exist */
extern int all_keys (char * contact, keyset ** keysets);

/* returns 1 if the keyset is valid and there was no prior public key
 * for this contact, returns 0 otherwise */
extern int set_contact_pubkey (keyset k, char * contact_key, int contact_ksize);
/* return 1 and set the address if the keyset is valid, 0 otherwise */
extern int set_contact_local_addr (keyset k, int nbits, char * address);
extern int set_contact_remote_addr (keyset k, int nbits, char * address);

/* if successful returns the key length and sets *key to point to
 * statically allocated storage for the key (do not modify in any way)
 * if not successful, returns 0 */
extern unsigned int get_contact_pubkey (keyset k, char ** key);
extern unsigned int get_my_pubkey (keyset k, char ** key);
extern unsigned int get_my_privkey (keyset k, char ** key);
/* returns the number of bits in the address, 0 if none */
/* address must have length at least ADDRESS_SIZE */
extern unsigned int get_local (keyset k, char * address);
extern unsigned int get_remote (keyset k, char * address);

/* a keyset may be marked as invalid.  The keys are not deleted, but can no
 * longer be accessed unless marked as valid again */
extern unsigned int mark_invalid (keyset k);
extern int invalid_keys (char * contact, keyset ** keysets);
extern unsigned int mark_valid (keyset k);

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
   from the pre-list, and "pair" from the post-list).

   The address may be written in many different ways, e.g. with '-' instead
   of '_', with '' instead of "" or no quotes at all (as long as the phrase
   is correctly identified)
 */

#define BITSTRING_BITS	16
#define BITSTRING_BYTES	2

/* returns a malloc'd string with the address.  The key is saved and may
 * be retrieved using the complete address.  May be called multiple times
 * to generate different keys. */
extern char * generate_key (int key_bits, char * phrase, char * lang,
                            int bitstring_bits, int min_bitstrings,
                            int give_feedback);

/* these give the "normal" version of the broadcast address, without the
 * language, bits, or both.  The existing string is modified in place */
extern char * delete_lang (char * key);
extern char * delete_bits (char * key);
extern char * delete_lang_bits (char * key);

/* useful, e.g. for requesting a key.  Returns the public key size. */
/* pubkey and privkey should be free'd when done */
extern int get_temporary_key (char ** pubkey, char ** privkey, int * privksize);

/* verifies that a key obtained by a key exchange matches the address */
/* the default lang and bits are used if they are not part of the address */
/* if save_is_correct != 0, also saves it to a file using the given address */
extern unsigned int verify_bc_key (char * address, char * key, int key_bits,
                                   char * default_lang, int default_bits,
                                   int save_if_correct);

struct bc_key_info {
  char address [ADDRESS_SIZE];      /* the address associated with this key */
  char * identifier;                /* the sender associated with this key */
  int pub_klen;
  char * pub_key;                   /* in a format suitable for sending */
  /* the remainder of the information is only valid for my keys.
   * for keys that belong to others, priv_klen will be zero */
  int priv_klen;
  char * priv_key;                  /* in a format suitable for decrypting */
};

/* if successful returns the number of keys and sets *keys to point to
 * statically allocated storage for the keys (do not modify in any way)
 * if not successful, returns 0 */
extern unsigned int get_own_keys (struct bc_key_info ** key);

/* if successful returns the number of keys and sets *keys to point to
 * statically allocated storage for the keys (do not modify in any way)
 * if not successful, returns 0 */
extern unsigned int get_other_keys (struct bc_key_info ** key);

/* return the specified key (statically allocated, do not modify), or NULL */
extern struct bc_key_info * get_own_key (char * address);
extern struct bc_key_info * get_other_key (char * address);

/* returns 1 for a successful parse, 0 otherwise */
extern int parse_ahra (char * ahra,
                       char ** phrase, int ** positions, int * num_positions,
                       char ** language, int * matching_bits, char ** reason);

#endif /* ALLNET_KEYS_H */
