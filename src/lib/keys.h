/* keys.h: manage keys on disk */

/* a key set consists of the contact name, my private and public keys,
 * the contact's public key, and possibly a local address and/or
 * a remote address */
/* each contact name is associated with 0 or more key sets */

/* broadcast keys are not associated with any specific contact. */

#ifndef ALLNET_KEYS_H
#define ALLNET_KEYS_H

#include "packet.h"		/* ADDRESS_SIZE */
#include "crypt_sel.h"		/* allnet_rsa_prvkey/pubkey */
#include "stream.h"		/* struct allnet_stream_encryption_state */

typedef int keyset;  /* opaque type, do not access directly */

/*************** operations on contacts ********************/

/* returns 0 or more */
extern int num_contacts ();

/* returns the number of contacts, and (if not NULL) has contacts point
 * to a dynamically allocated array of pointers to null-terminated
 * contact names (to free, call free (*contacts)). */
extern int all_contacts (char *** contacts);
/* same, but only individual contacts, not groups */
extern int all_individual_contacts (char *** contacts);

/* returns the keyset if successful, -1 if the contact already existed
 * creates a new private/public key pair, and if not NULL, also 
 * the contact public key, local and remote addresses
 * if a spare key of the requested size already exists, uses the spare key
 * if feedback is nonzero, gives feedback while creating the key
 * If the contact was already created, but does not have the peer's
 * info, returns as if it were a newly created contact after replacing
 * the contents of local (as long as loc_nbits matches the original nbits)
 * if there is no contact public key, marks the contact not visible */
extern keyset create_contact (const char * contact, int keybits, int feedback,
                              char * contact_key, int contact_ksize,
                              unsigned char * local, int loc_nbits,
                              unsigned char * remote, int rem_nbits);

/* change the name associated with a contact.  Fails and returns 0
 * if the old name does not exist, or if the new one does, and of
 * course for other reasons too.
 * returns 1 for success */
extern int rename_contact (const char * old, const char * new);

/* a contact may be marked as not visible.  Nothing is deleted,
 * but the contact can no longer be accessed unless made visible again.
 * invisible_contacts returns the number of hidden contacts, or 0.
 * if not 0 and contacts is not NULL, the contacts array is malloc'd,
 * should be free'd. */
extern int invisible_contacts (char *** contacts);
/* make_in/visible return 1 for success, 0 if not successful */
extern int make_invisible (const char * contact);
extern int make_visible (const char * contact);
/* returns 1 if the contact exists and is visible */
extern int is_visible (const char * contact);
/* returns 1 if the contact exists and is not visible */
extern int is_invisible (const char * contact);

/* this is the actual deletion. return 1 for success, 0 otherwise */
extern int delete_contact (const char * contact);

/*************** file state storage for contacts ******************/

/* return -1 if the file does not exist, the size otherwise.
 * if content is not NULL, malloc's enough space to hold the 
 * content (with null termination), and returns it */
extern int contact_file_get (const char * contact,
                             const char * fname, char ** content);
/* write the content to the file, returning 0 in case of error, 1 otherwise */
extern int contact_file_write (const char * contact, const char * fname,
                               const char * content, int clength);
/* return 1 if the file was deleted, 0 otherwise */
extern int contact_file_delete (const char * contact, const char * fname);

/*************** operations on groups of contacts ******************/

/* a contact may actually be a group of contacts. */
/* the members of a group may themselves be groups. */
/* deleting a group does not delete the members of the group. */
extern int is_group (const char * contact);   

/* group creation succeeds iff there is no prior contact or group
 * with the same name */
/* returns 1 for success, 0 for failure */
extern int create_group (const char * group);

/* returns the number of members of the group, and the names listed
 * in a dynamically allocated array (if not NULL, must be free'd) */
extern int group_membership (const char * group, char *** members);   

/* same, but (a) recursively examines all groups and subgroups, and
 * (b) includes one each of all non-group members of all (sub)groups */
extern int group_contacts (const char * group, char *** members);   

/* these return 0 for failure, 1 for success.  Reason for failures
 * include non-existence of the group or contact, or the group being
 * an individual contact rather than a group */
extern int add_to_group (const char * group, const char * contact);
extern int remove_from_group (const char * group, const char * contact);

/* return the count of groups of which this contact or group is a member
 * 0 if not a member of any group, -1 for errors
 * if groups is not NULL, also allocates and returns the list of groups */
extern int member_of_groups (const char * contact, char *** groups);
/* same, but also lists the groups of this contact's groups, and so on
 * recursively */
extern int member_of_groups_recursive (const char * contact, char *** groups);


/*************** operations on keysets and keys ********************/

/* returns -1 if the contact does not exist, and 0 or more otherwise */
extern int num_keysets (const char * contact);

/* returns the number of keysets.
 * malloc's a new keysets (must be free'd) and fills it with the keysets. */
/* returns -1 if the contact does not exist */
extern int all_keys (const char * contact, keyset ** keysets);

/* returns a pointer to a dynamically allocated (must be free'd).
 * name for the directory corresponding to this key. */
/* in case of error, returns NULL */
extern char * key_dir (keyset key);

/* returns 1 if the keyset is valid and there was no prior public key
 * for this contact, returns 0 otherwise */
extern int set_contact_pubkey (keyset k, char * contact_key, int contact_ksize);
/* return 1 and set the address if the keyset is valid, 0 otherwise */
extern int set_contact_local_addr (keyset k, int nbits,
                                   unsigned char * address);
extern int set_contact_remote_addr (keyset k, int nbits,
                                    unsigned char * address);

/* if successful returns the key length and sets *key to point to
 * statically allocated storage for the key (do not modify in any way)
 * if not successful, returns 0 */
extern unsigned int get_contact_pubkey (keyset k, allnet_rsa_pubkey * key);
extern unsigned int get_my_pubkey      (keyset k, allnet_rsa_pubkey * key);
extern unsigned int get_my_privkey     (keyset k, allnet_rsa_prvkey * key);
/* returns the number of bits in the address, 0 if none */
/* address must have length at least ADDRESS_SIZE */
extern unsigned int get_local (keyset k, unsigned char * address);
extern unsigned int get_remote (keyset k, unsigned char * address);
/* returnes a malloc'd copy of the contact name, or NULL for errors */
extern char * get_contact_name (keyset k);

/* a keyset may be marked as invalid.  The keys are not deleted, but can no
 * longer be accessed unless marked as valid again
 * invalid_keys returns the number of invalid keys, or 0.
 * mark_* return 1 for success, 0 if not successful */
extern int invalid_keys (const char * contact, keyset ** keysets);
extern int mark_invalid (const char * contact, keyset k);
extern int mark_valid (const char * contact, keyset k);

/* returns the number of contacts with incomplete key exchanges,
 * defined as contacts that have no contact public key, or have
 * an exchange file, or both.
 * if the number is greater than 0 and contacts is not NULL, fills contacts
 * with the names of those contacts (must be free'd)
 * likewise for keys -- exactly one key is returned per contact 
 * likewise for status, which is the OR (|) of one or more constants below */
#define KEYS_INCOMPLETE_NO_CONTACT_PUBKEY	1
#define KEYS_INCOMPLETE_HAS_EXCHANGE_FILE	2
extern int incomplete_key_exchanges (char *** contacts, keyset ** keys,
                                     int ** status);

/* manipulate the exchange file:
 * if both old_content and new_content are NULL, deletes the file if any
 * if old_content is not NULL, fills it in with the malloc'd contents of
 *   the file (must be free'd) if any, or NULL if the file does not exist
 * if new_content is not NULL, saves it as the new contents of the file,
 *   or if it is NULL, leaves the file unchanged.
 * except as described, always does what it can, without reporting errors */
extern void incomplete_exchange_file (const char * contact, keyset k,
                                      char ** old_content,
                                      const char * new_content);

/* create a spare key of the given size, returning the number of spare keys.
 * if random is not NULL and rsize >= keybits / 8, uses the bytes from
 * random to randomize the generated key
 * if keybits < 0, returns the number of spare keys without generating
 * any new key (and ignoring random/rsize)
 * returns 0 in case of error
 * should normally only be called after calling
 *    setpriority (PRIO_PROCESS, 0, n), with n >= 15 */
extern int create_spare_key (int keybits, char * random, int rsize);

/*************** operations on symmetric keys ********************/

/* returns the symmetric key size if any, or 0 otherwise */
/* if there is a symmetric key && key != NULL && ksize >= key size,
 * copies the key value into key */
/* to use allnet_stream_encrypt, use key state instead. */
extern int has_symmetric_key (const char * contact, char * key, int ksize);

/* returns 1 if the contact is valid and there was no prior symmetric key
 * for this contact and the ksize is adequate for a symmetric key,
 * returns 0 otherwise */
extern int set_symmetric_key (const char * contact, char * key, int ksize);

/* for use with allnet_stream_encrypt and decrypt.  You MUST save the state
 * after successfully encrypting or decrypting
 *
 * returns 1 if the state is available, 0 otherwise.
 * if state is not null, copies the state if available
 *
 * to initialize the state correctly, always call allnet_stream_init with
 * the key given by has_symmetric_key */
extern int symmetric_key_state (const char * contact,
                                struct allnet_stream_encryption_state * state);
/* returns 1 if the state was saved, 0 otherwise. */
extern int save_key_state (const char * contact,
                           struct allnet_stream_encryption_state * state);

/* after invalidating, can set a new symmetric key, and then the old
 * one can no longer be revalidated.  Until then, revalidation is an option
 * return 1 for success, 0 if the operation was not done for any reason */
extern int invalidate_symmetric_key (const char * contact);
extern int revalidate_symmetric_key (const char * contact);

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
extern void delete_lang (char * key);
extern void delete_bits (char * key);
extern void delete_lang_bits (char * key);

/* useful, e.g. for requesting a key.  Returns the public key size. */
/* pubkey and privkey should be free'd when done */
extern int get_temporary_key (char ** pubkey, allnet_rsa_prvkey * prvkey);

/* verifies that a key obtained by a key exchange matches the ahra */
/* the default lang and bits are used if they are not part of the address */
/* if save_is_correct != 0, also saves it to a file using the given address */
extern unsigned int verify_bc_key (const char * ahra,
                                   const char * key, int key_bits,
                                   const char * default_lang, int default_bits,
                                   int save_if_correct);

struct bc_key_info {
     /* the AllNet address associated with this key */
  unsigned char address [ADDRESS_SIZE];
  char * identifier;                /* the sender associated with this key */
  allnet_rsa_pubkey pub_key;        /* in a format suitable for encrypting */
  /* the remainder of the information is only valid for my keys.
   * for keys that belong to others, has_priv will be zero */
  int has_private;
  allnet_rsa_prvkey prv_key;        /* in a format suitable for decrypting */
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
extern struct bc_key_info * get_own_bc_key (const char * ahra);
extern struct bc_key_info * get_other_bc_key (const char * ahra);

/* returns 1 for a successful parse, 0 otherwise */
extern int parse_ahra (const char * ahra,
                       char ** phrase, int ** positions, int * num_positions,
                       char ** language, int * matching_bits, char ** reason);

/* record that we are requesting a broadcast key */
/* to do: in the future, may associate addresses and nbits with such keys */
extern void requesting_bc_key (const char * ahra);
/* return the number of requested broadcast keys.  For each, if the
 * variables is not NULL, return the AHRA -- dynamically allocated,
 * must be free'd (with a single free operation) */
extern int requested_bc_keys (char *** ahras);
/* record that the broadcast key request is no longer active */
extern void finished_bc_key_request (const char * ahra);

#endif /* ALLNET_KEYS_H */
