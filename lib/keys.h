/* keys.h: manage keys on disk */

/* a key set consists of the contact name, my private and public keys,
 * the contact's public key, and possibly a source address and/or
 * a destination address */
/* each contact name is associated with 0 or more key sets */

#ifndef ALLNET_KEYS_H
#define ALLNET_KEYS_H

typedef int keyset;  /* opaque type, do not access directly */

/*************** operations on contacts ********************/

/* returns 0 or more */
extern int num_contacts ();

/* returns the number of contacts, and has contacts point to a statically
 * allocated array of pointers to statically allocated null-terminated
 * contact names (do not modify in any way). */
extern int all_contacts (char *** contacts);

/* returns 1 if successful, 0 if the contact already existed */
/* creates a new private/public key pair, and if not NULL, also
 * the contact public key, source and destination addresses */
/* if feedback is nonzero, gives feedback while creating the key */
extern keyset create_contact (char * contact, int keybits, int feedback,
                              char * contact_key, int contact_ksize,
                              char * source, int src_nbits,
                              char * destination, int dst_nbits);

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
extern int set_contact_source_addr (keyset k, int nbits, char * address);
extern int set_contact_dest_addr (keyset k, int nbits, char * address);

/* if successful returns the key length and sets *key to point to
 * statically allocated storage for the key (do not modify in any way)
 * if not successful, returns 0 */
extern unsigned int get_contact_pubkey (keyset k, char ** key);
extern unsigned int get_my_pubkey (keyset k, char ** key);
extern unsigned int get_my_privkey (keyset k, char ** key);
/* returns the number of bits in the address, 0 if none */
/* address must have length at least ADDRESS_SIZE */
extern unsigned int get_source (keyset k, char * address);
extern unsigned int get_destination (keyset k, char * address);

/* a keyset may be marked as invalid.  The keys are not deleted, but can no
 * longer be accessed unless the marked as valid again */
extern unsigned int mark_invalid (keyset k);
extern int invalid_keys (char * contact, keyset ** keysets);
extern unsigned int mark_valid (keyset k);

#endif /* ALLNET_KEYS_H */
