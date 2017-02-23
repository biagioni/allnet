/* stream.h: interface to cryptography for data streams */

#ifndef STREAM_ENCRYPTION_H
#define STREAM_ENCRYPTION_H

#include <inttypes.h>    /* uint64_t */
#include "crypt_sel.h"   /* AES256_SIZE */

#define ALLNET_STREAM_KEY_SIZE		AES256_SIZE  /* 32 bytes, 256 bits */
#define ALLNET_STREAM_SECRET_SIZE	64	/* 64 bytes, 512 bits */

struct allnet_stream_encryption_state {
  char key [ALLNET_STREAM_KEY_SIZE];
  char secret [ALLNET_STREAM_SECRET_SIZE];
  int counter_size;
  int hash_size;
  uint64_t counter;
  int block_offset;   /* how many bytes we are into the block */
};

/* allnet_stream_init allocates and initializes state for encrypting and
 * decrypting.  It can do so from a given key and secret, or it can
 * initialize the the key and secret for the caller.
 *
 * one state should be used in one direction only, i.e. only for encrypting
 * or only for decrypting.
 *
 * key must have size ALLNET_STREAM_KEY_SIZE, and must be initialized by
 * the caller prior to calling allnet_stream_init (if init_key is 0) or
 * will be initialized by allnet_stream_init (if init_key is nonzero).
 * the secret is used for authentication, giving the hash, must be of size
 * ALLNET_STREAM_SECRET_SIZE, and is initialized by the caller
 * or by allnet_stream_init as for the key, depending on init_secret.
 * counter size and hash size are the number of bytes of counter and hmac
 * to be added to each outgoing packet, and checked on each incoming packet */
extern void allnet_stream_init (struct allnet_stream_encryption_state * state,
                                char * key, int init_key,
                                char * secret, int init_secret,
                                int counter_size, int hash_size);

/* allnet_stream_encrypt_buffer encrypts a buffer given an encryption state
 * state must have been initialized by allnet_stream_init
 * rsize must be >= tsize + counter_size + hash_size specified for state
 * returns the encrypted size for success, 0 for failure */
extern int
  allnet_stream_encrypt_buffer (struct allnet_stream_encryption_state * state,
                                const char * text, int tsize,
                                char * result, int rsize);

/* allnet_stream_encrypt_buffer decrypts a buffer given an encryption state
 * the buffer must normally have been created by a corresponding call to
 * allnet_stream_encrypt_buffer, usually on a remote system.
 *
 * state must have been initialized by allnet_stream_init
 * tsize must be >= csize - counter_size - hash_size specified for state
 * returns 1 for successful authentication and decryption, 0 otherwise
 * note: an attacker has a 256^-hash_size chance of sending a packet that
 * decrypt_buffer will consider authentic.  In such cases, decrypt_buffer
 * will return 1 but, in most cases, the decrypted text will be meaningless */
extern int
  allnet_stream_decrypt_buffer (struct allnet_stream_encryption_state * state,
                                const char * packet, int psize,
                                char * text, int tsize);

#endif /* STREAM_ENCRYPTION_H */
