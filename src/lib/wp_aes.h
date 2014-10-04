/* wp_aes.h: header file for AES encryption */

/* this library is named for W. Wesley Peterson, who wrote the code this
 * library is loosely based on before he passed away in 2009 */

#ifndef WP_AES_H 
#define WP_AES_H 

#include <stdint.h>

/* AES keys can have 128, 192, or 256 bits */
#define AES_KEY_128_BYTES	16
#define AES_KEY_192_BYTES	24
#define AES_KEY_256_BYTES	32

#define WP_AES_BLOCK_SIZE	16

/* for AES in counter mode, only encryption is used
 * in, out may be the same or different buffer, both should
 * have WP_AES_BLOCK_SIZE bytes
 * ksize must be 16, 24, or 32 */
extern void wp_aes_encrypt_block (int ksize, const char * key,
                                  const char * in, char * out);

#endif /* WP_AES_H */
