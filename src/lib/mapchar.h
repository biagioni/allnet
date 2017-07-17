/* mapchar.h: encode characters to 4-bit strings in ways that make it more
 *            difficult to make mistakes.
 * also encode numeric positions as memorable strings
 */

#ifndef ALLNET_MAPCHAR_H
#define ALLNET_MAPCHAR_H

#define		MAPCHAR_IGNORE_CHAR	16
#define		MAPCHAR_UNKNOWN_CHAR	17
#define		MAPCHAR_EOS		18
/* convert the first character pointed to by char into an int, and return it */
/* the return value is in 0..15 for valid characters, MAPCHAR_IGNORE_CHAR
 * for recognized characters that we ignore, and MAPCHAR_UKNOWN_CHAR for
 * any unrecognized character.  MAPCHAR_EOS is returned at the end of the
 * string. */
/* the second argument is set to point to the next character,
 * except in the case of MAPCHAR_EOS, when it is set to the first argument */
extern int map_char (const char * string, const char ** end);

/* convert each character in the string, and return a newly allocated
 * char array with the mapped characters.  The number of bytes in the newly
 * allocated char array is returned.
 * If the last byte only has one character, it is padded with 4 zero bits */
extern int map_string (const char * string, char ** result);

/* functions to encode numeric positions as memorable strings */ 

#define MAX_AADDR_CODE		16383

/* allocates and return a string representing the value.  If the value
 * is greater than or equal to 2^14 (16384), returns NULL */
/* if the language is unavailable, returns an available language,
 * usually english */
extern char * aaddr_encode_value (int value, const char * lang); 

/* return a value encoded by the string, or -1 in case of errors. */
extern int aaddr_decode_value (char * string, int slen); 

/* returns the maximum length of a pair in the given language */
extern int max_pair_len (const char * lang);

#endif /* ALLNET_MAPCHAR_H */
