/* dcache.h: cache information, deleting the Least Recently Used when needed */
/* caches arbitrary user data.  Each entry has data given by a pointer. */

/* not to be confused with acache, which does the allnet packet caching */

#ifndef DCACHE_H
#define DCACHE_H

/* When getting rid of the data, the release function is called.  If
 * the data was malloc'd, the release function might be "free". */
/* the release function should not call any other cache function
 * (if it does, it will be detected, and the call will return immediately) */
typedef void (* release_function) (void * data);

/* initialize a cache and return it (or NULL in case of errors).
 * max_entries identifies the number of entries in the cache.
 * the release function is used when data is removed to make room for
 * newer data.  data is new when first inserted, or whenever
 * record_usage is called */
extern void * cache_init  (int max_entries, release_function f,
                           const char * caller_name);

extern void cache_close (void * cache);

/* function to determine whether to return a given entry */
/* should return nonzero for a matching entry (higher values for a
 * better match), and 0 for no match */
/* arg1 is whatever was passed in to the call to cache_get_matching */
typedef int (* match_function) (void * arg1, void * data);
/* the maximum value that should be returned by a match function */
#define MAX_MATCH	0x7fffffff
/* return one matching element.  Subsequent calls with the same
 * parameters will return successive matching elements. */
/* if there is no match, returns NULL */
extern void * cache_get_match (void * cache, match_function f, void * arg1);
/* return all matching elements, sorted in order from highest to lowest match.
 * The result is the number of matches. which are returned in array.
 * The caller should free array when done.
 * if there is no match, returns 0 and array is set to NULL */
extern int cache_all_matches (void * cache, match_function f, void * arg1,
                              void *** array);

/* function to call on every element */
typedef void (* map_function) (void * arg1, void * data);
extern void cache_map (void * cache, map_function f, void * arg1);

/* calls to record that this entry was active at this time */
extern void cache_record_usage (void * cache, void * data);

/* call to add a new entry to the cache */
/* may close the least recently active entry */
extern void cache_add (void * cache, void * data);

/* calls to explicitly remove a cache entry */
/* assuming the element is found, calls the corresponding
 * release function */
/* returns 1 if successful, 0 if unable to remove */
extern int cache_remove (void * cache, void * data);

/* randomly select up to max elements from the cache and place them into
 * the array, which must have room for at least max void* pointers */
/* returns the number filled in, which may be less than max, 0 for errors */
extern int cache_random (void * cache, int max, void ** array);

#endif /* DCACHE_H */
