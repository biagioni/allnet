/* dcache.c: cache information, deleting the Least Recently Used when needed */
/* caches arbitrary user data.  Each entry has data given by a pointer. */

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

#include "util.h"
#include "dcache.h"

/* When getting rid of the data, the release function is called.  If
 * the data was malloc'd, the release function might be "free". */
/* the release function should not call any other cache function
 * (if it does, it will be detected, and the call will return immediately) */
/*
typedef void (* release_function) (void * data);
*/

struct dcache_entry {
  void * data;
  unsigned char spare;   /* used by cache_all_matches and cache_random */
};

struct dcache {
  pthread_mutex_t mutex;
  int max_entries;
  int num_entries;
  release_function f;
  int last_match;
  int busy;   /* 0, except when calling f */
  char * name;
/* the entries are kept in order of last usage, most recently used first */
  struct dcache_entry entries [0];
};

/* initialize a cache and return it (or NULL in case of errors).
 * max_entries identifies the number of entries in the cache.
 * the release function is used when data is removed to make room for
 * newer data.  data is new when first inserted, or whenever
 * record_usage is called */
void * cache_init  (int max_entries, release_function f,
                    const char * caller_name)
{
  int size = sizeof (struct dcache)
           + max_entries * sizeof (struct dcache_entry);
  struct dcache * result = malloc_or_fail (size, "cache_init");
/*
  printf ("allocated %p, %d bytes = %zd + %d * %zd\n", result,
          size, sizeof (struct dcache), max_entries,
          sizeof (struct dcache_entry));
*/
  result->f = f;
  result->max_entries = max_entries;
  result->num_entries = 0;
  result->last_match = 0;
  result->busy = 0;
  result->name = strcpy_malloc (caller_name, "dcache cache_init name");
  pthread_mutex_init (&(result->mutex), NULL);
  int i;
  for (i = 0; i < max_entries; i++)
    result->entries [i].data = NULL;
  return result;
}

/* called with lock held */
static void release_entry (struct dcache * cache, int index)
{
  cache->busy = 1;
  cache->f (cache->entries [index].data);   /* release the data */
  cache->busy = 0;
  cache->entries [index].data = NULL;
#ifdef DEBUG_PRINT
  printf ("released entry %d of %d (max %d)\n",
          index, cache->num_entries, cache->max_entries);
#endif /* DEBUG_PRINT */
}

void cache_close (void * cp)
{
  struct dcache * cache = (struct dcache *) cp;
  int i;
  pthread_mutex_lock (&(cache->mutex));
  for (i = 0; i < cache->num_entries; i++)
    if (cache->entries [i].data != NULL)
      release_entry (cache, i);
  /* do not unlock!!!   Prevents further use of the cache */
  printf ("%s: closing cache, lock still held, will never use again\n",
          cache->name);
  /* pthread_mutex_unlock (&(cache->mutex)); */
}

/* function to determine whether to return a given entry */
/* should return nonzero for a matching entry, and 0 otherwise */
/* arg1 is whatever was passed in to the call to cache_get_match */
/*
typedef int (* match_function) (void * arg1, void * data);
 */
/* return one matching element.  Subsequent calls with the same
 * parameters will return successive matching elements. */
/* if there is no match, returns NULL */
void * cache_get_match (void * cp, match_function f, void * arg1)
{
  struct dcache * cache = (struct dcache *) cp;
  if (cache->busy) return NULL;
  pthread_mutex_lock (&(cache->mutex));
  int count;
  for (count = 0; count < cache->num_entries; count++) {
    int index = (cache->last_match + count) % cache->num_entries; 
    struct dcache_entry * cep = cache->entries + index;
    if (f (arg1, cep->data)) {
      cache->last_match = index + 1;  /* % cache->num_entries, but no matter */ 
      void * result = cep->data;
      pthread_mutex_unlock (&(cache->mutex));
      return result;
    }
  }
  pthread_mutex_unlock (&(cache->mutex));
  return NULL;
}

/* return all matching elements, sorted in order from highest to lowest match.
 * The result is the number of matches. which are returned in array.
 * The caller should free array when done.
 * if there is no match, returns 0 and array is set to NULL */
int cache_all_matches (void * cp, match_function f, void * arg, void *** array)
{
  *array = NULL;
  struct dcache * cache = (struct dcache *) cp;
  if (cache->busy)
    return 0;
  pthread_mutex_lock (&(cache->mutex));
  int size = cache->num_entries * sizeof (int);
  int * matches = malloc_or_fail (size, "cache_all_matches");
  int i, j;
  for (i = 0; i < cache->num_entries; i++) {
    matches [i] = f (arg, cache->entries [i].data);
    if (matches [i] > MAX_MATCH)
      matches [i] = MAX_MATCH;
  }
  int count = 0;
  for (i = 0; i < cache->num_entries; i++)
    if (matches [i] != 0)
      count++;
  if (count == 0) {
    pthread_mutex_unlock (&(cache->mutex));
    free (matches);
    return count;
  }
  void * * result = malloc_or_fail (count * sizeof (void *), "cache_all");
  int min = 0;
  int found = 0;
  while (found < count) {
    int new_min = MAX_MATCH;
    /* find the next value in the matches array */
    for (i = 0; i < cache->num_entries; i++)
      if ((matches [i] > min) && (matches [i] < new_min))
        new_min = matches [i];
    min = new_min;
/* printf ("in dcache loop, min %d found %d count %d\n", min, found, count); */
    /* add all the entries with that value into the result array */
    for (i = 0; i < cache->num_entries; i++) {
      if (matches [i] == min) {
/* printf ("in dcache if, result [%d] set to cache->entries [%d] (%p)\n",
count - found - 1, i, cache->entries [i].data); */
        /* this puts them in reverse order:
              result [count - found - 1] = cache->entries [i].data;
         * not sure why, but I was doing that for a while.
         */
        result [found] = cache->entries [i].data;
        found++;
        if (found > count) {   /* found should never exceed count */
          printf ("coding error in dcache.c, %d/%d, min %d, %d entries\n",
                  found, count, min, cache->num_entries);
          for (j = 0; j < cache->num_entries; j++)
            printf ("%d ", matches [j]);
          printf ("\nerror, exiting\n");
          exit (1);
        }
      }
    }
  }
  pthread_mutex_unlock (&(cache->mutex));
  free (matches);
  *array = result;
  return count;
}

/* function to call on every element */
/*
typedef void (* map_function) (void * arg1, void * data);
*/
void cache_map (void * cp, map_function f, void * arg1)
{
  struct dcache * cache = (struct dcache *) cp;
  if (cache->busy) return;
  pthread_mutex_lock (&(cache->mutex));
  int index;
  for (index = 0; index < cache->num_entries; index++)
    f (arg1, cache->entries [index].data);
  pthread_mutex_unlock (&(cache->mutex));
}

/* returns the index if a match is found, or -1 if not found */
/* called with lock held */
static int find_data (struct dcache * cache, void * data)
{
  if (data == NULL)
    return -1;
  int i;
  for (i = 0; i < cache->num_entries; i++)
    if (cache->entries [i].data == data)
      return i;
  return -1;
}

/* called with lock held */
static void record_usage (struct dcache * cache, int index)
{
  /* move this record to the front of the entries list, keeping the rest
   * in order */
  struct dcache_entry ce = cache->entries [index];
  int i;
  for (i = index; i > 0; i--)
    cache->entries [i] = cache->entries [i - 1];
  cache->entries [0] = ce;
}

void cache_record_usage (void * cp, void * data)
{
  struct dcache * cache = (struct dcache *) cp;
  if (cache->busy) return;
  pthread_mutex_lock (&(cache->mutex));
  int index = find_data (cache, data);
  if (index == -1)
    printf ("unable to record usage for data %p, not found\n", data);
  else
    record_usage (cache, index);
  pthread_mutex_unlock (&(cache->mutex));
}

/* call to add a new entry to the cache */
/* may close the least recently active entry */
void cache_add (void * cp, void * data)
{
/* printf ("cache_add, cache %p, data %p\n", cp, data); */
  struct dcache * cache = (struct dcache *) cp;
  if (cache->busy) return;
  pthread_mutex_lock (&(cache->mutex));

  /* if it is already in the cache, just record the usage */
  int found = find_data (cache, data);
  if (found != -1) {
    record_usage (cache, found);
    pthread_mutex_unlock (&(cache->mutex));
    return;
  }

  /* not in the cache */
  int index = cache->num_entries;
/* printf ("not in cache, index %d, max_entries %d\n", index,
          cache->max_entries);
  */
  if (index == cache->max_entries) {
    index--;
#ifdef DEBUG_PRINT
    printf ("calling release_entry (%d)\n", index);
#endif /* DEBUG_PRINT */
    release_entry (cache, index);   /* release it as needed */
  } else {    /* new entry, no need to release */
    cache->num_entries = cache->num_entries + 1;
  }
  cache->entries [index].data = data;
  record_usage (cache, index);    /* move it to the front */
/* printf ("now in cache, num_entries %d, max_entries %d\n",
          cache->num_entries, cache->max_entries); */
  pthread_mutex_unlock (&(cache->mutex));
}

/* called with lock held */
static int actual_remove (struct dcache * cache, int index)
{
  if ((cache->num_entries <= 0) || (index < 0) ||
      (index >= cache->num_entries)) {
    printf ("cache unable to remove %d from %d\n", index, cache->num_entries);
    return 0;
  }
#ifdef DEBUG_PRINT
  printf ("remove calling release_entry (%d)\n", index);
#endif /* DEBUG_PRINT */
  release_entry (cache, index);
  cache->num_entries--;
  int i;
  for (i = index; i < cache->num_entries; i++)
    cache->entries [i] = cache->entries [i + 1];
  return 1;
}

/* calls to explicitly remove a cache entry */
/* assuming the element is found, calls the corresponding
 * release function */
/* returns 1 if successful, 0 if unable to remove */
int cache_remove (void * cp, void * data)
{
  struct dcache * cache = (struct dcache *) cp;
  if (cache->busy) return 0;
  pthread_mutex_lock (&(cache->mutex));
  int index = find_data (cache, data);
  int result = 0;
  if (index == -1)
    printf ("%s: unable to remove data %p, not found\n", cache->name, data);
  else
    result = actual_remove (cache, index);
  pthread_mutex_unlock (&(cache->mutex));
  return result;
}

/* randomly select up to max elements from the cache and place them into
 * the array, which must have room for at least max void* pointers */
/* returns the number filled in, which may be less than max, 0 for errors */
int cache_random (void * cp, int max, void ** array)
{
  if (max <= 0) return 0;
  struct dcache * cache = (struct dcache *) cp;
  if (cache->busy) return 0;
  pthread_mutex_lock (&(cache->mutex));
  int i;
  if (cache->num_entries > 0) {
/*  printf ("cache_random (%d, %d)\n", max, cache->num_entries); */
    int * permutation = random_permute (cache->num_entries);
    if (max > cache->num_entries)
      max = cache->num_entries;
    for (i = 0; i < max; i++)
      array [i] = cache->entries [permutation [i]].data;
    free (permutation);
  } else {
    max = 0;
  }
  pthread_mutex_unlock (&(cache->mutex));

  return max;
}

