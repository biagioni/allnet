/* pqueue.h: priority queue for broadcasting over the local area network (not thread safe) */

#ifndef ALLNET_PQUEUE_H
#define ALLNET_PQUEUE_H

#include "priority.h"   /* ALLNET_PRIORITY_MAX */

/**
 * Backoff value for lowest possible priority element.
 * Used for dropping element after # queue_iter_inc_backoff () * calls
 */
#define ALLNET_PQUEUE_MIN_BACKOFF 2
/**
 * Backoff value for highest possible priority element.
 * Used for dropping element after # queue_iter_inc_backoff () * calls
 */
#define ALLNET_PQUEUE_MAX_BACKOFF 18

/** Get backoff threshold based on AllNet priority. */
#define ALLNET_PQUEUE_BACKOFF_THRESHOLD(p) ((int) ( \
          ALLNET_PQUEUE_MIN_BACKOFF + \
          ((long)(p) \
           * (ALLNET_PQUEUE_MAX_BACKOFF - ALLNET_PQUEUE_MIN_BACKOFF) \
           / ALLNET_PRIORITY_MAX)))

extern void queue_init (int max_bytes);

/* return the highest priority of any item in the queue */
extern int queue_max_priority (void);

/* return how many bytes are in the queue */
extern int queue_total_bytes (void);

/**
 * Add new element to priority queue
 * If needed, items with lower priority will be removed to make room for the new
 * element. The queue remains unchanged if not enough room can be found.
 * @param value Element to add. The element is copied into the queue.
 * @param size Size of element to add.
 * @param priority Priority of new element.
 * @return 1 on success, 0 on failure (not enough space)
 */
extern int queue_add (const char * queue_element, int size, int priority);

/* to visit all the elements of the queue, call queue_iter_start(),
 * then repeatedly call queue_iter_next until it returns 0
 * after any successful call to queue_iter_next, may call queue_iter_remove
 */
extern void queue_iter_start (void);

/* Fills in *queue_element with a reference to the next object, *next_size
 * with its length, *priority with its priority, *backoff with the current
 * backoff value and returns 1.
 *
 * if the iteration has reached the end, or for any other error, returns 0. */
extern int queue_iter_next (char * * queue_element, int * next_size,
                            int * priority, int * backoff);

/**
 * Increment backoff counter for current element. The message is removed when
 * the threshold is crossed.
 * Must only be called after a successful call to queue_iter_next ().
 * @return 1 if counter has been incremented, 0 if element has been removed.
 */
extern int queue_iter_inc_backoff (void);

/**
 * Remove current element from queue and free internal resources.
 * Must be called at most once after a successful call to queue_iter_next ().
 */
extern void queue_iter_remove (void);

#endif /* ALLNET_PQUEUE_H */
