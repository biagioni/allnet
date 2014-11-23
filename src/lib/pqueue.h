/* pqueue.h: priority queue for broadcasting over the local area network (not thread safe) */

#ifndef ALLNET_PQUEUE_H
#define ALLNET_PQUEUE_H

extern void queue_init (int max_bytes, int max_backoff_threshold);

/* return the highest priority of any item in the queue */
extern int queue_max_priority ();

/* return how many bytes are in the queue */
extern int queue_total_bytes ();

extern void queue_add (const char * queue_element, int size, int priority);

/* to visit all the elements of the queue, call queue_iter_start(),
 * then repeatedly call queue_iter_next until it returns 0
 * after any successful call to queue_iter_next, may call queue_iter_remove
 */
extern void queue_iter_start ();

/* Fills in *queue_element with a reference to the next object, *next_size
 * with its length, *priority with its priority, *backoff with the current
 * backoff value and returns 1.
 *
 * if the iteration has reached the end, or for any other error, returns 0. */
extern int queue_iter_next (char * * queue_element, int * next_size,
                            int * priority, int * backoff);

/* Increment backoff counter for current element and return 1.
 * The message is removed when the threshold is crossed and 0 is returned
 */
extern int queue_iter_inc_backoff ();

/* call at most once after a successful call to queue_iter_next */
extern void queue_iter_remove ();

#endif /* ALLNET_PQUEUE_H */
