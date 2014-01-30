/* pqueue.h: priority queue for broadcasting over the local area network */

#ifndef ALLNET_PQUEUE_H
#define ALLNET_PQUEUE_H

extern void queue_init (int max_bytes);

/* return the highest priority of any item in the queue */
extern int queue_max_priority ();

/* return how many bytes are in the queue */
extern int queue_total_bytes ();

extern void queue_add (char * queue_element, int size, int priority);

/* to visit all the elements of the queue, call queue_iter_start(),
 * then repeatedly call queue_iter_next until it returns 0
 * after any successful call to queue_iter_next, may call queue_iter_remove
 */
extern void queue_iter_start ();

/* Fills in *queue_element with a reference to the next object, *next_size
 * with its length, and *priority with its priority, and returns 1.
 *
 * if the iteration has reached the end, or for any other error, returns 0. */
extern int queue_iter_next (char * * queue_element, int * next_size,
                            int * priority);

/* call at most once after a successful call to queue_iter_next */
extern void queue_iter_remove ();

#endif /* ALLNET_PQUEUE_H */
