/* allnet_queue.h: used to transmit messages between allnet blocks */
/* each queue of messages has limited size.  If a message
 * is added to a queue that is already full, the lowest priority
 * message in the queue is discarded to make room for the new message */

#ifndef ALLNET_QUEUE_H
#define ALLNET_QUEUE_H

struct allnet_queue;  /* defined internally, opaque type */

/* this is a global.  It is not used by allnet_queue.c, but may be used
 * by code that uses allnet_queue.c.  It is declared in allnet_queue.c
 * If used, it must be initialized by code that is not in allnet_queue.c */
/* all queue numbers (equivalent to file descriptors) are negative indices
 * into this array.  So, queue number x (x < 0) is at index -x - 1 */
extern struct allnet_queue * * allnet_queues;

/* queue may be malloc'd, should be free'd with queue_recycle */
extern struct allnet_queue * allnet_queue_new (const char * debug_name,
                                               unsigned int max_packets,
                                               unsigned int max_bytes);
extern void allnet_queue_recycle (struct allnet_queue *);

/* succeeds and returns 1 as long as the queue is valid and plen <= max_bytes.
 * returns 0 otherwise */
extern int allnet_enqueue (struct allnet_queue * queue,
                           const unsigned char * packet, unsigned int plen,
                           unsigned int priority);

/* the packet must point to plen bytes of available space.
 * when called, *nqueue should be the number of queues that queues points to
 *              on successful return, this call sets *nqueue to the number of
 *              the queue (0-based) from which the packet is taken
 * when called, *plen should be the number of bytes that packet points to
 *              on successful return, this call sets *plen to the length of
 *              the packet
 * on successful return, this call sets *priority to the priority
 * if timeout_ms is zero, this call returns immediately
 * if timeout_ms is (unsigned int) -1, this call blocks until a packet is ready
 * returns 1 if it returns a packet
 * returns 0 if all the queues are empty and the timeout expired
 * returns -2 and fills in *plen and *nqueue if there is a packet available,
 *            but it is larger than *plen
 * returns -1 for any other errors */
extern int allnet_dequeue (struct allnet_queue ** queues, unsigned int * nqueue,
                           unsigned char * packet, unsigned int * plen,
                           unsigned int * priority, unsigned int timeout_ms);

/* returns 1 if a packet was discarded, 0 otherwise */
extern int allnet_queue_discard_first (struct allnet_queue * queue);

/* returns the number of packets in the queue, or -1 if the queue
 * has been recycled */
extern int allnet_queue_size (struct allnet_queue * queue);

/* returns the debug name and possibly other information */
extern const char * allnet_queue_info (struct allnet_queue * queue);

#endif /* ALLNET_QUEUE_H */
