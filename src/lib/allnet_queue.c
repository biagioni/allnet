/* queue.c: used to transmit messages between allnet blocks */
/* each queue of messages has limited size.  If a message
 * is added to a queue that is already full, the lowest priority
 * message in the queue is discarded to make room for the new message */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>

#include "allnet_queue.h"

/* global, but not used in this code */
struct allnet_queue * * allnet_queues = NULL;

struct queue_entry {
  unsigned int start_offset;  /* allnet_queue_buf + start_offset */
  unsigned int length;
  unsigned int priority;
};

struct allnet_queue {
  int valid;
  char * debug_info;
  pthread_mutex_t mutex;
  unsigned int count;      /* number of filled queue entries */
  unsigned int first;      /* number of first filled queue entry, if any */
  unsigned int max_packets;
  unsigned int max_bytes;
  struct queue_entry packets [1];  /* actually, max_packets entries */
  /* max_packets queue_entries followed by max_bytes bytes */
  /* address of the bytes buffer is available from allnet_queue_buf */
};

#define allnet_queue_buf(q)	((unsigned char *)(q) +            \
                                 sizeof(struct allnet_queue) +     \
                                 (((q)->max_packets - 1) *         \
                                  sizeof (struct queue_entry)))

/* queue may be malloc'd, should be free'd with queue_recycle */
struct allnet_queue * allnet_queue_new (const char * debug_name,
                                        unsigned int max_packets,
                                        unsigned int max_bytes)
{
  if (max_packets == 0)
    printf ("allnet_queue_new %s warning: max_packets is 0\n", debug_name);
  if (max_bytes == 0)
    printf ("allnet_queue_new %s warning: max_bytes is 0\n", debug_name);
  size_t size = strlen (debug_name) + 1 + sizeof (struct allnet_queue) +
                max_packets * sizeof (struct queue_entry) + max_bytes;
  struct allnet_queue * result = malloc (size);
  if (result == NULL) {
    printf ("%s: unable to allocate queue, size %ld, %d packets, %d bytes\n",
            debug_name, (long)size, max_packets, max_bytes);
    return NULL;
  }
  result->valid = 0;
  pthread_mutex_init (&(result->mutex), NULL);
  result->debug_info = ((char *)(result)) + size - (strlen (debug_name) + 1);
  strcpy (result->debug_info, debug_name);
  result->count = 0;
  result->first = 0;
  result->max_packets = max_packets;
  result->max_bytes = max_bytes;
  result->valid = 1;
  return result;
}

void allnet_queue_recycle (struct allnet_queue * queue)
{
  if (! queue->valid) {
    printf ("allnet_queue_new %s warning: double free\n", queue->debug_info);
    return;
  }
printf ("freeing %s: %d, %d, %d, %d %d\n", queue->debug_info,
        queue->valid, queue->count, queue->first,
        queue->max_packets, queue->max_bytes);
  queue->valid = 0;
  pthread_mutex_destroy (&(queue->mutex));
  free (queue);
}

static unsigned int used_space (struct allnet_queue * queue)
{
  unsigned int i;
  unsigned int result = 0;
  int index = queue->first;
  for (i = 0; i < queue->count; i++) {
    result += queue->packets [index].length;
    index = (index + 1) % queue->max_packets;
  }
  return result;
}

static struct queue_entry * find_entry_and_space (struct allnet_queue * queue,
                                                  unsigned int length)
{
  if (queue->count == 0) {
    queue->first = 0;
    queue->packets [0].length = length;
    queue->packets [0].start_offset = 0;
    queue->count = 1;
    return queue->packets;  /* return the first entry */
  }
  /* find the index of the last valid packet, use it to compute start */
  int last = (queue->first + queue->count - 1) % queue->max_packets;
  int start = (queue->packets [last].start_offset +
               queue->packets [last].length) % queue->max_bytes;
  int result;   /* index of new packet. Initialize entry before we return */
  if (queue->count < queue->max_packets) {
    result = (last + 1) % queue->max_packets;    /* index for new packet */
    queue->count = queue->count + 1;       /* count including new packet */
  } else {   /* discard the first packet */
    result = queue->first;
    queue->first = (queue->first + 1) % queue->max_packets;
  }
  queue->packets [result].length = 0;     /* don't count as used_space */
  while ((used_space (queue) + length > queue->max_bytes) &&
         (queue->count > 0)) { 
    queue->packets [queue->first].length = 0;   /* discard one more packet */
    queue->first = (queue->first + 1) % queue->max_packets;
    queue->count = queue->count - 1;       /* count including new packet */
  }
  if ((used_space (queue) + length > queue->max_bytes)) { /* error */
    printf ("error: queue count %d, total %d bytes, unable to handle %d/%d\n",
            queue->count, used_space (queue), length, queue->max_bytes);
    queue->count = 0;   /* remove all packets from the queue */
    return find_entry_and_space (queue, length);
  }
  queue->packets [result].start_offset = start;
  queue->packets [result].length = length;
  return queue->packets + result;
}

/* succeeds and returns 1 as long as the queue is valid and plen <= max_bytes.
 * returns 0 otherwise */
int allnet_enqueue (struct allnet_queue * queue,
                    const unsigned char * packet, unsigned int plen,
                    unsigned int priority)
{
  int x = 0;
  if ((! queue->valid) || (plen >= queue->max_bytes))
    printf ("queue->valid %d, plen %d, queue->max_bytes %d\n",
            queue->valid, plen, queue->max_bytes);
  x = x * x;
  if ((! queue->valid) || (plen >= queue->max_bytes))
    x = 2 / x;  /* crash, and hopefully dump core */
  if ((! queue->valid) || (plen >= queue->max_bytes))
    return 0;
  pthread_mutex_lock (&(queue->mutex));
  if (queue->valid) {
    struct queue_entry * free = find_entry_and_space (queue, plen);
    unsigned char * storage = allnet_queue_buf (queue);
    unsigned char * start = storage + free->start_offset;
    if (free->start_offset + plen <= queue->max_bytes) {
      memcpy (start, packet, plen);
    } else {   /* copy to the start of the storage */
      int initial = queue->max_bytes - free->start_offset;
      memcpy (start, packet, initial);
      memcpy (storage, packet + initial, plen - initial);
    }
    free->priority = priority;
/* printf ("added %d-byte message, queue has %d messages\n", plen, queue->count); */
    pthread_mutex_unlock (&(queue->mutex));
    return 1;
  }  /* else invalid queue, no need to unlock */
  printf ("error %s: invalid queue in allnet_enqueue\n", queue->debug_info);
  return 0;
}

static void sleep_ms (unsigned long ms)
{
  if (ms > 0) {
    struct timespec time;
    time.tv_sec = ms / 1000;
    time.tv_nsec = (ms % 1000) * 1000 * 1000;
    nanosleep (&time, NULL);
  }
}

/* returns the index of a queue that has a packet, while holding the
 * lock for that queue.
 * if someone else is holding the lock for a queue, may incorrectly
 * report that the queue has no packets 
 * if no queue has a packet, returns -1 (and no lock is held) */
static int queue_has (struct allnet_queue ** queues, unsigned int n)
{
  int restart = 1;
  int loop_count = 0;
  int start = random () % n;
  while ((restart) && (loop_count++ < 3)) {
    restart = 0;
    unsigned int counter;
    for (counter = 0; counter < n; counter++) {
      int i = (((int)counter) + start) % n;
      if ((queues [i]->valid) && (queues [i]->count > 0)) {
        if (pthread_mutex_trylock (&(queues [i]->mutex)) == 0) {
          /* we have the lock */
          if ((queues [i]->valid) && (queues [i]->count > 0))
             /* count is still nonzero, we found one */
            return i;   /* returning with lock held */
          /* count became zero while trying the lock, release the lock */
          pthread_mutex_unlock (&(queues [i]->mutex));
        } else { /* mutex is locked by someone else, allow searching again */
          restart = 1;
        }
      }
    }
  }
  return -1;
}

/* returns 1 and fills in *plen if it returns a packet
 * returns -2 and fills in *plen if the first packet is larger than *plen
 * returns -1 for any other errors (e.g. if the queue is empty) */
static int dequeue_unlock (struct allnet_queue * queue, unsigned char * packet,
                           unsigned int * plen, unsigned int * priority)
{
  if (queue->count == 0) {
    pthread_mutex_unlock (&(queue->mutex));
    return -1;
  }
  struct queue_entry * e = queue->packets + queue->first;
  int buffer_length = *plen;
  int packet_length = e->length;
  *plen = packet_length;
  if (buffer_length < packet_length) {
    pthread_mutex_unlock (&(queue->mutex));
    return -2;   /* we set *plen, so record the size */
  }
  int copy_length = packet_length;
  unsigned char * storage = allnet_queue_buf (queue);
  unsigned char * start_ptr = storage + e->start_offset;
  if (e->start_offset + copy_length > queue->max_bytes)
    copy_length = queue->max_bytes - e->start_offset;
  memcpy (packet, start_ptr, copy_length);
  if (copy_length < packet_length)    /* data wraps around in storage */
    memcpy (packet + copy_length, storage, packet_length - copy_length);
  *priority = e->priority;
    
  queue->first = (queue->first + 1) % queue->max_packets;
  queue->count = queue->count - 1;
  pthread_mutex_unlock (&(queue->mutex));
  return 1;
}

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
int allnet_dequeue (struct allnet_queue ** queues, unsigned int * nqueue,
                    unsigned char * packet, unsigned int * plen,
                    unsigned int * priority, unsigned int timeout_ms)
{
  unsigned int n = *nqueue;
  if (n == 0) {
    if (timeout_ms == (unsigned int) -1) {
      printf ("error: blocking forever\n");
      while (1)
        sleep_ms (1000);
    }
    sleep_ms (timeout_ms);
    return 0;
  }
  /* simple implementation: loop, checking the queues
   * and sleeping 1ms until timeout */
  while (1) {
    int index = queue_has (queues, n);
    if (index >= 0) { /* the lock for queues [index] is held */
      *nqueue = index;
      return dequeue_unlock (queues [index], packet, plen, priority);
    }
    if (timeout_ms == 0)
      return 0;
    if (timeout_ms != (unsigned int) -1)
      timeout_ms--;
    sleep_ms (1);
  }
  return -1;   /* should never get here */
}

/* returns 1 if a packet was discarded, 0 otherwise */
int allnet_queue_discard_first (struct allnet_queue * queue)
{
  int result = 0;
  pthread_mutex_lock (&(queue->mutex));
  if (queue->count > 0) {
    queue->first = (queue->first + 1) % queue->max_packets;
    queue->count = queue->count - 1;
    result = 1;
  }
  pthread_mutex_unlock (&(queue->mutex));
  return result;
}

/* returns the number of packets in the queue, or -1 if the queue
 * has been recycled */
int allnet_queue_size (struct allnet_queue * queue)
{
  return queue->count;
}

/* returns the debug name and possibly other information */
const char * allnet_queue_info (struct allnet_queue * queue)
{
  return queue->debug_info;
}

#ifdef QUEUE_UNIT_TEST

#define MTU	10000

static int count = 10;         /* number of tests */
static int max_packet = 1000;  /* max packet size */
static struct allnet_queue * * q = NULL;   /* queues */
static int * thread_args = NULL;

static void init_buffer (unsigned char * buffer, unsigned int x,
                         unsigned int i, unsigned int size)
{
  if (size > 2) {
    buffer [0] = x;
    buffer [1] = i;
    buffer [2] = 0;
    int i;
    for (i = 3; i < size; i++)
      buffer [i] = i;
    unsigned int sum = 0;
    for (i = 0; i < size; i++)
      sum += buffer [i];
    buffer [2] = sum;
  }
}

static int check_buffer (unsigned char * buffer, unsigned int size)
{
  if (size <= 2)
    return 1;
  unsigned int checksum = buffer [2];
  unsigned int sum = 0;
  buffer [2] = 0;
  int i;
  for (i = 0; i < size; i++)
    sum += buffer [i];
  sum = sum % 256;
  if (sum != checksum)
    printf ("error: sum %d != checksum %d\n", sum, checksum);
  return (sum == checksum);
}

static void * add_thread (void * arg)
{
  unsigned int x = * (unsigned int *) arg;
  unsigned char buffer [MTU];
  unsigned int i;
  for (i = 0; i <= x; i++) {
    int index = count - x - 1;
    int size = max_packet * i / (x + 1);
    if (size > MTU)
      size = MTU;
    init_buffer (buffer, x, i, size);
    int priority = x * x + i;
    int result = allnet_enqueue (q [index], buffer, size, priority);
    int packets = allnet_queue_size (q [index]);
    printf ("%d/%d enqueing %d bytes with priority %d on queue %d, -> %d, %d\n",
            x, i, size, priority, index, result, packets);
    sleep (1);
  }
  printf ("add_thread for %s done\n", allnet_queue_info (q [x]));
  return NULL;
}

static void * remove_thread (void * arg)
{
  unsigned int x = * (unsigned int *) arg;
  while (1) {
    long int first_queue = random () % count;
    long int num_queues = random ();
    if (x == 0) {   /* harvest from all the queues */
      first_queue = 0;
      num_queues = count;
    }
    if (first_queue + num_queues > count)
      num_queues = count - first_queue;
    unsigned int nqueue = num_queues;
    unsigned char packet [MTU];
    memset (packet, 55, MTU);
    unsigned int plen = (max_packet > MTU) ? MTU : max_packet;
    unsigned int priority;
    time_t start = time (NULL);
    int result = allnet_dequeue (q + first_queue, &nqueue, packet, &plen,
                                 &priority, 3000);
    time_t end = time (NULL);
    int check = (result > 0) ? (check_buffer (packet, plen)) : 0;
    printf ("deq %d [%d..%d]=>%d %d, n %d, p %d/%d, len %d, pri %d, %ds, sizes %d %d %d %d %d %d %d %d %d %d\n",
            x, (int)first_queue, (int)(first_queue + num_queues - 1), result,
            check, nqueue + (int)first_queue, packet [0], packet [1],
            plen, priority, (int) (end - start),
            allnet_queue_size(q [0]),
            allnet_queue_size(q [1]),
            allnet_queue_size(q [2]),
            allnet_queue_size(q [3]),
            allnet_queue_size(q [4]),
            allnet_queue_size(q [5]),
            allnet_queue_size(q [6]),
            allnet_queue_size(q [7]),
            allnet_queue_size(q [8]),
            allnet_queue_size(q [9]));
    if (result == 0)
      break;
    if (check == 0)
      result = 10 / check;
    sleep (x + 1);
  }
  return NULL;
}

int main (int argc, char ** argv)
{
  int i;
  q = malloc (count * sizeof (struct allnet_queue *));
  thread_args = malloc (count * sizeof (int));
  pthread_t * a = malloc (count * sizeof (pthread_t));
  pthread_t * r = malloc (count * sizeof (pthread_t));
  for (i = 0; i < count; i++) {
    char name [100];
    snprintf (name, sizeof (name), "test queue %d", i);
    q [i] = allnet_queue_new (name, i + 1, max_packet * (i + 1));
  }
  for (i = 0; i < count; i++) {
    thread_args [i] = i;
    pthread_create (a + i, NULL, add_thread, (void *) (thread_args + i));
    pthread_create (r + i, NULL, remove_thread, (void *) (thread_args + i));
  }
  for (i = 0; i < count; i++) {
    pthread_join (a [i], NULL);
    pthread_join (r [i], NULL);
  }
  printf ("all threads have completed\n");
  for (i = 0; i < count; i++)
    allnet_queue_recycle (q [i]);
  return 0;
}

#endif /* QUEUE_UNIT_TEST */
