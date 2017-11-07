/* pqueue.c: priority queue for broadcasting over the local area network (not thread safe) */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pqueue.h"

/* a doubly-linked list of queue elements, kept in order of priority */
struct queue_element {
  struct queue_element * next;  /* null at the end of the linked list */
  struct queue_element * prev;  /* null at the head of the linked list */
  int priority;
  int backoff;
  int size;
  char data [0];   /* actually, however many chars size says */
};

static struct queue_element * head = NULL;
static struct queue_element * tail = NULL;
static int max_size = 0;
static int current_size = 0;

void queue_init (int max_bytes)
{
  head = NULL;
  tail = NULL;
  max_size = max_bytes;
  current_size = 0;
}

/** Remove the last element (if any) from the queue */
static void remove_tail ()
{
  if (tail == NULL)   /* queue is empty */
    return;
  if (current_size < tail->size) {
    printf ("error in remove_tail: current size %d, tail size %d\n",
            current_size, tail->size);
    current_size = 0;
  } else {
    current_size -= tail->size;
  }
  struct queue_element * saved_tail = tail;
  if ((head == tail) || (tail->prev == NULL)) {
    tail = NULL;
    head = NULL;
  } else {
    tail->prev->next = NULL;
    tail = tail->prev;
  }
  free (saved_tail);
}

/**
 * Try to make room for a new element.
 * Elements of lower priority will be removed to make room for the new one if
 * needed. Queue remains unchanged if new element doesn't fit.
 * @param wanted Size needed for new element
 * @param priority Priority of new element.
 * @return 1 if new element has enough room, 0 otherwise.
 */
static int make_room (int wanted, int priority)
{
  if (current_size + wanted <= max_size)
    return 1;
  if ((wanted > max_size) || (tail == NULL))
    return 0;

  int possible_space = 0;
  int removable = 0;
  struct queue_element * qel = tail;
  while ((qel != NULL) && (qel->priority < priority) &&
         (current_size - possible_space + wanted > max_size)) {
    possible_space += qel->size;
    ++removable;
    qel = qel->prev;
  }
  /* only clear elements if new element will fit */
  if (current_size - possible_space + wanted <= max_size) {
    while (removable--)
      remove_tail ();
    return 1;
  }
  return 0;
}

/* return the highest priority of any item in the queue */
int queue_max_priority ()
{
  if (head == NULL)
    return 0;
  return head->priority;
}

/* return how many bytes are in the queue */
int queue_total_bytes ()
{
  return current_size;
}

static struct queue_element *
  new_element (const char * value, int size, int priority,
               struct queue_element * prev, struct queue_element * next)
{
  int total_size = size + sizeof (struct queue_element);
  struct queue_element * result = malloc (total_size);
  if (result == NULL) {
    printf ("pqueue: Unable to malloc %d bytes for %d content, aborting\n",
            total_size, size);
    exit (1);
  }
  result->prev = prev;
  result->next = next;
  result->priority = priority;
  result->backoff = 0;
  result->size = size;
  memcpy (result->data, value, size);
  return result;
}

/**
 * Add new element to priority queue
 * If needed, items with lower priority will be removed to make room for the new
 * element. The queue remains unchanged if not enough room can be found.
 * @param value Element to add. The element is copied into the queue.
 * @param size Size of element to add.
 * @param priority Priority of new element.
 * @return 1 on success, 0 on failure (not enough space)
 */
int queue_add (const char * value, int size, int priority)
{
  if (! make_room (size, priority))
    return 0;
  current_size += size;
  if ((head == NULL) || (head->priority < priority)) {
    struct queue_element * new =
      new_element (value, size, priority, NULL, head);
    if (head != NULL)
      head->prev = new;
    head = new;
    if (tail == NULL)
      tail = new;
    return 1;
  }
  struct queue_element * node = head;
  while ((node != NULL) && (node->priority >= priority))
    node = node->next;
  if (node == NULL) {  /* add at the tail */
    tail->next = new_element (value, size, priority, tail, NULL);
    tail = tail->next;
    return 1;
  }
  /* found a node whose priority < the new priority, so add before it */
  struct queue_element * prev = node->prev;
  node->prev = new_element (value, size, priority, prev, node);
  prev->next = node->prev;
  return 1;
}

static struct queue_element * iter_next = NULL;
static struct queue_element * iter_remove = NULL;

void queue_iter_start ()
{
  iter_next = head;
  iter_remove = NULL;
}

/* Fills in *queue_element with a reference to the next object, *next_size
 * with its length, *priority with its priority, *backoff with the current
 * backoff value and returns 1.
 *
 * if the iteration has reached the end, or for any other error, returns 0. */
int queue_iter_next (char * * queue_element, int * next_size, int * priority,
                     int * backoff)
{
  iter_remove = NULL;     /* in case we fail, make sure we cannot remove */
  if (iter_next == NULL)
    return 0;
  *queue_element = iter_next->data;
  *next_size = iter_next->size;
  *priority = iter_next->priority;
  *backoff = iter_next->backoff;
  iter_remove = iter_next;
  iter_next = iter_next->next;
  return 1;
}

/**
 * Increment backoff counter for current element. The message is removed when
 * the threshold is crossed.
 * Must only be called after a successful call to queue_iter_next ().
 * @return 1 if counter has been incremented, 0 if element has been removed.
 */
int queue_iter_inc_backoff ()
{
  if (iter_remove == NULL)
    return 0; /* item doesn't exist */
  (iter_remove->backoff)++;
  long p = iter_remove->priority;
  if (iter_remove->backoff > ALLNET_PQUEUE_BACKOFF_THRESHOLD (p)) {
    queue_iter_remove ();
    return 0;
  }
  return 1;
}

/**
 * Remove current element from queue and free internal resources.
 * Must be called at most once after a successful call to queue_iter_next ().
 */
void queue_iter_remove ()
{
  if (iter_remove == NULL) {
    printf ("error: queue_iter_remove, but iter_remove is NULL\n");
    return;
  }
  if (iter_remove->prev != NULL)
    iter_remove->prev->next = iter_remove->next;
  else
    head = iter_remove->next;
  if (iter_remove->next != NULL)
    iter_remove->next->prev = iter_remove->prev;
  else
    tail = iter_remove->prev;
  free (iter_remove);
  iter_remove = NULL;
}

#ifdef TEST_PRIORITY_QUEUE
#define ALLNET_PQUEUE_MAX_BACKOFF 2
#include <assert.h>
static void queue_print_one (struct queue_element * node)
{
  printf ("(%p<-%p->%p): %d, %d, %d [%02x %02x]\n", node->prev, node, node->next,
          node->size, node->priority, node->backoff,
           node->data [0] & 0xff, node->data [1] & 0xff);
}

static void queue_print (char * desc)
{
  if (head == NULL) {
    printf ("%s: (empty queue)\n", desc);
  } else {
    printf ("%s:\n", desc);
    struct queue_element * node = head;
    while (node != NULL) {
      queue_print_one (node);
      node = node->next;
    }
  }
}

int main (int argc, char ** argv)
{
  queue_init (100);
  queue_print ("after init");
  queue_add ("foo", 3, 7);
  queue_print ("after adding foo, priority 7");
  queue_add ("bar", 3, 77);
  queue_print ("after adding bar, priority 77");
  char buffer [96] = "baz";
  queue_add (buffer, 96, 37);
  queue_print ("after adding buffer, priority 37");

  queue_init (100);
  queue_print ("\nafter second init");
  queue_add ("foo", 3, 77);
  queue_print ("after adding foo, priority 77");
  queue_add ("bar", 3, 7);
  queue_print ("after adding bar, priority 7");
  queue_add (buffer, 96, 37);
  queue_print ("after adding buffer, priority 37");

  queue_init (100);
  queue_print ("\nafter third init");
  queue_add ("foo", 3, 77);
  queue_print ("after adding foo, priority 77");
  queue_add ("bar", 3, 37);
  queue_print ("after adding bar, priority 37");
  queue_add (buffer, 96, 7);
  queue_print ("after adding buffer, priority 7");

  /* backoff test */
  queue_init (100);
  queue_print ("\nafter fourth init");
  queue_add ("foo", 3, 77);
  char * m;
  int s, p, b;
  queue_iter_start ();
  assert (queue_iter_next (&m, &s, &p, &b));
  assert (queue_iter_inc_backoff ());
  queue_print ("after adding foo and incrementing once, priority 77");
  assert (queue_iter_inc_backoff ());
  assert (!queue_iter_inc_backoff ());
  queue_print ("after incrementing foo, priority 77 over backoff");
  queue_add ("foo", 3, 77);
  queue_print ("after adding foo, priority 77");
  queue_iter_start ();
  assert (queue_iter_next (&m, &s, &p, &b));
  assert (queue_iter_inc_backoff ()); /* foo == 1 */
  queue_add ("bar", 3, 77);
  queue_print ("after inc'foo and adding bar, priority 77");
  queue_iter_start ();
  assert (queue_iter_next (&m, &s, &p, &b));
  assert (queue_iter_inc_backoff ()); /* foo == 2 */
  queue_add ("baz", 3, 77);
  queue_print ("after inc'foo adding baz, priority 77");
  queue_iter_start ();
  assert (queue_iter_next (&m, &s, &p, &b));
  assert (!queue_iter_inc_backoff ()); /* foo == 3 -> delete */
  queue_print ("after incrementing foo over backoff");
  queue_iter_start ();
  assert (queue_iter_next (&m, &s, &p, &b));
  assert (queue_iter_next (&m, &s, &p, &b));
  assert (queue_iter_inc_backoff ()); /* baz == 1 */
  assert (queue_iter_inc_backoff ()); /* baz == 2 */
  queue_print ("after incrementing baz to backoff");
  assert (!queue_iter_inc_backoff ()); /* baz == 3 -> delete */
  queue_print ("after incrementing baz over backoff");
  queue_iter_start ();
  assert (queue_iter_next (&m, &s, &p, &b));
  assert (queue_iter_inc_backoff ()); /* bar == 1 */
  assert (queue_iter_inc_backoff ()); /* bar == 2 */
  assert (!queue_iter_inc_backoff ()); /* bar == 3 -> delete */
  queue_iter_start ();
  assert (!queue_iter_next (&m, &s, &p, &b));
}
#endif /* TEST_PRIORITY_QUEUE */
