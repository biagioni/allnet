/* reassembly.c: functions useful for reassembly of large packets */

#include <stdio.h>
#include <string.h>

#include "chat.h"
#include "lib/packet.h"
#include "lib/sha.h"
#include "lib/util.h"

/* given the ack for an entire large message, compute the individual
 * ack for a given packet sequence number
 * the message_ack, packet_ack, and packet_id must each have
 * ALLNET_MESSAGE_ID_SIZE, (packet_id maybe NULL), the sequence
 * must have ALLNET_SEQUENCE_SIZE */
void compute_ack (const char * message_ack, const char * sequence,
                  char * packet_ack, char * packet_id)
{
  char intermediate [ALLNET_MESSAGE_ID_SIZE];
  int i;
  for (i = 0; i < ALLNET_MESSAGE_ID_SIZE; i++)  /* invert the ack */
    intermediate [i] = message_ack [i] ^ 0xff;
/* print_buffer (message_ack, ALLNET_MESSAGE_ID_SIZE, "original ack", 100, 0);
print_buffer (intermediate, ALLNET_MESSAGE_ID_SIZE, ", inverted ack", 100, 1);
int fragment_seq = readb64 (sequence + (ALLNET_SEQUENCE_SIZE - 8));
printf ("sequence %d, ", fragment_seq); */
  for (i = 0; i < ALLNET_MESSAGE_ID_SIZE && i < ALLNET_SEQUENCE_SIZE; i++)
    intermediate [i] ^= sequence [i];  /* xor with the sequence number */
/* print_buffer (intermediate, ALLNET_MESSAGE_ID_SIZE, "intermediate", 100, 1); */
  sha512_bytes (intermediate, ALLNET_MESSAGE_ID_SIZE,
                packet_ack, ALLNET_MESSAGE_ID_SIZE);
/* print_buffer (packet_ack, ALLNET_MESSAGE_ID_SIZE, "final ack", 100, 1); */
  if (packet_id != NULL) {
    sha512_bytes (packet_ack, ALLNET_MESSAGE_ID_SIZE,
                  packet_id, ALLNET_MESSAGE_ID_SIZE);
/* print_buffer (packet_id, ALLNET_MESSAGE_ID_SIZE, "packet_id", 100, 0); */
  }
}

/* only malloc if there is plenty of space left */
static void * safer_malloc (size_t nbytes)
{
  void * result = malloc (nbytes);
  if (result == NULL)
    return NULL;
  /* allocate the same space again, plus 8MiB for good measure */
  void * safety = malloc (nbytes * 3 + 8 * 1024 * 1024);
  if (safety == NULL) {
    free (result);
    return NULL;
  }
  /* were able to allocate the safety bytes, there must be plenty of space
   * left, so free the safety bytes, and return the original result */
  free (safety);
  /* initialize the buffer to all zeros.  The caller relies on this
   * to clear the bitmap. */
  memset (result, 0, nbytes);
  return result;
}

#define CD_SIZE		CHAT_DESCRIPTOR_SIZE	/* more concise */

#define FRAGMENT_DATA_SIZE	(ALLNET_FRAGMENT_SIZE - CD_SIZE)

struct partial_reassembly {
  char * buffer;  /* chat descriptor stored here, data and bitmap follow */
  size_t num_fragments;    /* in units of FRAGMENT_DATA_SIZE */
  size_t actual_size; /* in bytes, not known until we see the last fragment */
  char * data;    /* points to num_fragments * FRAGMENT_DATA_SIZE bytes */
  char * bitmap;  /* points to (num_fragments + 7) / 8 bytes */
};

#define MAX_REASSEMBLIES	5  /* max simultaneous reassemblies */

struct partial_reassembly reassemblies [MAX_REASSEMBLIES];

/* returns 1 for success, 0 for failure */
static int allocate_reassembly (int reassembly_index, int num_fragments,
                                const char * cdp)
{
  if (reassembly_index < 0)
    allnet_crash ("allocate_reassembly reassembly_index < 0");
  if (reassembly_index >= MAX_REASSEMBLIES)
    allnet_crash ("allocate_reassembly reassembly_index >= MAX_REASSEMBLIES");
  if (num_fragments < 2) {
    printf ("error in allocate_reassembly, %d fragments\n", num_fragments);
    return 0;
  }
  ssize_t dsize = num_fragments * FRAGMENT_DATA_SIZE;
  ssize_t bsize = (num_fragments + 7) / 8;
  char * buffer = safer_malloc (CD_SIZE + dsize + bsize);
  if (buffer == NULL)
    return 0;
  reassemblies [reassembly_index].buffer = buffer;
  reassemblies [reassembly_index].data = buffer + CD_SIZE;
  /* the bitmap is set to all 0s by safer_malloc */
  reassemblies [reassembly_index].bitmap = buffer + CD_SIZE + dsize;
  reassemblies [reassembly_index].num_fragments = num_fragments;
  reassemblies [reassembly_index].actual_size = 0; /* not known yet */
  memcpy (buffer, cdp, CD_SIZE);
  return 1;
}

/* returns 1 if the buffer contains a completely reassembled message,
 * 0 otherwise */
static int reassembly_is_complete (int reassembly_index)
{
  if (reassembly_index < 0)
    allnet_crash ("reassembly_is_complete reassembly_index < 0");
  if (reassembly_index >= MAX_REASSEMBLIES)
    allnet_crash ("reassembly_is_complete reassembly_index >= MAX");
  if (reassemblies [reassembly_index].num_fragments < 2)
    allnet_crash ("reassembly_is_complete num_fragments < 2");
  if (reassemblies [reassembly_index].buffer == NULL)
    allnet_crash ("reassembly_is_complete buffer is null");
  if (reassemblies [reassembly_index].data == NULL)
    allnet_crash ("reassembly_is_complete data is null");
  if (reassemblies [reassembly_index].bitmap == NULL)
    allnet_crash ("reassembly_is_complete bitmap is null");
  if (reassemblies [reassembly_index].actual_size == 0)
    return 0;   /* we have not yet received the final fragment */
  int f;
  for (f = 0; f < reassemblies [reassembly_index].num_fragments; f++) {
    int bitmap_index = f / 8;
    int bit_index = f % 8;
    if ((reassemblies [reassembly_index].bitmap [bitmap_index] &
         (1 << bit_index)) == 0)
      return 0;  /* fragment missing */
  }
  return 1;      /* we have all the pieces */
}

/* returns 1 for success, 0 for failure including if this packet is duplicate */
static int save_fragment (int reassembly_index,
                          unsigned long long int fragment_number,
                          const char * fragment, int fsize)
{
  if (reassembly_index < 0)
    allnet_crash ("allocate_reassembly reassembly_index < 0");
  if (reassembly_index >= MAX_REASSEMBLIES)
    allnet_crash ("allocate_reassembly reassembly_index >= MAX_REASSEMBLIES");
  if ((fsize > FRAGMENT_DATA_SIZE) ||
      ((fragment_number + 1 < reassemblies [reassembly_index].num_fragments) &&
       (fsize != FRAGMENT_DATA_SIZE))) {
    printf ("illegal fragment has %d/%d bytes, index %llu/%zd, %d\n",
            fsize, (int) FRAGMENT_DATA_SIZE, fragment_number,
            reassemblies [reassembly_index].num_fragments, reassembly_index);
    return 0;              
  }
  int bitmap_index = fragment_number / 8;
  int bit_index = fragment_number % 8;
/* printf ("fragment number %llu, bitmap index %d, bit index %d, byte %02x, len %zd\n",
fragment_number, bitmap_index, bit_index, 
reassemblies [reassembly_index].bitmap [bitmap_index] & 0xff,
reassemblies [reassembly_index].actual_size); */
  if (reassemblies [reassembly_index].bitmap [bitmap_index] & (1 << bit_index))
    return 0;   /* we already have it */
  /* save the fragment */
  reassemblies [reassembly_index].bitmap [bitmap_index] |= (1 << bit_index);
/* printf ("new byte %02x\n",
reassemblies [reassembly_index].bitmap [bitmap_index] & 0xff); */
  memcpy (reassemblies [reassembly_index].data +
          (fragment_number * FRAGMENT_DATA_SIZE), fragment, fsize);
/* if (fragment_number + 1 == reassemblies [reassembly_index].num_fragments)
printf ("last fragment, fsize %d, total %ld\n", fsize,
       ((reassemblies [reassembly_index].num_fragments - 1) 
       * FRAGMENT_DATA_SIZE + fsize)); */
  if (fragment_number + 1 == reassemblies [reassembly_index].num_fragments)
    reassemblies [reassembly_index].actual_size = 
       (reassemblies [reassembly_index].num_fragments - 1) 
       * FRAGMENT_DATA_SIZE + fsize;
  return 1;
}

/* returns the message if this packet completes the reassembly,
 * NULL otherwise
 * if this call returns a complete message, the message should be free'd.
 * either way, this call free's text */
char * record_message_packet (const struct allnet_header * hp, int psize,
                              const char * text, int * tsize)
{
  char * npackets = ALLNET_NPACKETS(hp, hp->transport, psize);
  char * sequence = ALLNET_SEQUENCE(hp, hp->transport, psize);
  if ((npackets == NULL) || (sequence == NULL)) {
    printf ("error: record_message_packet transport %x\n", hp->transport);
    return NULL;
  }
  static int initialized = 0;
  int i;
  if (! initialized) {
    memset (reassemblies, 0, sizeof (reassemblies));
    initialized = 1;
  }
  unsigned long long int n = readb64 (npackets + (ALLNET_SEQUENCE_SIZE - 8));
  unsigned long long int fragment_number =
        readb64 (sequence + (ALLNET_SEQUENCE_SIZE - 8));
  const char * data = text + CD_SIZE;
  int dsize = *tsize - CD_SIZE;
  int free_index = -1;
  for (i = 0; i < MAX_REASSEMBLIES; i++) {
    if (reassemblies [i].num_fragments == 0) {
      free_index = i;    /* this slot is available */
    } else if (memcmp (text, reassemblies [i].buffer, CD_SIZE) == 0) {
      if (n != reassemblies [i].num_fragments) {
        printf ("error: n is %llu != %zd\n", n, reassemblies [i].num_fragments);
        return NULL;
      }
      /* found an incomplete reassembly matching this chat descriptor */
      if (! save_fragment (i, fragment_number, data, dsize)) {
        printf ("did not save fragment\n");
        return NULL;
      }
      if (reassembly_is_complete (i)) {
        char * result = reassemblies [i].buffer;
        *tsize = CD_SIZE + reassemblies [i].actual_size;
        reassemblies [i].num_fragments = 0;   /* clear the entry */
        return result;
      }
      return NULL;   /* reassembly is not complete */
    }
  }
  if (free_index < 0) {   /* make room by deleting the oldest entry */
    free (reassemblies [0].buffer);
    free_index = MAX_REASSEMBLIES - 1;
    for (i = 0; i < free_index; i++)
      reassemblies [i] = reassemblies [i + 1];
    reassemblies [free_index].num_fragments = 0;   /* clear the entry */
  }
  if (! allocate_reassembly (free_index, n, text)) {
    printf ("unable to allocate reassembly of size %llu\n", n);
    return NULL;
  }
  if (! save_fragment (free_index, fragment_number, data, dsize)) {
    printf ("did not save first fragment\n");
    return NULL;
  }
  if (reassembly_is_complete (free_index))
    printf ("error: reassembly is complete after first fragment!\n");
  return NULL;
}
