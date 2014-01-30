/* payload.h: definition of AllNet payload headers */

#ifndef PAYLOAD_H
#define PAYLOAD_H

/* the contents of a data packet begin with a message ack (if
 * ALLNET_TRANSPORT_ACK_REQ is set) followed by an application identifier,
 * somewhat similar to a port number in TCP/UDP, and often a content type,
 * again somewhat similar to a MIME type (some applications will not need
 * a content type).
 *
 * Since AllNet is 8-bit safe, there is no need for transfer encoding.
 */

struct allnet_payload_header {
  unsigned char application [4];	/* in big-endian order */
  unsigned char content_type [4];	/* in big-endian order */
};

struct allnet_payload_header_ack {      /* more common */
  unsigned char message_ack [MESSAGE_ID_SIZE];
  unsigned char application [4];	/* in big-endian order */
  unsigned char content_type [4];	/* in big-endian order */
};

/* some common content types */
#define ALLNET_CONTENT_TEXT			0x00020000
#define ALLNET_CONTENT_IMAGE			0x00030000
#define ALLNET_CONTENT_SOUND			0x00040000

/* plain text and HTML are UTF-8 unless indicated otherwise.
#define ALLNET_CONTENT_TEXT_PLAIN		(1 | ALLNET_CONTENT_TEXT)
#define ALLNET_CONTENT_TEXT_HTML		(2 | ALLNET_CONTENT_TEXT)

#define ALLNET_CONTENT_IMAGE_TIFF		(1 | ALLNET_CONTENT_IMAGE)
#define ALLNET_CONTENT_IMAGE_JPEG		(2 | ALLNET_CONTENT_IMAGE)
#define ALLNET_CONTENT_IMAGE_GIF		(3 | ALLNET_CONTENT_IMAGE)
#define ALLNET_CONTENT_IMAGE_PNG		(4 | ALLNET_CONTENT_IMAGE)

/* a sequence has a number of payloads in a single message */
#define ALLNET_CONTENT_SEQUENCE			0x00010000

struct allnet_sequence {	/* content_type ALLNET_CONTENT_SEQUENCE */
  unsigned char message_ack [MESSAGE_ID_SIZE];
  struct allnet_payload_header payload_id;
};

#endif /* PAYLOAD_H */
