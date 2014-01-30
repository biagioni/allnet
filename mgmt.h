/* mgmt.h: definition of AllNet management headers */

#ifndef MGMT_H
#define MGMT_H

#include "packet.h"

/* management packets can be very different from each other.  Each has
 * its own header */

/* beacons are locally broadcast by wireless receivers to indicate the receiver
 * is ready to receive data.  Becaons should always be sent with hops = 0
 * and max_hops = 1, so hops and max_hops can be ignored when receiving
 * beacons.
 *
 * If I send a beacon, "destination", if any, indicates what packets I
 * am most interested in receiving, and "source", if any,
 * indicates the sender address(es) I am most interested in receiving from.
 * senders may use these to favor some among otherwise equal-priority packets.
 *
 * a beacon carries, in big-endian order, the length of time the receiver
 * is planning to stay awake.  The time is in nanoseconds (10^-9s).
 * A receiver who is listening continuously may use a value of 0 for the time.
 *
 * the receiver nonce identifies the ultimate data receiver, that is, the
 * device that sends the original management beacon.  The sender nonce
 * identifies the sender of data.
 *
 * Senders sleep a random time between 5ms and 15ms before replying to
 * a beacon.  Normally, at the end of a transmission, a sender will
 * issue its own beacon, and the erstwhile receiver has priority in
 * replying to that beacon -- others may reply after 5-15ms.
 */
#define NONCE_SIZE		32
struct allnet_mgmt_beacon {
  unsigned char receiver_nonce [NONCE_SIZE];   /* to distinguish receivers */
  unsigned char awake_time [8];	/* nanoseconds plan to stay awake, MSB first */
};

struct allnet_mgmt_beacon_reply {
  unsigned char receiver_nonce [NONCE_SIZE]; /* replying to: */
  unsigned char sender_nonce [NONCE_SIZE];   /* to distinguish senders */
};

struct allnet_mgmt_beacon_grant {
  unsigned char receiver_nonce [NONCE_SIZE]; /* grant from: */
  unsigned char sender_nonce [NONCE_SIZE];   /*         to: */
  unsigned char send_time [8];	/* nanoseconds max transmission time */
};

#include <netinet/in.h>   /* type struct in6_addr */

/* a basic IPv4 or IPv6 address.  All 16 bytes of the IPv6 address are
 * sent, even if only 4 bytes of IPv4 are included.  Four-byte IPv4
 * address x.y.z.w is sent as 0:0:0:0:0:ffff:xy:zw
 * 24 bytes altogether
 */
struct internet_addr {
  struct in6_addr ip;         /* for ip4 x.y.z.w, send 0:0:0:0:0:ffff:xy:zw */
  unsigned short port;        /* sent in big-endian order */
  unsigned char ip_version;   /* the integer 4 or 6 */
  char pad [5];               /* always sent as 0 */
};

/* used to send address mapping information to aip,
 * and peer information from aip */
struct addr_info {
  struct internet_addr ip;   /* how to reach the peer */
  unsigned char destination [ADDRESS_SIZE];
  unsigned char nbits;       /* how many bits of the destination are given */
  char pad [7];              /* always sent as 0 */
};

/* sent to a connecting listener to let them know who else to connect to */
/* - sent in response to a peer request, or */
/* - sent right before closing the connection/forgetting the UDP */
struct allnet_mgmt_peers {
  unsigned char num_peers;
  char pad [7];              /* always sent as 0 */
  struct internet_addr peers [0];   /* num_peers address info structs */
};

/* a DHT message reports a number of DHT nodes, each claiming to accept
 * messages for a given destination address */
struct allnet_dht_info {
  unsigned char destination [ADDRESS_SIZE];
  struct internet_addr ip;      /* how to reach the peer */
};

struct allnet_mgmt_dht {
  unsigned char num_dht_nodes;
  char pad [7];
  struct allnet_dht_info nodes [0];   /* how to reach each DHT */
};

/* a trace message is designed to have functionality similar to both
 * ping and traceroute in the internet.   The ID of intermediate nodes
 * is free-form.
 * To minimize the impact of denial-of-service attacks, trace replies
 * are sent with the lowest possible priority, and trace messages
 * (trace requests) with a priority just above the lowest possible.
 */
struct allnet_mgmt_trace {
  unsigned char nonce [MESSAGE_ID_SIZE];   /* returned in the reply */
  unsigned char pubkey_size [2];      /* public key size in bytes, MSB first */
  unsigned char pubkey [0];           /* no pubkey gives unencrypted replies */
};

/* if a pubkey was provided, this is the structure of the decrypted message */
/* otherwise, this is the structure of the plaintext message */
/* the message may or may not be signed by the sender */
struct allnet_mgmt_trace_reply {
  unsigned char nonce [MESSAGE_ID_SIZE];
  unsigned char node_bytes;
  unsigned char node_info [0];  /* node_bytes worth of printable info,
                                   e.g. IP addresses or other identification */
};

/* a trace path may be returned by any of a number of means, including
 * an encrypted application message.  It may also be returned as an
 * unencrypted management message containing an allnet_trace_info.
 * if such a message carries a valid ack, it is treated as an ack,
 * that is, sent with the same priority as a corresponding ack.   Otherwise
 * it is sent with low priority to lessen the opportunity for DoS attacks.
 */
struct allnet_mgmt_trace_path {
#define ALLNET_MGMT_TRACE_NONE		0
#define ALLNET_MGMT_TRACE_ID		1
#define ALLNET_MGMT_TRACE_ACK		2
  unsigned char trace_type;		/* none, ID, or ACK */
  unsigned char pad [7];
  unsigned char id_or_ack [MESSAGE_ID_SIZE];
  struct allnet_trace_entry trace [ALLNET_NUM_TRACES];
};

/* the header that precedes each of the management messages */
struct allnet_header_mgmt {
  /* specify the kind of management message */
#define ALLNET_MGMT_BEACON		1	/* ready to receive */
#define ALLNET_MGMT_BEACON_REPLY	2	/* ready to send */
#define ALLNET_MGMT_BEACON_GRANT	3	/* go ahead and send */
#define ALLNET_MGMT_PEER_REQUEST	4	/* no content */
#define ALLNET_MGMT_PEERS		5	/* use these peers */
#define ALLNET_MGMT_DHT			6	/* DHT information */
#if 0
#define ALLNET_MGMT_TRACE_REQ		7	/* request a trace response */
#define ALLNET_MGMT_TRACE_REPLY		8	/* response to trace req */
#endif /* 0 */
#define ALLNET_MGMT_TRACE_PATH		9	/* response to trace header */
  unsigned char mgmt_type;   /* every management packet has this */
  char mpad [7];
};

#define ALLNET_MGMT_HEADER_SIZE(t)	\
	(ALLNET_SIZE(t) + (sizeof (struct allnet_header_mgmt)))

#define ALLNET_BEACON_HEADER_SIZE(t)	\
	(ALLNET_MGMT_HEADER_SIZE(t) + (sizeof (struct allnet_mgmt_beacon)))

#define ALLNET_PEER_HEADER_SIZE(t, npeers)	\
	(ALLNET_MGMT_HEADER_SIZE(t) + (sizeof (struct allnet_mgmt_peers)) + \
	 (npeers) * sizeof (struct internet_addr))

#endif /* MGMT_H */
