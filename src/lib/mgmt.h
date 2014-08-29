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
  struct internet_addr ip; /* how to reach the peer */
  unsigned char destination [ADDRESS_SIZE];
  unsigned char nbits;     /* how many bits of the destination are given */
  /* for DHT nodes, nbits should always equal ADDRESS_BITS.  Received
   * entries that have fewer bits should be ignored */
  unsigned char type;      /* Rendezvous Point or DHT node -- one of: */
#define ALLNET_ADDR_INFO_TYPE_NONE	0    /* not a valid entry */
#define ALLNET_ADDR_INFO_TYPE_RP	1
#define ALLNET_ADDR_INFO_TYPE_DHT	2
  char pad [6];              /* always sent as 0 */
};

/* sent to a connecting listener to let them know who else to connect to */
/* - sent in response to a peer request, or */
/* - sent right before closing the connection/forgetting the UDP */
struct allnet_mgmt_peers {
  unsigned char num_peers;
  char pad [7];              /* always sent as 0 */
  /* num_sender_addresses + num_peers internet addr structs */
  struct internet_addr peers [0];
};

/* a DHT message reports a number of DHT nodes, each claiming to accept
 * messages for a given destination address */
struct allnet_mgmt_dht {
  unsigned char num_sender;    /* num addresses belonging to sender */
  unsigned char num_dht_nodes; /* num addresses belonging to other nodes */
  char pad [6];
  unsigned char timestamp  [ALLNET_TIME_SIZE];
  /* how to reach each DHT node, beginning with the sender */
  struct addr_info nodes [0];
};

/* a trace should contain a timestamp of the time of receipt using the
 * receiving/forwarding node's clock, as well as the number of hops
 * from the packet we are responding to (if any, 0 if none).
 * The timestamp is in fixed-point format: an allnet time in the first
 * ALLNET_TIME_SIZE bytes, followed by a fraction of a second.
 * the fraction of a second is in binary, (multiplied by 2^64).
 *
 * A precision gives the number of valid bits in the fraction, and may be 0.
 *
 * Preferably the precision should not be higher than the accuracy of
 * the local system clock, but since the accuracy can be hard to
 * estimate exactly, a default precision may be used.
 *
 * since times are sometimes accurate to powers of 10, we use precision > 64
 * to mean a decimal number <= (10^(precision-64)) is stored in the low-order
 * part of fraction, and this should be used as the fractional part.  So
 * for example a precision of 67 means 3 digits, or 1ms precision.
 * if the fraction > (10^(precision-64)), the fraction is not valid or usable.
 *
 * The trace may optionally carry an AllNet address.  Any unused bits of
 * the address should be set to zero. */
struct allnet_mgmt_trace_entry {
  unsigned char precision;      /* see comment */
  unsigned char nbits;          /* meaningful bits of address, may be zero */
  unsigned char hops_seen;      /* may be zero */
  unsigned char pad [5];
  unsigned char seconds [ALLNET_TIME_SIZE];
  unsigned char seconds_fraction [ALLNET_TIME_SIZE];
  unsigned char address [ADDRESS_SIZE];
};


/* a trace message is designed to have functionality similar to both
 * ping and traceroute in the internet.
 * when originally sent, the message should have one entry, the ID
 * of the sender.
 * if public key is provided, the results may be encrypted by the sender.
 */
struct allnet_mgmt_trace_req {
  unsigned char intermediate_replies; /* 0 to only request final reply */
  unsigned char num_entries;          /* number of entries, must be >= 1 */
  unsigned char pubkey_size [2];      /* public key size in bytes, MSB first */
                                      /* may be zero to give no public key */
  unsigned char pad [4];              /* always send as 0s */
  unsigned char trace_id [MESSAGE_ID_SIZE];   /* returned in the reply */
  struct allnet_mgmt_trace_entry trace [0]; /* really, trace [num_entries] */
  unsigned char pubkey [0];           /* no pubkey gives unencrypted replies */
};

/* if a pubkey was provided, this is the structure of the decrypted message */
/* otherwise, this is the structure of the plaintext message */
/* (the first byte is not encrypted, and indicates whether the rest of the */
/* message is encrypted) */
/* the message may or may not be signed by the sender */
/* an intermediate reply will normally have just one unsigned,
 * unencrypted entry */
/* To minimize the impact of denial-of-service attacks, trace replies
 * are sent with the lowest possible priority. */
struct allnet_mgmt_trace_reply {
  unsigned char encrypted;            /* 1 for encrypted, 0 for clear */
  unsigned char intermediate_reply;   /* 0 if it is a final reply */
  unsigned char num_entries;          /* number of entries, must be >= 1 */
  unsigned char pad [5];              /* always send as 0s */
  unsigned char trace_id [MESSAGE_ID_SIZE];
  struct allnet_mgmt_trace_entry trace [0]; /* really, trace [num_entries] */
};

/* keepalives have no content, only the header */

/* a data request specifies one or more message/packet IDs.  The
 * packets/messages are sent back if cached.  Any unsatisfied request
 * is forwarded onwards. */
struct allnet_mgmt_id_request {
  unsigned char n [2];                /* number of packet IDs, big-endian */
  unsigned char pad [6];              /* always send as 0s */
  unsigned char ids [MESSAGE_ID_SIZE * 0];  /* really, MESSAGE_ID_SIZE * n */
};

/* the header that precedes each of the management messages */
struct allnet_mgmt_header {
  /* specify the kind of management message */
#define ALLNET_MGMT_BEACON		1	/* ready to receive */
#define ALLNET_MGMT_BEACON_REPLY	2	/* ready to send */
#define ALLNET_MGMT_BEACON_GRANT	3	/* go ahead and send */
#define ALLNET_MGMT_PEER_REQUEST	4	/* no content */
#define ALLNET_MGMT_PEERS		5	/* use these peers */
#define ALLNET_MGMT_DHT			6	/* DHT information */
#define ALLNET_MGMT_TRACE_REQ		7	/* request a trace response */
#define ALLNET_MGMT_TRACE_REPLY		8	/* response to trace req */
#define ALLNET_MGMT_KEEPALIVE		9	/* to keep connection open */
#define ALLNET_MGMT_ID_REQUEST		10	/* request specific IDs */
  unsigned char mgmt_type;   /* every management packet has this */
  char mpad [7];
};

#define ALLNET_MGMT_HEADER_SIZE(t)	\
	(ALLNET_SIZE(t) + (sizeof (struct allnet_mgmt_header)))

#define ALLNET_BEACON_SIZE(t)	\
	(ALLNET_MGMT_HEADER_SIZE(t) + (sizeof (struct allnet_mgmt_beacon)))

#define ALLNET_PEER_SIZE(t, npeers)	\
	(ALLNET_MGMT_HEADER_SIZE(t) + (sizeof (struct allnet_mgmt_peers)) + \
	 (npeers) * sizeof (struct internet_addr))

#define ALLNET_DHT_SIZE(t, naddrs)	\
	(ALLNET_MGMT_HEADER_SIZE(t) + (sizeof (struct allnet_mgmt_dht)) + \
	 (naddrs) * sizeof (struct addr_info))

#define ALLNET_TRACE_REQ_SIZE(t, n, ks)	\
	(ALLNET_MGMT_HEADER_SIZE(t) +   \
         (sizeof (struct allnet_mgmt_trace_req)) + \
	 (n) * sizeof (struct allnet_mgmt_trace_entry) + \
         (ks))

#define ALLNET_TRACE_REPLY_SIZE(t, n)	\
	(ALLNET_MGMT_HEADER_SIZE(t) +   \
         (sizeof (struct allnet_mgmt_trace_reply)) + \
	 (n) * sizeof (struct allnet_mgmt_trace_entry))

#define ALLNET_ID_REQ_SIZE(t, n)	\
	(ALLNET_MGMT_HEADER_SIZE(t) +   \
         (sizeof (struct allnet_mgmt_id_request)) + \
	 (n) * MESSAGE_ID_SIZE)

#endif /* MGMT_H */
