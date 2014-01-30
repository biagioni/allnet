/* packet.h: definition of AllNet packet headers */

#ifndef PACKET_H
#define PACKET_H

/* allnet keeps two ports: allnet port, for exchanges among peers,
 * and allnet local port, for connection by local clients to the allnet daemon
 */
#define ALLNET_PORT 	     (htons (0xa119))  /* ALLNet */
#define ALLNET_PORT_STRING   ("41241")         /* same */
#define ALLNET_LOCAL_PORT    (htons (0xa11e))  /* ALLnEt, 41246 */

#define ALLNET_WIFI_PROTOCOL (htons (0xa119))  /* ALLNet */

/* for receiving allnet messages, the receiver must know in advance what the
 * maximum packet size will be.  So allnet defines a maximum size, which
 * includes all headers.  This number is 12345 rounded down to the nearest
 * multiple of 4,096 */
#define ALLNET_MTU		12288          /* max size for a packet */

/* the allnet basic header has:
 * an 8-bit number b of valid bits in the destination ID
 * an 8-bit number of hops already traversed, 0 when first sent
 * an 8-bit maximum number of hops left
 * an 8-bit next header ID, 0 if there is no next header
 * an 8-bit number of valid bits in the source      ID
 * an 8-bit number of valid bits in the destination ID
 * an 8-bit signature algorithm, 0 if none
 * 8 bits of padding
 * a 64-bit source      ID (source      address)
 * a 64-bit destination ID (destination address)
 *    each address is up to 64 bits, plus a byte that gives the number of bits
 * for signed packets, the source (if any bits specified) indicates the
 *    key to use to verify the signature
 * for encrypted packets, the destination (if any bits specified) indicates
 *    the key to use to decrypt the packet
 *
 * the signature, if any, is in the last sig_size * 16 bytes of the packet
 * in this case, the last 2 bytes in the packet are the number n
 * of bytes in the signature, and the signature is in the n bytes
 * preceding the size.  If the size is not valid for the given signature
 * algorithm, the signature is not valid.
 *
 * the signature, if any, covers all the bytes from the end of this header
 * to the beginning of the signature.  That means, for encrypted packets,
 * that the signature is computed over the encrypted data.
 *
 * the signature size is in big-endian order, that is, packet [size - 2]
 * has the MSB, and packet [size - 1] the LSB of the size.
 */

#define ADDRESS_SIZE		 	 8	/* 8 bytes or 64 bits */
#define ADDRESS_BITS	 	(ADDRESS_SIZE * 8)	/* 64 */

struct allnet_header {
#define ALLNET_VERSION		2	/* this is version 2, 2013/01/31 */
  unsigned char version;
#define ALLNET_TYPE_DATA	1	/* normal encrypted data */
#define ALLNET_TYPE_DATA_ACK	2	/* acknowledge data */
#define ALLNET_TYPE_DATA_REQ	3	/* request data */
#define ALLNET_TYPE_KEY_XCHG	4	/* key exchange */
#define ALLNET_TYPE_KEY_REQ	5	/* request for public key */
#define ALLNET_TYPE_KEY_REPLY	6	/* public key in response to request */
#define ALLNET_TYPE_CLEAR	7	/* cleartext message */
#define ALLNET_TYPE_MGMT	8	/* AllNet and DHT information */
  unsigned char packet_type;
  unsigned char hops;	   /* times this packet has been recvd, initially 0 */
  unsigned char max_hops;  /* if on receipt hops+1 >= max_hops, do not fwd */
  unsigned char src_nbits; /* num valid bits in the source address */
  unsigned char dst_nbits; /* num valid bits in the destination address */
  unsigned char sig_algo;  /* signature algorithm, constants are below */
  unsigned char pad;       /* space so everything is aligned properly */
  unsigned char source      [ADDRESS_SIZE];
  unsigned char destination [ADDRESS_SIZE];
};

/* 24 bytes (192 bits) */
#define ALLNET_HEADER_SIZE	(sizeof (struct allnet_header))

/* used in sig_algo */
#define ALLNET_SIGTYPE_NONE			  0
#define ALLNET_SIGTYPE_RSA_PKCS1		  1
#define ALLNET_SIGTYPE_secp128r1		130
/* signature appears at the end of the packet, with the number of bytes in the
 * last 2 bytes */
struct allnet_signature {
  unsigned char certificate [0];
  unsigned char sig_nbits [2];   /* number of bytes, MSB first */
};


/* the 128-bit packet ID is only used for data, and data_ack packets,
 * and is only present for these packets.
 * - data packets have in the packet_id field the first PACKET_ID_SIZE
 *   bytes of the sha512 hash of the first PACKET_ID_BYTES bytes of the
 *   decrypted message.  These bytes are usually a random nonce R, and
 *   are placed into the packet_id field of the corresponding ack message.
 */

#define PACKET_ID_SIZE			16	/*  16 bytes or 128 bits */
#define PACKET_ID_BITS			(PACKET_ID_SIZE * 8)	/* 128 bits */

struct allnet_header_data {
  /* fields from the basic header */
  unsigned char version;
  unsigned char packet_type;            /* DATA, DATA_ACK, or DATA_REQ */
  unsigned char hops;
  unsigned char max_hops;
  unsigned char src_nbits;
  unsigned char dst_nbits;
  unsigned char sig_algo;
  unsigned char pad;
  unsigned char source      [ADDRESS_SIZE];
  unsigned char destination [ADDRESS_SIZE];
  /* additional field */
  unsigned char packet_id   [PACKET_ID_SIZE];
  /* in a data message, this header is followed by the actual encrypted data */
  /* in a data ack, this header may be followed by byte(s) to make it unique */
};

/* 40 bytes (320 bits) */
#define ALLNET_HEADER_DATA_SIZE		(sizeof (struct allnet_header_data))

/* a key exchange message carries a public key followed by
 * an hmac of (the public key followed by a secret nonce).
 * there are two special key exchanges:
 * ALLNET_TYPE_KEY_REQ
 * - this only carries a (partial) fingerprint of a public key.  The public
 *   key being requested should match the given fingerprint, and be for
 *   transmissions to the given source address from the given destination
 *   address.
 *   The priority of any reply should be significantly lower (to the
 *   point of only getting sent if idle for a long time) for any request
 *   with no or too few bits of source, destination and fingerprint
 * ALLNET_TYPE_KEY_REPLY
 * - this only carries a key and no hmac
 */

#define EXPIRATION_TIME_SIZE	8

/* clear messages may optionally carry an expiration time */
/* the expiration time, if not all 0's, is the number of seconds
 * since midnight, Jan 1, 2000, GMT.  This is encoded in big-endian order */
struct allnet_header_clear {
  /* fields from the basic header */
  unsigned char version;
  unsigned char packet_type;            /* CLEAR */
  unsigned char hops;
  unsigned char max_hops;
  unsigned char src_nbits;
  unsigned char dst_nbits;
  unsigned char sig_algo;
  unsigned char pad;
  unsigned char source      [ADDRESS_SIZE];
  unsigned char destination [ADDRESS_SIZE];
  /* additional field */
  unsigned char expiration  [EXPIRATION_TIME_SIZE];
};

/* 32 bytes (256 bits) */
#define ALLNET_HEADER_CLEAR_SIZE	(sizeof (struct allnet_header_clear))

/* management packets can be very different from each other.  Each has
 * its own header */

/* beacons are locally broadcast by wireless receivers to indicate they
 * are ready to receive data.  Becaons should always be sent with hops = 0
 * and max_hops = 1, so hops and max_hops can be ignored when receiving
 * beacons.
 *
 * If I send a beacon, "destination", if any, indicates what packets I
 * am most interested in receiving, and "source", if any,
 * indicates the sender address(es) I am most interested in receiving from.
 * senders may use these to favor some among otherwise equal-priority packets.
 *
 * a beacon carries, in big-endian order, the length of time the receiver
 * is planning to stay awake.  The time is in nanoseconds (10^-9s), so the
 * maximum time is 4.294967295 s.  A receiver who is listening continuously
 * should use a value of 0 for the time.
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
  unsigned char awake_time [4];	/* nanoseconds plan to stay awake, MSB first */
};

struct allnet_mgmt_beacon_reply {
  unsigned char receiver_nonce [NONCE_SIZE]; /* replying to: */
  unsigned char sender_nonce [NONCE_SIZE];   /* to distinguish senders */
};

struct allnet_mgmt_beacon_grant {
  unsigned char receiver_nonce [NONCE_SIZE]; /* grant from: */
  unsigned char sender_nonce [NONCE_SIZE];   /*         to: */
  unsigned char send_time [4];	/* nanoseconds max transmission time */
};

#include <netinet/in.h>   /* type struct in6_addr */

/* a basic IPv4 or IPv6 address.  All 16 bytes of the IPv6 address are
 * sent, even if only 4 bytes of IPv4 are included.  Four-byte IPv4
 * address x.y.z.w is sent as 0:0:0:0:0:ffff:xy:zw
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
  struct internet_addr ip [0];   /* how to reach the peer */
};

struct allnet_mgmt_dht {
  unsigned char num_dht_nodes;
  char pad [7];
  struct allnet_dht_info nodes [0];   /* how to reach each DHT */
};

/* the header that precedes each of the management messages */
struct allnet_header_mgmt {
  /* fields from the basic header */
  unsigned char version;
  unsigned char packet_type;            /* MGMT */
  unsigned char hops;
  unsigned char max_hops;
  unsigned char src_nbits;
  unsigned char dst_nbits;
  unsigned char sig_algo;
  unsigned char pad;
  unsigned char source      [ADDRESS_SIZE];
  unsigned char destination [ADDRESS_SIZE];
  /* additional fields, some of them optional */
  unsigned char mgmt_type;   /* every management packet has this */
  char mpad [7];
};

#define ALLNET_MGMT_HEADER_SIZE	(sizeof (struct allnet_header_mgmt))
#define ALLNET_BEACON_HEADER_SIZE	\
	(ALLNET_MGMT_HEADER_SIZE + (sizeof (struct allnet_mgmt_beacon)))
#define ALLNET_PEER_HEADER_SIZE(npeers)	\
	(ALLNET_MGMT_HEADER_SIZE + (sizeof (struct allnet_mgmt_peers)) + \
	 npeers * sizeof (struct internet_addr))

#define ALLNET_MGMT_BEACON		1	/* ready to receive */
#define ALLNET_MGMT_BEACON_REPLY	2	/* ready to send */
#define ALLNET_MGMT_BEACON_GRANT	3	/* go ahead and send */

#define ALLNET_MGMT_PEER_REQUEST	4	/* no content */
#define ALLNET_MGMT_PEERS		5	/* use these peers */

#define ALLNET_MGMT_DHT			6	/* DHT information */

#endif /* PACKET_H */
