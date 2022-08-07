/* packet.h: definition of AllNet packet headers */

#ifndef PACKET_H
#define PACKET_H

/* allnet uses two ports: allnet port, for exchanges among peers on different
 * machines, and allnet local port, for connection by local clients to
 * the allnet daemon
 * port numbers are in host byte order, use allnet_htons to
 * convert to network byte order
 */
#define ALLNET_PORT 	     0xa119  /* ALLNet, 41241 */
#define ALLNET_LOCAL_PORT    0xa11e  /* ALLnEt, 41246 */

/* protocol number used when sending/receiving over 802.11, WiFi */
#define ALLNET_WIFI_PROTOCOL 0xa119  /* ALLNet, 41241 */

/* multicast link-local address used for IPv6:
 * the hex spells out "ALLNet LOCAL BroadCAST" twice in a row */
#define ALLNET_IPV6_MCAST  "ff02:a119:10ca:1bca:52a1:1910:ca1b:ca53"

/* for receiving allnet messages, the receiver must know in advance what the
 * maximum packet size will be.  So allnet defines a maximum size, which
 * includes all headers.  This number is 12345 rounded down to the nearest
 * multiple of 4,096 */
#define ALLNET_MTU		12288          /* max size for a packet */

/* the allnet basic header has:
 * an 8-bit allnet version number
 * an 8-bit message type
 * an 8-bit number of hops already traversed, 0 when first sent
 * an 8-bit maximum number of hops left
 * an 8-bit number of valid bits in the source      ID
 * an 8-bit number of valid bits in the destination ID
 * an 8-bit signature algorithm, 0 if none
 * an 8-bit transport requests including ack and expiration, 0 if none
 * a 64-bit source      ID (source      address)
 * a 64-bit destination ID (destination address)
 *    each address is up to 64 bits, plus a byte that gives the number of bits
 * for signed messages (signature algorithm not 0), the source (if any
 *    bits specified) suggests which keys to use to verify the signature
 * for encrypted messages, the destination (if any bits specified) suggests
 *    which keys to use to decrypt the message
 *
 * if a messsage is signed, the last 2 bytes in the message are the number
 * sig_size of bytes in the signature, and the signature itself is stored
 * immediately preceding these 2 bytes.
 *
 * the signature size is in big-endian order, that is, message [size - 2]
 * has the MSB, and message [size - 1] the LSB of the size.
 *
 * If the size is not valid for the given signature algorithm, or the
 * size is too large for the packet, the signature is not valid.
 *
 * the signature, if any, covers all the bytes from the end of the header
 * to the beginning of the signature.  That means, for encrypted messages,
 * that the signature is computed over the encrypted data.
 */

#define ALLNET_ADDRESS_SIZE		  8	/* 8 bytes or 64 bits */
#define ALLNET_ADDRESS_BITS	 	(ALLNET_ADDRESS_SIZE * 8)   /* 64 */

struct allnet_header {
#define ALLNET_VERSION		3	/* this is version 3, 2014/01/01 */
  unsigned char version;
#define ALLNET_TYPE_DATA	1	/* normal encrypted data */
#define ALLNET_TYPE_ACK		2	/* acknowledgement */
#define ALLNET_TYPE_DATA_REQ	3	/* request data */
#define ALLNET_TYPE_KEY_XCHG	4	/* key exchange */
#define ALLNET_TYPE_KEY_REQ	5	/* request for public key */
#define ALLNET_TYPE_CLEAR	6	/* cleartext message */
#define ALLNET_TYPE_MGMT	7	/* AllNet and DHT information, mgmt.h */
  unsigned char message_type;
  unsigned char hops;	   /* times this packet has been recvd, initially 0 */
  unsigned char max_hops;  /* if on receipt hops+1 >= max_hops, do not fwd */
  unsigned char src_nbits; /* num valid bits in the source address */
  unsigned char dst_nbits; /* num valid bits in the destination address */
  unsigned char sig_algo;  /* signature algorithm, constants are below */
#define ALLNET_TRANSPORT_NONE	0	/* no special requests */
  unsigned char transport; /* type of transport requests, 0 if none */
  unsigned char source      [ALLNET_ADDRESS_SIZE];
  unsigned char destination [ALLNET_ADDRESS_SIZE];
/* the next fields are only present if transport so indicates */
};

/* a message is invalid under the following circumstances:
 * non-zero transport for ALLNET_TYPE_ACK
 * payload for ALLNET_TYPE_ACK not a multiple (> 0) of MESSAGE_ID_SIZE payload
 * ALLNET_TRANSPORT_ACK_REQ bit set, but payload less than MESSAGE_ID_SIZE
 * ALLNET_TRANSPORT_LARGE bit set without ALLNET_TRANSPORT_ACK_REQ bit
 * ALLNET_TRANSPORT_EXPIRATION bit set but the expiration time is in the past
 * non-zero sig_algo and the signature size >= (packet size - header size)
 *
 * invalid messages are normally discarded by allnet hosts
 */

/* 24 bytes (192 bits) */
#define ALLNET_HEADER_SIZE	(sizeof (struct allnet_header))

/* the maximum number of acks in an ack packet is 64, giving a total
 * ack packet size of 1048 bytes = 1024 (acks) + 24 (header).
 * an ack received with n hops remaining may be included in any
 * outgoing ack packet that has at most n-1 hops remaining. */
#define ALLNET_MAX_ACKS	((1048 - ALLNET_HEADER_SIZE) / ALLNET_MESSAGE_ID_SIZE)

/* used in sig_algo */
#define ALLNET_SIGTYPE_NONE			  0
#define ALLNET_SIGTYPE_RSA_PKCS1		  1
#define ALLNET_SIGTYPE_secp128r1		  2
#define ALLNET_SIGTYPE_HMAC_SHA512		  3

/* signature appears at the end of the message.  For variable-sized
 * signatures, e.g. ALLNET_SIGTYPE_RSA_PKCS1, the number of bytes
 * is sent in the two bytes following the signature */
struct allnet_variable_signature {
  unsigned char certificate [0];
  unsigned char sig_nbytes [2];   /* number of bytes, MSB first */
};

/* ALLNET_TYPE_KEY_XCHG carries a public key (for DH, g^a mod p)
 *   followed by an hmac of (the public key followed by a secret nonce)
 *   followed by a random bitstring.  The random bitstring allows
 *   the message to be resent, without the retransmission being seen
 *   as duplicate.
 *   If one side uses a secret nonce of the form ABCDEF, the other side
 *   uses DEFABC as a secret nonce, i.e. with the halves reversed.
 *   This prevents confusion between the keys I send and the keys
 *   I am meant to receive.
 *   RSA public keys are 513 bytes.
 *   for all other keys, the first byte is a code identifying the key type.
 *   Diffie-Hellman has code+DH+hmac+random = 1+56+64+16=137 bytes
 * ALLNET_TYPE_KEY_REQ
 *   carries a (partial) fingerprint of a public key.  The public key sent
 *   in response should match the given fingerprint.
 *   The reply is sent as a broadcast (CLEAR) message, using as
 *   destination address the source address of the key request.
 *   A key request carries a number of bits in the fingerprint (may be zero),
 *   then a corresponding number of bytes of fingerprint, and a
 *   random bitstring.
 * ALLNET_TYPE_CLEAR
 *   the key sent in response to a subscription (KEY_REQ) starts with
 *   an app media header, with app "keyd" and media ALLNET_MEDIA_PUBLIC_KEY
 *   This is followed by the key, then a random bitstring.
 */
#define ALLNET_KEY_XCHG_DH_AES_SECRET	101  /* code in the first byte */
#define ALLNET_KEY_RANDOM_PAD_SIZE	16  /* should be >= MESSAGE_ID_SIZE */
struct allnet_key_exchange {
  unsigned char public_key [0];     /* public key to be used -- 513 for RSA */
  unsigned char hmac [64];          /* confirms knowledge of secret nonce */
  unsigned char random [ALLNET_KEY_RANDOM_PAD_SIZE]; /* make each msg unique */
};
struct allnet_key_request {
  unsigned char nbits_fingerprint;  /* number of bits in the fingerprint,
                                       may be zero */
  unsigned char fingerprint [0];    /* (nbits + 7) / 8 bytes of fingerprint,
                                       identifies requested public key */
  unsigned char random [ALLNET_KEY_RANDOM_PAD_SIZE]; /* make each msg unique */
};
struct allnet_key_reply {
  unsigned char app_media_header [8];/* keyd and ALLNET_MEDIA_PUBLIC_KEY */
  unsigned char public_key [0];     /* public key -- 513 bytes for RSA */
  unsigned char random [ALLNET_KEY_RANDOM_PAD_SIZE]; /* make each msg unique */
};

/* these are the transport bits.
 * a data packet should typically carry at least one of ACK_REQ,
 * EXPIRATION, or DO_NOT_CACHE.
 * A broadcast packet will typically be an EXPIRATION packet.
 * a LARGE packet must also be an ACK_REQ packet.
 * All other flags can be used independently of each other */
#define ALLNET_TRANSPORT_STREAM		1	/* related packets */
#define ALLNET_TRANSPORT_ACK_REQ	2	/* message_id allows acking */
#define ALLNET_TRANSPORT_LARGE		4	/* packets part of 1 message */
#define ALLNET_TRANSPORT_EXPIRATION	8	/* expiration specified */
#define ALLNET_TRANSPORT_DO_NOT_CACHE	16	/* no reason to cache this */

/* a stream is a collection of related messages, such that if too many
 * of them are dropped, might as well drop the rest.  This allows
 * intermediate forwarders to do call control, rejecting or terminating
 * streams that would exceed available resources.  It allows forwarders
 * to make committments to provide good service to some streams rather
 * than bad service to all equally.
 *
 * forwarders likely will follow rules such as the following:
 * - forwarding a stream is a binary decision: either on or off
 * - messages for an unsupported stream are substantially lowered in
 *   priority, not directly dropped
 * - an unsupported stream may be supported again later if conditions warrant
 * - turning streams off is a probabilistic process, i.e. desirability of
 *   a stream makes it more likely, but not certain, it will be carried
 * - in choosing which streams to drop, older streams should be kept
 *   in preference to newer streams (discourages stream churn)
 * - in choosing which streams to drop, streams with heavier traffic
 *   should be dropped rather than streams with lighter traffic
 * - but a stream with 2x traffic should be slightly less likely to be dropped
 *   than two streams each with x traffic (discourages creating multiple
 *   streams to carry the traffic of a single stream -- unless the two
 *   substreams really are independently useful)
 */

/* the 128-bit message ID is used for messages that should be acked.
 * Such messages set the ALLNET_TRANSPORT_ACK_REQ bit.
 * the message ID is the first MESSAGE_ID_SIZE bytes of the sha512 hash
 * of the message ACK, which is the first MESSAGE_ID_SIZE bytes
 * of the decrypted message.  For unencrypted messages, it is simply
 * the first MESSAGE_ID_SIZE bytes of the message.  The user data
 * follows the message ACK.
 *
 * Any recipient of a message ACK can tell (by hashing the ACK) that the
 * message ACK corresponds to the message ID.
 * A node receiving a message ACK and holding a copy of the message
 * can now delete this stored copy.  It may temporarily save a copy of
 * the ack, so as to ack any duplicate copies of the original message.
 *
 * the message ACK, or, for large messages, each packet ACK, is usually
 * a random nonce R.
 *
 * An ack message (ALLNET_TYPE_ACK) may carry any number of packet ACKs,
 * to ack different messages or packets in a single ack message
 *
 * encrypted messages are acked by the final recipient after decrypting
 * the message (nodes forwarding the message cannot decrypt it, so cannot
 * generate valid acks).  Cleartext messages are acked by each hop.
 *
 * A large message is a request to the network to either deliver
 * all the packets of a message, or none.  Unlike a stream, the
 * number of packets must be known in advance (messages in a stream may
 * be large messages).
 * Large messages set the bits ALLNET_TRANSPORT_ACK_REQ and
 * ALLNET_TRANSPORT_LARGE bits (only setting the ALLNET_TRANSPORT_LARGE
 * bit makes no sense and will normally lead to the packet being dropped).
 *
 * packets of a large message include a packet ID that is the hash of
 * the packet ACK, included as the first MESSAGE_ID_SIZE bytes of each packet.
 * The user data follows the packet ACK.  The message ACK is then the first
 * MESSAGE_ID_SIZE bytes of the sha512 hash of the concatenation of all
 * the packet ACKs, in the correct sequence.  The message ID is the first
 * MESSAGE_ID_SIZE bytes of the sha512 hash of this message ACK.
 *
 * Each packet may be acked independently if an encryption scheme, such
 * as counter mode, allows independent decryption of individual packets,
 * or if a sequential encryption mode is used and packets are received
 * in sequence.
 *
 * for large messages, both encrypted and cleartext, acknowledgement of
 * the message acknowledges every packet in the message.
 */

/* both long-lived streams and large packets are hard to hide from
 * traffic analysis.
 */
/* expiration simply reports when the message is no longer useful.  Packets
 * with shorter expiration may be given higher priority by intermediate
 * forwarders.
 */

#define ALLNET_STREAM_ID_SIZE		4	/*  4 bytes or 32 bits */
#define ALLNET_MESSAGE_ID_SIZE		16	/*  16 bytes or 128 bits */
#define ALLNET_MESSAGE_ID_BITS		(ALLNET_MESSAGE_ID_SIZE * 8) /* 128b */
#define ALLNET_SEQUENCE_SIZE		16	/*  16 bytes or 128 bits */

#define ALLNET_LARGE_HEADER_SIZE	\
		(ALLNET_MESSAGE_ID_SIZE + 2 * ALLNET_SEQUENCE_SIZE)
/* any data message with more than 1024 bytes of data will be fragmented */
#define ALLNET_FRAGMENT_SIZE		1024

/* any message may optionally carry an expiration time */
/* the expiration time, if not all 0's, is the number of seconds
 * since midnight, Jan 1, 2000, GMT.  This is encoded in big-endian order
 */

#define ALLNET_TIME_SIZE	8

/* the unix epoch begins Jan 1, 1970, the AllNet epoch on Jan 1, 2000.
 * The difference is: */
#define ALLNET_Y2K_SECONDS_IN_UNIX	946684800

/* a message with all possible header fields */
struct allnet_header_max {
  unsigned char version;
  unsigned char message_type;
  unsigned char hops;	   /* times this packet has been recvd, initially 0 */
  unsigned char max_hops;  /* if on receipt hops+1 >= max_hops, do not fwd */
  unsigned char src_nbits; /* num valid bits in the source address */
  unsigned char dst_nbits; /* num valid bits in the destination address */
  unsigned char sig_algo;  /* signature algorithm, constants are below */
  unsigned char transport; /* type of transport requests, 0 if none */
  unsigned char source      [ALLNET_ADDRESS_SIZE];
  unsigned char destination [ALLNET_ADDRESS_SIZE];
  /* stream_id is present if transport includes ALLNET_TRANSPORT_STREAM */
  unsigned char stream_id   [ALLNET_STREAM_ID_SIZE];
  /* message_id is present if transport includes ALLNET_TRANSPORT_ACK_REQ */
  unsigned char message_id  [ALLNET_MESSAGE_ID_SIZE];
  /* packet_id, npackets and sequence are present if ALLNET_TRANSPORT_LARGE */
  /* such packets have the same message_id, different packet_id */
  unsigned char packet_id   [ALLNET_MESSAGE_ID_SIZE];
  unsigned char npackets    [ALLNET_SEQUENCE_SIZE];
  unsigned char sequence    [ALLNET_SEQUENCE_SIZE];
  /* expiration is present if transport includes ALLNET_TRANSPORT_EXPIRATION */
  unsigned char expiration  [ALLNET_TIME_SIZE];
};

#define ALLNET_SIZE(t)	((ALLNET_HEADER_SIZE) + \
 ((((t) & ALLNET_TRANSPORT_ACK_REQ   ) == 0) ? 0 : (ALLNET_MESSAGE_ID_SIZE)) + \
 ((((t) & ALLNET_TRANSPORT_LARGE     ) == 0) ? 0:(ALLNET_LARGE_HEADER_SIZE)) + \
 ((((t) & ALLNET_TRANSPORT_STREAM    ) == 0) ? 0 : (ALLNET_STREAM_ID_SIZE)) + \
 ((((t) & ALLNET_TRANSPORT_EXPIRATION) == 0) ? 0 : (ALLNET_TIME_SIZE)))

#define ALLNET_SIZE_HEADER(hp)	(ALLNET_SIZE((hp)->transport))

#define ALLNET_STREAM_ID(hp, t, s)		\
 (((s < ALLNET_SIZE(t)) || 		\
   (((t) & ALLNET_TRANSPORT_STREAM) == 0)) ? NULL : \
   (((char *) (hp)) + ALLNET_HEADER_SIZE))

#define ALLNET_AFTER_STREAM_ID(t, s)	\
 ((s < ALLNET_SIZE(t)) ? s :		\
  ((((t) & ALLNET_TRANSPORT_STREAM) == 0) ? ALLNET_HEADER_SIZE : \
   (ALLNET_HEADER_SIZE + ALLNET_STREAM_ID_SIZE)))

#define ALLNET_MESSAGE_ID(hp, t, s)	\
 (((s < ALLNET_SIZE(t)) || 	\
   (((t) & ALLNET_TRANSPORT_ACK_REQ) == 0)) ? NULL : \
  (((char *) (hp)) + ALLNET_AFTER_STREAM_ID(t, s)))

#define ALLNET_AFTER_MESSAGE_ID(t, s)	\
 ((s < ALLNET_SIZE(t)) ? s :		\
  ((ALLNET_AFTER_STREAM_ID(t, s)) +		\
   ((((t) & ALLNET_TRANSPORT_ACK_REQ) == 0) ? 0 : ALLNET_MESSAGE_ID_SIZE)))

#define ALLNET_PACKET_ID(hp, t, s)		\
 (((s < ALLNET_SIZE(t)) || 	\
   (((t) & ALLNET_TRANSPORT_ACK_REQ) == 0) || \
   (((t) & ALLNET_TRANSPORT_LARGE) == 0)) ? NULL : \
  (((char *) (hp)) + ALLNET_AFTER_MESSAGE_ID(t, s)))

#define ALLNET_NPACKETS(hp, t, s)		\
 (((s < ALLNET_SIZE(t)) || 	\
   (((t) & ALLNET_TRANSPORT_ACK_REQ) == 0) || \
   (((t) & ALLNET_TRANSPORT_LARGE) == 0)) ? NULL : \
  (((char *) (hp)) + ALLNET_AFTER_MESSAGE_ID(t, s) + ALLNET_MESSAGE_ID_SIZE))

#define ALLNET_SEQUENCE(hp, t, s)		\
 (((s < ALLNET_SIZE(t)) || 	\
   (((t) & ALLNET_TRANSPORT_ACK_REQ) == 0) || \
   (((t) & ALLNET_TRANSPORT_LARGE) == 0)) ? NULL : \
  (((char *) (hp)) + ALLNET_AFTER_MESSAGE_ID(t, s) + ALLNET_MESSAGE_ID_SIZE + \
                   ALLNET_SEQUENCE_SIZE))

#define ALLNET_AFTER_SEQUENCE(t, s)	\
 ((s < ALLNET_SIZE(t)) ? s :		\
  (ALLNET_AFTER_MESSAGE_ID(t, s) + 		\
   ((((t) & ALLNET_TRANSPORT_LARGE) == 0) ? 0 : \
    (ALLNET_MESSAGE_ID_SIZE + ALLNET_SEQUENCE_SIZE * 2))))

#define ALLNET_EXPIRATION(hp, t, s)		\
 (((s < ALLNET_SIZE(t)) || (((t) & ALLNET_TRANSPORT_EXPIRATION) == 0)) ? NULL: \
  (((char *) (hp)) + ALLNET_AFTER_SEQUENCE(t, s)))

#define ALLNET_AFTER_EXPIRATION(t, s)	\
 ((s < ALLNET_SIZE(t)) ? s :		\
  (ALLNET_AFTER_SEQUENCE(t, s) + 		\
   ((((t) & ALLNET_TRANSPORT_EXPIRATION) == 0) ? 0 : ALLNET_TIME_SIZE)))

#define ALLNET_AFTER_HEADER(t, s)	(ALLNET_AFTER_EXPIRATION(t, s))

#define ALLNET_DATA_START(hp, t, s)		\
  (((char *) (hp)) + ALLNET_AFTER_HEADER(t, s))

/* data messages and clear messages carry, after the message ID (if any),
 * an application and media header that identifies the intended application
 * and media type.  It is up to the receiving application to use these
 * to identify messages intended for itself.
 */
/* AllNet media types are defined in media.h */
#define ALLNET_APP_ID_SIZE		4
#define ALLNET_MEDIA_ID_SIZE		4
struct allnet_app_media_header {
  unsigned char app [ALLNET_APP_ID_SIZE];
  unsigned char media [ALLNET_MEDIA_ID_SIZE];
};

/* a data request may specify the earliest time from which a message is
 * desired (a time of zero means any time).  It may also specify a bitmap
 * of destinations that are of interest -- 2^x bits.  Each bit in
 * the bitmap, when set to one, specifies that destinations matching
 * that prefix are of interest.  if x = destination_bits_power_two > 0,
 * the bitmap has 2^x bits, and floor((2^x + 7) / 8) bytes.
 * The bits within a byte are 1 << (7 - bit number), so that for example
 * 0xe6 has bits 0, 1, 2, 5, and 6 set, whereas bits 3, 4, and 7 are not set,
 * though in general it is easiest to use the allnet_bitmap_byte_*
 * functions from util.h/c
 * Similarly for the source bitmap and the message ID bitmap.
 * messages are sent back only if they match ALL the requested constraints.
 * a zero-bit bitmap will match all packets, as will a 0 time "since".
 * note that _power_two of 0 would normally imply a 1-bit bitmap, which
 * is not useful.  Therefore, a _power_two of 0 means no bits.
 *
 * mid stands for message id, and can be used to request acks for message
 * IDs known to be missing. 
 *
 * the padding is set to random bytes.  This allows us to distinguish
 * retransmitted and looped packets from new transmissions.
 * It also allows for future compatible expansion of this message format.
 *
 * An empty data request message is also allowed, and requests all
 * packets addressed TO the sender of the request.  In this case, any
 * packet with a 0-bit destination address will match any data request,
 * and a data request with a 0-bit source address will match any packet.
 */
#define ALLNET_TOKEN_SIZE	ALLNET_MESSAGE_ID_SIZE		/* 16 bytes */
struct allnet_data_request {
  unsigned char token [ALLNET_TOKEN_SIZE];
  unsigned char since [ALLNET_TIME_SIZE];
  unsigned char dst_bits_power_two;  /* bitmap has 2^this bits */
  unsigned char src_bits_power_two;  /* bitmap has 2^this bits */
  unsigned char mid_bits_power_two;  /* message ID bitmap has 2^this bits */
  unsigned char padding [5];	     /* sent as random, ignored on receipt */
  unsigned char dst_bitmap [0];
  unsigned char src_bitmap [0];
  unsigned char mid_bitmap [0];      /* message ID for messages */
};

#endif /* PACKET_H */
