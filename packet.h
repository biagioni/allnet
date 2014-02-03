/* packet.h: definition of AllNet packet headers */

#ifndef PACKET_H
#define PACKET_H

/* allnet uses two ports: allnet port, for exchanges among peers on different
 * machines, and allnet local port, for connection by local clients to
 * the allnet daemon
 */
#define ALLNET_PORT 	     (htons (0xa119))  /* ALLNet, 41241 */
#define ALLNET_LOCAL_PORT    (htons (0xa11e))  /* ALLnEt, 41246 */

/* protocol number used when sending/receiving over 802.11, WiFi */
#define ALLNET_WIFI_PROTOCOL (htons (0xa119))  /* ALLNet, 41241 */

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
 * If the size is not valid for the given signature algorithm, the
 * signature is not valid.
 *
 * the signature, if any, covers all the bytes from the end of the header
 * to the beginning of the signature.  That means, for encrypted messages,
 * that the signature is computed over the encrypted data.
 */

#define ADDRESS_SIZE		 	 8	/* 8 bytes or 64 bits */
#define ADDRESS_BITS	 	(ADDRESS_SIZE * 8)	/* 64 */

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
  unsigned char source      [ADDRESS_SIZE];
  unsigned char destination [ADDRESS_SIZE];
/* the next fields are only present if transport so indicates */
};

/* a message is invalid under the following circumstances:
 * non-zero transport for ALLNET_TYPE_ACK or ALLNET_TYPE_DATA_REQ
 * payload for ALLNET_TYPE_ACK not a multiple (> 0) of MESSAGE_ID_SIZE payload
 * ALLNET_TRANSPORT_ACK_REQ bit set, but payload less than MESSAGE_ID_SIZE
 * ALLNET_TRANSPORT_LARGE bit set without ALLNET_TRANSPORT_ACK_REQ bit
 * ALLNET_TRANSPORT_EXPIRATION bit set but the expiration time is in the past
 *
 * invalid messages are normally discarded by allnet hosts
 */

/* 24 bytes (192 bits) */
#define ALLNET_HEADER_SIZE	(sizeof (struct allnet_header))

/* used in sig_algo */
#define ALLNET_SIGTYPE_NONE			  0
#define ALLNET_SIGTYPE_RSA_PKCS1		  1
#define ALLNET_SIGTYPE_secp128r1		130
/* signature appears at the end of the message, with the number of bytes
 * in the last 2 bytes */
struct allnet_signature {
  unsigned char certificate [0];
  unsigned char sig_nbits [2];   /* number of bytes, MSB first */
};

/* ALLNET_TYPE_KEY_XCHG carries a public key followed by
 *   an hmac of (the public key followed by a secret nonce).
 * ALLNET_TYPE_KEY_REQ
 *   carries a (partial) fingerprint of a public key.  The public key sent
 *   in response should match the given fingerprint, and be for transmissions
 *   to the given source address from the given destination address.
 *   The reply is sent as a normal data message, encrypted using the
 *   given reply key (usually, a different reply key is used for
 *   each request)
 *   If the reply key is not given, the answer is sent in the clear.
 */
struct allnet_key_exchange {
  unsigned char nbytes_hmac;  	    /* number of bytes in the hmac */
  unsigned char hmac [0];           /* confirms knowledge of secret nonce */
  unsigned char public_key [0];     /* public key to be used */
};
struct allnet_key_request {
  unsigned char nbytes_fingerprint;  /* number of bytes in the fingerprint */
  unsigned char fingerprint [0];     /* nbytes of fingerprint,
                                        identifies requested public key */
  unsigned char reply_key [0];       /* public key for reply, may be omitted */
};

/* a LARGE packet must be an ACK packet.  All the other flags are orthogonal */
#define ALLNET_TRANSPORT_STREAM		1	/* related packets */
#define ALLNET_TRANSPORT_ACK_REQ	2	/* message_id allows acking */
#define ALLNET_TRANSPORT_LARGE		4	/* packets part of 1 message */
#define ALLNET_TRANSPORT_EXPIRATION	8	/* expiration specified */
#define ALLNET_TRANSPORT_TRACE		16	/* report path traversed */

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
 * The user data tne follows the packet ACK.  The message ACK is then the first
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
 * trace requests that new information be added to the message header
 * about the current forwarder (this is optional).  The forwarder
 * may also send an intermediate response listing the message ID rather
 * than the message ACK.  This provides the functionality of traceroute.
 *
 * A sender of a trace message should always set the first entry, so that
 * a trace with num_entries == 0 is not valid.
 *
 * although the final recipient may return the response in any manner
 * desired, intermediate responses are always returned as
 * ALLNET_MGMT_TRACE_PATH messages, sent with very low priority.
 *
 * The presence or absence of a TRACE flag should not affect the priority
 * of messages in any way, although the overall message size might.
 */

#define MESSAGE_ID_SIZE			16	/*  16 bytes or 128 bits */
#define MESSAGE_ID_BITS			(MESSAGE_ID_SIZE * 8)	/* 128 bits */
#define SEQUENCE_SIZE			16	/*  16 bytes or 128 bits */

#define LARGE_HEADER_SIZE		(MESSAGE_ID_SIZE + 2 * SEQUENCE_SIZE)

/* any message may optionally carry an expiration time */
/* the expiration time, if not all 0's, is the number of seconds
 * since midnight, Jan 1, 2000, GMT.  This is encoded in big-endian order
 */

#define ALLNET_TIME_SIZE	8

/* the unix epoch begins Jan 1, 1970, the AllNet epoch on Jan 1, 2000.
 * The difference is: */
#define Y2K_SECONDS_IN_UNIX	946720800

/* a trace should contain a timestamp of the time of receipt using the
 * receiving/forwarding node's clock.
 * The timestamp is in fixed-point format: an allnet time in the first
 * ALLNET_TIME_SIZE bytes, followed by a fraction of a second.
 * the fraction of a second is in binary, (multiplied by 2^64).
 * A precision gives the number of valid bits in the fraction, and may be 0.
 *
 * since times are sometimes accurate to powers of 10, we use nbits > 64
 * means a decimal number <= (10^(nbits-64)) is stored in the low-order
 * part of fraction, and this should be used as the fractional part.
 * if the value > (10^(nbits-64)), the fraction is not valid or usable.
 *
 * The trace may optionally carry an AllNet address.  Any unused bits of
 * the address should be set to zero. */
struct allnet_trace_entry {
  unsigned char precision;      /* see comment */
  unsigned char nbits;          /* meaningful bits of address, may be zero */
                                /* or n-64 digits if n > 64 */
                                /* or -1/0xff/255 for an unused entry */
  unsigned char pad [6];
  unsigned char seconds [ALLNET_TIME_SIZE];
  unsigned char seconds_fraction [ALLNET_TIME_SIZE];
  unsigned char address [ADDRESS_SIZE];
};

/* every trace packet carries this many traces.  Trace entries are kept
 * in FIFO order, with each new entry replacing the oldest. */
/* unused entries have an illegal value of nbits = 0xff/255 */
/* each trace entry takes 32 bytes, so an overall trace size is 512 bytes */
#define ALLNET_NUM_TRACES	16
#define ALLNET_TRACE_SIZE	(sizeof (struct allnet_trace_entry) * \
				ALLNET_NUM_TRACES)

#define ALLNET_UNUSED_TRACE	0xff
#define ALLNET_VALID_TRACE(th, index)	\
	((((th) [index].nbits) & 0xff) <= ADDRESS_BITS)

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
  unsigned char source      [ADDRESS_SIZE];
  unsigned char destination [ADDRESS_SIZE];
  unsigned char stream_id   [MESSAGE_ID_SIZE]; /* if ALLNET_TRANSPORT_STREAM */
  unsigned char message_id  [MESSAGE_ID_SIZE]; /* if ALLNET_TRANSPORT_ACK_REQ */
  unsigned char packet_id   [MESSAGE_ID_SIZE]; /* if ALLNET_TRANSPORT_LARGE */
  unsigned char npackets    [SEQUENCE_SIZE];   /* if ALLNET_TRANSPORT_LARGE */
  unsigned char sequence    [SEQUENCE_SIZE];   /* if ALLNET_TRANSPORT_LARGE */
  unsigned char expiration  [ALLNET_TIME_SIZE];
                                          /* if ALLNET_TRANSPORT_EXPIRATION */
  struct allnet_trace_entry trace [ALLNET_NUM_TRACES];
                                               /* if ALLNET_TRANSPORT_TRACE */
};

#define ALLNET_SIZE(t)	((ALLNET_HEADER_SIZE) + \
 ((((t) & ALLNET_TRANSPORT_ACK_REQ   ) == 0) ? 0 : (MESSAGE_ID_SIZE)) + \
 ((((t) & ALLNET_TRANSPORT_LARGE     ) == 0) ? 0 : (LARGE_HEADER_SIZE)) + \
 ((((t) & ALLNET_TRANSPORT_STREAM    ) == 0) ? 0 : (MESSAGE_ID_SIZE)) + \
 ((((t) & ALLNET_TRANSPORT_EXPIRATION) == 0) ? 0 : (ALLNET_TIME_SIZE)) + \
 ((((t) & ALLNET_TRANSPORT_TRACE     ) == 0) ? 0 : (ALLNET_TRACE_SIZE)))

#define ALLNET_SIZE_HEADER(hp)	(ALLNET_SIZE((hp)->transport))

#define ALLNET_STREAM_ID(hp, t, s)		\
 (((s < ALLNET_SIZE(t)) || 		\
   (((t) & ALLNET_TRANSPORT_STREAM) == 0)) ? NULL : \
   (((char *) hp) + ALLNET_HEADER_SIZE))

#define ALLNET_AFTER_STREAM_ID(t, s)	\
 ((s < ALLNET_SIZE(t)) ? s :		\
  ((((t) & ALLNET_TRANSPORT_STREAM) == 0) ? ALLNET_HEADER_SIZE : \
   (ALLNET_HEADER_SIZE + MESSAGE_ID_SIZE)))

#define ALLNET_MESSAGE_ID(hp, t, s)	\
 (((s < ALLNET_SIZE(t)) || 	\
   (((t) & ALLNET_TRANSPORT_ACK_REQ) == 0)) ? NULL : \
  (((char *) hp) + ALLNET_AFTER_STREAM_ID(t, s)))

#define ALLNET_AFTER_MESSAGE_ID(t, s)	\
 ((s < ALLNET_SIZE(t)) ? s :		\
  ((ALLNET_AFTER_STREAM_ID(t, s)) +		\
   ((((t) & ALLNET_TRANSPORT_ACK_REQ) == 0) ? 0 : MESSAGE_ID_SIZE)))

#define ALLNET_PACKET_ID(hp, t, s)		\
 (((s < ALLNET_SIZE(t)) || 	\
   (((t) & ALLNET_TRANSPORT_ACK_REQ) == 0) || \
   (((t) & ALLNET_TRANSPORT_LARGE) == 0)) ? NULL : \
  (((char *) hp) + ALLNET_AFTER_STREAM_ID(t, s) + MESSAGE_ID_SIZE))

#define ALLNET_NPACKETS(hp, t, s)		\
 (((s < ALLNET_SIZE(t)) || 	\
   (((t) & ALLNET_TRANSPORT_ACK_REQ) == 0) || \
   (((t) & ALLNET_TRANSPORT_LARGE) == 0)) ? NULL : \
  (((char *) hp) + ALLNET_AFTER_STREAM_ID(t, s) + MESSAGE_ID_SIZE * 2))

#define ALLNET_SEQUENCE(hp, t, s)		\
 (((s < ALLNET_SIZE(t)) || 	\
   (((t) & ALLNET_TRANSPORT_ACK_REQ) == 0) || \
   (((t) & ALLNET_TRANSPORT_LARGE) == 0)) ? NULL : \
  (((char *) hp) + ALLNET_AFTER_MESSAGE_ID(t, s) + MESSAGE_ID_SIZE + \
                   SEQUENCE_SIZE))

#define ALLNET_AFTER_SEQUENCE(t, s)	\
 ((s < ALLNET_SIZE(t)) ? s :		\
  (ALLNET_AFTER_MESSAGE_ID(t, s) + 		\
   ((((t) & ALLNET_TRANSPORT_LARGE) == 0) ? 0 : \
    (MESSAGE_ID_SIZE + SEQUENCE_SIZE * 2))))

#define ALLNET_EXPIRATION(hp, t, s)		\
 (((s < ALLNET_SIZE(t)) || (((t) & ALLNET_TRANSPORT_EXPIRATION) == 0)) ? NULL: \
  (((char *) hp) + ALLNET_AFTER_SEQUENCE(t, s)))

#define ALLNET_AFTER_EXPIRATION(t, s)	\
 ((s < ALLNET_SIZE(t)) ? s :		\
  (ALLNET_AFTER_SEQUENCE(t, s) + 		\
   ((((t) & ALLNET_TRANSPORT_EXPIRATION) == 0) ? 0 : ALLNET_TIME_SIZE)))

#define ALLNET_TRACE(hp, t, s)		\
 (((s < ALLNET_SIZE(t)) || (((t) & ALLNET_TRANSPORT_TRACE) == 0)) ? NULL: \
  (((char *) hp) + ALLNET_AFTER_EXPIRATION(t, s)))

#define ALLNET_AFTER_TRACE(t, s)	\
 ((s < ALLNET_SIZE(t)) ? s :		\
  (ALLNET_AFTER_EXPIRATION(t, s) + 		\
   ((((t) & ALLNET_TRANSPORT_TRACE) == 0) ? 0 : ALLNET_TRACE_SIZE)))

#define ALLNET_AFTER_HEADER(t, s)	(ALLNET_AFTER_TRACE(t, s))

#define ALLNET_DATA_START(hp, t, s)		\
  (((char *) hp) + ALLNET_AFTER_HEADER(t, s))

#endif /* PACKET_H */
