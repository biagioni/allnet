/* adht.c: maintain a Distributed Hash Table of connected nodes */
 * every allnet node that has an externally reachable IP (erIP) address
 *  joins a global internet-wide DHT
 * the DHT is used to subdivide the address space among different DHT nodes
 * messages sent to a destination address are only sent to DHT nodes
 *  accepting messages for that part of the address space.
 * addresses have up to 64 bits.  Each DHT node keeps track of up to
 *  n * 64 other DHT nodes, where usually n = 4.
 * a DHT node self-selects an address a, and perhaps additional addresses a1...
 * since addresses are numeric, each value a places the DHT node into the
 *  DHT at a location corresponding to a, such that the DHT node has
 *  successors b, c, d, e, f, ...
 * each DHT node accepts messages for the part of the address space
 *  from a to the 4th successor of a
 * in this example, it accepts all addresses a, b, c, d, up to but
 *  not including e
 * if a DHT node receives a message that it does not accept, it attempts
 *  to forward the message to a DHT node closer to the address
 * messages that match many DHT nodes are no longer forwarded once they
 *  reach a matching node
 * if there are fewer than 4 nodes in the DHT, each node accepts all messages
 */
/* adht always keeps track of nodes in the DHT, and forwards messages
 *  accordingly
 * if the node has an erIP, adht also stores messages to addresses it
 *  takes responsibility for
 */
