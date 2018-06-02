/* app_util.h: utilities for apps */

#ifndef ALLNET_APP_UTIL_H
#define ALLNET_APP_UTIL_H

#define KEEPALIVE_SECONDS	10  /* apps should send a keepalive every 10s */

/* returns a UDP socket used to send messages to the allnet daemon
 * or receive messages from the allnet daemon
 * returns -1 in case of failure
 * arg0 is the first argument that main gets -- useful for finding binaries
 * path, if not NULL, tells allnet what path to use for config files
 * to receive messages, the application MUST send messages (perhaps empty)
 * at least once every 10 seconds otherwise, after a while (about 1 minute)
 * allnet will stop forwarding messages to this socket.
 * NOTICE: this can only be called ONCE in any given process, so if there is
 * no fork, there still should only be one call to this function. */
extern int connect_to_local (const char * program_name,
                             const char * arg0,
                             const char * path,
                             int start_allnet_if_needed,
                             int start_keepalive_thread);

/* return 1 for success, 0 otherwise */
extern int local_send (const char * message, int msize, unsigned int priority);
extern void local_send_keepalive (int send_even_if_recently_sent);
/* return the message size > 0 for success, 0 otherwise. timeout in ms */
extern int local_receive (unsigned int timeout,
                          char ** message, unsigned int * priority);

/* since allnet may run on devices with limited power, some things
 * (speculative computation, i.e. stuff that is not needed immediately)
 * may be postponed if we are not plugged in to power */
extern int speculative_computation_is_ok (void);  /* initially yes */
extern void set_speculative_computation (int ok);

#ifdef GET_BCKEY_IS_IMPLEMENTED
/* retrieve or request a public key.
 *
 * if successful returns the key length and sets *key to point to
 * statically allocated storage for the key (do not modify in any way)
 * if not successful, returns 0.
 *
 * max_time_ms and max_hops are only used if the address has not
 * been seen before.  If so, a key request is sent with max_hops, and
 * we wait at most max_time_ms (or quit after receiving max_keys).
 */
extern unsigned int get_bckey (pd p, char * address, char ** key,
                               int max_time_ms, int max_keys, int max_hops);
#endif /* GET_BCKEY_IS_IMPLEMENTED */


#endif /* ALLNET_APP_UTIL_H */
