/* abc.h: broadcast messages on local interfaces */

#ifndef ALLNET_ABC_H
#define ALLNET_ABC_H

#include "packet.h"
#include "sockets.h"

#define ALLNET_IPV4_BROADCAST_PORT      (ALLNET_PORT + 1)  /* 41242 */
#define ALLNET_IPV6_BROADCAST_PORT      (ALLNET_PORT + 2)  /* 41243 */

extern int add_local_broadcast_sockets (struct socket_set * sockets);

#endif /* ALLNET_ABC_H */
