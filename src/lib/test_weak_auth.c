/* test_weak_auth.c: make sure allnetd doesn't send us UDP traffic if
 * we fail to respond to the authenticating keepalives, or respond with
 * bogus ones */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "packet.h"
#include "mgmt.h"

static void print_buffer (char * buffer, int blen, const char * desc)
{
  if (desc != NULL) printf ("%s: ", desc);
  for (int i = 0; i < blen; i++)
    printf ("%02x.", buffer [i] & 0xff);
  printf ("\n");
}

int main (int argc, char ** argv)
{
  char * dest = "127.0.0.1";   /* loopback */
  int send_count = 1;
  int recv_count = -1;  /* forever */
  if (argc > 1)
    dest = argv [1];
  if (argc > 2)
    send_count = atoi (argv [2]);
  if (argc > 3)
    recv_count = atoi (argv [3]);
  printf ("destination %s, send %d, recv %d\n", dest, send_count, recv_count);
  struct sockaddr_storage sas;
  socklen_t slen;
  memset (&sas, 0, sizeof (sas));
  struct sockaddr_in * sinp = (struct sockaddr_in *) &sas;
  struct sockaddr_in6 * sinp6 = (struct sockaddr_in6 *) &sas;
  if (inet_pton (AF_INET, dest, &(sinp->sin_addr))) {
    sinp->sin_family = AF_INET;
    sinp->sin_port = htons (ALLNET_PORT);
    slen = sizeof (struct sockaddr_in);
  } else if (inet_pton (AF_INET6, dest, &(sinp6->sin6_addr))) {
    sinp6->sin6_family = AF_INET6;
    sinp6->sin6_port = htons (ALLNET_PORT);
    slen = sizeof (struct sockaddr_in6);
  } else {
    printf ("invalid address %s\n", dest);
    return 1;
  }
  struct sockaddr * sap = (struct sockaddr *) &sas;
  int sock = socket (sap->sa_family, SOCK_DGRAM, IPPROTO_UDP);
  if (sock < 0) {
    perror ("socket");
    return 2;
  }
  int sent = 0;
  int rcvd = 0;
  while (((send_count == -1) || (sent < send_count)) ||
         ((recv_count == -1) || (rcvd < recv_count))) {
    if ((send_count == -1) || (sent < send_count)) {
      char buffer [48];
      memset (buffer, 0, sizeof (buffer));
      struct allnet_header * hp = (struct allnet_header *) buffer;
      struct allnet_mgmt_header * mhp =
        (struct allnet_mgmt_header *) (buffer + 24);
      hp->version = ALLNET_VERSION;
      hp->message_type = ALLNET_TYPE_MGMT;
      hp->max_hops = 1;
      mhp->mgmt_type = ALLNET_MGMT_KEEPALIVE;
      print_buffer (buffer, 32, "sending");
      size_t r = sendto (sock, buffer, 32, 0, sap, slen);
      if (r != 32) {
        perror ("sendto");
        printf ("sendto of 32 bytes returned %zd\n", r);
      }
      sent++;
    }
    if ((recv_count == -1) || (rcvd < recv_count)) {
      char buffer [ALLNET_MTU + 48];
      struct sockaddr_storage addr;
      socklen_t alen = sizeof (addr);
      size_t r = recvfrom (sock, buffer, sizeof (buffer), 0,
                           (struct sockaddr *) &addr, &alen);
      if (r <= 0) {
        perror ("recvfrom");
        printf ("recvfrom returned %zd\n", r);
      } else {
        print_buffer (buffer, r, "received");
      }
      rcvd++;
    }
  }
  return 0;
}
