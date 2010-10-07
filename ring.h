#ifndef __RING_H__
#define __RING_H_

#include <netinet/in.h>

#define KNET_RING_DEFPORT 50000
#define KNET_RING_RCVBUFF 8192


struct knet_ring {
	int sock;
	union {
		sa_family_t sa_family;
		struct sockaddr_in in;
		struct sockaddr_in6 in6;
	} info;
	struct knet_ring *next;
};


int knet_ring_listen(in_port_t port);
int knet_ring_connect(struct knet_ring *ring);
void knet_ring_disconnect(struct knet_ring *ring);


#endif
