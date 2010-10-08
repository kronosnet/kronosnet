#ifndef __RING_H__
#define __RING_H__

#include <netinet/in.h>

#define KNET_RING_DEFPORT 50000
#define KNET_RING_RCVBUFF 8192


struct knet_ring {
	int sock;
	struct sockaddr_storage info;
	struct knet_ring *next;
};


int knet_ring_listen(const struct sockaddr *addr_info, const size_t addr_len);
int knet_ring_connect(struct knet_ring *ring);
void knet_ring_disconnect(struct knet_ring *ring);


#endif
