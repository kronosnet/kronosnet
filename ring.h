#ifndef __RING_H__
#define __RING_H__

#include <netinet/in.h>

#define KNET_RING_DEFPORT 50000
#define KNET_RING_RCVBUFF 8192

#define KNET_RING_FLAGFLOAT 0x01

struct knet_ring {
	int sockfd;
	int flags;
	struct sockaddr_storage info;
	struct knet_ring *next;
};

int knet_ring_listen(const struct sockaddr *addr_info, const size_t addr_len);
int knet_ring_init(struct knet_ring *ring, sa_family_t family);
void knet_ring_free(struct knet_ring *ring);
ssize_t knet_ring_send(struct knet_ring *ring, const void *buf, size_t len);

#endif
