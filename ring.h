#ifndef __RING_H__
#define __RING_H__

#include <netinet/in.h>

#define KNET_RING_DEFPORT 50000
#define KNET_RING_RCVBUFF 8192

/* knet_ring flags */
#define KNET_RING_ENABLED 0x01
#define KNET_RING_FLOAT   0x02

struct knet_ring {
	int sockfd;
	struct sockaddr_storage address;
	struct knet_host *host;
	struct knet_ring *next;
};

struct knet_host {
	int flags;
	struct sockaddr_storage address;
	struct knet_host *next;
};

#define KNET_FRAME_MAGIC 0x12344321
#define KNET_FRAME_VERSION 0x00000001
#define KNET_FRAME_DATA 0x00
#define KNET_FRAME_PING 0x01

struct knet_frame {
	uint32_t magic;
	uint32_t version;
	uint16_t type;
	uint16_t flags;
	uint32_t __pad;
} __attribute__((packed));

int knet_ring_start(struct knet_ring *ring);
void knet_ring_stop(struct knet_ring *ring);
inline ssize_t knet_ring_send(struct knet_ring *ring, struct knet_frame *frame, size_t len);

#endif
