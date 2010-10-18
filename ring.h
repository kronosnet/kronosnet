#ifndef __RING_H__
#define __RING_H__

#include <stdint.h>
#include <netinet/in.h>

typedef struct __knet_handle *knet_handle_t;

#define KNET_RING_DEFPORT 50000
#define KNET_RING_RCVBUFF 8192

struct knet_host {
	unsigned int active:1; /* data packets are sent to all links */
	struct knet_link *link;
	struct knet_host *next;
};

struct knet_link {
	int sock;
	unsigned int enabled:1;	/* link is enabled for data */
	struct sockaddr_storage address;
	struct knet_link *next;
};

#define KNET_FRAME_MAGIC 0x12344321
#define KNET_FRAME_VERSION 0x01

#define KNET_FRAME_DATA 0x00
#define KNET_FRAME_PING 0x01
#define KNET_FRAME_PONG 0x02

struct knet_frame {
	uint32_t magic;
	uint8_t	version;
	uint8_t type;
	uint16_t __pad;
} __attribute__((packed));

knet_handle_t knet_handle_new(void);
int knet_handle_getfd(knet_handle_t knet_h);

int knet_host_add(knet_handle_t khandle, struct knet_host *host);
int knet_host_remove(knet_handle_t khandle, struct knet_host *host);
int knet_host_foreach(knet_handle_t khandle, int (*action)(struct knet_host *, void *), void *data);

int knet_bind(struct sockaddr *address, socklen_t addrlen);
ssize_t knet_dispatch(int sockfd, struct knet_frame *frame, size_t len);
void knet_send(struct knet_host *host, struct knet_frame *frame, size_t len);

#endif
