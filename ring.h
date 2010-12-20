#ifndef __RING_H__
#define __RING_H__

#include <stdint.h>
#include <netinet/in.h>

typedef struct knet_handle *knet_handle_t;

#define KNET_RING_DEFPORT 50000
#define KNET_RING_RCVBUFF 8388608

#define KNET_MAX_HOST 65536
#define KNET_MAX_LINK 8
#define KNET_MAX_HOST_LEN 64

struct knet_link {
	uint8_t link_id;
	int sock;
	char ipaddr[KNET_MAX_HOST_LEN];
	char port[6];
	struct sockaddr_storage address;
	unsigned int ready:1; /* link is configured and ready to be used */
	unsigned int enabled:1;	/* link is enabled for data */
	unsigned long long latency; /* average latency computed by fix/exp */
	unsigned int latency_exp;
	unsigned int latency_fix;
	unsigned long long ping_interval;
	unsigned long long pong_timeout;
	struct timespec ping_last;
	struct timespec pong_last;
};

struct knet_host {
	uint16_t node_id;
	char name[KNET_MAX_HOST_LEN];
	unsigned int active:1; /* data packets are sent to all links */
	struct knet_listener *listener;
	struct knet_link link[KNET_MAX_LINK];
	struct knet_host *next;
};

struct knet_listener {
	int sock;
	char ipaddr[KNET_MAX_HOST_LEN];
	char port[6];
	struct sockaddr_storage address;
	struct knet_listener *next;
};

union knet_frame_data {
	uint8_t			kfd_data[0];
	struct {
		uint16_t	kfd_node;
		uint8_t		kfd_link;
		struct timespec	kfd_time;
	};
} __attribute__((packed));

struct knet_frame {
	uint32_t 		kf_magic;
	uint8_t			kf_version;
	uint8_t			kf_type;
	uint16_t		__pad;
	union knet_frame_data	kf_payload;
} __attribute__((packed));

#define kf_data kf_payload.kfd_data
#define kf_node kf_payload.kfd_node
#define kf_link kf_payload.kfd_link
#define kf_time kf_payload.kfd_time

#define KNET_FRAME_SIZE (sizeof(struct knet_frame) - sizeof(union knet_frame_data))

#define KNET_FRAME_MAGIC 0x12344321
#define KNET_FRAME_VERSION 0x01

#define KNET_FRAME_DATA 0x00
#define KNET_FRAME_PING 0x01
#define KNET_FRAME_PONG 0x03

knet_handle_t knet_handle_new(int fd, uint16_t node_id);
void knet_handle_setfwd(knet_handle_t knet_h, int enabled);
int knet_handle_free(knet_handle_t knet_h);

int knet_host_add(knet_handle_t knet_h, uint16_t node_id);
int knet_host_acquire(knet_handle_t knet_h, struct knet_host **host);
int knet_host_get(knet_handle_t knet_h, uint16_t node_id, struct knet_host **host);
int knet_host_release(knet_handle_t knet_h, struct knet_host **host);
int knet_host_remove(knet_handle_t knet_h, uint16_t node_id);

void knet_link_timeout(struct knet_link *lnk, time_t interval, time_t timeout, int precision);

#define KNET_HOST_FOREACH_NEXT 0	/* next host */
#define KNET_HOST_FOREACH_FOUND 1	/* host found, exit loop */

struct knet_host_search {
	int 			param1;	/* user parameter 1 */
	void 			*data1;	/* user data pointer 1 */
	void 			*data2;	/* user data pointer 2 */
	int 			retval;	/* search return value */
};

typedef int (*knet_link_fn_t)(knet_handle_t knet_h, struct knet_host *host, struct knet_host_search *data);
int knet_host_foreach(knet_handle_t knet_h, knet_link_fn_t linkfun, struct knet_host_search *data);

int knet_listener_acquire(knet_handle_t knet_h, struct knet_listener **head, int writelock);
int knet_listener_release(knet_handle_t knet_h);
int knet_listener_add(knet_handle_t knet_h, struct knet_listener *listener);
int knet_listener_remove(knet_handle_t knet_h, struct knet_listener *listener);

#endif
