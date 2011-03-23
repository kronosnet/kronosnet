#ifndef __KNETHANDLE_H__
#define __KNETHANDLE_H__

/* NOTE: you shouldn't need to include this header normally, it is provided for
 *       testing purpose only.
 */

#include "libknet.h"

#define timespec_diff(start, end, diff) \
do { \
	if (end.tv_sec > start.tv_sec) \
		*(diff) = ((end.tv_sec - start.tv_sec) * 1000000000llu) \
					+ end.tv_nsec - start.tv_nsec; \
	else \
		*(diff) = end.tv_nsec - start.tv_nsec; \
} while (0);

struct knet_handle {
	int sockfd;
	int epollfd;
	uint16_t node_id;
	unsigned int enabled:1;
	struct knet_host *host_head;
	struct knet_host *host_index[KNET_MAX_HOST];
	struct knet_listener *listener_head;
	struct knet_frame *databuf;
	struct knet_frame *pingbuf;
	pthread_t control_thread;
	pthread_t heartbt_thread;
	pthread_rwlock_t list_rwlock;
};

#endif
