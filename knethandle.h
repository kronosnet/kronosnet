#ifndef __KNETHANDLE_H__
#define __KNETHANDLE_H__

/* NOTE: you shouldn't need to include this header normally, it is provided for
 *       testing purpose only.
 */

#include "ring.h"

struct knet_handle {
	int sock[2];
	int epollfd;
	struct knet_host *host_head;
	struct knet_listener *listener_head;
	struct knet_frame *databuf;
	struct knet_frame *pingbuf;
	pthread_t control_thread;
	pthread_t heartbt_thread;
	pthread_rwlock_t list_rwlock;
};

#endif
