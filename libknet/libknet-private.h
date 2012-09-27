#ifndef __KNETHANDLE_H__
#define __KNETHANDLE_H__

/* NOTE: you shouldn't need to include this header normally, it is provided for
 *       testing purpose only.
 */

#include "libknet.h"

#define KNET_DATABUFSIZE 131072 /* 128k */
#define KNET_PINGBUFSIZE sizeof(struct knet_frame)

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
	int tap_to_links_epollfd;
	int recv_from_links_epollfd;
	uint16_t node_id;
	unsigned int enabled:1;
	struct knet_host *host_head;
	struct knet_host *host_index[KNET_MAX_HOST];
	struct knet_listener *listener_head;
	struct knet_frame *tap_to_links_buf;
	unsigned char *tap_to_links_buf_crypt;
	struct knet_frame *recv_from_links_buf;
	unsigned char *recv_from_links_buf_crypt;
	struct knet_frame *pingbuf;
	unsigned char *pingbuf_crypt;
	pthread_t tap_to_links_thread;
	pthread_t recv_from_links_thread;
	pthread_t heartbt_thread;
	pthread_rwlock_t list_rwlock;
	struct crypto_instance *crypto_instance;
	off_t dst_nodeid_offset;
	size_t dst_nodeid_len;
	seq_num_t bcast_seq_num;
	seq_num_t ucast_seq_num;
};

int _fdset_cloexec(int fd);

#endif
