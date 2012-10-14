#ifndef __LIBKNET_PRIVATE_H__
#define __LIBKNET_PRIVATE_H__

/*
 * NOTE: you shouldn't need to include this header normally
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
	uint16_t node_id;
	unsigned int enabled:1;
	int sockfd;
	int pipefd[2];
	int tap_to_links_epollfd;
	int recv_from_links_epollfd;
	int dst_link_handler_epollfd;
	struct knet_host *host_head;
	struct knet_host *host_tail;
	struct knet_host *host_index[KNET_MAX_HOST];
	struct knet_listener *listener_head;
	struct knet_frame *tap_to_links_buf;
	struct knet_frame *recv_from_links_buf;
	struct knet_frame *pingbuf;
	pthread_t tap_to_links_thread;
	pthread_t recv_from_links_thread;
	pthread_t heartbt_thread;
	pthread_t dst_link_handler_thread;
	pthread_rwlock_t list_rwlock;
	struct crypto_instance *crypto_instance;
	unsigned char *tap_to_links_buf_crypt;
	unsigned char *recv_from_links_buf_crypt;
	unsigned char *pingbuf_crypt;
	seq_num_t bcast_seq_num_tx;
	uint8_t dst_host_filter;
	int (*dst_host_filter_fn) (
		const unsigned char *outdata,
		ssize_t outdata_len,
		uint16_t src_node_id,
		uint16_t *dst_host_ids,
		size_t *dst_host_ids_entries);
};

int _fdset_cloexec(int fd);
int _fdset_nonblock(int fd);
int _dst_cache_update(knet_handle_t knet_h, uint16_t node_id);
int knet_should_deliver(struct knet_host *host, int bcast, seq_num_t seq_num);
void knet_has_been_delivered(struct knet_host *host, int bcast, seq_num_t seq_num);

#endif
