/*
 * Copyright (C) 2010-2012 Red Hat, Inc.  All rights reserved.
 *
 * Authors: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *          Federico Simoncelli <fsimon@kronosnet.org>
 *
 * This software licensed under GPL-2.0+, LGPL-2.0+
 */

#ifndef __INTERNALS_H__
#define __INTERNALS_H__

/*
 * NOTE: you shouldn't need to include this header normally
 */

#include "libknet.h"

#define KNET_DATABUFSIZE KNET_MAX_PACKET_SIZE + KNET_FRAME_SIZE + sizeof(seq_num_t)
#define KNET_DATABUFSIZE_CRYPT KNET_DATABUFSIZE * 2

#define timespec_diff(start, end, diff) \
do { \
	if (end.tv_sec > start.tv_sec) \
		*(diff) = ((end.tv_sec - start.tv_sec) * 1000000000llu) \
					+ end.tv_nsec - start.tv_nsec; \
	else \
		*(diff) = end.tv_nsec - start.tv_nsec; \
} while (0);

struct knet_listener {
	int sock;
	struct sockaddr_storage address;
	struct knet_listener *next;
};


struct knet_link {
	/* required */
	struct sockaddr_storage src_addr;
	struct sockaddr_storage dst_addr;
	/* configurable */
	unsigned int dynamic; /* see KNET_LINK_DYN_ define above */
	uint8_t  priority; /* higher priority == preferred for A/P */
	unsigned long long ping_interval; /* interval */
	unsigned long long pong_timeout; /* timeout */
	unsigned int latency_fix; /* precision */
	/* status */
	struct knet_link_status status;
	/* internals */
	uint8_t link_id;
	int listener_sock;
	unsigned int remoteconnected:1; /* link is enabled for data (peer view) */
	unsigned int donnotremoteupdate:1;    /* define source of the update */
	unsigned int host_info_up_sent:1; /* 0 if we need to notify remote that link is up */
	unsigned int latency_exp;
	struct timespec ping_last;
};

#define KNET_CBUFFER_SIZE 4096
/*
typedef uint64_t seq_num_t;
#define SEQ_MAX UINT64_MAX
*/
typedef uint16_t seq_num_t;
#define SEQ_MAX UINT16_MAX

struct knet_host {
	/* required */
	uint16_t node_id;
	/* configurable */
	uint8_t link_handler_policy;
	char name[KNET_MAX_HOST_LEN];
	/* internals */
	char bcast_circular_buffer[KNET_CBUFFER_SIZE];
	seq_num_t bcast_seq_num_rx;
	char ucast_circular_buffer[KNET_CBUFFER_SIZE];
	seq_num_t ucast_seq_num_tx;
	seq_num_t ucast_seq_num_rx;
	struct knet_link link[KNET_MAX_LINK];
	uint8_t active_link_entries;
	uint8_t active_links[KNET_MAX_LINK];
	struct knet_host *next;
};

struct knet_handle {
	uint16_t node_id;
	unsigned int enabled:1;
	int sockfd;
	int logfd;
	uint8_t log_levels[KNET_MAX_SUBSYSTEMS];
	int hostpipefd[2];
	int dstpipefd[2];
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
	pthread_rwlock_t host_rwlock;
	pthread_mutex_t host_mutex;
	pthread_cond_t host_cond;
	struct crypto_instance *crypto_instance;
	unsigned char *tap_to_links_buf_crypt;
	unsigned char *recv_from_links_buf_crypt;
	unsigned char *pingbuf_crypt;
	seq_num_t bcast_seq_num_tx;
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
int _send_host_info(knet_handle_t knet_h, const void *data, const size_t datalen);
int _should_deliver(struct knet_host *host, int bcast, seq_num_t seq_num);
void _has_been_delivered(struct knet_host *host, int bcast, seq_num_t seq_num);

int _listener_add(knet_handle_t knet_h, struct knet_link *lnk);
int _listener_remove(knet_handle_t knet_h, struct knet_link *lnk);

void log_msg(knet_handle_t knet_h, uint8_t subsystem, uint8_t msglevel,
	     const char *fmt, ...) __attribute__((format(printf, 4, 5)));;

#define log_err(knet_h, subsys, fmt, args...) log_msg(knet_h, subsys, KNET_LOG_ERR, fmt, ##args)
#define log_warn(knet_h, subsys, fmt, args...) log_msg(knet_h, subsys, KNET_LOG_WARN, fmt, ##args)
#define log_info(knet_h, subsys, fmt, args...) log_msg(knet_h, subsys, KNET_LOG_INFO, fmt, ##args)
#define log_debug(knet_h, subsys, fmt, args...) log_msg(knet_h, subsys, KNET_LOG_DEBUG, fmt, ##args)

#endif
