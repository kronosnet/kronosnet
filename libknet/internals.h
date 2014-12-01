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
	uint8_t pong_count; /* how many ping/pong to send/receive before link is up */
	/* status */
	struct knet_link_status status;
	/* internals */
	uint8_t link_id;
	int listener_sock;
	unsigned int configured:1; /* set to 1 if src/dst have been configured */
	unsigned int remoteconnected:1; /* link is enabled for data (peer view) */
	unsigned int donnotremoteupdate:1;    /* define source of the update */
	unsigned int host_info_up_sent:1; /* 0 if we need to notify remote that link is up */
	unsigned int latency_exp;
	uint8_t received_pong;
	struct timespec ping_last;
	/* used by PMTUD thread as temp per-link variables and should always contain the onwire_len value! */
	uint16_t last_good_mtu;
	uint16_t last_bad_mtu;
	uint16_t last_sent_mtu;
	uint16_t last_recv_mtu;
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
	uint16_t host_id;
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
	uint16_t host_id;
	unsigned int enabled:1;
	int sockfd;
	int logfd;
	uint8_t log_levels[KNET_MAX_SUBSYSTEMS];
	int hostpipefd[2];
	int dstpipefd[2];
	int tap_to_links_epollfd;
	int recv_from_links_epollfd;
	int dst_link_handler_epollfd;
	int pmtud_in_progress;
	int pmtud_fini_requested;
	unsigned int pmtud_interval;
	unsigned int link_mtu;
	unsigned int data_mtu;
	struct knet_host *host_head;
	struct knet_host *host_tail;
	struct knet_host *host_index[KNET_MAX_HOST];
	uint16_t host_ids[KNET_MAX_HOST];
	size_t   host_ids_entries;
	struct knet_listener *listener_head;
	struct knet_frame *tap_to_links_buf;
	struct knet_frame *recv_from_links_buf;
	struct knet_frame *pingbuf;
	struct knet_frame *pmtudbuf;
	pthread_t tap_to_links_thread;
	pthread_t recv_from_links_thread;
	pthread_t heartbt_thread;
	pthread_t dst_link_handler_thread;
	pthread_t pmtud_link_handler_thread;
	int lock_init_done;
	pthread_rwlock_t list_rwlock;
	pthread_rwlock_t listener_rwlock;
	pthread_rwlock_t host_rwlock;
	pthread_mutex_t host_mutex;
	pthread_cond_t host_cond;
	pthread_mutex_t pmtud_mutex;
	pthread_cond_t pmtud_cond;
	pthread_mutex_t pmtud_timer_mutex;
	pthread_cond_t pmtud_timer_cond;
	struct crypto_instance *crypto_instance;
	uint16_t sec_header_size;
	uint16_t sec_block_size;
	uint16_t sec_hash_size;
	uint16_t sec_salt_size;
	unsigned char *tap_to_links_buf_crypt;
	unsigned char *recv_from_links_buf_crypt;
	unsigned char *pingbuf_crypt;
	unsigned char *pmtudbuf_crypt;
	seq_num_t bcast_seq_num_tx;
	int (*dst_host_filter_fn) (
		const unsigned char *outdata,
		ssize_t outdata_len,
		uint16_t src_node_id,
		uint16_t *dst_host_ids,
		size_t *dst_host_ids_entries);
	void (*pmtud_notify_fn) (
		unsigned int link_mtu,
		unsigned int data_mtu);
	int fini_in_progress;
};

#endif
