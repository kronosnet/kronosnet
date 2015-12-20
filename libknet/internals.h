/*
 * Copyright (C) 2010-2015 Red Hat, Inc.  All rights reserved.
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
#include "onwire.h"

#define KNET_DATABUFSIZE KNET_MAX_PACKET_SIZE + KNET_HEADER_ALL_SIZE
#define KNET_DATABUFSIZE_CRYPT_PAD 1024
#define KNET_DATABUFSIZE_CRYPT KNET_DATABUFSIZE + KNET_DATABUFSIZE_CRYPT_PAD

#define PCKT_FRAG_MAX UINT8_MAX

#define KNET_EPOLL_MAX_EVENTS KNET_DATAFD_MAX

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
	uint32_t last_good_mtu;
	uint32_t last_bad_mtu;
	uint32_t last_sent_mtu;
	uint32_t last_recv_mtu;
};

#define KNET_CBUFFER_SIZE 4096

struct knet_host_defrag_buf {
	char buf[KNET_MAX_PACKET_SIZE];
	uint8_t in_use;			/* 0 buffer is free, 1 is in use */
	seq_num_t pckt_seq;		/* identify the pckt we are receiving */
	uint8_t frag_recv;		/* how many frags did we receive */
	uint8_t frag_map[PCKT_FRAG_MAX];/* bitmap of what we received? */
	uint8_t	last_first;		/* special case if we receive the last fragment first */
	uint16_t frag_size;		/* normal frag size (not the last one) */
	uint16_t last_frag_size;	/* the last fragment might not be aligned with MTU size */
	struct timespec last_update;	/* keep time of the last pckt */
};

struct knet_host {
	/* required */
	uint16_t host_id;
	/* configurable */
	uint8_t link_handler_policy;
	char name[KNET_MAX_HOST_LEN];
	/* status */
	struct knet_host_status status;
	/* internals */
	char bcast_circular_buffer[KNET_CBUFFER_SIZE];
	seq_num_t bcast_seq_num_rx;
	char ucast_circular_buffer[KNET_CBUFFER_SIZE];
	seq_num_t ucast_seq_num_tx;
	seq_num_t ucast_seq_num_rx;
	/* defrag/(reassembly buffers */
	struct knet_host_defrag_buf defrag_buf[KNET_MAX_LINK];
	char bcast_circular_buffer_defrag[KNET_CBUFFER_SIZE];
	char ucast_circular_buffer_defrag[KNET_CBUFFER_SIZE];
	/* link stuff */
	struct knet_link link[KNET_MAX_LINK];
	pthread_mutex_t active_links_mutex;
	uint8_t active_link_entries;
	uint8_t active_links[KNET_MAX_LINK];
	struct knet_host *next;
};

struct knet_sock {
	int sockfd[2];   /* sockfd[0] will always be application facing
			  * and sockfd[1] internal if sockpair has been created by knet */
	int is_socket;   /* check if it's a socket for recvmmsg usage */
	int is_created;  /* knet created this socket and has to clean up on exit/del */
	int in_use;      /* set to 1 if it's use, 0 if free */
	int has_error;   /* set to 1 if there were errors reading from the sock
			  * and socket has been removed from epoll */
};

struct knet_handle {
	uint16_t host_id;
	unsigned int enabled:1;
	struct knet_sock sockfd[KNET_DATAFD_MAX];
	int logfd;
	uint8_t log_levels[KNET_MAX_SUBSYSTEMS];
	int hostsockfd[2];
	int dstsockfd[2];
	int send_to_links_epollfd;
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
	struct knet_header *recv_from_sock_buf[PCKT_FRAG_MAX];
	struct knet_header *send_to_links_buf[PCKT_FRAG_MAX];
	struct knet_header *recv_from_links_buf[PCKT_FRAG_MAX];
	struct knet_header *pingbuf;
	struct knet_header *pmtudbuf;
	pthread_t send_to_links_thread;
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
	unsigned char *send_to_links_buf_crypt[PCKT_FRAG_MAX];
	unsigned char *recv_from_links_buf_crypt;
	unsigned char *recv_from_links_buf_decrypt;
	unsigned char *pingbuf_crypt;
	unsigned char *pmtudbuf_crypt;
	seq_num_t bcast_seq_num_tx;
	void *dst_host_filter_fn_private_data;
	int (*dst_host_filter_fn) (
		void *private_data,
		const unsigned char *outdata,
		ssize_t outdata_len,
		uint8_t tx_rx,
		uint16_t this_host_id,
		uint16_t src_node_id,
		int8_t *channel,
		uint16_t *dst_host_ids,
		size_t *dst_host_ids_entries);
	void *pmtud_notify_fn_private_data;
	void (*pmtud_notify_fn) (
		void *private_data,
		unsigned int link_mtu,
		unsigned int data_mtu);
	void *host_status_change_notify_fn_private_data;
	void (*host_status_change_notify_fn) (
		void *private_data,
		uint16_t host_id,
		uint8_t reachable,
		uint8_t remote,
		uint8_t external);
	void *sock_notify_fn_private_data;
	void (*sock_notify_fn) (
		void *private_data,
		int datafd,
		int8_t channel,
		uint8_t tx_rx,
		int error,
		int errorno);
	int fini_in_progress;
};

#endif
