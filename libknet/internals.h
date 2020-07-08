/*
 * Copyright (C) 2010-2020 Red Hat, Inc.  All rights reserved.
 *
 * Authors: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *          Federico Simoncelli <fsimon@kronosnet.org>
 *
 * This software licensed under LGPL-2.0+
 */

#ifndef __KNET_INTERNALS_H__
#define __KNET_INTERNALS_H__

/*
 * NOTE: you shouldn't need to include this header normally
 */

#include <pthread.h>
#include <stddef.h>
#include <qb/qblist.h>
#include "libknet.h"
#include "onwire.h"
#include "compat.h"
#include "threads_common.h"

#define KNET_DATABUFSIZE KNET_MAX_PACKET_SIZE + KNET_HEADER_ALL_SIZE

#define KNET_DATABUFSIZE_CRYPT_PAD 1024
#define KNET_DATABUFSIZE_CRYPT KNET_DATABUFSIZE + KNET_DATABUFSIZE_CRYPT_PAD

#define KNET_DATABUFSIZE_COMPRESS_PAD 1024
#define KNET_DATABUFSIZE_COMPRESS KNET_DATABUFSIZE + KNET_DATABUFSIZE_COMPRESS_PAD

#define KNET_RING_RCVBUFF 8388608

#define PCKT_FRAG_MAX UINT8_MAX
#define PCKT_RX_BUFS  512

#define KNET_EPOLL_MAX_EVENTS KNET_DATAFD_MAX + 1

#define KNET_INTERNAL_DATA_CHANNEL KNET_DATAFD_MAX

/*
 * Size of threads stack. Value is choosen by experimenting, how much is needed
 * to sucesfully finish test suite, and at the time of writing patch it was
 * ~300KiB. To have some room for future enhancement it is increased
 * by factor of 3 and rounded.
 */
#define KNET_THREAD_STACK_SIZE (1024 * 1024)

typedef void *knet_transport_link_t; /* per link transport handle */
typedef void *knet_transport_t;      /* per knet_h transport handle */
struct  knet_transport_ops;          /* Forward because of circular dependancy */

struct knet_mmsghdr {
	struct msghdr msg_hdr;	/* Message header */
	unsigned int  msg_len;	/* Number of bytes transmitted */
};

struct knet_link {
	/* required */
	struct sockaddr_storage src_addr;
	struct sockaddr_storage dst_addr;
	/* configurable */
	unsigned int dynamic;			/* see KNET_LINK_DYN_ define above */
	uint8_t  priority;			/* higher priority == preferred for A/P */
	unsigned long long ping_interval;	/* interval */
	unsigned long long pong_timeout;	/* timeout */
	unsigned long long pong_timeout_adj;	/* timeout adjusted for latency */
	uint8_t pong_timeout_backoff;		/* see link.h for definition */
	unsigned int latency_max_samples;	/* precision */
	uint8_t pong_count;			/* how many ping/pong to send/receive before link is up */
	uint64_t flags;
	/* status */
	struct knet_link_status status;
	/* internals */
	pthread_mutex_t link_stats_mutex;	/* used to update link stats */
	uint8_t link_id;
	uint8_t transport;                      /* #defined constant from API */
	knet_transport_link_t transport_link;   /* link_info_t from transport */
	int outsock;
	unsigned int configured:1;		/* set to 1 if src/dst have been configured transport initialized on this link*/
	unsigned int transport_connected:1;	/* set to 1 if lower level transport is connected */
	uint8_t received_pong;
	struct timespec ping_last;
	/* used by PMTUD thread as temp per-link variables and should always contain the onwire_len value! */
	uint32_t proto_overhead;		/* IP + UDP/SCTP overhead. NOT to be confused
						   with stats.proto_overhead that includes also knet headers
						   and crypto headers */
	struct timespec pmtud_last;
	uint32_t last_ping_size;
	uint32_t last_good_mtu;
	uint32_t last_bad_mtu;
	uint32_t last_sent_mtu;
	uint32_t last_recv_mtu;
	uint32_t pmtud_crypto_timeout_multiplier;/* used by PMTUd to adjust timeouts on high loads */
	uint8_t has_valid_mtu;
};

#define KNET_CBUFFER_SIZE 4096

struct knet_host_defrag_buf {
	char buf[KNET_DATABUFSIZE];
	uint8_t in_use;			/* 0 buffer is free, 1 is in use */
	seq_num_t pckt_seq;		/* identify the pckt we are receiving */
	uint8_t frag_recv;		/* how many frags did we receive */
	uint8_t frag_map[PCKT_FRAG_MAX];/* bitmap of what we received? */
	uint8_t	last_first;		/* special case if we receive the last fragment first */
	ssize_t frag_size;		/* normal frag size (not the last one) */
	ssize_t last_frag_size;		/* the last fragment might not be aligned with MTU size */
	struct timespec last_update;	/* keep time of the last pckt */
};

struct knet_host {
	/* required */
	knet_node_id_t host_id;
	/* configurable */
	uint8_t link_handler_policy;
	char name[KNET_MAX_HOST_LEN];
	/* status */
	struct knet_host_status status;
	/* internals */
	char circular_buffer[KNET_CBUFFER_SIZE];
	seq_num_t rx_seq_num;
	seq_num_t untimed_rx_seq_num;
	seq_num_t timed_rx_seq_num;
	uint8_t got_data;
	/* defrag/reassembly buffers */
	struct knet_host_defrag_buf defrag_buf[KNET_MAX_LINK];
	char circular_buffer_defrag[KNET_CBUFFER_SIZE];
	/* link stuff */
	struct knet_link link[KNET_MAX_LINK];
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

struct knet_fd_trackers {
	uint8_t transport;		    /* transport type (UDP/SCTP...) */
	uint8_t data_type;		    /* internal use for transport to define what data are associated
					     * with this fd */
	void *data;			    /* pointer to the data */
	void *access_list_match_entry_head; /* pointer to access list match_entry list head */
};

#define KNET_MAX_FDS KNET_MAX_HOST * KNET_MAX_LINK * 4

#define KNET_MAX_COMPRESS_METHODS UINT8_MAX

#define KNET_MAX_CRYPTO_INSTANCES 2

struct knet_handle_stats_extra {
	uint64_t tx_crypt_pmtu_packets;
	uint64_t tx_crypt_pmtu_reply_packets;
	uint64_t tx_crypt_ping_packets;
	uint64_t tx_crypt_pong_packets;
};

struct knet_handle {
	knet_node_id_t host_id;
	unsigned int enabled:1;
	struct knet_sock sockfd[KNET_DATAFD_MAX + 1];
	int logfd;
	uint8_t log_levels[KNET_MAX_SUBSYSTEMS];
	int hostsockfd[2];
	int dstsockfd[2];
	int send_to_links_epollfd;
	int recv_from_links_epollfd;
	int dst_link_handler_epollfd;
	uint8_t use_access_lists; /* set to 0 for disable, 1 for enable */
	unsigned int pmtud_interval;
	unsigned int manual_mtu;
	unsigned int data_mtu;	/* contains the max data size that we can send onwire
				 * without frags */
	struct knet_host *host_head;
	struct knet_host *host_index[KNET_MAX_HOST];
	knet_transport_t transports[KNET_MAX_TRANSPORTS+1];
	struct knet_fd_trackers knet_transport_fd_tracker[KNET_MAX_FDS]; /* track status for each fd handled by transports */
	struct knet_handle_stats stats;
	struct knet_handle_stats_extra stats_extra;
	pthread_mutex_t handle_stats_mutex;	/* used to protect handle stats */
	uint32_t reconnect_int;
	knet_node_id_t host_ids[KNET_MAX_HOST];
	size_t host_ids_entries;
	struct knet_header *recv_from_sock_buf;
	struct knet_header *send_to_links_buf[PCKT_FRAG_MAX];
	struct knet_header *recv_from_links_buf[PCKT_RX_BUFS];
	struct knet_header *pingbuf;
	struct knet_header *pmtudbuf;
	uint8_t threads_status[KNET_THREAD_MAX];
	uint8_t threads_flush_queue[KNET_THREAD_MAX];
	useconds_t threads_timer_res;
	pthread_mutex_t threads_status_mutex;
	pthread_t send_to_links_thread;
	pthread_t recv_from_links_thread;
	pthread_t heartbt_thread;
	pthread_t dst_link_handler_thread;
	pthread_t pmtud_link_handler_thread;
	pthread_rwlock_t global_rwlock;		/* global config lock */
	pthread_mutex_t pmtud_mutex;		/* pmtud mutex to handle conditional send/recv + timeout */
	pthread_cond_t pmtud_cond;		/* conditional for above */
	pthread_mutex_t tx_mutex;		/* used to protect knet_send_sync and TX thread */
	pthread_mutex_t hb_mutex;		/* used to protect heartbeat thread and seq_num broadcasting */
	pthread_mutex_t backoff_mutex;		/* used to protect dst_link->pong_timeout_adj */
	pthread_mutex_t kmtu_mutex;		/* used to protect kernel_mtu */
	uint32_t kernel_mtu;			/* contains the MTU detected by the kernel on a given link */
	int pmtud_waiting;
	int pmtud_running;
	int pmtud_forcerun;
	int pmtud_abort;
	struct crypto_instance *crypto_instance[KNET_MAX_CRYPTO_INSTANCES + 1]; /* store an extra pointer to allow 0|1|2 values without too much magic in the code */
	uint8_t crypto_in_use_config;		/* crypto config to use for TX */
	uint8_t crypto_only;			/* allow only crypto (1) or also clear (0) traffic */
	size_t sec_block_size;
	size_t sec_hash_size;
	size_t sec_salt_size;
	unsigned char *send_to_links_buf_crypt[PCKT_FRAG_MAX];
	unsigned char *recv_from_links_buf_crypt;
	unsigned char *recv_from_links_buf_decrypt;
	unsigned char *pingbuf_crypt;
	unsigned char *pmtudbuf_crypt;
	int compress_model;
	int compress_level;
	size_t compress_threshold;
	void *compress_int_data[KNET_MAX_COMPRESS_METHODS]; /* for compress method private data */
	unsigned char *recv_from_links_buf_decompress;
	unsigned char *send_to_links_buf_compress;
	seq_num_t tx_seq_num;
	pthread_mutex_t tx_seq_num_mutex;
	uint8_t has_loop_link;
	uint8_t loop_link;
	void *dst_host_filter_fn_private_data;
	int (*dst_host_filter_fn) (
		void *private_data,
		const unsigned char *outdata,
		ssize_t outdata_len,
		uint8_t tx_rx,
		knet_node_id_t this_host_id,
		knet_node_id_t src_node_id,
		int8_t *channel,
		knet_node_id_t *dst_host_ids,
		size_t *dst_host_ids_entries);
	void *pmtud_notify_fn_private_data;
	void (*pmtud_notify_fn) (
		void *private_data,
		unsigned int data_mtu);
	void *host_status_change_notify_fn_private_data;
	void (*host_status_change_notify_fn) (
		void *private_data,
		knet_node_id_t host_id,
		uint8_t reachable,
		uint8_t remote,
		uint8_t external);
	void *link_status_change_notify_fn_private_data;
	void (*link_status_change_notify_fn) (
		void *private_data,
		knet_node_id_t host_id,
		uint8_t link_id,
		uint8_t connected,
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
	uint64_t flags;
};

extern pthread_rwlock_t shlib_rwlock;       /* global shared lib load lock */

/*
 * NOTE: every single operation must be implementend
 *       for every protocol.
 */

/*
 * for now knet supports only IP protocols (udp/sctp)
 * in future there might be others like ARP
 * or TIPC.
 * keep this around as transport information
 * to use for access lists and other operations
 */

#define TRANSPORT_PROTO_LOOPBACK 0
#define TRANSPORT_PROTO_IP_PROTO 1

/*
 * some transports like SCTP can filter incoming
 * connections before knet has to process
 * any packets.
 * GENERIC_ACL -> packet has to be read and filterted
 * PROTO_ACL -> transport provides filtering at lower levels
 *              and packet does not need to be processed
 */

typedef enum {
	USE_NO_ACL,
	USE_GENERIC_ACL,
	USE_PROTO_ACL
} transport_acl;

/*
 * make it easier to map values in transports.c
 */
#define TRANSPORT_PROTO_NOT_CONNECTION_ORIENTED 0
#define TRANSPORT_PROTO_IS_CONNECTION_ORIENTED  1

typedef struct knet_transport_ops {
/*
 * transport generic information
 */
	const char *transport_name;
	const uint8_t transport_id;
	const uint8_t built_in;

	uint8_t transport_protocol;
	transport_acl transport_acl_type;

/*
 * connection oriented protocols like SCTP
 * don´t need dst_addr in sendto calls and
 * on some OSes are considered EINVAL.
 */
	uint8_t transport_is_connection_oriented;

	uint32_t transport_mtu_overhead;
/*
 * transport init must allocate the new transport
 * and perform all internal initializations
 * (threads, lists, etc).
 */
	int (*transport_init)(knet_handle_t knet_h);
/*
 * transport free must releases _all_ resources
 * allocated by tranport_init
 */
	int (*transport_free)(knet_handle_t knet_h);

/*
 * link operations should take care of all the
 * sockets and epoll management for a given link/transport set
 * transport_link_disable should return err = -1 and errno = EBUSY
 * if listener is still in use, and any other errno in case
 * the link cannot be disabled.
 *
 * set_config/clear_config are invoked in global write lock context
 */
	int (*transport_link_set_config)(knet_handle_t knet_h, struct knet_link *link);
	int (*transport_link_clear_config)(knet_handle_t knet_h, struct knet_link *link);

/*
 * transport callback for incoming dynamic connections
 * this is called in global read lock context
 */
	int (*transport_link_dyn_connect)(knet_handle_t knet_h, int sockfd, struct knet_link *link);


/*
 * return the fd to use for access lists
 */
	int (*transport_link_get_acl_fd)(knet_handle_t knet_h, struct knet_link *link);

/*
 * per transport error handling of recvmmsg
 * (see _handle_recv_from_links comments for details)
 */

/*
 * transport_rx_sock_error is invoked when recvmmsg returns <= 0
 *
 * transport_rx_sock_error is invoked with both global_rdlock
 */

	int (*transport_rx_sock_error)(knet_handle_t knet_h, int sockfd, int recv_err, int recv_errno);

/*
 * transport_tx_sock_error is invoked with global_rwlock and
 * it's invoked when sendto or sendmmsg returns =< 0
 *
 * it should return:
 * -1 on internal error
 *  0 ignore error and continue
 *  1 retry
 *    any sleep or wait action should happen inside the transport code
 */
	int (*transport_tx_sock_error)(knet_handle_t knet_h, int sockfd, int recv_err, int recv_errno);

/*
 * this function is called on _every_ received packet
 * to verify if the packet is data or internal protocol error handling
 *
 * it should return:
 * -1 on error
 *  0 packet is not data and we should continue the packet process loop
 *  1 packet is not data and we should STOP the packet process loop
 *  2 packet is data and should be parsed as such
 *
 * transport_rx_is_data is invoked with both global_rwlock
 * and fd_tracker read lock (from RX thread)
 */
	int (*transport_rx_is_data)(knet_handle_t knet_h, int sockfd, struct knet_mmsghdr *msg);

/*
 * this function is called by links.c when a link down event is recorded
 * to notify the transport that packets are not going through, and give
 * transport the opportunity to take actions.
 */
	int (*transport_link_is_down)(knet_handle_t knet_h, struct knet_link *link);
} knet_transport_ops_t;

struct pretty_names {
	const char *name;
	uint8_t val;
};

#endif
