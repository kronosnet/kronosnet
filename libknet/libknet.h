/*
 * Copyright (C) 2010-2012 Red Hat, Inc.  All rights reserved.
 *
 * Authors: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *          Federico Simoncelli <fsimon@kronosnet.org>
 *
 * This software licensed under GPL-2.0+, LGPL-2.0+
 */

#ifndef __LIBKNET_H__
#define __LIBKNET_H__

#include <stdint.h>
#include <netinet/in.h>

typedef struct knet_handle *knet_handle_t;

#define KNET_RING_DEFPORT 50000
#define KNET_RING_RCVBUFF 8388608

#define KNET_MAX_HOST 65536
#define KNET_MAX_LINK 8
#define KNET_MAX_HOST_LEN 64
#define KNET_MAX_PORT_LEN 6

#define KNET_CBUFFER_SIZE 4096
/*
typedef uint64_t seq_num_t;
#define SEQ_MAX UINT64_MAX
*/
typedef uint16_t seq_num_t;
#define SEQ_MAX UINT16_MAX

#define KNET_LINK_STATIC  0 /* link com is static ip (default) */
#define KNET_LINK_DYN_SRC 1 /* link com has src dynamic ip */
#define KNET_LINK_DYN_DST 2 /* link com is dst from dyn src */

struct knet_link {
	uint8_t link_id;
	int listener_sock;
	char src_ipaddr[KNET_MAX_HOST_LEN];
	char src_port[KNET_MAX_PORT_LEN];
	struct sockaddr_storage src_addr;
	char dst_ipaddr[KNET_MAX_HOST_LEN];
	char dst_port[KNET_MAX_PORT_LEN];
	struct sockaddr_storage dst_addr;
	unsigned int configured:1; /* link is configured and ready to be used */
	unsigned int connected:1;	/* link is enabled for data (local view) */
	unsigned int remoteconnected:1; /* link is enabled for data (peer view) */
	unsigned int donnotremoteupdate:1;    /* define source of the update */
	unsigned int dynamic; /* see KNET_LINK_DYN_ define above */
	unsigned int dynconnected:1; /* link has been activated by remote dynip */
	uint8_t  priority; /* higher priority == preferred for A/P */
	unsigned int host_info_up_sent:1; /* 0 if we need to notify remote that link is up */
	unsigned long long latency; /* average latency computed by fix/exp */
	unsigned int latency_exp;
	unsigned int latency_fix;
	unsigned long long ping_interval;
	unsigned long long pong_timeout;
	struct timespec ping_last;
	struct timespec pong_last;
};

#define KNET_LINK_POLICY_PASSIVE 0
#define KNET_LINK_POLICY_ACTIVE  1
#define KNET_LINK_POLICY_RR      2

struct knet_host {
	uint16_t node_id;
	char name[KNET_MAX_HOST_LEN];
	char bcast_circular_buffer[KNET_CBUFFER_SIZE];
	seq_num_t bcast_seq_num_rx;
	char ucast_circular_buffer[KNET_CBUFFER_SIZE];
	seq_num_t ucast_seq_num_tx;
	seq_num_t ucast_seq_num_rx;
	struct knet_link link[KNET_MAX_LINK];
	uint8_t active_link_entries;
	uint8_t active_links[KNET_MAX_LINK];
	uint8_t link_handler_policy;
	struct knet_host *next;
};

#define KNET_MIN_KEY_LEN 1024
#define KNET_MAX_KEY_LEN 4096

#define KNET_DST_FILTER_DISABLE 0 /* pckt goes everywhere */
#define KNET_DST_FILTER_ENABLE  1 /* pckt goes via dst_host_filter,
				     see knet_ether_filter for example */

/*
 * dst_host_filter_fn should return
 * -1 on error, pkt is discarded
 *  0 all good, send pkt to dst_host_ids and there are dst_host_ids_entries in buffer ready
 *  1 send it to all hosts. contents of dst_host_ids and dst_host_ids_entries is ignored.
 */

#define KNET_SUB_COMMON      0 /* common.c */
#define KNET_SUB_HANDLE      1 /* handle.c alloc/dealloc config changes */
#define KNET_SUB_HOST        2 /* host add/del/modify */
#define KNET_SUB_LISTENER    3 /* listeners add/del/modify... */
#define KNET_SUB_LINK        4 /* link add/del/modify */
#define KNET_SUB_TAP_T       5 /* tap thread */
#define KNET_SUB_LINK_T      6 /* link thread */
#define KNET_SUB_SWITCH_T    7 /* switching thread */
#define KNET_SUB_HB_T        8 /* heartbeat thread */
#define KNET_SUB_FILTER      9 /* (ether)filter errors */
#define KNET_SUB_CRYPTO     10 /* crypto.c generic layer */
#define KNET_SUB_NSSCRYPTO  11 /* nsscrypto.c */
#define KNET_SUB_LAST        KNET_SUB_NSSCRYPTO
#define KNET_MAX_SUBSYSTEMS KNET_SUB_LAST + 1

#define KNET_LOG_ERR         0 /* unrecoverable errors/conditions */
#define KNET_LOG_WARN        1 /* recoverable errors/conditions */
#define KNET_LOG_INFO        2 /* info, link up/down, config changes.. */
#define KNET_LOG_DEBUG       3

#define KNET_MAX_LOG_MSG_SIZE    1024

struct knet_log_msg {
	uint8_t	subsystem;	/* KNET_SUB_* */
	uint8_t msglevel;	/* KNET_LOG_* */
	char	msg[KNET_MAX_LOG_MSG_SIZE - (sizeof(uint8_t)*2)];
};

struct knet_handle_cfg {
	int		to_net_fd;
	int		log_fd;
	uint8_t		default_log_level;
	uint16_t	node_id;
	uint8_t		dst_host_filter;
	int		(*dst_host_filter_fn) (
				const unsigned char *outdata,
				ssize_t outdata_len,
				uint16_t src_node_id,
				uint16_t *dst_host_ids,
				size_t *dst_host_ids_entries);
};

knet_handle_t knet_handle_new(const struct knet_handle_cfg *knet_handle_cfg);
void knet_handle_setfwd(knet_handle_t knet_h, int enabled);
int knet_handle_free(knet_handle_t knet_h);

struct knet_handle_crypto_cfg {
	char		crypto_model[16];
	char		crypto_cipher_type[16];
	char		crypto_hash_type[16];
	unsigned char	private_key[KNET_MAX_KEY_LEN];
	unsigned int	private_key_len;
};

int knet_handle_crypto(knet_handle_t knet_h, struct knet_handle_crypto_cfg *knet_handle_crypto_cfg);

int knet_host_add(knet_handle_t knet_h, uint16_t node_id);
int knet_host_acquire(knet_handle_t knet_h, struct knet_host **host);
int knet_host_get(knet_handle_t knet_h, uint16_t node_id, struct knet_host **host);
int knet_host_release(knet_handle_t knet_h, struct knet_host **host);
int knet_host_remove(knet_handle_t knet_h, uint16_t node_id);
int knet_host_set_policy(knet_handle_t knet_h, uint16_t node_id, int policy);

int knet_link_enable(knet_handle_t knet_h, uint16_t node_id, struct knet_link *lnk, int configured);
void knet_link_timeout(knet_handle_t knet_h, uint16_t node_id, struct knet_link *lnk, time_t interval, time_t timeout, int precision);
int knet_link_priority(knet_handle_t knet_h, uint16_t node_id, struct knet_link *lnk, uint8_t priority);

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

/* logging */
void knet_set_log_level(knet_handle_t knet_h, uint8_t subsystem, uint8_t level);
const char *knet_get_subsystem_name(uint8_t subsystem);
const char *knet_get_loglevel_name(uint8_t level);
uint8_t knet_get_subsystem_id(const char *name);
uint8_t knet_get_loglevel_id(const char *name);

#endif
