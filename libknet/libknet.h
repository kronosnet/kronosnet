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

#define KNET_MAX_HOST 65536
#define KNET_MAX_LINK 8
#define KNET_MAX_HOST_LEN 64
#define KNET_MAX_PORT_LEN 6

/* handle */

struct knet_handle_cfg {
	int		to_net_fd;
	int		log_fd;
	uint8_t		default_log_level;
	uint16_t	node_id;
};

knet_handle_t knet_handle_new(const struct knet_handle_cfg *knet_handle_cfg);

/*
 * dst_host_filter_fn should return
 * -1 on error, pkt is discarded
 *  0 all good, send pkt to dst_host_ids and there are dst_host_ids_entries in buffer ready
 *    dst_host_ids must be at least KNET_MAX_HOST big.
 *  1 send it to all hosts. contents of dst_host_ids and dst_host_ids_entries is ignored.
 */

int knet_handle_enable_filter(knet_handle_t knet_h,
			      int (*dst_host_filter_fn) (
					const unsigned char *outdata,
					ssize_t outdata_len,
					uint16_t src_node_id,
					uint16_t *dst_host_ids,
					size_t *dst_host_ids_entries));

void knet_handle_setfwd(knet_handle_t knet_h, int enabled);
int knet_handle_free(knet_handle_t knet_h);

/* crypto */

#define KNET_MIN_KEY_LEN 1024
#define KNET_MAX_KEY_LEN 4096

struct knet_handle_crypto_cfg {
	char		crypto_model[16];
	char		crypto_cipher_type[16];
	char		crypto_hash_type[16];
	unsigned char	private_key[KNET_MAX_KEY_LEN];
	unsigned int	private_key_len;
};

int knet_handle_crypto(knet_handle_t knet_h, struct knet_handle_crypto_cfg *knet_handle_crypto_cfg);

/* host */

int knet_host_add(knet_handle_t knet_h, uint16_t node_id);
int knet_host_remove(knet_handle_t knet_h, uint16_t node_id);

/* name must be <= KNET_MAX_HOST_LEN */
int knet_host_set_name(knet_handle_t knet_h, uint16_t node_id, const char *name);

/* name must be at least = KNET_MAX_HOST_LEN */
int knet_host_get_name(knet_handle_t knet_h, uint16_t node_id, char *name);

/* name must be <= KNET_MAX_HOST_LEN */
int knet_host_get_id(knet_handle_t knet_h, const char *name, uint16_t *node_id);

/* get a list of configured hosts in an array of uint16_t of size MAX_HOST */
int knet_host_list(knet_handle_t knet_h, uint16_t *host_ids, size_t *ids_entries);

/*
 * define switching policies
 */
#define KNET_LINK_POLICY_PASSIVE 0
#define KNET_LINK_POLICY_ACTIVE  1
#define KNET_LINK_POLICY_RR      2

int knet_host_set_policy(knet_handle_t knet_h, uint16_t node_id, int policy);
int knet_host_get_policy(knet_handle_t knet_h, uint16_t node_id, int *policy);

/* link */

int knet_link_config(knet_handle_t knet_h, uint16_t node_id, uint8_t link_id,
		     struct sockaddr_storage *src_addr,
		     struct sockaddr_storage *dst_addr);

int knet_link_enable(knet_handle_t knet_h, uint16_t node_id, uint8_t link_id, int configured);

int knet_link_set_timeout(knet_handle_t knet_h, uint16_t node_id, uint8_t link_id, time_t interval, time_t timeout, unsigned int precision);
int knet_link_get_timeout(knet_handle_t knet_h, uint16_t node_id, uint8_t link_id, time_t *interval, time_t *timeout, unsigned int *precision);

int knet_link_set_priority(knet_handle_t knet_h, uint16_t node_id, uint8_t link_id, uint8_t priority);
int knet_link_get_priority(knet_handle_t knet_h, uint16_t node_id, uint8_t link_id, uint8_t *priority);

#define KNET_LINK_STATIC  0 /* link com is static ip (default) */
#define KNET_LINK_DYN_SRC 1 /* link com has src dynamic ip */
#define KNET_LINK_DYN_DST 2 /* link com is dst from dyn src */

int knet_link_set_dynamic(knet_handle_t knet_h, uint16_t node_id, uint8_t link_id, unsigned int dynamic);
int knet_link_get_dynamic(knet_handle_t knet_h, uint16_t node_id, uint8_t link_id, unsigned int *dynamic);

struct knet_link_status {
	char src_ipaddr[KNET_MAX_HOST_LEN];
	char src_port[KNET_MAX_PORT_LEN];
	char dst_ipaddr[KNET_MAX_HOST_LEN];
	char dst_port[KNET_MAX_PORT_LEN];
	unsigned int configured:1; /* link is configured and ready to be used */
	unsigned int connected:1;       /* link is enabled for data (local view) */
	unsigned int dynconnected:1; /* link has been activated by remote dynip */
	unsigned long long latency; /* average latency computed by fix/exp */
	struct timespec pong_last;
};

int knet_link_get_status(knet_handle_t knet_h,
			 uint16_t node_id,
			 uint8_t link_id,
			 struct knet_link_status *status);

/* logging */

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

#define KNET_MAX_LOG_MSG_SIZE    256

struct knet_log_msg {
	uint8_t	subsystem;	/* KNET_SUB_* */
	uint8_t msglevel;	/* KNET_LOG_* */
	char	msg[KNET_MAX_LOG_MSG_SIZE - (sizeof(uint8_t)*2)];
};

void knet_set_log_level(knet_handle_t knet_h, uint8_t subsystem, uint8_t level);
const char *knet_get_subsystem_name(uint8_t subsystem);
const char *knet_get_loglevel_name(uint8_t level);
uint8_t knet_get_subsystem_id(const char *name);
uint8_t knet_get_loglevel_id(const char *name);

#endif
