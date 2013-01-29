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

/*
 * libknet limits
 */

/*
 * maximum number of hosts
 */

#define KNET_MAX_HOST 65536

/*
 * maximum number of links between 2 hosts
 */

#define KNET_MAX_LINK 8

/*
 * maximum packet size that should be written to net_fd
 *  see knet_handle_new for details
 */

#define KNET_MAX_PACKET_SIZE 131072

/*
 * buffers used for pretty logging
 *  host is used to store both ip addresses and hostnames
 */

#define KNET_MAX_HOST_LEN 64
#define KNET_MAX_PORT_LEN 6

typedef struct knet_handle *knet_handle_t;

/*
 * handle structs/API calls
 */

/*
 * knet_handle_new
 *
 * host_id  - each host in a knet is identified with a unique
 *            ID. when creating a new handle local host_id
 *            must be specified (0 to UINT16T_MAX are all valid).
 *            It is user responsibility to check that the value
 *            is unique, or bad might happen.
 *
 * net_fd   - read/write file descriptor (must be > 0).
 *            knet will read data here to send to the other hosts
 *            and will write data received from the network.
 *            Each data packet can be of max size KNET_MAX_PACKET_SIZE!
 *            Applications might be able to write more data at a time
 *            but they will be delivered in KNET_MAX_PACKET_SIZE chunks.
 *
 * log_fd   - write file descriptor. If set to a value > 0, it will be used
 *            to write log packets (see below) from libknet to the application.
 *            Set to 0 will disable logging from libknet.
 *            It is possible to enable logging at any given time (see logging API
 *            below).
 *            make sure to either read from this filedescriptor properly and/or
 *            mark it O_NONBLOCK, otherwise if the fd becomes full, libknet could
 *            block.
 *
 * default_log_level -
 *            if logfd is specified, it will initialize all subsystems to log
 *            at default_log_level value. (see logging API below)
 *
 * on success, a new knet_handle_t is returned.
 * on failure, NULL is returned and errno is set.
 */

knet_handle_t knet_handle_new(uint16_t host_id,
			      int      net_fd,
			      int      log_fd,
			      uint8_t  default_log_level);

/*
 * knet_handle_free
 *
 * knet_h   - pointer to knet_handle_t
 *
 * destroy a knet handle, free all resources
 *
 * knet_handle_free returns:
 *
 * 0 on success
 * -1 on error and errno is set.
 */

int knet_handle_free(knet_handle_t knet_h);

/*
 * knet_handle_enable_filter
 * 
 * knet_h   - pointer to knet_handle_t
 *
 * dst_host_filter_fn -
 *            is a callback function that is invoked every time
 *            a packet hits net_fd (see knet_handle_new).
 *            the function allows users to tell libknet where the
 *            packet has to be delivered.
 *
 *            const unsigned char *outdata - is a pointer to the
 *                                           current packet
 *            ssize_t outdata_len          - lenght of the above data
 *            uint16_t src_host_id         - host_id that generated the
 *                                           packet
 *            uint16_t *dst_host_ids       - array of KNET_MAX_HOST uint16_t
 *                                           where to store the destinations
 *            size_t *dst_host_ids_entries - number of hosts to send the message
 *
 * dst_host_filter_fn should return
 * -1 on error, packet is discarded
 *  0 packet is unicast and should be sent to dst_host_ids and there are
 *    dst_host_ids_entries in buffer ready
 *  1 packet is broadcast/multicast and is sent all hosts.
 *    contents of dst_host_ids and dst_host_ids_entries is ignored.
 *  (see also kronosnetd/etherfilter.* for an example that filters based
 *   on ether protocol)
 *
 * knet_handle_enable_filter returns:
 *
 * 0 on success
 * -1 on error and errno is set.
 */

int knet_handle_enable_filter(knet_handle_t knet_h,
			      int (*dst_host_filter_fn) (
					const unsigned char *outdata,
					ssize_t outdata_len,
					uint16_t src_host_id,
					uint16_t *dst_host_ids,
					size_t *dst_host_ids_entries));

/*
 * knet_handle_setfwd
 *
 * knet_h   - pointer to knet_handle_t
 *
 * enable   - set to 1 to allow data forwarding, 0 to disable data forwarding.
 *
 * knet_handle_setfwd returns:
 *
 * 0 on success
 * -1 on error and errno is set.
 *
 * By default data forwarding is off.
 */

int knet_handle_setfwd(knet_handle_t knet_h, unsigned int enabled);

/*
 * knet_handle_crypto
 *
 * knet_h   - pointer to knet_handle_t
 *
 * knet_handle_crypto_cfg -
 *            pointer to a knet_handle_crypto_cfg structure
 *
 *            crypto_model should contain the model name.
 *                         Currently only "nss" is supported.
 *                         Setting to "none" will disable crypto.
 *
 *            crypto_cipher_type
 *                         should contain the cipher algo name.
 *                         It can be set to "none" to disable
 *                         encryption.
 *                         Currently supported by "nss" model:
 *                         "3des", "aes128", "aes192" and "aes256".
 *
 *            crypto_hash_type
 *                         should contain the hashing algo name.
 *                         It can be set to "none" to disable
 *                         hashing.
 *                         Currently supported by "nss" model:
 *                         "md5", "sha1", "sha256", "sha384" and "sha512".
 *
 *            private_key  will contain the private shared key.
 *                         It has to be at least KNET_MIN_KEY_LEN long.
 *
 *            private_key_len
 *                         lenght of the provided private_key.
 *
 * Implementation notes/current limitations:
 * - enabling crypto, will increase latency as packets have
 *   to processed.
 * - enabling crypto might reduce the overall throughtput
 *   due to crypto data overhead.
 * - re-keying is not implemented yet.
 * - private/public key encryption/hashing is not currently
 *   planned.
 * - crypto key must be the same for all hosts in the same
 *   knet instance.
 * - it is safe to call knet_handle_crypto multiple times at runtime.
 *   The last config will be used.
 *   IMPORTANT: a call to knet_handle_crypto can fail due:
 *              1) obtain locking to change config
 *              2) errors to initializes the crypto level.
 *   This can happen even in subsequent calls to knet_handle_crypto.
 *   A failure in crypto init, might leave your traffic unencrypted!
 *   It's best to stop data forwarding (see above), change crypto config,
 *   start forward again.
 *
 * knet_handle_crypto returns:
 *
 * 0 on success
 * -1 on locking error and errno is set.
 * -2 on crypto initialization error. No errno is provided at the moment.
 */

#define KNET_MIN_KEY_LEN 1024
#define KNET_MAX_KEY_LEN 4096

struct knet_handle_crypto_cfg {
	char		crypto_model[16];
	char		crypto_cipher_type[16];
	char		crypto_hash_type[16];
	unsigned char	private_key[KNET_MAX_KEY_LEN];
	unsigned int	private_key_len;
};

int knet_handle_crypto(knet_handle_t knet_h,
		       struct knet_handle_crypto_cfg *knet_handle_crypto_cfg);

/*
 * host structs/API calls
 */

/*
 * knet_host_add
 *
 * knet_h   - pointer to knet_handle_t
 *
 * host_id  - each host in a knet is identified with a unique ID
 *            (see also knet_handle_new documentation above)
 *
 * knet_host_add returns:
 *
 * 0 on success
 * -1 on error and errno is set.
 */

int knet_host_add(knet_handle_t knet_h, uint16_t host_id);

/*
 * knet_host_remove
 *
 * knet_h   - pointer to knet_handle_t
 *
 * host_id  - each host in a knet is identified with a unique ID
 *            (see also knet_handle_new documentation above)
 *
 * knet_host_remove returns:
 *
 * 0 on success
 * -1 on error and errno is set.
 */

int knet_host_remove(knet_handle_t knet_h, uint16_t host_id);

/*
 * knet_host_set_name
 *
 * knet_h   - pointer to knet_handle_t 
 * 
 * host_id  - see above
 *
 * name     - this name will be used for pretty logging and eventually
 *            search for hosts (see also get_name and get_id below).
 *            Only up to KNET_MAX_HOST_LEN - 1 bytes will be copied.
 *
 * knet_host_set_name returns:
 *
 * 0 on success 
 * -1 on error and errno is set. 
 */ 

int knet_host_set_name(knet_handle_t knet_h, uint16_t host_id,
		       const char *name);

/*
 * knet_host_get_name_by_host_id
 *
 * knet_h   - pointer to knet_handle_t
 *
 * host_id  - see above
 *
 * name     - pointer to a preallocated buffer of atleast size KNET_MAX_HOST_LEN
 *            where the current host name will be stored
 *            (as set by knet_host_set_name or default by knet_host_add)
 *
 * knet_host_get_name_by_host_id returns:
 *
 * 1 if host is found and name is valid
 * 0 if host is not found. name is left untouched.
 * -1 on error and errno is set.
 */

int knet_host_get_name_by_host_id(knet_handle_t knet_h, uint16_t host_id,
				  char *name);

/*
 * knet_host_get_id_by_host_name
 *
 * knet_h   - pointer to knet_handle_t
 *
 * name     - name to lookup, max len KNET_MAX_HOST_LEN
 *
 * host_id  - where to store the result
 *
 * knet_host_get_id_by_host_name returns:
 *
 * 1 if host is found and name is valid
 * 0 if host is not found. name is left untouched.
 * -1 on error and errno is set.
 */

int knet_host_get_id_by_host_name(knet_handle_t knet_h, const char *name,
				  uint16_t *host_id);

/* get a list of configured hosts in an array of uint16_t of size MAX_HOST */
/* 
 * knet_host_get_host_list
 * 
 * knet_h   - pointer to knet_handle_t
 *
 * host_ids - array of at lest KNET_MAX_HOST size
 *
 * host_ids_entries -
 *            number of entries writted in host_ids
 *
 * knet_host_get_host_list returns:
 *
 * 0 on success
 * -1 on error and errno is set.
 */

int knet_host_get_host_list(knet_handle_t knet_h,
			    uint16_t *host_ids, size_t *host_ids_entries);


/*
 * define switching policies
 */

#define KNET_LINK_POLICY_PASSIVE 0
#define KNET_LINK_POLICY_ACTIVE  1
#define KNET_LINK_POLICY_RR      2

/*
 * knet_host_set_policy
 *
 * knet_h   - pointer to knet_handle_t 
 * 
 * host_id  - see above
 *
 * policy   - there are currently 3 kind of simple switching policies
 *            as defined above, based on link configuration.
 *            KNET_LINK_POLICY_PASSIVE - the active link with the lowest
 *                                       priority will be used.
 *                                       if one or more active links share
 *                                       the same priority, the one with
 *                                       lowest link_id will be used.
 *
 *            KNET_LINK_POLICY_ACTIVE  - all active links will be used
 *                                       simultaneously to send traffic.
 *                                       link priority is ignored.
 *
 *            KNET_LINK_POLICY_RR      - round-robin policy, every packet
 *                                       will be send on a different active
 *                                       link.
 *
 * knet_host_set_policy returns:
 *
 * 0 on success 
 * -1 on error and errno is set. 
 */ 

int knet_host_set_policy(knet_handle_t knet_h, uint16_t host_id,
			 int policy);

/*
 * knet_host_get_policy
 *
 * knet_h   - pointer to knet_handle_t 
 * 
 * host_id  - see above
 *
 * policy   - will contain the current configured switching policy.
 *            Default is passive when creating a new host.
 *
 * knet_host_get_policy returns:
 *
 * 0 on success 
 * -1 on error and errno is set. 
 */ 

int knet_host_get_policy(knet_handle_t knet_h, uint16_t host_id,
			 int *policy);

/*
 * link structs/API calls
 *
 * every host allocated/managed by knet_host_* has
 * KNET_MAX_LINK structures to define the network
 * paths that connect 2 hosts.
 *
 * Each link is identified by a link_id that has a
 * values between 0 and KNET_MAX_LINK - 1.
 *
 * KNOWN LIMITATIONS:
 *
 * - let's assume the scenario where two hosts are connected
 *   with any number of links. link_id must match on both sides.
 *   If host_id 0 link_id 0 is configured to connect IP1 to IP2 and
 *   host_id 0 link_id 1 is configured to connect IP3 to IP4,
 *   host_id 1 link_id 0 _must_ connect IP2 to IP1 and likewise
 *   host_id 1 link_id 1 _must_ connect IP4 to IP3.
 *   We might be able to lift this restriction in future, by using
 *   other data to determine src/dst link_id, but for now deal with it.
 *
 * - 
 */

/*
 * knet_link_set_config
 *
 * knet_h    - pointer to knet_handle_t 
 * 
 * host_id   - see above
 *
 * link_id   - see above
 *
 * src_addr  - sockaddr_storage that can be either IPv4 or IPv6
 *
 * dst_addr  - sockaddr_storage that can be either IPv4 or IPv6
 *             this can be null if we don't know the incoming
 *             IP address/port and the link will remain quiet
 *             till the node on the other end will initiate a
 *             connection
 *
 * knet_link_set_config returns:
 *
 * 0 on success 
 * -1 on error and errno is set. 
 */

int knet_link_set_config(knet_handle_t knet_h, uint16_t host_id, uint8_t link_id,
			 struct sockaddr_storage *src_addr,
			 struct sockaddr_storage *dst_addr);

/*
 * knet_link_get_config
 *
 * knet_h    - pointer to knet_handle_t 
 * 
 * host_id   - see above
 *
 * link_id   - see above
 *
 * src_addr  - sockaddr_storage that can be either IPv4 or IPv6
 *
 * dst_addr  - sockaddr_storage that can be either IPv4 or IPv6
 *             this can be null if the link has dynamic incoming connection
 *
 * knet_link_set_config returns:
 *
 * 1 on success and the link is dynamic, dst_addr is unknown/unconfigured
 * 0 on success and both src and dst have been configured by set_config
 * -1 on error and errno is set. 
 */

int knet_link_get_config(knet_handle_t knet_h, uint16_t host_id, uint8_t link_id,
			 struct sockaddr_storage *src_addr,
			 struct sockaddr_storage *dst_addr);

/*
 * knet_link_set_enable
 *
 * knet_h    - pointer to knet_handle_t 
 * 
 * host_id   - see above
 *
 * link_id   - see above
 *
 * enabled   - 0 disable the link, 1 enable the link
 *
 * knet_link_set_enable returns:
 *
 * 0 on success 
 * -1 on error and errno is set. 
 */

int knet_link_set_enable(knet_handle_t knet_h, uint16_t host_id, uint8_t link_id,
			 int enabled);

/*
 * knet_link_get_enable
 *
 * knet_h    - pointer to knet_handle_t 
 * 
 * host_id   - see above
 *
 * link_id   - see above
 *
 * enabled   - 0 disable the link, 1 enable the link
 *
 * knet_link_get_enable returns:
 *
 * 0 on success 
 * -1 on error and errno is set. 
 */

int knet_link_get_enable(knet_handle_t knet_h, uint16_t host_id, uint8_t link_id,
			 int *enabled);

int knet_link_set_timeout(knet_handle_t knet_h, uint16_t node_id, uint8_t link_id, time_t interval, time_t timeout, unsigned int precision);
int knet_link_get_timeout(knet_handle_t knet_h, uint16_t node_id, uint8_t link_id, time_t *interval, time_t *timeout, unsigned int *precision);

int knet_link_set_priority(knet_handle_t knet_h, uint16_t node_id, uint8_t link_id, uint8_t priority);
int knet_link_get_priority(knet_handle_t knet_h, uint16_t node_id, uint8_t link_id, uint8_t *priority);

struct knet_link_status {
	char src_ipaddr[KNET_MAX_HOST_LEN];
	char src_port[KNET_MAX_PORT_LEN];
	char dst_ipaddr[KNET_MAX_HOST_LEN];
	char dst_port[KNET_MAX_PORT_LEN];
	unsigned int enabled:1;		/* link is configured and admin enabled for traffic */
	unsigned int connected:1;       /* link is connected for data (local view) */
	unsigned int dynconnected:1;	/* link has been activated by remote dynip */
	unsigned long long latency;	/* average latency computed by fix/exp */
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
	char	msg[KNET_MAX_LOG_MSG_SIZE - (sizeof(uint8_t)*2)];
	uint8_t	subsystem;	/* KNET_SUB_* */
	uint8_t msglevel;	/* KNET_LOG_* */
};

void knet_set_log_level(knet_handle_t knet_h, uint8_t subsystem, uint8_t level);
const char *knet_get_subsystem_name(uint8_t subsystem);
const char *knet_get_loglevel_name(uint8_t level);
uint8_t knet_get_subsystem_id(const char *name);
uint8_t knet_get_loglevel_id(const char *name);

#endif
