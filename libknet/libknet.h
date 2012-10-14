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

#define KNET_CBUFFER_SIZE 4096
/*
typedef uint64_t seq_num_t;
#define SEQ_MAX UINT64_MAX
*/
typedef uint16_t seq_num_t;
#define SEQ_MAX UINT16_MAX

struct knet_link {
	uint8_t link_id;
	int sock;
	char ipaddr[KNET_MAX_HOST_LEN];
	char port[6];
	struct sockaddr_storage address;
	unsigned int configured:1; /* link is configured and ready to be used */
	unsigned int connected:1;	/* link is enabled for data */
	uint8_t  priority; /* higher priority == preferred for A/P */
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
	struct knet_listener *listener;
	struct knet_link link[KNET_MAX_LINK];
	uint8_t active_link_entries;
	uint8_t active_links[KNET_MAX_LINK];
	uint8_t link_handler_policy;
	struct knet_host *next;
};

struct knet_listener {
	int sock;
	char ipaddr[KNET_MAX_HOST_LEN];
	char port[6];
	struct sockaddr_storage address;
	struct knet_listener *next;
};

union knet_frame_data {
	struct {
		seq_num_t	kfd_seq_num;
		uint8_t		kfd_data[0];
	} data;
	struct {
		uint8_t		kfd_link;
		struct timespec	kfd_time;
	} ping;
} __attribute__((packed));

struct knet_frame {
	uint32_t 		kf_magic;
	uint8_t			kf_version;
	uint8_t			kf_type;
	uint16_t		kf_node;
	union knet_frame_data	kf_payload;
} __attribute__((packed));

#define kf_seq_num kf_payload.data.kfd_seq_num
#define kf_data kf_payload.data.kfd_data
#define kf_link kf_payload.ping.kfd_link
#define kf_time kf_payload.ping.kfd_time

#define KNET_FRAME_SIZE (sizeof(struct knet_frame) - sizeof(union knet_frame_data))

#define KNET_FRAME_MAGIC 0x12344321
#define KNET_FRAME_VERSION 0x01

#define KNET_FRAME_DATA 0x00
#define KNET_FRAME_PING 0x81
#define KNET_FRAME_PONG 0x82
#define KNET_FRAME_PMSK 0x80 /* ping/pong packet mask */

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

struct knet_handle_cfg {
	int		fd;
	uint16_t	node_id;
	uint8_t		dst_host_filter;
	int		(*dst_host_filter_fn) (
				const unsigned char *outdata,
				ssize_t outdata_len,
				uint16_t src_node_id,
				uint16_t *dst_host_ids,
				size_t *dst_host_ids_entries);
};

int ether_host_filter_fn (const unsigned char *outdata,
			  ssize_t outdata_len,
			  uint16_t src_node_id,
			  uint16_t *dst_host_ids,
			  size_t *dst_host_ids_entries);

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

int knet_link_enable(knet_handle_t knet_h, uint16_t node_id, struct knet_link *lnk, int configured);
void knet_link_timeout(struct knet_link *lnk, time_t interval, time_t timeout, int precision);

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

int knet_listener_acquire(knet_handle_t knet_h, struct knet_listener **head, int writelock);
int knet_listener_release(knet_handle_t knet_h);
int knet_listener_add(knet_handle_t knet_h, struct knet_listener *listener);
int knet_listener_remove(knet_handle_t knet_h, struct knet_listener *listener);

#endif
