#ifndef __NETSOCKET_H__
#define __NETSOCKET_H__

#include <stdint.h>

#define DEFAULT_PORT 50000
#define DEFAULT_RCVBUFF 8192

#define KNETD_PKCT_TYPE_DATA	0
#define KNETD_PKCT_TYPE_PING	1
#define KNETD_PKCT_TYPE_PONG	2
#define KNETD_PKCT_TYPE_SYN	3
#define KNETD_PKCT_TYPE_ACK	4

#define KNETD_COMPRESS_OFF	0
#define KNETD_COMPRESS_ON	1

#define KNETD_ENCRYPTION_OFF	0
#define KNETD_ENCRYPTION_ON	1

/* change those to uint8 and UINT8_MAX to test rollover */
/*
typedef uint32_t seq_num_t;
#define SEQ_MAX UINT32_MAX
*/
typedef uint16_t seq_num_t;
#define SEQ_MAX	UINT16_MAX

struct knet_header {
	uint32_t magic;
	uint32_t version;
	uint32_t dst_nodeid;
	uint32_t src_nodeid;
	seq_num_t seq_num;
	uint32_t pckt_type:4;
	uint32_t compress:1;
	uint32_t encryption:1;
	uint32_t padding:26;
};

int setup_net_listener(void);

#endif
