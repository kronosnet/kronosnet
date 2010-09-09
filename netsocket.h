#ifndef __NETSOCKET_H__
#define __NETSOCKET_H__

#include <stdint.h>

#define DEFAULT_PORT 50000

#define CNETD_PKCT_TYPE_DATA	0
#define CNETD_PKCT_TYPE_PING	1
#define CNETD_PKCT_TYPE_PONG	2

#define CNETD_COMPRESS_OFF	0
#define CNETD_COMPRESS_ON	1

#define CNETD_ENCRYPTION_OFF	0
#define CNETD_ENCRYPTION_ON	1

/* change those to uint8 and UINT8_MAX to test rollover */
/*
typedef uint32_t seq_num_t;
#define SEQ_MAX UINT32_MAX
*/
typedef uint16_t seq_num_t;
#define SEQ_MAX	UINT16_MAX

struct cnet_header {
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
