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

struct cnet_header {
	uint32_t magic;
	uint32_t nodeid;
	uint32_t seq_num;
	uint32_t pckt_type:4;
	uint32_t compress:1;
	uint32_t encryption:1;
	uint32_t padding:26;
};

int setup_net_listener(void);

#endif
