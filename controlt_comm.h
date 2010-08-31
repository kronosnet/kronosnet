#ifndef __CONTROLT_COMM_H__
#define __CONTROLT_COMM_H__

#include "config.h"
#include <stdint.h>

#define	CLUSTERNETD_SOCKNAME	RUNDIR "/clusternetd.sock"

#define CNETD_MAGIC	0x12344321
#define CNETD_VERSION	0x00000001

#define CNETD_CMD_QUIT		1
#define CNETD_CMD_STATUS	2

struct ctrl_header {
	uint32_t magic;
	uint32_t version;
	uint32_t command;
	uint32_t option;
	uint32_t len;
	int data;		/* embedded command-specific data, for convenience */
	int unused1;
	int unsued2;
};

void init_header(struct ctrl_header *h, int cmd, int extra_len);

#endif
