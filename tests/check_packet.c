#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <error.h>

#include "knet.h"


char eth_frame[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ether_dhost */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ether_shost */
	0x08, 0x00, /* ether_type */
};

char bcast4_mac[] = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, /* ether_dhost */
};

char bcast6_mac[] = {
	0x33, 0x33, /* ether_dhost */
};


int main(int argc, char *argv[])
{
	uint32_t nid;

	memmove(eth_frame, knet_hwvend, sizeof(knet_hwvend));

	eth_frame[5] = 0x01;

	nid = knet_hwtoid(eth_frame);
	if (nid != 0x01)
		error(EXIT_FAILURE, -EINVAL, "eth_frame1 failed");

	eth_frame[5] = 0x02;

	nid = knet_hwtoid(eth_frame);
	if (nid != 0x02)
		error(EXIT_FAILURE, -EINVAL, "eth_frame2 failed");

	memmove(eth_frame, bcast4_mac, sizeof(bcast4_mac));

	nid = knet_hwtoid(eth_frame);
	if (nid != 0)
                error(EXIT_FAILURE, -EINVAL, "bcast4_mac failed");

	memmove(eth_frame, bcast6_mac, sizeof(bcast6_mac));

	nid = knet_hwtoid(eth_frame);
	if (nid != 0)
                error(EXIT_FAILURE, -EINVAL, "bcast6_mac failed");

	return 0;
}

