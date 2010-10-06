#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <error.h>

#include "nodes.h"
#include "packet.h"


char eth_frame[] = {
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, /* ether_dhost */
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
	struct node n;

	memset(&n, 0, sizeof(struct node));
	n.nodeid = 1;
	memmove(n.hwaddress, eth_frame, sizeof(n.hwaddress));

	nid = packet_to_nodeid(eth_frame, &n);
	if (nid != n.nodeid)
		error(EXIT_FAILURE, -EINVAL, "eth_frame1 failed");

	memset(eth_frame, 0x00, ETH_ALEN);

	nid = packet_to_nodeid(eth_frame, &n);
	if (nid != 0)
		error(EXIT_FAILURE, -EINVAL, "eth_frame2 failed");

	memmove(eth_frame, bcast4_mac, sizeof(bcast4_mac));

	nid = packet_to_nodeid(eth_frame, &n);
	if (nid != 0)
                error(EXIT_FAILURE, -EINVAL, "bcast4_mac failed");

	memmove(eth_frame, bcast6_mac, sizeof(bcast6_mac));

	nid = packet_to_nodeid(eth_frame, &n);
	if (nid != 0)
                error(EXIT_FAILURE, -EINVAL, "bcast6_mac failed");

	return 0;
}

