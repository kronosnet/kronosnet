#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <alloca.h>
#include <error.h>

#include "nodes.h"
#include "packet.h"

char node_req[] = {
	0x01, 0x01, 0x01, 0x01, 0x01, 0x01, /* ether_dhost */
	0x02, 0x02, 0x02, 0x02, 0x02, 0x02, /* ether_shost */
	0x08, 0x00, /*ether_type */
};

char bcast4_req[] = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, /* ether_dhost */
	0x02, 0x02, 0x02, 0x02, 0x02, 0x02, /* ether_shost */
	0x08, 0x00, /*ether_type */
};

char bcast6_req[] = {
	0x33, 0x33, 0x33, 0x00, 0x00, 0x01, /* ether_dhost */
	0x02, 0x02, 0x02, 0x02, 0x02, 0x02, /* ether_shost */
	0x08, 0x00, /*ether_type */
};

#define KNET_DATASIZE 1024

int main(int argc, char *argv[])
{
	struct node n1, *target;
	memset(&n1, 0, sizeof(struct node));

	memset(n1.hwaddress, 0x01, ETH_ALEN);

	target = pckt_target(node_req, &n1);
	if (target != &n1)
		error(EXIT_FAILURE, -EINVAL, "node_req test1 failed");

	memset(n1.hwaddress, 0x02, ETH_ALEN);

	target = pckt_target(node_req, &n1);
	if (target != 0)
		error(EXIT_FAILURE, -EINVAL, "node_req test2 failed");

	target = pckt_target(bcast4_req, &n1);
	if (target != 0)
                error(EXIT_FAILURE, -EINVAL, "bcast4_req failed");


	target = pckt_target(bcast6_req, &n1);
	if (target != 0)
                error(EXIT_FAILURE, -EINVAL, "bcast6_req failed");


	return 0;
}

