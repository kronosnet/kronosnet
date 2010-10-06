#include "config.h"

#include <stdio.h>
#include <arpa/inet.h>

#include "packet.h"
#include "nodes.h"
#include "logging.h"

static uint8_t ipv4_bcast[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
static uint8_t ipv6_bcast[] = { 0x33, 0x33, 0x33 };

struct node *pckt_target(void *packet, struct node *node)
{
	struct ether_header *ether = (struct ether_header *) packet;
	struct ether_addr *dst_mac = (struct ether_addr *) ether->ether_dhost;

	if (memcmp(ipv4_bcast, dst_mac, sizeof(ipv4_bcast)) == 0)
		return 0;

	if (memcmp(ipv6_bcast, dst_mac, sizeof(ipv6_bcast)) == 0)
		return 0;

	while (node) {
		if (memcmp(node->hwaddress, dst_mac, ETH_ALEN) == 0)
			return node;
		node = node->next;
	}

	return 0;
}

