#include "config.h"

#include <stdio.h>
#include <arpa/inet.h>

#include "packet.h"
#include "netsocket.h"

static uint8_t ipv4_bcast[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
static uint8_t ipv6_bcast[] = { 0x33, 0x33 };

inline uint32_t packet_to_nodeid(void *packet, struct node *node)
{
	struct ether_header *eth_h = packet;

	if (memcmp(ipv4_bcast, eth_h->ether_dhost, sizeof(ipv4_bcast)) == 0)
		return 0;

	if (memcmp(ipv6_bcast, eth_h->ether_dhost, sizeof(ipv6_bcast)) == 0)
		return 0;

	while (node) {
		if (memcmp(node->hwaddress, eth_h->ether_dhost, ETH_ALEN) == 0)
			return node->nodeid;
		node = node->next;
	}

	return 0;
}

