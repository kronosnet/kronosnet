#ifndef __PACKET_H__
#define __PACKET_H__

#include <netinet/ether.h>
#include "netsocket.h"

#define IEEE_802_3_MAX_LEN 1500
#define ETHERTYPE_UNK 0x0000

struct node *pckt_target(void *packet, struct node *node);

#endif
