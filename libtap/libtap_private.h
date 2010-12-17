#ifndef __LIBTAP_PRIVATE_H__
#define __LIBTAP_PRIVATE_H__

#include <net/if.h>

#define MAX_IP_CHAR	128
#define MAX_PREFIX_CHAR	4
#define MAX_MAC_CHAR	18

struct tap_ip {
	char ip_addr[MAX_IP_CHAR];
	char prefix[MAX_PREFIX_CHAR];
	struct tap_ip *next;
};

struct tap_iface {
	struct ifreq ifr;
	char default_mac[MAX_MAC_CHAR];
	int knet_tap_fd;
	int default_mtu;
	struct tap_ip *tap_ip;
	struct tap_iface *next;
};
#define ifname ifr.ifr_name

struct tap_config {
	struct tap_iface *tap_head;
	int tap_sockfd;
};

#endif
