#ifndef __LIBTAP_PRIVATE_H__
#define __LIBTAP_PRIVATE_H__

#include <net/if.h>

struct tap_ip {
	char *ipaddr[128];
	char prefix[4];
	int active;
	struct tap_ip *next;
};

struct tap_iface {
        struct ifreq ifr;
        int knet_tap_fd;
	int default_mtu;
	char default_mac[18];
	struct tap_iface *next;
};
#define ifname ifr.ifr_name

struct tap_config {
	struct tap_iface *tap_head;
	int tap_sockfd;
};

#endif
