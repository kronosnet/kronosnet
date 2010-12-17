#ifndef __LIBTAP_PRIVATE_H__
#define __LIBTAP_PRIVATE_H__

#include <net/if.h>

struct knet_tap {
        struct ifreq ifr;
        int knet_tap_fd;
	int default_mtu;
	char default_mac[18];
	struct knet_tap *next;
};

#define ifname ifr.ifr_name

struct tap_config {
	struct knet_tap *tap_head;
	int tap_sockfd;
};

#endif
