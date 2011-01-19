#ifndef __LIBTAP_PRIVATE_H__
#define __LIBTAP_PRIVATE_H__

#include <net/if.h>
#include <limits.h>

#define MAX_IP_CHAR	128
#define MAX_PREFIX_CHAR	4
#define MAX_MAC_CHAR	18

struct _ip {
	char ip_addr[MAX_IP_CHAR];
	char prefix[MAX_PREFIX_CHAR];
	struct _ip *next;
};

struct _iface {
	struct ifreq ifr;
	int fd;
	char default_mac[MAX_MAC_CHAR];
	int default_mtu;
	char updownpath[PATH_MAX];
	int hasupdown;
	int up;
	struct _ip *ip;
	struct _iface *next;
};
#define ifname ifr.ifr_name

struct _config {
	struct _iface *head;
	int sockfd;
};

#endif
