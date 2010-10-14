#ifndef __KNET_H__
#define __KNET_H__

#include <stdlib.h>
#include <net/if.h>

struct knet_eth {
	struct ifreq ifr;
	int knet_etherfd;
};

struct knet_eth *knet_open(char *dev, size_t dev_size);
void knet_close(struct knet_eth *knet_eth);

int knet_get_mtu(const struct knet_eth *knet_eth);
int knet_set_mtu(struct knet_eth *knet_eth, const int mtu);

int knet_get_mac(const struct knet_eth *knet_eth, char **ether_addr);
int knet_set_mac(struct knet_eth *knet_eth, const char *ether_addr);

int knet_set_up(struct knet_eth *knet_eth);
int knet_set_down(struct knet_eth *knet_eth);

int knet_add_ip(struct knet_eth *knet_eth, const char *ip_addr,
		const char *prefix);
int knet_del_ip(struct knet_eth *knet_eth, const char *ip_addr,
		const char *prefix);

#endif
