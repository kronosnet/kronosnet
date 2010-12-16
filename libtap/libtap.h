#ifndef __KNET_H__
#define __KNET_H__

#include <stdlib.h>
#include <net/if.h>

struct knet_tap {
	struct ifreq ifr;
	int knet_tap_fd;
};

struct knet_tap *knet_tap_open(char *dev, size_t dev_size);
void knet_tap_close(struct knet_tap *knet_tap);

int knet_tap_get_mtu(const struct knet_tap *knet_tap);
int knet_tap_set_mtu(struct knet_tap *knet_tap, const int mtu);

int knet_tap_get_mac(const struct knet_tap *knet_tap, char **ether_addr);
int knet_tap_set_mac(struct knet_tap *knet_tap, const char *ether_addr);

int knet_tap_set_up(struct knet_tap *knet_tap);
int knet_tap_set_down(struct knet_tap *knet_tap);

int knet_tap_add_ip(struct knet_tap *knet_tap, const char *ip_addr,
		const char *prefix);
int knet_tap_del_ip(struct knet_tap *knet_tap, const char *ip_addr,
		const char *prefix);

#endif
