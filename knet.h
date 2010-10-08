#ifndef __KNET_H__
#define __KNET_H__

#include <stdlib.h>
#include <net/ethernet.h>

int knet_open(char *dev, size_t dev_size);
int knet_close(int fd);

int knet_get_mtu(void);
int knet_set_mtu(int mtu);

int knet_get_mac(struct ether_addr *);
int knet_set_mac(const struct ether_addr *);

#endif
