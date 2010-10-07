#ifndef __KNET_H__
#define __KNET_H__

#include <stdlib.h>

int knet_open(char *dev, size_t dev_size);
int knet_close(int fd);

int knet_get_mtu(void);
int knet_set_mtu(int mtu);

#endif
