#ifndef __KNET_H__
#define __KNET_H__

#include <stdlib.h>

int knet_open(char *dev, size_t dev_size);
int knet_get_mtu(char *dev);
int knet_close(int fd);
int knet_read(int fd, char *buf, int len);
int knet_write(int fd, char *buf, int len);

#endif
