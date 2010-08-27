#ifndef __TUN_H__
#define __TUN_H__

#include <stdlib.h>

int cnet_open(char *dev, size_t dev_size);
int cnet_get_mtu(char *dev);
int cnet_close(int fd);
int cnet_read(int fd, char *buf, int len);
int cnet_write(int fd, char *buf, int len);

#endif
