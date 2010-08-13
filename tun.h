#ifndef __TUN_H__
#define __TUN_H__

#include <stdlib.h>

int tun_open(char *dev, size_t dev_size);
int tun_close(int fd);
int tun_read(int fd, char *buf, int len);
int tun_write(int fd, char *buf, int len);

#endif
