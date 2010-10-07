#ifndef __KNET_H__
#define __KNET_H__

#include <stdlib.h>
#include <stdint.h>

/*
 * TODO: Make this configurable
 */
#define IPROUTE_CMD	"/sbin/ip"

int knet_open(char *dev, size_t dev_size);
int knet_set_hwid(char *dev, uint32_t nodeid);
uint32_t knet_hwtoid(void *packet);
int knet_get_mtu(char *dev);
int knet_close(int fd);
int knet_read(int fd, char *buf, int len);
int knet_write(int fd, char *buf, int len);
extern int knet_up(const char *dev_name, int mtu);
extern int knet_add_ip(const char *dev_name, const char *ip);

extern uint8_t knet_hwvend[2];

#endif
