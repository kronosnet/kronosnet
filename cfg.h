#ifndef __CFG_H__
#define __CFG_H__

#include <stdint.h>

#include "knet.h"
#include "ring.h"

struct knet_cfg_eth {
	char name[IFNAMSIZ];
	uint8_t node_id;
	int mtu;
	int default_mtu;
};

struct knet_cfg {
	struct knet_cfg_eth cfg_eth;
	struct knet_eth *knet_eth;
	knet_handle_t *knet_ring;
	struct knet_cfg *next;
};

struct knet_cfg_top {
	char *conffile;
	char *ip_addr;
	char *port;
	struct knet_cfg *knet_cfg;
};

struct knet_cfg *knet_get_iface(const char *name, const int create);
void knet_destroy_iface(struct knet_cfg *knet_iface);

int knet_read_config(void);
int knet_write_config(void);

extern struct knet_cfg_top knet_cfg_head;

#endif
