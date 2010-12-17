#ifndef __CFG_H__
#define __CFG_H__

#include <stdint.h>
#include <net/if.h>

#include "libtap.h"
#include "ring.h"

struct knet_cfg_ip {
	char *ipaddr;
	char *prefix;
	int  active;
	struct knet_cfg_ip *next;
};

struct knet_cfg_eth {
	knet_tap_t knet_tap;
	char name[IFNAMSIZ];
	uint8_t node_id;
	struct knet_cfg_ip *knet_ip;
};

struct knet_cfg_ring {
	knet_handle_t knet_h;
	int base_port;
};

struct knet_cfg {
	struct knet_cfg_eth cfg_eth;
	struct knet_cfg_ring cfg_ring;
	int active;
	struct knet_cfg *next;
};

struct knet_cfg_top {
	char *conffile;
	char *vty_ip;
	char *vty_port;
	struct knet_cfg *knet_cfg;
};

struct knet_cfg_ip *knet_get_ip(struct knet_cfg *knet_iface,
				const char *ipaddr, const char *prefix,
				const int create);
void knet_destroy_ip(struct knet_cfg *knet_iface, struct knet_cfg_ip *knet_ip);

struct knet_cfg *knet_get_iface(const char *name, const int create);
void knet_destroy_iface(struct knet_cfg *knet_iface);

extern struct knet_cfg_top knet_cfg_head;

#endif
