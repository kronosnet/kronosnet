#ifndef __CFG_H__
#define __CFG_H__

#include <stdint.h>

#include "knet.h"
#include "ring.h"

struct knet_cfg_ip {
	char *ipaddr;
	char *prefix;
	int  active;
	struct knet_cfg_ip *next;
};

struct knet_cfg_eth {
	struct knet_eth *knet_eth;
	char name[IFNAMSIZ];
	uint8_t node_id;
	int mtu;
	int default_mtu;
	struct knet_cfg_ip *knet_ip;
};

struct knet_cfg_ring {
	knet_handle_t knet_h;
	int base_port;
};

struct knet_cfg_bridge {
	pthread_t eth2ring;
	pthread_t ring2eth;
	int active;
};

struct knet_cfg {
	struct knet_cfg_eth cfg_eth;
	struct knet_cfg_ring cfg_ring;
	struct knet_cfg_bridge cfg_bridge;
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

void knet_start_bridge(struct knet_cfg *iface);
void knet_stop_bridge(struct knet_cfg *iface);

extern struct knet_cfg_top knet_cfg_head;

#endif
