#include "config.h"

#include <pthread.h>
#include <unistd.h>

#include "cfg.h"
#include "knet.h"
#include "utils.h"

static void free_knet_ip(struct knet_cfg_ip *knet_ip)
{
	if (knet_ip->ipaddr)
		free(knet_ip->ipaddr);
	if (knet_ip->prefix)
		free(knet_ip->prefix);
	if (knet_ip)
		free(knet_ip);
}

struct knet_cfg_ip *knet_get_ip(struct knet_cfg *knet_iface,
				const char *ipaddr, const char *prefix,
				const int create)
{
	int found = 0, err = 0;
	struct knet_cfg_ip *knet_ip = knet_iface->cfg_eth.knet_ip;

	while (knet_ip != NULL) {
		if ((!strcmp(knet_ip->ipaddr, ipaddr)) && (!strcmp(knet_ip->prefix, prefix))) {
			found = 1;
			break;
		}
		knet_ip = knet_ip->next;
	}

	if ((!found) && (create)) {
		knet_ip = malloc(sizeof(struct knet_cfg_ip));
		if (!knet_ip)
			goto out_clean;

		memset(knet_ip, 0, sizeof(struct knet_cfg_ip));

		knet_ip->ipaddr = strdup(ipaddr);
		if (!knet_ip->ipaddr) {
			err = -1;
			goto out_clean;
		}

		knet_ip->prefix = strdup(prefix);
		if (!knet_ip->prefix) {
			err = -1;
			goto out_clean;
		}

		knet_ip->next = knet_iface->cfg_eth.knet_ip;
		knet_iface->cfg_eth.knet_ip = knet_ip;
	}

out_clean:
	if (err) {
		free_knet_ip(knet_ip);
		knet_ip = NULL;
	}

	return knet_ip;
}

void knet_destroy_ip(struct knet_cfg *knet_iface, struct knet_cfg_ip *knet_ip)
{
	struct knet_cfg_ip *knet_ip_tmp = knet_iface->cfg_eth.knet_ip;
	struct knet_cfg_ip *knet_ip_prev = knet_iface->cfg_eth.knet_ip;

	while (knet_ip_tmp != knet_ip) {
		knet_ip_prev = knet_ip_tmp;
		knet_ip_tmp = knet_ip_tmp->next;
	}

	if (knet_ip_tmp == knet_ip) {
		if (knet_ip_tmp == knet_ip_prev) {
			knet_iface->cfg_eth.knet_ip = knet_ip_tmp->next;
		} else {
			knet_ip_prev->next = knet_ip_tmp->next;
		}
		free_knet_ip(knet_ip);
		knet_ip = NULL;
	}
	return;
}

struct knet_cfg *knet_get_iface(const char *name, int create)
{
	struct knet_cfg *knet_iface = knet_cfg_head.knet_cfg;
	int found = 0;

	while (knet_iface != NULL) {
		if (!strcmp(knet_iface->cfg_eth.name, name)) {
			found = 1;
			break;
		}
		knet_iface = knet_iface->next;
	}

	if ((!found) && (create)) {
		knet_iface = malloc(sizeof(struct knet_cfg));
		if (!knet_iface)
			goto out_clean;

		memset(knet_iface, 0, sizeof(struct knet_cfg));
		memcpy(knet_iface->cfg_eth.name, name,
			sizeof(knet_iface->cfg_eth.name));

		knet_iface->cfg_ring.base_port = KNET_RING_DEFPORT;

		knet_iface->next = knet_cfg_head.knet_cfg;
		knet_cfg_head.knet_cfg = knet_iface;
	}

out_clean:

	return knet_iface;
}

void knet_destroy_iface(struct knet_cfg *knet_iface)
{
	struct knet_cfg *knet_iface_tmp = knet_cfg_head.knet_cfg;
	struct knet_cfg *knet_iface_prev = knet_cfg_head.knet_cfg;

	while (knet_iface_tmp != knet_iface) {
		knet_iface_prev = knet_iface_tmp;
		knet_iface_tmp = knet_iface_tmp->next;
	}

	if (knet_iface_tmp == knet_iface) {
		if (knet_iface_tmp == knet_iface_prev) {
			knet_cfg_head.knet_cfg = knet_iface_tmp->next;
		} else {
			knet_iface_prev->next = knet_iface_tmp->next;
		}
		free(knet_iface);
	}
}
