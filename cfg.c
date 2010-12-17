#include "config.h"

#include <pthread.h>
#include <unistd.h>
#include <stdlib.h>

#include "cfg.h"
#include "libtap.h"
#include "utils.h"

struct knet_cfg *knet_get_iface(const char *name, int create)
{
	struct knet_cfg *knet_iface = knet_cfg_head.knet_cfg;
	int found = 0;

	while (knet_iface != NULL) {
		if (!strcmp(knet_tap_get_name(knet_iface->cfg_eth.knet_tap), name)) {
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
