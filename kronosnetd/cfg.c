/*
 * Copyright (C) 2010-2012 Red Hat, Inc.  All rights reserved.
 *
 * Author: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *
 * This software licensed under GPL-2.0+, LGPL-2.0+
 */

#include "config.h"

#include <pthread.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include "cfg.h"
#include "libtap.h"

struct knet_cfg *knet_get_iface(const char *name, int create)
{
	struct knet_cfg *knet_iface = knet_cfg_head.knet_cfg;
	int found = 0;

	while (knet_iface != NULL) {
		if (!strcmp(tap_get_name(knet_iface->cfg_eth.tap), name)) {
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

		strncpy(knet_iface->knet_handle_crypto_cfg.crypto_model,
			"none",
			sizeof(knet_iface->knet_handle_crypto_cfg.crypto_model) - 1);

		strncpy(knet_iface->knet_handle_crypto_cfg.crypto_cipher_type,
			"none",
			sizeof(knet_iface->knet_handle_crypto_cfg.crypto_cipher_type) - 1);

		strncpy(knet_iface->knet_handle_crypto_cfg.crypto_hash_type,
			"none",
			sizeof(knet_iface->knet_handle_crypto_cfg.crypto_hash_type) - 1);

		if (knet_cfg_head.knet_cfg) {
			struct knet_cfg *knet_iface_last = knet_cfg_head.knet_cfg;

			while (knet_iface_last->next != NULL) {
				knet_iface_last = knet_iface_last->next;
			}
			knet_iface_last->next = knet_iface;
		} else {
			knet_cfg_head.knet_cfg = knet_iface;
		}
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
