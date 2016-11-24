/*
 * Copyright (C) 2010-2015 Red Hat, Inc.  All rights reserved.
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
	struct knet_cfg *knet_iface = NULL;
	struct qb_list_head *pos;
	int found = 0;

	qb_list_for_each(pos, &knet_cfg_head.cfg_head) {
		knet_iface = qb_list_entry(pos, struct knet_cfg, list);
		if (!strcmp(tap_get_name(knet_iface->cfg_eth.tap), name)) {
			found = 1;
			break;
		}
	}

	if ((!found) && (create)) {
		knet_iface = malloc(sizeof(struct knet_cfg));
		if (!knet_iface)
			goto out_clean;

		memset(knet_iface, 0, sizeof(struct knet_cfg));

		qb_list_init(&knet_iface->list);

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

		qb_list_add_tail(&knet_iface->list, &knet_cfg_head.cfg_head);
	}

out_clean:

	return knet_iface;
}

void knet_destroy_iface(struct knet_cfg *knet_iface)
{
	qb_list_del(&knet_iface->list);
	free(knet_iface);
}
