/*
 * Copyright (C) 2010-2015 Red Hat, Inc.  All rights reserved.
 *
 * Authors: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *          Federico Simoncelli <fsimon@kronosnet.org>
 *
 * This software licensed under GPL-2.0+, LGPL-2.0+
 */

#ifndef __CFG_H__
#define __CFG_H__

#include <stdint.h>
#include <net/if.h>

#include "qb/qblist.h"
#include "libtap.h"
#include "libknet.h"

#define KNET_RING_DEFPORT 50000

struct knet_cfg_eth {
	tap_t tap;
	int auto_mtu;
	uint16_t node_id;
};

struct knet_cfg_ring {
	knet_handle_t knet_h;
	int data_mtu;
	int base_port;
};

struct knet_cfg {
	struct knet_cfg_eth cfg_eth;
	struct knet_cfg_ring cfg_ring;
	int active;
	struct knet_handle_crypto_cfg knet_handle_crypto_cfg;
	struct qb_list_head list;
};

struct knet_cfg_top {
	char *conffile;
	char *logfile;
	char *vty_ipv4;
	char *vty_ipv6;
	char *vty_port;
	struct qb_list_head cfg_head;
};

struct knet_cfg *knet_get_iface(const char *name, const int create);
void knet_destroy_iface(struct knet_cfg *knet_iface);

extern struct knet_cfg_top knet_cfg_head;

#endif
