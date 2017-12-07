/*
 * Copyright (C) 2010-2017 Red Hat, Inc.  All rights reserved.
 *
 * Author: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *
 * This software licensed under GPL-2.0+, LGPL-2.0+
 */

#ifndef __NOZZLE_INTERNALS_H__
#define __NOZZLE_INTERNALS_H__

#include "config.h"
#include <net/if.h>

struct nozzle_lib_config {
	struct nozzle_iface *head;
	int ioctlfd;
};

#define IPADDR_CHAR_MAX   128
#define PREFIX_CHAR_MAX	    4

struct nozzle_ip {
	char ip_addr[IPADDR_CHAR_MAX];
	char prefix[PREFIX_CHAR_MAX];
	int  domain;
	struct nozzle_ip *next;
};

#define MACADDR_CHAR_MAX   18

struct nozzle_iface {
	struct ifreq ifr;
	int fd;
	char nozzlename[IFNAMSIZ];
	char default_mac[MACADDR_CHAR_MAX];
	int default_mtu;
	int current_mtu;
	char updownpath[PATH_MAX - 11 - 1 - IFNAMSIZ]; /* 11 = post-down.d 1 = / */
	int hasupdown;
	int up;
	struct nozzle_ip *ip;
	struct nozzle_iface *next;
};
#define ifname ifr.ifr_name

#endif
