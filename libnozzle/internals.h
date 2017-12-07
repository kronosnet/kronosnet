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

#define MAX_IP_CHAR	128
#define MAX_PREFIX_CHAR	4
#define MAX_MAC_CHAR	18

struct _ip {
	char ip_addr[MAX_IP_CHAR];
	char prefix[MAX_PREFIX_CHAR];
	int  domain;
	struct _ip *next;
};

struct nozzle_iface {
	struct ifreq ifr;
	int fd;
	char nozzlename[IFNAMSIZ];
	char default_mac[MAX_MAC_CHAR];
	int default_mtu;
	int current_mtu;
	char updownpath[PATH_MAX - 11 - 1 - IFNAMSIZ]; /* 11 = post-down.d 1 = / */
	int hasupdown;
	int up;
	struct _ip *ip;
	struct nozzle_iface *next;
};
#define ifname ifr.ifr_name

struct _config {
	struct nozzle_iface *head;
	int sockfd;
};

#endif
