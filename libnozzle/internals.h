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
	char ipaddr[IPADDR_CHAR_MAX];
	char prefix[PREFIX_CHAR_MAX];
	int  domain;			/* AF_INET or AF_INET6 */
	struct nozzle_ip *next;
};

#define MACADDR_CHAR_MAX   18

/*
 * 11 = post-down.d
 * 1  = /
 */
#define UPDOWN_PATH_MAX    PATH_MAX - 11 - 1 - IFNAMSIZ

struct nozzle_iface {
	char name[IFNAMSIZ];		/* interface name */
	int fd;				/* interface fd */
	int up;				/* interface status 0 is down, 1 is up */
	/*
	 * extra data
	 */
	struct nozzle_ip *ip;		/* configured ip addresses */

	/*
	 * default MAC address assigned by the kernel at creation time
	 */
	char default_mac[MACADDR_CHAR_MAX];

	int default_mtu;		/* MTU assigned by the kernel at creation time */
	int current_mtu;		/* MTU configured by libnozzle user */

	int hasupdown;			/* interface has up/down path to scripts configured */
	char updownpath[UPDOWN_PATH_MAX]; /* path to up/down scripts if configured */

	struct nozzle_iface *next;
};

#define ifname ifr.ifr_name

int execute_shell_command(const char *command, char **error_string);
int run_updown(const nozzle_t nozzle, const char *action, char **error_string);

#endif