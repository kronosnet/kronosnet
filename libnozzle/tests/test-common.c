/*
 * Copyright (C) 2018 Red Hat, Inc.  All rights reserved.
 *
 * Author: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *
 * This software licensed under GPL-2.0+, LGPL-2.0+
 */

#include "config.h"

#include <string.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <limits.h>
#include <unistd.h>
#include <sys/types.h>

#include "test-common.h"

void need_root(void)
{
	if (geteuid() != 0) {
		printf("This test requires root privileges\n");
		exit(SKIP);
	}
}

int is_if_in_system(char *name)
{
	struct ifaddrs *ifap = NULL;
	struct ifaddrs *ifa;
	int found = 0;

	if (getifaddrs(&ifap) < 0) {
		printf("Unable to get interface list.\n");
		return -1;
	}

	ifa = ifap;

	while (ifa) {
		if (!strncmp(name, ifa->ifa_name, IFNAMSIZ)) {
			found = 1;
			break;
		}
		ifa=ifa->ifa_next;
	}

	freeifaddrs(ifap);
	return found;
}
