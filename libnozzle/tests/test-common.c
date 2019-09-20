/*
 * Copyright (C) 2018-2019 Red Hat, Inc.  All rights reserved.
 *
 * Author: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *
 * This software licensed under GPL-2.0+
 */

#include "config.h"

#include <string.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <limits.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>

#include "test-common.h"

void need_root(void)
{
	if (geteuid() != 0) {
		printf("This test requires root privileges\n");
		exit(SKIP);
	}
}

int test_iface(char *name, size_t size, const char *updownpath)
{
	nozzle_t nozzle;

	nozzle=nozzle_open(name, size, updownpath);
	if (!nozzle) {
		printf("Unable to open nozzle.\n");
		return -1;
	}
	printf("Created interface: %s\n", name);

	if (is_if_in_system(name) > 0) {
		printf("Found interface %s on the system\n", name);
	} else {
		printf("Unable to find interface %s on the system\n", name);
	}

	if (!nozzle_get_handle_by_name(name)) {
		printf("Unable to find interface %s in nozzle db\n", name);
	} else {
		printf("Found interface %s in nozzle db\n", name);
	}

	nozzle_close(nozzle);

	if (is_if_in_system(name) == 0)
		printf("Successfully removed interface %s from the system\n", name);

	return 0;
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

int get_random_byte(void)
{
	pid_t mypid;
	uint8_t *pid;
	uint8_t randombyte = 0;
	uint8_t i;

	if (sizeof(pid_t) < 4) {
		printf("pid_t is smaller than 4 bytes?\n");
		exit(77);
	}

	mypid = getpid();
	pid = (uint8_t *)&mypid;

	for (i = 0; i < sizeof(pid_t); i++) {
		if (pid[i] == 0) {
			pid[i] = 128;
		}
	}

	randombyte = pid[1];

	return randombyte;
}

void make_local_ips(char *testipv4_1, char *testipv4_2, char *testipv6_1, char *testipv6_2)
{
	pid_t mypid;
	uint8_t *pid;
	uint8_t i;

	memset(testipv4_1, 0, IPBUFSIZE);
	memset(testipv4_2, 0, IPBUFSIZE);
	memset(testipv6_1, 0, IPBUFSIZE);
	memset(testipv6_2, 0, IPBUFSIZE);

	mypid = getpid();
	pid = (uint8_t *)&mypid;

	for (i = 0; i < sizeof(pid_t); i++) {
		if ((pid[i] == 0) || (pid[i] == 255)) {
			pid[i] = 128;
		}
	}

	snprintf(testipv4_1,
		 IPBUFSIZE - 1,
		 "127.%u.%u.%u",
		 pid[1],
		 pid[2],
		 pid[0]);

	snprintf(testipv4_2,
		 IPBUFSIZE - 1,
		 "127.%u.%d.%u",
		 pid[1],
		 pid[2]+1,
		 pid[0]);

	snprintf(testipv6_1,
		 IPBUFSIZE - 1,
		 "fd%x:%x%x::1",
		 pid[1],
		 pid[2],
		 pid[0]);

	snprintf(testipv6_2,
		 IPBUFSIZE - 1,
		 "fd%x:%x%x:1::1",
		 pid[1],
		 pid[2],
		 pid[0]);
}
