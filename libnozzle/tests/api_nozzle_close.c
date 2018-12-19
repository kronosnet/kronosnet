/*
 * Copyright (C) 2018 Red Hat, Inc.  All rights reserved.
 *
 * Author: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *
 * This software licensed under GPL-2.0+, LGPL-2.0+
 */

#include "config.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <limits.h>
#include <sys/socket.h>
#include <net/ethernet.h>

#ifdef KNET_LINUX
#include <linux/if_tun.h>
#include <netinet/ether.h>
#endif
#ifdef KNET_BSD
#include <net/if_dl.h>
#endif

#include "test-common.h"

char testipv4_1[IPBUFSIZE];
char testipv4_2[IPBUFSIZE];
char testipv6_1[IPBUFSIZE];
char testipv6_2[IPBUFSIZE];

static int test(void)
{
	char device_name[2*IFNAMSIZ];
	size_t size = IFNAMSIZ;
	nozzle_t nozzle;

	memset(device_name, 0, sizeof(device_name));

	/*
	 * this test is duplicated from api_nozzle_open.c
	 */
	printf("Testing random nozzle interface:\n");
	if (test_iface(device_name, size,  NULL) < 0) {
		printf("Unable to create random interface\n");
		return -1;
	}

	printf("Testing ERROR conditions\n");

	printf("Testing nozzle_close with NULL nozzle\n");
	if ((nozzle_close(NULL) >= 0) || (errno != EINVAL)) {
		printf("Something is wrong in nozzle_close sanity checks\n");
		return -1;
	}

	printf("Testing nozzle_close with random bytes nozzle pointer\n");

	nozzle = (nozzle_t)0x1;

	if ((nozzle_close(nozzle) >= 0) || (errno != EINVAL)) {
		printf("Something is wrong in nozzle_close sanity checks\n");
		return -1;
	}

	return 0;
}

/*
 * requires running the test suite with valgrind
 */
static int check_nozzle_close_leak(void)
{
	char device_name[IFNAMSIZ];
	size_t size = IFNAMSIZ;
	int err=0;
	nozzle_t nozzle;

	printf("Testing close leak (needs valgrind)\n");

	memset(device_name, 0, size);

	nozzle = nozzle_open(device_name, size, NULL);
	if (!nozzle) {
		printf("Unable to init %s\n", device_name);
		return -1;
	}

	printf("Adding ip: %s/24\n", testipv4_1);

	err = nozzle_add_ip(nozzle, testipv4_1, "24");
	if (err < 0) {
		printf("Unable to assign IP address\n");
		err=-1;
		goto out_clean;
	}

	printf("Adding ip: %s/24\n", testipv4_2);

	err = nozzle_add_ip(nozzle, testipv4_2, "24");
	if (err < 0) {
		printf("Unable to assign IP address\n");
		err=-1;
		goto out_clean;
	}

out_clean:
	nozzle_close(nozzle);

	return err;
}

int main(void)
{
	need_root();

	make_local_ips(testipv4_1, testipv4_2, testipv6_1, testipv6_2);

	if (test() < 0)
		return FAIL;

	if (check_nozzle_close_leak() < 0)
		return FAIL;

	return 0;
}
