/*
 * Copyright (C) 2018-2026 Red Hat, Inc.  All rights reserved.
 *
 * Author: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *
 * This software licensed under GPL-2.0+
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
#ifdef KNET_SOLARIS
#include <sys/ethernet.h>
#else
#include <net/ethernet.h>
#endif
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
	int err = 0;

	memset(device_name, 0, sizeof(device_name));

	/*
	 * this test is duplicated from api_nozzle_open.c
	 */
	printf("Testing random nozzle interface:\n");
	if (test_iface(device_name, size,  NULL) < 0) {
		printf("*** FAIL on line %d. Unable to create random interface\n", __LINE__);
		return -1;
	}

	printf("Testing ERROR conditions\n");

	printf("Testing nozzle_close with NULL nozzle\n");
	FAIL_ON_SUCCESS(nozzle_close(NULL), EINVAL);

	printf("Testing nozzle_close with random bytes nozzle pointer\n");
	nozzle = (nozzle_t)0x1;
	FAIL_ON_SUCCESS(nozzle_close(nozzle), EINVAL);

	return 0;

out_clean:
	return err;
}

/*
 * requires running the test suite with valgrind
 */
static int check_nozzle_close_leak(void)
{
	char device_name[IFNAMSIZ];
	size_t size = IFNAMSIZ;
	int err=0;
	nozzle_t nozzle = NULL;

	printf("Testing close leak (needs valgrind)\n");

	memset(device_name, 0, size);

	printf("Creating nozzle interface\n");
	FAIL_ON_NULL(nozzle, nozzle_open(device_name, size, NULL));

	printf("Adding ip: %s/24\n", testipv4_1);
	FAIL_ON_ERR(nozzle_add_ip(nozzle, testipv4_1, "24"));

	printf("Adding ip: %s/24\n", testipv4_2);
	FAIL_ON_ERR(nozzle_add_ip(nozzle, testipv4_2, "24"));

out_clean:
	if (nozzle) {
		nozzle_close(nozzle);
	}

	return err;
}

int main(void)
{
	need_root();
	need_tun();

	make_local_ips(testipv4_1, testipv4_2, testipv6_1, testipv6_2);

	if (test() < 0)
		return FAIL;

	if (check_nozzle_close_leak() < 0)
		return FAIL;

	return 0;
}
