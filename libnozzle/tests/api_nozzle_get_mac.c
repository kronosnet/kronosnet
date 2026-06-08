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

static int test(void)
{
	char device_name[IFNAMSIZ];
	size_t size = IFNAMSIZ;
	int err=0;
	nozzle_t nozzle = NULL;
	char *current_mac = NULL, *temp_mac = NULL, *err_mac = NULL;
	struct ether_addr *cur_mac, *tmp_mac;

	printf("Testing get MAC\n");

	memset(device_name, 0, size);
	printf("Creating nozzle interface\n");
	FAIL_ON_NULL(nozzle, nozzle_open(device_name, size, NULL));

	printf("Get current MAC\n");
	FAIL_ON_ERR(nozzle_get_mac(nozzle, &current_mac));

	printf("Current MAC: %s\n", current_mac);

	printf("Setting MAC: 00:01:01:01:01:01\n");
	FAIL_ON_ERR(nozzle_set_mac(nozzle, "00:01:01:01:01:01"));

	printf("Get current MAC after setting\n");
	FAIL_ON_ERR(nozzle_get_mac(nozzle, &temp_mac));

	printf("Current MAC: %s\n", temp_mac);

	cur_mac = ether_aton(current_mac);
	tmp_mac = ether_aton(temp_mac);

	printf("Comparing MAC addresses\n");
	if (memcmp(cur_mac, tmp_mac, sizeof(struct ether_addr))) {
		printf("*** FAIL on line %d. Mac addresses are not the same?!\n", __LINE__);
		err = -1;
		goto out_clean;
	}

	printf("Testing ERROR conditions\n");

	printf("Testing invalid nozzle handle\n");
	errno = 0;
	FAIL_ON_SUCCESS(nozzle_get_mac(NULL, &err_mac), EINVAL);

	printf("Testing NULL mac pointer\n");
	errno = 0;
	FAIL_ON_SUCCESS(nozzle_get_mac(nozzle, NULL), EINVAL);

out_clean:
	if (err_mac) {
		printf("*** FAIL on line %d. Something managed to set err_mac!\n", __LINE__);
		err = -1;
		free(err_mac);
	}

	if (current_mac)
		free(current_mac);
	if (temp_mac)
		free(temp_mac);

	if (nozzle) {
		nozzle_close(nozzle);
	}

	return err;
}

int main(void)
{
	need_root();
	need_tun();

	if (test() < 0)
		return FAIL;

	return PASS;
}
