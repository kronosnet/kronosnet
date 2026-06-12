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
	char *original_mac = NULL, *current_mac = NULL, *temp_mac = NULL;
	struct ether_addr *orig_mac, *cur_mac, *tmp_mac;

	printf("Testing set MAC\n");

	memset(device_name, 0, size);
	printf("Creating nozzle interface\n");
	FAIL_ON_NULL(nozzle, nozzle_open(device_name, size, NULL));

	printf("Get current MAC\n");
	FAIL_ON_ERR(nozzle_get_mac(nozzle, &original_mac));
	orig_mac = ether_aton(original_mac);

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
	FAIL_ON_NONZERO(memcmp(cur_mac, tmp_mac, sizeof(struct ether_addr)), "MAC addresses are not the same?!");

	printf("Testing reset_mac\n");
	FAIL_ON_ERR(nozzle_reset_mac(nozzle));

	if (current_mac) {
		free(current_mac);
		current_mac = NULL;
	}

	printf("Get current MAC after reset\n");
	FAIL_ON_ERR(nozzle_get_mac(nozzle, &current_mac));

	cur_mac = ether_aton(current_mac);
	FAIL_ON_NONZERO(memcmp(cur_mac, orig_mac, sizeof(struct ether_addr)), "MAC addresses are not the same after reset?!");

	printf("Testing ERROR conditions\n");

	printf("Testing NULL mac address\n");
	errno = 0;
	FAIL_ON_SUCCESS(nozzle_set_mac(nozzle, NULL), EINVAL);

	printf("Testing invalid nozzle handle\n");
	errno = 0;
	FAIL_ON_SUCCESS(nozzle_set_mac(NULL, current_mac), EINVAL);

out_clean:
	if (current_mac)
		free(current_mac);
	if (temp_mac)
		free(temp_mac);
	if (original_mac)
		free(original_mac);

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
