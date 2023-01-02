/*
 * Copyright (C) 2018-2023 Red Hat, Inc.  All rights reserved.
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
#include <net/ethernet.h>

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
	nozzle_t nozzle;
	char *original_mac = NULL, *current_mac = NULL, *temp_mac = NULL;
	struct ether_addr *orig_mac, *cur_mac, *tmp_mac;

	printf("Testing set MAC\n");

	memset(device_name, 0, size);
	nozzle = nozzle_open(device_name, size, NULL);
	if (!nozzle) {
		printf("Unable to init %s\n", device_name);
		return -1;
	}

	printf("Get current MAC\n");

	if (nozzle_get_mac(nozzle, &original_mac) < 0) {
		printf("Unable to get current MAC address.\n");
		err = -1;
		goto out_clean;
	}
	orig_mac = ether_aton(original_mac);

	if (nozzle_get_mac(nozzle, &current_mac) < 0) {
		printf("Unable to get current MAC address.\n");
		err = -1;
		goto out_clean;
	}

	printf("Current MAC: %s\n", current_mac);

	printf("Setting MAC: 00:01:01:01:01:01\n");

	if (nozzle_set_mac(nozzle, "00:01:01:01:01:01") < 0) {
		printf("Unable to set current MAC address.\n");
		err = -1;
		goto out_clean;
	}

	if (nozzle_get_mac(nozzle, &temp_mac) < 0) {
		printf("Unable to get current MAC address.\n");
		err = -1;
		goto out_clean;
	}

	printf("Current MAC: %s\n", temp_mac);

	cur_mac = ether_aton(current_mac);
	tmp_mac = ether_aton(temp_mac);

	printf("Comparing MAC addresses\n");
	if (memcmp(cur_mac, tmp_mac, sizeof(struct ether_addr))) {
		printf("Mac addresses are not the same?!\n");
		err = -1;
		goto out_clean;
	}

	printf("Testing reset_mac\n");
	if (nozzle_reset_mac(nozzle) < 0) {
		printf("Unable to reset mac address\n");
		err = -1;
		goto out_clean;
	}

	if (current_mac) {
		free(current_mac);
		current_mac = NULL;
	}

	if (nozzle_get_mac(nozzle, &current_mac) < 0) {
		printf("Unable to get current MAC address.\n");
		err = -1;
		goto out_clean;
	}

	cur_mac = ether_aton(current_mac);
	if (memcmp(cur_mac, orig_mac, sizeof(struct ether_addr))) {
		printf("Mac addresses are not the same?!\n");
		err = -1;
		goto out_clean;
	}

	printf("Testing ERROR conditions\n");

	printf("Pass NULL to set_mac (pass1)\n");
	errno = 0;
	if ((nozzle_set_mac(nozzle, NULL) >= 0) || (errno != EINVAL)) {
		printf("Something is wrong in nozzle_set_mac sanity checks\n");
		err = -1;
		goto out_clean;
	}

	printf("Pass NULL to set_mac (pass2)\n");
	errno = 0;
	if ((nozzle_set_mac(NULL, current_mac) >= 0) || (errno != EINVAL)) {
		printf("Something is wrong in nozzle_set_mac sanity checks\n");
		err = -1;
		goto out_clean;
	}

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
