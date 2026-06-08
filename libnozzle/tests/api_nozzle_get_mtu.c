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

#include "test-common.h"

static int test(void)
{
	char device_name[IFNAMSIZ];
	size_t size = IFNAMSIZ;
	int err=0;
	nozzle_t nozzle = NULL;

	int current_mtu = 0;
	int expected_mtu = 1500;

	printf("Testing get MTU\n");

	memset(device_name, 0, size);

	printf("Creating nozzle interface\n");
	FAIL_ON_NULL(nozzle, nozzle_open(device_name, size, NULL));

	printf("Comparing default MTU\n");
	current_mtu = nozzle_get_mtu(nozzle);
	if (current_mtu < 0) {
		printf("*** FAIL on line %d. nozzle_get_mtu failed: %s\n", __LINE__, strerror(errno));
		err = -1;
		goto out_clean;
	}
	if (current_mtu != expected_mtu) {
		printf("*** FAIL on line %d. current mtu [%d] does not match expected default [%d]\n", __LINE__, current_mtu, expected_mtu);
		err = -1;
		goto out_clean;
	}

#ifdef KNET_SOLARIS
	// Solaris doesn't allow MTU > 1500
	expected_mtu = 900;
#else
	expected_mtu = 9000;
#endif
	printf("Setting MTU to %d\n", expected_mtu);
	FAIL_ON_ERR(nozzle_set_mtu(nozzle, expected_mtu));

	printf("Verifying MTU was set correctly\n");
	current_mtu = nozzle_get_mtu(nozzle);
	if (current_mtu < 0) {
		printf("*** FAIL on line %d. nozzle_get_mtu failed: %s\n", __LINE__, strerror(errno));
		err = -1;
		goto out_clean;
	}
	if (current_mtu != expected_mtu) {
		printf("*** FAIL on line %d. current mtu [%d] does not match expected value [%d]\n", __LINE__, current_mtu, expected_mtu);
		err = -1;
		goto out_clean;
	}

	printf("Testing ERROR conditions\n");

	printf("Passing NULL to get_mtu\n");
	current_mtu = nozzle_get_mtu(NULL);
	if ((current_mtu >= 0) || (errno != EINVAL)) {
		printf("*** FAIL on line %d. nozzle_get_mtu(NULL) should have failed with EINVAL: %s\n", __LINE__, strerror(errno));
		err = -1;
		goto out_clean;
	}

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

	if (test() < 0)
		return FAIL;

	return PASS;
}
