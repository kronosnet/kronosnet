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
	FAIL_ON_ERR_ONLY(current_mtu = nozzle_get_mtu(nozzle), "nozzle_get_mtu failed");
	FAIL_ON_NONZERO(current_mtu != expected_mtu, "current mtu does not match expected default");

#ifdef KNET_SOLARIS
	// Solaris doesn't allow MTU > 1500
	expected_mtu = 900;
#else
	expected_mtu = 9000;
#endif
	printf("Setting MTU to %d\n", expected_mtu);
	FAIL_ON_ERR(nozzle_set_mtu(nozzle, expected_mtu));

	printf("Verifying MTU was set correctly\n");
	FAIL_ON_ERR_ONLY(current_mtu = nozzle_get_mtu(nozzle), "nozzle_get_mtu failed");
	FAIL_ON_NONZERO(current_mtu != expected_mtu, "current mtu does not match expected value");

	printf("Testing ERROR conditions\n");

	printf("Passing NULL to get_mtu\n");
	FAIL_ON_NOT_ERR_ONLY(nozzle_get_mtu(NULL), EINVAL, "nozzle_get_mtu(NULL) should have failed with EINVAL");

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
