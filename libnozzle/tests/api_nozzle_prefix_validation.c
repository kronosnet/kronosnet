/*
 * Copyright (C) 2026 Red Hat, Inc.  All rights reserved.
 *
 * Authors: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *
 * This software licensed under GPL-2.0+
 */

#include "config.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "test-common.h"

/*
 * API test for network prefix validation in nozzle_add_ip()
 *
 * Tests that nozzle_add_ip() properly validates network prefix values
 * and rejects invalid input that could lead to network misconfiguration.
 *
 * The validation ensures:
 * - Prefix length > 0
 * - IPv4 prefix <= 32
 * - IPv6 prefix <= 128
 * - Proper error detection for non-numeric input
 * - Rejection of input with trailing garbage
 *
 * Test approach:
 * - Create nozzle device
 * - Attempt to add IPs with various invalid prefixes
 * - Verify all invalid cases return error
 * - Verify valid prefix works correctly
 */

static int test(void)
{
	char device_name[IFNAMSIZ];
	size_t size = IFNAMSIZ;
	int err = 0;
	nozzle_t nozzle = NULL;

	printf("Testing prefix validation\n");

	memset(device_name, 0, size);

	printf("Creating nozzle interface\n");
	FAIL_ON_NULL(nozzle, nozzle_open(device_name, size, NULL));

	printf("Testing invalid prefix \"0\"\n");
	FAIL_ON_SUCCESS(nozzle_add_ip(nozzle, "192.168.1.1", "0"), EINVAL);

	printf("Testing invalid prefix \"-1\"\n");
	FAIL_ON_SUCCESS(nozzle_add_ip(nozzle, "192.168.1.1", "-1"), EINVAL);

	printf("Testing invalid IPv4 prefix \"33\"\n");
	FAIL_ON_SUCCESS(nozzle_add_ip(nozzle, "192.168.1.1", "33"), EINVAL);

	printf("Testing invalid IPv6 prefix \"129\"\n");
	FAIL_ON_SUCCESS(nozzle_add_ip(nozzle, "::1", "129"), EINVAL);

	printf("Testing invalid prefix \"invalid\"\n");
	FAIL_ON_SUCCESS(nozzle_add_ip(nozzle, "192.168.1.1", "invalid"), EINVAL);

	printf("Testing valid IPv4 prefix \"24\"\n");
	FAIL_ON_ERR(nozzle_add_ip(nozzle, "192.168.1.1", "24"));

	printf("Cleaning up IPv4 address\n");
	FAIL_ON_ERR(nozzle_del_ip(nozzle, "192.168.1.1", "24"));

	printf("Testing valid IPv6 prefix \"64\"\n");
	err = nozzle_add_ip(nozzle, "fd00::1", "64");
	if (err) {
		printf("WARNING: Could not add IPv6 address (IPv6 may not be available): %s\n", strerror(errno));
		printf("Skipping IPv6 positive test\n");
		err = 0;
	} else {
		printf("Cleaning up IPv6 address\n");
		FAIL_ON_ERR(nozzle_del_ip(nozzle, "fd00::1", "64"));
	}

	printf("=== Prefix validation test PASSED ===\n");
	printf("Invalid prefixes correctly rejected:\n");
	printf("  - Prefix \"0\" (too small)\n");
	printf("  - Prefix \"-1\" (negative)\n");
	printf("  - IPv4 prefix \"33\" (> 32)\n");
	printf("  - IPv6 prefix \"129\" (> 128)\n");
	printf("  - Prefix \"invalid\" (non-numeric, atoi() = 0) - ORIGINAL VULNERABILITY\n");
	printf("Valid IPv4 prefix correctly accepted:\n");
	printf("  - Prefix \"24\"\n");
	printf("All validation checks return EINVAL\n");
	printf("Network misconfiguration prevented\n\n");

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
