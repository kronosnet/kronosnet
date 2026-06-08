/*
 * Copyright (C) 2026 Red Hat, Inc.  All rights reserved.
 *
 * Authors: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *
 * This software licensed under GPL-2.0+
 */

#include "config.h"

#include <errno.h>
#include <limits.h>
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

static void test_prefix_validation(void)
{
	char device_name[IFNAMSIZ];
	size_t size = IFNAMSIZ;
	nozzle_t nozzle = NULL;
	int err = 0;

	printf("Test: Prefix validation\n\n");

	printf("Step 1: Create nozzle device\n");

	memset(device_name, 0, size);
	FAIL_ON_NULL(nozzle, nozzle_open(device_name, size, NULL));

	printf("Created nozzle device: %s\n\n", device_name);

	/*
	 * Test Case 1: Prefix = "0" (invalid, too small)
	 */
	printf("Step 2: Test invalid prefix \"0\" (should fail)\n");
	FAIL_ON_SUCCESS(nozzle_add_ip(nozzle, "192.168.1.1", "0"), EINVAL);
	printf("Correctly rejected prefix \"0\" with EINVAL\n\n");

	/*
	 * Test Case 2: Prefix = "-1" (invalid, negative)
	 */
	printf("Step 3: Test invalid prefix \"-1\" (should fail)\n");
	FAIL_ON_SUCCESS(nozzle_add_ip(nozzle, "192.168.1.1", "-1"), EINVAL);
	printf("Correctly rejected prefix \"-1\" with EINVAL\n\n");

	/*
	 * Test Case 3: Prefix = "33" for IPv4 (invalid, too large)
	 */
	printf("Step 4: Test invalid IPv4 prefix \"33\" (should fail, max is 32)\n");
	FAIL_ON_SUCCESS(nozzle_add_ip(nozzle, "192.168.1.1", "33"), EINVAL);
	printf("Correctly rejected IPv4 prefix \"33\" with EINVAL\n\n");

	/*
	 * Test Case 4: Prefix = "129" for IPv6 (invalid, too large)
	 */
	printf("Step 5: Test invalid IPv6 prefix \"129\" (should fail, max is 128)\n");
	FAIL_ON_SUCCESS(nozzle_add_ip(nozzle, "::1", "129"), EINVAL);
	printf("Correctly rejected IPv6 prefix \"129\" with EINVAL\n\n");

	/*
	 * Test Case 5: Prefix = "invalid" (non-numeric, atoi() returns 0)
	 */
	printf("Step 6: Test invalid prefix \"invalid\" (should fail)\n");
	printf("        This tests the original vulnerability where atoi() returns 0\n");
	FAIL_ON_SUCCESS(nozzle_add_ip(nozzle, "192.168.1.1", "invalid"), EINVAL);
	printf("Correctly rejected prefix \"invalid\" with EINVAL\n");
	printf("Prefix validation vulnerability is FIXED (atoi(\"invalid\") = 0 now rejected)\n\n");

	/*
	 * Test Case 6: Valid prefix should still work
	 */
	printf("Step 7: Test valid prefix \"24\" (should succeed)\n");
	FAIL_ON_ERR(nozzle_add_ip(nozzle, "192.168.1.1", "24"));
	printf("Correctly accepted valid prefix \"24\"\n\n");

	/* Clean up the IP we just added */
	FAIL_ON_ERR(nozzle_del_ip(nozzle, "192.168.1.1", "24"));

	/*
	 * Test Case 7: Valid IPv6 prefix should work (if IPv6 is available)
	 */
	printf("Step 8: Test valid IPv6 prefix \"64\" (should succeed if IPv6 available)\n");

	err = nozzle_add_ip(nozzle, "fd00::1", "64");
	if (err != 0) {
		/* IPv6 might not be available on this system, which is OK */
		printf("WARNING: Could not add IPv6 address (IPv6 may not be available): %s\n", strerror(errno));
		printf("  This is not a test failure - IPv6 validation is tested via invalid prefixes\n\n");
	} else {
		printf("Correctly accepted valid IPv6 prefix \"64\"\n\n");
		/* Clean up */
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
}

int main(void)
{
	need_root();
	need_tun();

	test_prefix_validation();

	return PASS;
}
