/*
 * Copyright (C) 2018-2026 Red Hat, Inc.  All rights reserved.
 *
 * Authors: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *
 * This software licensed under GPL-2.0+
 */

#ifndef __NOZZLE_TEST_COMMON_H__
#define __NOZZLE_TEST_COMMON_H__

#include "internals.h"
#include "libnozzle.h"

/*
 * error codes from automake test-driver
 */

#define PASS	0
#define SKIP	77
#define ERROR	99
#define FAIL	-1

/*
 * Test execution macros
 *
 * These macros simplify error checking in libnozzle tests.
 * On failure, they set err = -1 and jump to out_clean label for cleanup.
 *
 * All tests using these macros must:
 *  - Have an 'int err' variable
 *  - Have an 'out_clean:' label for cleanup
 *  - Clean up resources (nozzle handles, etc.) in the out_clean block
 */

/*
 * FAIL_ON_ERR(fn) - Execute function and fail test if it returns error
 *
 * For functions that return 0 on success, non-zero on error (most nozzle APIs).
 * Prints function name with "FOE:" prefix, and on failure prints line number and errno.
 *
 * Example:
 *   FAIL_ON_ERR(nozzle_add_ip(nozzle, "192.168.1.1", "24"));
 */
#define FAIL_ON_ERR(fn) \
	do { \
		int _foe_res; \
		printf("FOE: %s\n", #fn); \
		if ((_foe_res = fn) != 0) { \
			int savederrno = errno; \
			printf("*** FAIL on line %d. %s failed: %s\n", __LINE__, #fn, strerror(savederrno)); \
			err = -1; \
			goto out_clean; \
		} \
	} while(0)

/*
 * FAIL_ON_SUCCESS(fn, errcode) - Execute function and fail if succeeds or returns wrong errno
 *
 * For negative testing. Expects fn to fail with specific errno.
 * Fails test if fn returns 0 (success) or -1 with wrong errno.
 *
 * Example:
 *   FAIL_ON_SUCCESS(nozzle_add_ip(NULL, "192.168.1.1", "24"), EINVAL);
 */
#define FAIL_ON_SUCCESS(fn, errcode) \
	do { \
		int _fos_res; \
		printf("FOS: %s\n", #fn); \
		if (((_fos_res = fn) == 0) || \
		    ((_fos_res == -1) && (errno != errcode))) { \
			int savederrno = errno; \
			printf("*** FAIL on line %d. %s did not return correct error: %s (expected %s)\n", \
			       __LINE__, #fn, strerror(savederrno), strerror(errcode)); \
			err = -1; \
			goto out_clean; \
		} \
	} while(0)

/*
 * FAIL_ON_NULL(var, fn) - Execute function and fail if it returns NULL
 *
 * For functions that return pointers (nozzle_open, nozzle_get_handle_by_name).
 * Assigns result to var, fails if NULL.
 *
 * Example:
 *   FAIL_ON_NULL(nozzle, nozzle_open(device_name, size, NULL));
 */
#define FAIL_ON_NULL(var, fn) \
	do { \
		printf("FON: %s\n", #fn); \
		var = fn; \
		if (!var) { \
			int savederrno = errno; \
			printf("*** FAIL on line %d. %s returned NULL: %s\n", __LINE__, #fn, strerror(savederrno)); \
			err = -1; \
			goto out_clean; \
		} \
	} while(0)

/*
 * FAIL_ON_NOT_NULL(var, fn, errcode) - Execute function and fail if doesn't return NULL with correct errno
 *
 * For negative testing of pointer-returning functions.
 * Expects fn to return NULL with specific errno.
 *
 * Example:
 *   FAIL_ON_NOT_NULL(nozzle2, nozzle_open(device_name, size, NULL), EBUSY);
 */
#define FAIL_ON_NOT_NULL(var, fn, errcode) \
	do { \
		printf("FONN: %s\n", #fn); \
		var = fn; \
		if ((var != NULL) || (errno != errcode)) { \
			int savederrno = errno; \
			printf("*** FAIL on line %d. %s should have returned NULL with errno %s, got errno %s\n", \
			       __LINE__, #fn, strerror(errcode), strerror(savederrno)); \
			err = -1; \
			goto out_clean; \
		} \
	} while(0)

/*
 * common facilities
 */

#define IPBUFSIZE 1024

void need_root(void);
void need_tun(void);
int test_iface(char *name, size_t size, const char *updownpath);
int is_if_in_system(char *name);
int get_random_byte(void);
void make_local_ips(char *testipv4_1, char *testipv4_2, char *testipv6_1, char *testipv6_2);

#endif
