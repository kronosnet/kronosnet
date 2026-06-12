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
			char expected_err[256]; \
			snprintf(expected_err, sizeof(expected_err), "%s", strerror(errcode)); \
			printf("*** FAIL on line %d. %s did not return correct error: %s (expected %s)\n", \
			       __LINE__, #fn, strerror(savederrno), expected_err); \
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
			char expected_err[256]; \
			snprintf(expected_err, sizeof(expected_err), "%s", strerror(errcode)); \
			printf("*** FAIL on line %d. %s should have returned NULL with errno %s, got errno %s\n", \
			       __LINE__, #fn, expected_err, strerror(savederrno)); \
			err = -1; \
			goto out_clean; \
		} \
	} while(0)

/*
 * FAIL_ON_NONZERO(expr, message) - Fail if expression evaluates to non-zero
 *
 * For comparisons and other operations that should return 0 (like memcmp, strcmp).
 * Use when checking non-API-call expressions that indicate failure when non-zero.
 *
 * Example:
 *   FAIL_ON_NONZERO(memcmp(buf1, buf2, sizeof(buf1)), "Buffers should match");
 */
#define FAIL_ON_NONZERO(expr, message) \
	do { \
		int _fonz_res; \
		printf("FONZ: %s\n", #expr); \
		if ((_fonz_res = (expr)) != 0) { \
			printf("*** FAIL on line %d. %s (result: %d)\n", __LINE__, message, _fonz_res); \
			err = -1; \
			goto out_clean; \
		} \
	} while(0)

/*
 * FAIL_ON_ZERO(expr, message) - Fail if expression evaluates to zero
 *
 * For operations that should return non-zero on success.
 * Use when an expression returning 0 indicates failure.
 *
 * Example:
 *   FAIL_ON_ZERO(strcmp(str1, str2), "Strings should differ");
 */
#define FAIL_ON_ZERO(expr, message) \
	do { \
		int _foz_res; \
		printf("FOZ: %s\n", #expr); \
		if ((_foz_res = (expr)) == 0) { \
			printf("*** FAIL on line %d. %s (result: %d)\n", __LINE__, message, _foz_res); \
			err = -1; \
			goto out_clean; \
		} \
	} while(0)

/*
 * FAIL_ON_ERR_ONLY(expr, message) - Fail if expression returns -1
 *
 * For functions that return -1 on error (like file descriptors, system calls).
 * Checks specifically for -1, not any negative value.
 * Named to match libknet's FAIL_ON_ERR_ONLY macro.
 *
 * Example:
 *   FAIL_ON_ERR_ONLY(fcntl(fd, F_GETFD), "fcntl should succeed");
 */
#define FAIL_ON_ERR_ONLY(expr, message) \
	do { \
		int _foeo_res; \
		printf("FOEO: %s\n", #expr); \
		if ((_foeo_res = (expr)) == -1) { \
			int savederrno = errno; \
			printf("*** FAIL on line %d. %s: %s (result: %d)\n", __LINE__, message, strerror(savederrno), _foeo_res); \
			err = -1; \
			goto out_clean; \
		} \
	} while(0)

/*
 * FAIL_ON_NOT_ERR_ONLY(expr, errcode, message) - Fail if expression doesn't return -1 with correct errno
 *
 * For negative testing of functions that return -1 on error.
 * Expects expr to return -1 with specific errno.
 * Named to match the FAIL_ON_ERR_ONLY pattern.
 *
 * Example:
 *   FAIL_ON_NOT_ERR_ONLY(test_iface(NULL, size, NULL), EINVAL, "NULL device name should fail");
 */
#define FAIL_ON_NOT_ERR_ONLY(expr, errcode, message) \
	do { \
		int _foneo_res; \
		printf("FONErrO: %s\n", #expr); \
		errno = 0; \
		_foneo_res = (expr); \
		if ((_foneo_res != -1) || (errno != errcode)) { \
			int savederrno = errno; \
			char expected_err[256]; \
			snprintf(expected_err, sizeof(expected_err), "%s", strerror(errcode)); \
			printf("*** FAIL on line %d. %s: expected -1 with errno %s, got result %d with errno %s\n", \
			       __LINE__, message, expected_err, _foneo_res, strerror(savederrno)); \
			err = -1; \
			goto out_clean; \
		} \
	} while(0)

/*
 * FAIL_ON_CMD(var, fn, error_str_ptr, message) - Execute command and fail if returns error
 *
 * For execute_bin_sh_command and similar functions that return int and optionally set error_string.
 * Prints error_string if set (for debugging), then checks return value.
 * Expects fn to return 0 on success.
 *
 * Example:
 *   FAIL_ON_CMD(err, execute_bin_sh_command(verifycmd, &error_string), error_string, "IP verification failed");
 */
#define FAIL_ON_CMD(var, fn, error_str_ptr, message) \
	do { \
		printf("FOCmd: %s\n", #fn); \
		var = fn; \
		if (error_str_ptr) { \
			printf("Error string: %s\n", error_str_ptr); \
			free(error_str_ptr); \
			error_str_ptr = NULL; \
		} \
		if (var) { \
			printf("*** FAIL on line %d. %s\n", __LINE__, message); \
			err = -1; \
			goto out_clean; \
		} \
	} while(0)

/*
 * FAIL_ON_CMD_SUCCESS(var, fn, error_str_ptr, message) - Execute command and fail if succeeds (returns 0)
 *
 * For negative testing with execute_bin_sh_command.
 * Expects fn to return non-zero (failure).
 *
 * Example:
 *   FAIL_ON_CMD_SUCCESS(err, execute_bin_sh_command(verifycmd, &error_string), error_string, "IP should not exist");
 */
#define FAIL_ON_CMD_SUCCESS(var, fn, error_str_ptr, message) \
	do { \
		printf("FOCmdS: %s\n", #fn); \
		var = fn; \
		if (error_str_ptr) { \
			printf("Error string: %s\n", error_str_ptr); \
			free(error_str_ptr); \
			error_str_ptr = NULL; \
		} \
		if (!var) { \
			printf("*** FAIL on line %d. %s\n", __LINE__, message); \
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
