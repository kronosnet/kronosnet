/*
 * Copyright (C) 2016-2026 Red Hat, Inc.  All rights reserved.
 *
 * Authors: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *
 * This software licensed under GPL-2.0+
 */

#ifndef __KNET_TEST_COMMON_H__
#define __KNET_TEST_COMMON_H__

#include "internals.h"
#include <sched.h>

/*
 * Test result codes (automake test-driver compatible)
 */
#define PASS	0	/* Test passed */
#define SKIP	77	/* Test skipped (missing feature, platform limitation) */
#define ERROR	99	/* Infrastructure error (not a test failure) */
#define FAIL	-1	/* Test failed */
#define CONTINUE 101	/* Internal: cleanup done, continue test (multi-phase tests) */

/*
 * IPv6 address access compatibility (BSD/Solaris)
 */
#ifndef s6_addr32
# ifdef KNET_SOLARIS
#  define s6_addr32 _S6_un._S6_u32
# else
#  define s6_addr32 __u6_addr.__u6_addr32
# endif
#endif

/*
 * TESTNODES - Default node count (tests can override with #undef/#define)
 */
#define TESTNODES 1

/*
 * Test timeout constants (in seconds, auto-scaled under valgrind)
 */
#define TEST_TIMEOUT_LONG       600	/* Multi-node convergence, crypto setup */
#define TEST_TIMEOUT_SHORT      10	/* Host reachability, packet wait */
#define TEST_TIMEOUT_QUICK      4	/* PMTUD, loopback operations */

/*
 * Port range for test link configuration (_ts_knet_link_set_config)
 */
#define TEST_PORT_BASE          1024			/* Start of user port range */
#define TEST_PORT_MIN           (TEST_PORT_BASE + 1)	/* Port scan start */
#define TEST_PORT_MAX           65535			/* Port scan end */

/*
 * log_test() - Write test log message to knet logging infrastructure
 *
 * Writes message with NULL knet handle (displayed as [testsuite]: prefix).
 * Messages appear in test output with timestamps via the logging thread.
 *
 * This macro is the primary way tests communicate progress and status.
 * Use instead of printf() inside test functions for consistent formatting
 * and timestamp correlation with knet internal logs.
 *
 * Parameters:
 *   logfd - write end of log pipe (from start_logging())
 *   fmt   - printf-style format string
 *   ...   - format arguments
 *
 * Example:
 *   log_test(logfd, "Testing link enable on host %d", host_id);
 *   log_test(logfd, "*** FAIL: Expected EINVAL, got %d", errno);
 */
#define log_test(logfd, fmt, ...) \
	do { \
		struct knet_log_msg _log_msg; \
		memset(&_log_msg, 0, sizeof(_log_msg)); \
		_log_msg.subsystem = KNET_SUB_UNKNOWN - 1; \
		snprintf(_log_msg.msg, KNET_MAX_LOG_MSG_SIZE, fmt, ##__VA_ARGS__); \
		if (write(logfd, &_log_msg, sizeof(_log_msg)) != sizeof(_log_msg)) { \
			fprintf(stderr, "Failed to write to log pipe\n"); \
		} \
	} while(0)

/*
 * TEST_EXIT_CLEAN() - Clean up knet handles and exit test
 *
 * For tests that create knet handles. Stops all nodes, closes links,
 * frees handles, stops logging, and exits with specified result.
 *
 * If result is CONTINUE, performs cleanup but returns to caller
 * instead of exiting (for multi-phase tests that run test() multiple
 * times with different configurations).
 *
 * Requires: knet_h array, TESTNODES defined, logfd
 * Parameter: r - result code (PASS, FAIL, SKIP, ERROR, or CONTINUE)
 *
 * Example:
 *   if (error_condition) {
 *       log_test(logfd, "Unexpected error occurred");
 *       TEST_EXIT_CLEAN(FAIL);
 *   }
 *   TEST_EXIT_CLEAN(PASS);  // At end of successful test
 */
#define TEST_EXIT_CLEAN(r) \
	do { \
		_ts_knet_handle_stop_everything(knet_h, TESTNODES, logfd); \
		if (r == CONTINUE) { \
			stop_logging(); \
			return; \
		} \
		TEST_EXIT(r); \
	} while(0)

/*
 * FAIL_ON_ERR() - Execute function and fail test if it returns error
 *
 * Executes fn and checks return value. If non-zero, logs failure with
 * line number and errno, then exits via TEST_EXIT_CLEAN(FAIL).
 *
 * Logs execution with "FOE:" prefix for test diagnostics, making it
 * easy to trace which function calls were attempted in test output.
 *
 * Use for functions that return 0 on success, non-zero on error
 * (most knet API functions follow this convention).
 *
 * Requires: logfd, knet_h array for cleanup
 * Parameter: fn - function call expression
 *
 * Example:
 *   FAIL_ON_ERR(knet_handle_enable_sock_notify(knet_h1, NULL, sock_notify));
 *   FAIL_ON_ERR(knet_host_add(knet_h1, 1));
 */
#define FAIL_ON_ERR(fn) \
	do { \
		int _foe_res; \
		log_test(logfd, "FOE: %s", #fn); \
		if ((_foe_res = fn) != 0) { \
			int savederrno = errno; \
			log_test(logfd, "*** FAIL on line %d. %s failed: %s", __LINE__, #fn, strerror(savederrno)); \
			TEST_EXIT_CLEAN(FAIL); \
		} \
	} while(0)

/*
 * FAIL_ON_SUCCESS() - Execute function and fail test if it succeeds or returns wrong error
 *
 * For negative testing. Executes fn expecting failure with specific errno.
 * Fails test if fn returns 0 (success) or -1 with wrong errno.
 *
 * Special handling: if fn returns -2, triggers TEST_EXIT_CLEAN(SKIP).
 * This allows tested functions to signal "feature not available" without
 * failing the test.
 *
 * Logs execution with "FOS:" prefix for test diagnostics.
 *
 * Requires: logfd, knet_h array for cleanup
 * Parameters:
 *   fn      - function call expression (expected to fail)
 *   errcode - expected errno value (e.g., EINVAL, EBUSY)
 *
 * Example:
 *   FAIL_ON_SUCCESS(knet_host_add(NULL, 1), EINVAL);  // NULL handle should fail
 *   FAIL_ON_SUCCESS(knet_link_set_config(knet_h1, 999, 0, ...), EINVAL);  // Invalid host_id
 */
#define FAIL_ON_SUCCESS(fn, errcode) \
	do { \
		int _fos_res; \
		log_test(logfd, "FOS: %s", #fn); \
		if (((_fos_res = fn) == 0) || \
		    ((_fos_res == -1) && (errno != errcode))) { \
			int savederrno = errno; \
			if (_fos_res == -2) { \
				TEST_EXIT_CLEAN(SKIP); \
			} else { \
				log_test(logfd, "*** FAIL on line %d. %s did not return correct error: %s", __LINE__, #fn, strerror(savederrno)); \
				TEST_EXIT_CLEAN(FAIL); \
			} \
		} \
	} while(0)

/*
 * FAIL_ON_ERR_ONLY() - Execute function and fail test if it returns -1
 *
 * Like FAIL_ON_ERR but only checks for -1 return value, not all non-zero.
 * Used for functions that may return positive values on success.
 *
 * Logs execution with "FOEO:" prefix for test diagnostics.
 *
 * Requires: logfd, knet_h array for cleanup
 * Parameter: fn - function call expression
 *
 * Example:
 *   // knet_send returns bytes sent (positive) on success, -1 on error
 *   FAIL_ON_ERR_ONLY(knet_send(knet_h1, buf, len, channel) >= 0 ? 0 : -1);
 */
#define FAIL_ON_ERR_ONLY(fn) \
	do { \
		int _foeo_res; \
		log_test(logfd, "FOEO: %s", #fn); \
		if ((_foeo_res = fn) == -1) { \
			int savederrno = errno; \
			log_test(logfd, "*** FAIL on line %d. %s failed: %s", __LINE__, #fn, strerror(savederrno)); \
			TEST_EXIT_CLEAN(FAIL); \
		} \
	} while(0)

/*
 * NOCLEAN macro variants
 *
 * For tests that don't create knet handles (e.g., API parameter validation tests).
 * These macros skip knet_h cleanup and directly call TEST_EXIT instead of
 * TEST_EXIT_CLEAN.
 *
 * Use when:
 *   - Testing API functions without creating knet handles
 *   - Testing utility functions (knet_strtoaddr, knet_addrtostr, etc.)
 *   - Early test phases before handle creation
 *   - Tests that only validate parameter checking
 *
 * The NOCLEAN variants have identical behavior to their regular counterparts,
 * except they don't attempt to clean up knet_h array (which doesn't exist in
 * these tests).
 *
 * Available: FAIL_ON_ERR_NOCLEAN, FAIL_ON_SUCCESS_NOCLEAN
 */

/*
 * FAIL_ON_ERR_NOCLEAN() - Execute function and fail test if error (no handle cleanup)
 *
 * Like FAIL_ON_ERR but directly exits with TEST_EXIT instead of TEST_EXIT_CLEAN.
 * For tests that don't create knet handles.
 *
 * Requires: logfd only (no knet_h array)
 * Parameter: fn - function call expression
 *
 * Example:
 *   FAIL_ON_ERR_NOCLEAN(knet_strtoaddr("192.168.1.1", 1234, &ss, sizeof(ss)));
 */
#define FAIL_ON_ERR_NOCLEAN(fn) \
	do { \
		int _foe_res; \
		log_test(logfd, "FOE: %s", #fn); \
		if ((_foe_res = fn) != 0) { \
			int savederrno = errno; \
			log_test(logfd, "*** FAIL on line %d. %s failed: %s", __LINE__, #fn, strerror(savederrno)); \
			TEST_EXIT(FAIL); \
		} \
	} while(0)

/*
 * FAIL_ON_SUCCESS_NOCLEAN() - Expect function failure (no handle cleanup)
 *
 * Like FAIL_ON_SUCCESS but directly exits with TEST_EXIT instead of TEST_EXIT_CLEAN.
 * For tests that don't create knet handles.
 *
 * Requires: logfd only (no knet_h array)
 * Parameters:
 *   fn      - function call expression (expected to fail)
 *   errcode - expected errno value
 *
 * Example:
 *   FAIL_ON_SUCCESS_NOCLEAN(knet_strtoaddr(NULL, 1234, &ss, sizeof(ss)), EINVAL);
 */
#define FAIL_ON_SUCCESS_NOCLEAN(fn, errcode) \
	do { \
		int _fos_res; \
		log_test(logfd, "FOS: %s", #fn); \
		if (((_fos_res = fn) == 0) || \
		    ((_fos_res == -1) && (errno != errcode))) { \
			int savederrno = errno; \
			if (_fos_res == -2) { \
				TEST_EXIT(SKIP); \
			} else { \
				log_test(logfd, "*** FAIL on line %d. %s did not return correct error: %s", __LINE__, #fn, strerror(savederrno)); \
				TEST_EXIT(FAIL); \
			} \
		} \
	} while(0)

/*
 * TEST_EXIT() - Stop logging, print result, and exit test
 *
 * Final exit point for all tests. Stops logging thread, prints
 * standardized result message ([PASS], [FAIL], [SKIP], [ERROR]),
 * and exits with appropriate code for automake test-driver.
 *
 * This macro should not be called directly from tests in most cases.
 * Use TEST_EXIT_CLEAN (for tests with knet handles) or the FAIL_ON_*
 * macros (which call TEST_EXIT_CLEAN or TEST_EXIT internally).
 *
 * Direct use is appropriate only when:
 * - Test has no knet handles and needs to exit early
 * - Final exit at end of main() after all cleanup is done
 *
 * Requires: TEST_NAME defined in test file (e.g., #define TEST_NAME "api_knet_host_add")
 * Parameter: result - result code (PASS=0, SKIP=77, ERROR=99, FAIL=-1)
 *
 * Example:
 *   #define TEST_NAME "api_knet_send"
 *   ...
 *   TEST_EXIT(PASS);  // At end of main() after all tests passed
 */
#define TEST_EXIT(result) \
	do { \
		stop_logging(); \
		if (result == PASS) printf("[PASS] %s\n", TEST_NAME); \
		else if (result == FAIL) printf("[FAIL] %s\n", TEST_NAME); \
		else if (result == SKIP) printf("[SKIP] %s\n", TEST_NAME); \
		else if (result == ERROR) printf("[ERROR] %s\n", TEST_NAME); \
		exit(result); \
	} while(0)

/*
 * Runtime environment detection
 */

/*
 * is_memcheck() - Check if running under valgrind memcheck
 * Returns: 1 if KNETMEMCHECK=yes, 0 otherwise
 */
int is_memcheck(void);

/*
 * is_helgrind() - Check if running under valgrind helgrind
 * Returns: 1 if KNETHELGRIND=yes, 0 otherwise
 */
int is_helgrind(void);

/*
 * Handle management helpers
 */

/*
 * find_plugins_path() - Locate crypto/compress plugins in build tree
 *
 * Searches LD_LIBRARY_PATH for directory containing knet plugins.
 * Used by _ts_knet_handle_start() to set plugin path for handles.
 *
 * Parameters:
 *   logfd - log file descriptor for diagnostics
 *
 * Returns: pointer to plugin path string, or NULL if not found
 */
char *find_plugins_path(int logfd);

/*
 * _ts_knet_handle_start() - Create and configure knet handle for testing
 *
 * Creates knet handle with logging, sets plugin path, starts threads.
 * Stores handle in knet_h_array[1] and returns it.
 *
 * Parameters:
 *   logfd        - log file descriptor from start_logging()
 *   log_level    - knet log level (KNET_LOG_DEBUG, etc.)
 *   knet_h_array - array to store handle (must have space for [2])
 *
 * Returns: knet handle pointer (also stored in knet_h_array[1])
 * Exits on error with TEST_EXIT(FAIL)
 */
knet_handle_t _ts_knet_handle_start(int logfd, uint8_t log_level, knet_handle_t knet_h_array[]);

/*
 * _ts_knet_link_set_config() - Configure knet link with automatic port selection
 *
 * Wraps knet_link_set_config with automatic free port detection.
 * Scans TEST_PORT_MIN to TEST_PORT_MAX for available port.
 * Sets up link on loopback with selected port.
 *
 * Parameters match knet_link_set_config plus logfd for logging
 *
 * Returns: 0 on success, -1 on error
 */
int _ts_knet_link_set_config(knet_handle_t knet_h, knet_node_id_t host_id, uint8_t link_id,
			     uint8_t transport, uint64_t flags, int family, int dynamic,
			     struct sockaddr_storage *lo, int logfd);

/*
 * Multi-node test helpers (for functional tests)
 */

/*
 * _ts_knet_handle_stop_everything() - Clean shutdown of all test nodes
 *
 * Disables forwarding, closes links, removes hosts, stops threads,
 * frees handles. Safe to call from error paths.
 *
 * Parameters:
 *   knet_h   - array of knet handles
 *   numnodes - number of nodes to clean up
 *   logfd    - log file descriptor
 */
void _ts_knet_handle_stop_everything(knet_handle_t knet_h[], uint8_t numnodes, int logfd);

/*
 * _ts_knet_handle_start_nodes() - Initialize multiple knet handles
 *
 * Creates and configures multiple knet handles for multi-node tests.
 * All handles configured with same log level.
 *
 * Parameters:
 *   knet_h    - array to store handles (size numnodes+1)
 *   numnodes  - number of nodes to create
 *   logfd     - log file descriptor
 *   log_level - knet log level for all nodes
 */
void _ts_knet_handle_start_nodes(knet_handle_t knet_h[], uint8_t numnodes, int logfd, uint8_t log_level);

/*
 * _ts_knet_handle_join_nodes() - Establish links between all test nodes
 *
 * Creates mesh topology - every node connected to every other node.
 * Each connection can have multiple links (numlinks parameter).
 *
 * Parameters:
 *   knet_h    - array of knet handles
 *   numnodes  - number of nodes
 *   numlinks  - number of links between each pair of nodes
 *   family    - address family (AF_INET, AF_INET6)
 *   transport - transport type (KNET_TRANSPORT_UDP, etc.)
 *   logfd     - log file descriptor
 */
void _ts_knet_handle_join_nodes(knet_handle_t knet_h[], uint8_t numnodes, uint8_t numlinks, int family, uint8_t transport, int logfd);

/*
 * _ts_knet_handle_disconnect_links() - Disable all links on handle
 *
 * Disables all configured links. Links remain configured but inactive.
 *
 * Returns: 0 on success, -1 on error
 */
int _ts_knet_handle_disconnect_links(knet_handle_t knet_h, int logfd);

/*
 * _ts_knet_handle_reconnect_links() - Re-enable all links on handle
 *
 * Enables all previously configured links.
 *
 * Returns: 0 on success, -1 on error
 */
int _ts_knet_handle_reconnect_links(knet_handle_t knet_h, int logfd);

/*
 * Logging infrastructure
 */

/*
 * start_logging() - Initialize test logging infrastructure
 *
 * Sets up logging pipe and starts background log thread.
 * Thread continuously drains log messages and prints with timestamps.
 * Registers atexit() handler for automatic cleanup.
 *
 * Parameter: std - FILE* for log output (usually stdout)
 * Returns: log file descriptor to pass to knet_handle_new and log_test()
 * Exits on error with FAIL
 *
 * Note: Safe to call multiple times (second call returns same logfd)
 */
int start_logging(FILE *std);

/*
 * stop_logging() - Stop logging thread and close pipes
 *
 * Stops log thread, drains remaining messages, closes pipes.
 * Safe to call multiple times (no-op if not running).
 * Called automatically by TEST_EXIT and atexit handler.
 */
void stop_logging(void);

/*
 * Address helpers
 */
int make_local_sockaddr(struct sockaddr_storage *lo, int offset, int logfd);	/* 127.0.0.1:TEST_PORT_BASE+offset */
int make_local_sockaddr6(struct sockaddr_storage *lo, int offset, int logfd);	/* ::1:TEST_PORT_BASE+offset */

/*
 * Wait and timing helpers
 */

/*
 * wait_for_host() - Wait for specific host to become reachable
 *
 * Uses knet host status notification callbacks to wait for host.
 * Automatically adjusts timeout when running under valgrind.
 *
 * Parameters:
 *   knet_h  - knet handle
 *   host_id - node ID to wait for
 *   seconds - timeout in seconds
 *   logfd   - log file descriptor
 *
 * Returns: 0 on success (host reachable), -1 on timeout or error
 */
int wait_for_host(knet_handle_t knet_h, uint16_t host_id, int seconds, int logfd);

/*
 * wait_for_packet() - Wait for data on knet datafd
 *
 * Polls datafd using select() with timeout.
 * Automatically adjusts timeout when running under valgrind.
 *
 * Parameters:
 *   knet_h  - knet handle
 *   seconds - timeout in seconds
 *   datafd  - data file descriptor to monitor
 *   logfd   - log file descriptor
 *
 * Returns: 0 when data available, -1 on timeout, sets errno = ETIMEDOUT
 */
int wait_for_packet(knet_handle_t knet_h, int seconds, int datafd, int logfd);

/*
 * wait_for_reply() - Wait for notification on pipe
 *
 * Polls pipe using poll() with timeout.
 * Used internally by wait_for_host and wait_for_nodes_state.
 * Automatically adjusts timeout when running under valgrind.
 *
 * Parameters:
 *   seconds - timeout in seconds
 *   pipefd  - pipe file descriptor to monitor
 *   logfd   - log file descriptor
 *
 * Returns: 0 when data available, -1 on timeout
 */
int wait_for_reply(int seconds, int pipefd, int logfd);

/*
 * test_sleep() - Sleep with logging
 *
 * Logs sleep operation and duration. Use instead of sleep()
 * for visibility in test output.
 *
 * Parameters:
 *   logfd   - log file descriptor
 *   seconds - duration in seconds
 */
void test_sleep(int logfd, int seconds);

/*
 * wait_for_nodes_state() - Wait for multiple nodes to reach state
 *
 * Uses knet host status notification callbacks to wait for nodes.
 * Automatically adjusts timeout when running under valgrind.
 *
 * Parameters:
 *   knet_h   - knet handle
 *   numnodes - expected number of nodes (including self)
 *   state    - desired state (1=up, 0=down)
 *   seconds  - timeout in seconds
 *   logfd    - log file descriptor
 *
 * Returns: 0 when all nodes reach state, -1 on timeout or error
 */
int wait_for_nodes_state(knet_handle_t knet_h, size_t numnodes,
			 uint8_t state, uint32_t seconds,
			 int logfd);

/*
 * Packet injection helper for testing RX validation
 * Creates and injects a packet with specified fragment parameters
 * Returns 0 on success, -1 on error
 */
int inject_packet(knet_handle_t knet_h,
		  uint8_t packet_type,
		  knet_node_id_t src_host_id,
		  uint8_t actual_link_id,
		  uint8_t claimed_link_id,
		  uint8_t frag_num,
		  uint8_t frag_seq,
		  seq_num_t seq_num,
		  const char *payload,
		  size_t payload_len);

/*
 * Log filter callback type
 * Called by log thread for each log line. Return 1 to set pattern_found flag.
 */
typedef int (*log_filter_fn)(int logfd, const char *log_line, void *private_data);

/*
 * Install a runtime log filter
 * The filter callback is invoked for each log line by the log thread.
 * Thread-safe via mutex protection.
 *
 * filter_fn: callback function to check log lines (NULL to disable filtering)
 * private_data: opaque pointer passed to filter callback
 */
void install_log_filter(int logfd, log_filter_fn filter_fn, void *private_data);

/*
 * Check if log filter found a match
 * Returns 1 if filter callback returned 1 for any log line, 0 otherwise
 * Resets the found flag after reading it.
 */
int check_log_pattern_found(void);

#endif
