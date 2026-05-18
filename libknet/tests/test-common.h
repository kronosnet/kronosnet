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
 * error codes from automake test-driver
 */

#define PASS	0
#define SKIP	77
#define ERROR	99
#define FAIL	-1
/* Extra for us to continue while still using the cleanup code */
#define CONTINUE 101

/* For *BSD compatibility */
#ifndef s6_addr32
# ifdef KNET_SOLARIS
#  define s6_addr32 _S6_un._S6_u32
# else
#  define s6_addr32 __u6_addr.__u6_addr32
# endif
#endif

/*
 * common facilities
 */
#define TESTNODES 1

/*
 * Test logging macro - writes to knet logging infrastructure
 * with NULL handle (displayed as [testsuite]: message)
 * Parameters: logfd - the write end of the log pipe, fmt - printf-style format string
 */
#define log_test(logfd, fmt, ...) \
	do { \
		struct knet_log_msg _log_msg; \
		memset(&_log_msg, 0, sizeof(_log_msg)); \
		snprintf(_log_msg.msg, KNET_MAX_LOG_MSG_SIZE, fmt, ##__VA_ARGS__); \
		if (write(logfd, &_log_msg, sizeof(_log_msg)) != sizeof(_log_msg)) { \
			fprintf(stderr, "Failed to write to log pipe\n"); \
		} \
	} while(0)

#define TEST_EXIT_CLEAN(r) \
	do { \
		_ts_knet_handle_stop_everything(knet_h, TESTNODES, logfd); \
		if (r == CONTINUE) { \
			stop_logging(); \
			return; \
		} \
		TEST_EXIT(r); \
	} while(0)

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
 * Helper macro to print test result and exit.
 * Handles PASS, FAIL, SKIP, and ERROR.
 * Requires TEST_NAME to be defined in the test file.
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

int is_memcheck(void);
int is_helgrind(void);

knet_handle_t _ts_knet_handle_start(int logfd, uint8_t log_level, knet_handle_t knet_h_array[]);

/*
 * knet_link_set_config wrapper required to find a free port
 */

int _ts_knet_link_set_config(knet_handle_t knet_h, knet_node_id_t host_id, uint8_t link_id,
			     uint8_t transport, uint64_t flags, int family, int dynamic,
			     struct sockaddr_storage *lo, int logfd);

/*
 * functional test helpers
 */
void _ts_knet_handle_stop_everything(knet_handle_t knet_h[], uint8_t numnodes, int logfd);
void _ts_knet_handle_start_nodes(knet_handle_t knet_h[], uint8_t numnodes, int logfd, uint8_t log_level);
void _ts_knet_handle_join_nodes(knet_handle_t knet_h[], uint8_t numnodes, uint8_t numlinks, int family, uint8_t transport, int logfd);
int _ts_knet_handle_disconnect_links(knet_handle_t knet_h, int logfd);
int _ts_knet_handle_reconnect_links(knet_handle_t knet_h, int logfd);

/*
 * high level logging functions.
 * automatically setup logpipes and start/stop logging thread.
 *
 * start_logging() - exits on error, returns logfd to pass to knet_handle_new
 *                   registers atexit handler for automatic cleanup
 * stop_logging()  - manually stops logging (safe to call multiple times)
 */
int start_logging(FILE *std);
void stop_logging(void);

int make_local_sockaddr(struct sockaddr_storage *lo, int offset, int logfd);
int make_local_sockaddr6(struct sockaddr_storage *lo, int offset, int logfd);
int wait_for_host(knet_handle_t knet_h, uint16_t host_id, int seconds, int logfd, FILE *std);
int wait_for_packet(knet_handle_t knet_h, int seconds, int datafd, int logfd, FILE *std);
void test_sleep(int logfd, int seconds);
int wait_for_nodes_state(knet_handle_t knet_h, size_t numnodes,
			 uint8_t state, uint32_t timeout,
			 int logfd, FILE *std);

#endif
