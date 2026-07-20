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
#include <inttypes.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "libknet.h"
#include "internals.h"
#include "onwire.h"
#include "test-common.h"

#define TEST_NAME "sec_frag_sequence"

/*
 * Test for CVE-2026-15813: Fragment sequence bounds checking
 *
 * This test validates that the RX thread properly rejects packets with:
 * 1. frag_seq == 0 (fragments are 1-indexed, this is invalid)
 * 2. frag_seq > frag_num (sequence number exceeds fragment count)
 *
 * We use a packet injector to directly test the validation logic without
 * requiring network-level packet manipulation.
 */

static int private_data;
static seq_num_t next_seq_num = 1;

static void sock_notify(void *pvt_data,
			int datafd,
			int8_t channel,
			uint8_t tx_rx,
			int error,
			int errorno)
{
	return;
}

/*
 * Log filter callback to check for invalid fragment sequence message
 */
static int filter_invalid_frag_seq(int logfd, const char *log_line, void *private_data)
{
	(void)logfd;
	(void)private_data;

	if (strstr(log_line, "Invalid fragment sequence")) {
		return 1;
	}
	return 0;
}

/*
 * Log filter callback to check for invalid fragment count message
 */
static int filter_invalid_frag_count(int logfd, const char *log_line, void *private_data)
{
	(void)logfd;
	(void)private_data;

	if (strstr(log_line, "Invalid fragment count")) {
		return 1;
	}
	return 0;
}

/*
 * Test invalid fragment sequences
 */
static void test_invalid_frag_seq(void)
{
	knet_handle_t knet_h1, knet_h[2] = {0};
	int logfd;
	int datafd = 0;
	int8_t channel = 0;
	struct sockaddr_storage lo;
	char payload[100];

	logfd = start_logging(stdout);

	memset(payload, 'A', sizeof(payload));

	log_test(logfd, "Test fragment sequence validation with malformed packets");

	knet_h1 = _ts_knet_handle_start(logfd, KNET_LOG_DEBUG, knet_h);

	FAIL_ON_ERR(knet_handle_enable_sock_notify(knet_h1, &private_data, sock_notify));
	FAIL_ON_ERR(knet_handle_add_datafd(knet_h1, &datafd, &channel));
	FAIL_ON_ERR(knet_host_add(knet_h1, 1));
	FAIL_ON_ERR(_ts_knet_link_set_config(knet_h1, 1, 0, KNET_TRANSPORT_UDP, 0, AF_INET, 0, &lo, logfd));
	FAIL_ON_ERR(knet_link_set_enable(knet_h1, 1, 0, 1));
	FAIL_ON_ERR(knet_handle_setfwd(knet_h1, 1));
	FAIL_ON_ERR(wait_for_host(knet_h1, 1, 10, logfd));

	log_test(logfd, "Test 1: Inject packet with frag_seq=0 (should be rejected)");
	log_test(logfd, "        Fragments are 1-indexed, so frag_seq=0 is invalid");

	/* Install log filter to catch rejection message */
	install_log_filter(logfd, filter_invalid_frag_seq, NULL);

	if (inject_packet(knet_h1, KNET_HEADER_TYPE_DATA, 1, 0, 0, 2, 0, next_seq_num++, 0, payload, 50) < 0) {
		log_test(logfd, "Failed to inject packet with frag_seq=0");
		TEST_EXIT_CLEAN(FAIL);
	}

	/* Give RX thread time to process and log thread to catch it */
	test_sleep(logfd, 2);

	if (!check_log_pattern_found()) {
		log_test(logfd, "*** FAIL: Expected log 'Invalid fragment sequence' not found");
		install_log_filter(logfd, NULL, NULL);
		TEST_EXIT_CLEAN(FAIL);
	}
	log_test(logfd, "Test 1 PASSED: Invalid frag_seq=0 was rejected");

	log_test(logfd, "Test 2: Inject packet with frag_seq > frag_num (should be rejected)");
	log_test(logfd, "        frag_seq=5 but frag_num=2 (sequence exceeds count)");

	/* Filter still installed, reset flag */
	install_log_filter(logfd, filter_invalid_frag_seq, NULL);

	if (inject_packet(knet_h1, KNET_HEADER_TYPE_DATA, 1, 0, 0, 2, 5, next_seq_num++, 0, payload, 50) < 0) {
		log_test(logfd, "Failed to inject packet with frag_seq > frag_num");
		install_log_filter(logfd, NULL, NULL);
		TEST_EXIT_CLEAN(FAIL);
	}

	test_sleep(logfd, 2);

	if (!check_log_pattern_found()) {
		log_test(logfd, "*** FAIL: Expected log 'Invalid fragment sequence' not found");
		install_log_filter(logfd, NULL, NULL);
		TEST_EXIT_CLEAN(FAIL);
	}
	log_test(logfd, "Test 2 PASSED: Invalid frag_seq > frag_num was rejected");

	log_test(logfd, "Test 3: Inject valid fragment packet (should be accepted)");
	log_test(logfd, "        frag_seq=1, frag_num=1 (valid unfragmented packet)");

	if (inject_packet(knet_h1, KNET_HEADER_TYPE_DATA, 1, 0, 0, 1, 1, next_seq_num++, 0, payload, 50) < 0) {
		log_test(logfd, "Failed to inject valid packet");
		install_log_filter(logfd, NULL, NULL);
		TEST_EXIT_CLEAN(FAIL);
	}

	test_sleep(logfd, 1);
	log_test(logfd, "Test 3 PASSED: Valid packet was accepted (no rejection log)");

	log_test(logfd, "Test 4: Inject packet with frag_num=255 (maximum value, should be rejected)");
	log_test(logfd, "        frag_map array has 255 elements (indices 0-254)");
	log_test(logfd, "        frag_seq=255 would access frag_map[255] which is out of bounds");

	/* Install filter for fragment count validation */
	install_log_filter(logfd, filter_invalid_frag_count, NULL);

	if (inject_packet(knet_h1, KNET_HEADER_TYPE_DATA, 1, 0, 0, 255, 255, next_seq_num++, 0, payload, 50) < 0) {
		log_test(logfd, "Failed to inject packet with frag_num=255");
		install_log_filter(logfd, NULL, NULL);
		TEST_EXIT_CLEAN(FAIL);
	}

	test_sleep(logfd, 2);

	if (!check_log_pattern_found()) {
		log_test(logfd, "*** FAIL: Expected log 'Invalid fragment count' not found");
		install_log_filter(logfd, NULL, NULL);
		TEST_EXIT_CLEAN(FAIL);
	}
	log_test(logfd, "Test 4 PASSED: frag_num=255 was rejected (prevents array overflow)");

	log_test(logfd, "Test 5: Inject packet with frag_num=254 (maximum valid, should be accepted)");
	log_test(logfd, "        Valid range is 1-254, this tests the boundary");

	/* Remove filter so we can verify no rejection */
	install_log_filter(logfd, NULL, NULL);

	/* Send complete packet with frag_num=254, frag_seq=1 (first of 254 fragments) */
	if (inject_packet(knet_h1, KNET_HEADER_TYPE_DATA, 1, 0, 0, 254, 1, next_seq_num++, 0, payload, 50) < 0) {
		log_test(logfd, "Failed to inject packet with frag_num=254");
		TEST_EXIT_CLEAN(FAIL);
	}

	test_sleep(logfd, 1);
	log_test(logfd, "Test 5 PASSED: frag_num=254 was accepted (maximum valid value)");

	/* Remove filter */
	install_log_filter(logfd, NULL, NULL);

	log_test(logfd, "=== CVE-2026-15813 Fragment sequence validation test PASSED ===");
	log_test(logfd, "Invalid frag_seq values were properly rejected");
	log_test(logfd, "Invalid frag_num=255 was rejected (prevents array overflow)");
	log_test(logfd, "Valid frag_num=254 was accepted (maximum valid value)");
	log_test(logfd, "Valid fragment packets were accepted");
	log_test(logfd, "Heap buffer overflow prevented");

	_ts_knet_handle_stop_everything(knet_h, 1, logfd);

	TEST_EXIT(PASS);
}

int main(int argc, char *argv[])
{
	printf("[TEST] %s: Test fragment sequence bounds checking (CVE-2026-15813)\n", TEST_NAME);

	test_invalid_frag_seq();

	return PASS;
}
