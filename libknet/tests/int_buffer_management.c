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

#include "libknet.h"
#include "internals.h"
#include "onwire.h"
#include "test-common.h"

#define TEST_NAME "int_buffer_management"

/*
 * Integration tests for defragmentation buffer management
 *
 * Note: stable1 does not have dynamic buffer growth/shrinking, so only
 * buffer reuse after reclamation is tested here.
 */

static int private_data;
static int logfd;
static struct sockaddr_storage lo;

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
 * Test: Buffer reuse after reclamation
 *
 * When a defragmentation buffer is reclaimed (due to sequence number window
 * moving forward), it must be properly cleared before being reused for a new
 * packet. This prevents data leakage from the old incomplete packet into the
 * new packet.
 *
 * This test verifies:
 * 1. Old incomplete packet creates buffer with known data pattern ('X')
 * 2. Sequence jump triggers reclamation (distance > KNET_CBUFFER_SIZE)
 * 3. New packet in reclaimed buffer contains only new data ('Z')
 * 4. No trace of old data remains
 * 5. Subsequent reuse continues to work correctly ('M'+'N')
 */
static void test_buffer_reuse_after_reclamation(knet_handle_t knet_h[], int datafd, int8_t channel)
{
	char payload_old_frag1[100];
	char payload_new[200];
	char recvbuf[KNET_MAX_PACKET_SIZE];
	struct knet_host *host;
	ssize_t len;
	int i;

	log_test(logfd, "=== Test: Buffer reuse after reclamation ===");

	memset(payload_old_frag1, 'X', sizeof(payload_old_frag1));
	memset(payload_new, 'Z', sizeof(payload_new));

	host = knet_h[1]->host_index[1];
	if (!host) {
		log_test(logfd, "ERROR: Host 1 not found");
		TEST_EXIT_CLEAN(FAIL);
	}

	/*
	 * Step 1: Create an incomplete packet (old data 'X')
	 */
	log_test(logfd, "Step 1: Sending incomplete packet (fragment 1/2, filled with 'X')");

	FAIL_ON_ERR(inject_packet(knet_h[1], KNET_HEADER_TYPE_DATA, 1, 0, 0,
				  2, 1, 5000, 0, payload_old_frag1, sizeof(payload_old_frag1)));

	/*
	 * Step 2: Send complete packet with distant sequence number to trigger reclamation
	 * Sequence distance > KNET_CBUFFER_SIZE (4096) will force reclamation of old buffer
	 */
	log_test(logfd, "Step 2: Sending complete packet with distant seq to trigger reclamation");
	log_test(logfd, "        New seq 10000, old seq 5000, distance = 5000 > 4096 (KNET_CBUFFER_SIZE)");

	FAIL_ON_ERR(inject_packet(knet_h[1], KNET_HEADER_TYPE_DATA, 1, 0, 0,
				  1, 1, 10000, 0, payload_new, sizeof(payload_new)));

	FAIL_ON_ERR(wait_for_packet(knet_h[1], 5, datafd, logfd));
	len = knet_recv(knet_h[1], recvbuf, sizeof(recvbuf), channel);

	if (len != (ssize_t)sizeof(payload_new)) {
		log_test(logfd, "ERROR: Received %zd bytes, expected %zu", len, sizeof(payload_new));
		TEST_EXIT_CLEAN(FAIL);
	}

	log_test(logfd, "        Received packet: %zd bytes", len);

	/*
	 * Step 3: Verify all data is 'Z' (new packet)
	 * If buffer wasn't properly cleared, might see 'X' from old packet
	 */
	log_test(logfd, "Step 3: Verify no data leakage from old packet");

	for (i = 0; i < (int)sizeof(payload_new); i++) {
		if (recvbuf[i] != 'Z') {
			log_test(logfd, "ERROR: Data leakage detected at byte %d", i);
			log_test(logfd, "       Expected 'Z' (0x5A), got 0x%02x", (unsigned char)recvbuf[i]);
			if (recvbuf[i] == 'X') {
				log_test(logfd, "       Found 'X' from old packet - buffer not cleared!");
			}
			TEST_EXIT_CLEAN(FAIL);
		}
	}

	log_test(logfd, "        All %zu bytes verified as 'Z' - no leakage", sizeof(payload_new));

	/*
	 * Step 4: Reuse the same buffer again with different data
	 * This verifies the buffer continues to work correctly
	 */
	log_test(logfd, "Step 4: Reuse buffer with new 2-fragment packet");

	char payload_m[150], payload_n[150];
	memset(payload_m, 'M', sizeof(payload_m));
	memset(payload_n, 'N', sizeof(payload_n));

	/* Use same sequence 10000 area but different number */
	FAIL_ON_ERR(inject_packet(knet_h[1], KNET_HEADER_TYPE_DATA, 1, 0, 0,
				  2, 1, 10010, 0, payload_m, sizeof(payload_m)));

	FAIL_ON_ERR(inject_packet(knet_h[1], KNET_HEADER_TYPE_DATA, 1, 0, 0,
				  2, 2, 10010, 0, payload_n, sizeof(payload_n)));

	FAIL_ON_ERR(wait_for_packet(knet_h[1], 5, datafd, logfd));
	len = knet_recv(knet_h[1], recvbuf, sizeof(recvbuf), channel);

	if (len != (ssize_t)(sizeof(payload_m) + sizeof(payload_n))) {
		log_test(logfd, "ERROR: Received %zd bytes, expected %zu",
			 len, sizeof(payload_m) + sizeof(payload_n));
		TEST_EXIT_CLEAN(FAIL);
	}

	log_test(logfd, "        Received reassembled packet: %zd bytes", len);

	/*
	 * Step 5: Verify fragment 1 is 'M' and fragment 2 is 'N'
	 */
	log_test(logfd, "Step 5: Verify reassembled packet integrity");

	for (i = 0; i < (int)sizeof(payload_m); i++) {
		if (recvbuf[i] != 'M') {
			log_test(logfd, "ERROR: Fragment 1 corrupted at byte %d: got 0x%02x, expected 'M'",
				 i, (unsigned char)recvbuf[i]);
			TEST_EXIT_CLEAN(FAIL);
		}
	}

	for (i = 0; i < (int)sizeof(payload_n); i++) {
		if (recvbuf[sizeof(payload_m) + i] != 'N') {
			log_test(logfd, "ERROR: Fragment 2 corrupted at byte %d: got 0x%02x, expected 'N'",
				 i, (unsigned char)recvbuf[sizeof(payload_m) + i]);
			TEST_EXIT_CLEAN(FAIL);
		}
	}

	log_test(logfd, "        Fragment 1: %zu bytes of 'M' verified", sizeof(payload_m));
	log_test(logfd, "        Fragment 2: %zu bytes of 'N' verified", sizeof(payload_n));

	log_test(logfd, "PASS: Buffer reuse after reclamation works correctly");
}

static void test_buffer_management(void)
{
	knet_handle_t knet_h1, knet_h[2] = {0};
	int datafd = 0;
	int8_t channel = -1;

	logfd = start_logging(stdout);

	knet_h1 = _ts_knet_handle_start(logfd, KNET_LOG_DEBUG, knet_h);

	log_test(logfd, "Setting up buffer management test");

	FAIL_ON_ERR(knet_handle_enable_sock_notify(knet_h1, &private_data, sock_notify));
	FAIL_ON_ERR(knet_handle_add_datafd(knet_h1, &datafd, &channel));
	FAIL_ON_ERR(knet_host_add(knet_h1, 1));

	/*
	 * Configure UDP link (to ourselves)
	 */
	FAIL_ON_ERR(_ts_knet_link_set_config(knet_h1, 1, 0, KNET_TRANSPORT_UDP, 0, AF_INET, 0, &lo, logfd));
	FAIL_ON_ERR(knet_link_set_enable(knet_h1, 1, 0, 1));
	FAIL_ON_ERR(knet_handle_setfwd(knet_h1, 1));
	FAIL_ON_ERR(wait_for_host(knet_h1, 1, 10, logfd));

	test_sleep(logfd, 1);

	/* Run test - only buffer reuse test applies to stable1 */
	test_buffer_reuse_after_reclamation(knet_h, datafd, channel);

	log_test(logfd, "=== Buffer management test PASSED ===");

	TEST_EXIT_CLEAN(PASS);
}

int main(int argc, char *argv[])
{
	printf("[TEST] %s: Defragmentation buffer management test\n", TEST_NAME);

	test_buffer_management();

	return PASS;
}
