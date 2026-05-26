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
#include "onwire_v1.h"
#include "test-common.h"

#define TEST_NAME "int_buffer_management"

/*
 * Integration tests for defragmentation buffer management
 *
 * This test exercises dynamic buffer allocation and reclamation:
 * 1. Dynamic buffer growth - exceeding initial 32 buffers triggers expansion
 * 2. Dynamic buffer shrinking - idle buffers are deallocated to reclaim memory
 * 3. Buffer reuse verification - reclaimed buffers are properly cleared before reuse
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
 * Test 1: Dynamic buffer growth
 *
 * When all defragmentation buffers are in use, the system should:
 * 1. Detect that no free buffers are available
 * 2. Reallocate the buffer array by doubling its size
 * 3. Initialize new buffers to zero
 * 4. Continue accepting fragmented packets without data loss
 *
 * This test verifies:
 * - Buffer allocation starts at defrag_bufs_min (32)
 * - Filling all 32 buffers triggers reallocation to 64
 * - New buffers are properly initialized
 * - Packet reception continues correctly after growth
 */
static void test_buffer_growth(knet_handle_t knet_h[], int datafd, int8_t channel)
{
	char payload_frag1[100];
	char payload_frag2[100];
	char recvbuf[KNET_MAX_PACKET_SIZE];
	struct knet_host *host;
	ssize_t len;
	seq_num_t base_seq = 10000;
	int i, initial_buffers, buffers_after_growth;

	log_test(logfd, "=== Test 1: Dynamic buffer growth ===");

	memset(payload_frag1, 'A', sizeof(payload_frag1));
	memset(payload_frag2, 'B', sizeof(payload_frag2));

	/* Access host internals to check buffer state */
	host = knet_h[1]->host_index[1];
	if (!host) {
		log_test(logfd, "ERROR: Host 1 not found");
		TEST_EXIT_CLEAN(FAIL);
	}

	initial_buffers = host->allocated_defrag_bufs;
	log_test(logfd, "Initial buffer allocation: %d buffers", initial_buffers);

	/*
	 * Step 1: Fill all initial buffers with incomplete packets
	 * (send only fragment 1/2 for each)
	 */
	log_test(logfd, "Step 1: Filling all %d initial buffers with incomplete packets", initial_buffers);

	for (i = 0; i < initial_buffers; i++) {
		FAIL_ON_ERR(inject_packet(knet_h[1], KNET_HEADER_TYPE_DATA, 1, 0, 0,
					  2, 1, base_seq + i, 0, payload_frag1, sizeof(payload_frag1)));
		usleep(100); /* Small delay to ensure distinct timestamps */
	}

	/* Verify all buffers are now in use */
	int in_use_count = 0;
	for (i = 0; i < host->allocated_defrag_bufs; i++) {
		if (host->defrag_bufs[i].in_use) {
			in_use_count++;
		}
	}

	log_test(logfd, "        Buffers in use: %d/%d", in_use_count, host->allocated_defrag_bufs);

	if (in_use_count != initial_buffers) {
		log_test(logfd, "WARNING: Expected %d buffers in use, got %d", initial_buffers, in_use_count);
	}

	/*
	 * Step 2: Send additional incomplete packet to trigger buffer growth
	 * Growth happens during packet processing, so we complete the packet first
	 */
	log_test(logfd, "Step 2: Sending additional packet to trigger buffer growth");

	FAIL_ON_ERR(inject_packet(knet_h[1], KNET_HEADER_TYPE_DATA, 1, 0, 0,
				  2, 1, base_seq + initial_buffers, 0, payload_frag1, sizeof(payload_frag1)));

	/* Complete the packet to trigger processing and buffer growth */
	FAIL_ON_ERR(inject_packet(knet_h[1], KNET_HEADER_TYPE_DATA, 1, 0, 0,
				  2, 2, base_seq + initial_buffers, 0, payload_frag2, sizeof(payload_frag2)));

	/* Wait for packet to be processed */
	FAIL_ON_ERR(wait_for_packet(knet_h[1], 5, datafd, logfd));
	len = knet_recv(knet_h[1], recvbuf, sizeof(recvbuf), channel);

	/* Now check if buffer growth occurred */
	buffers_after_growth = host->allocated_defrag_bufs;
	log_test(logfd, "        Buffer allocation after growth trigger: %d buffers", buffers_after_growth);

	if (buffers_after_growth != initial_buffers * 2) {
		log_test(logfd, "ERROR: Expected buffer growth to %d, got %d",
			 initial_buffers * 2, buffers_after_growth);
		TEST_EXIT_CLEAN(FAIL);
	}

	/*
	 * Step 3: Verify packet was received correctly after growth
	 */
	log_test(logfd, "Step 3: Verifying packet received correctly after growth");

	if (len != 200) {
		log_test(logfd, "ERROR: Received packet size %zd, expected 200", len);
		TEST_EXIT_CLEAN(FAIL);
	}

	log_test(logfd, "        Received packet after growth: %zd bytes", len);

	/* Verify data integrity */
	for (i = 0; i < 100; i++) {
		if (recvbuf[i] != 'A' || recvbuf[100 + i] != 'B') {
			log_test(logfd, "ERROR: Data corruption after buffer growth");
			TEST_EXIT_CLEAN(FAIL);
		}
	}

	log_test(logfd, "PASS: Buffer growth from %d to %d verified, packet reception works correctly",
		 initial_buffers, buffers_after_growth);
}

/*
 * Test 2: Buffer reuse after reclamation
 *
 * When a buffer is reclaimed (due to sequence distance or timeout), the system must:
 * 1. Clear all buffer state including frag_map, data, timestamps
 * 2. Mark the buffer as available for reuse
 * 3. Ensure no data from old packet leaks into new packet
 *
 * This test verifies:
 * - Reclaimed buffer is completely cleared
 * - New packet using reclaimed buffer has correct data
 * - No cross-contamination between old and new packet data
 */
static void test_buffer_reuse_after_reclamation(knet_handle_t knet_h[], int datafd, int8_t channel)
{
	char payload_old_frag1[100];
	char payload_new[200];
	char recvbuf[KNET_MAX_PACKET_SIZE];
	struct knet_host *host;
	ssize_t len;
	int i;

	log_test(logfd, "=== Test 2: Buffer reuse after reclamation ===");

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
	 * If buffer wasn't properly cleared, we might see 'X' from the old packet
	 */
	log_test(logfd, "Step 3: Verifying buffer was properly cleared before reuse");

	for (i = 0; i < len; i++) {
		if (recvbuf[i] != 'Z') {
			log_test(logfd, "ERROR: Data corruption at byte %d: got 0x%02x, expected 'Z'",
				 i, (unsigned char)recvbuf[i]);
			log_test(logfd, "ERROR: Old buffer data ('X') leaked into new packet!");
			TEST_EXIT_CLEAN(FAIL);
		}
	}

	log_test(logfd, "        All %zd bytes verified: no data leakage from reclaimed buffer", len);

	/*
	 * Step 4: Send another incomplete packet using same sequence number as original
	 * This reuses the buffer that was just reclaimed
	 */
	log_test(logfd, "Step 4: Reusing reclaimed buffer with new incomplete packet (seq 5000)");

	char payload_reuse_frag1[100];
	char payload_reuse_frag2[100];

	memset(payload_reuse_frag1, 'M', sizeof(payload_reuse_frag1));
	memset(payload_reuse_frag2, 'N', sizeof(payload_reuse_frag2));

	FAIL_ON_ERR(inject_packet(knet_h[1], KNET_HEADER_TYPE_DATA, 1, 0, 0,
				  2, 1, 5000, 0, payload_reuse_frag1, sizeof(payload_reuse_frag1)));
	FAIL_ON_ERR(inject_packet(knet_h[1], KNET_HEADER_TYPE_DATA, 1, 0, 0,
				  2, 2, 5000, 0, payload_reuse_frag2, sizeof(payload_reuse_frag2)));

	FAIL_ON_ERR(wait_for_packet(knet_h[1], 5, datafd, logfd));
	len = knet_recv(knet_h[1], recvbuf, sizeof(recvbuf), channel);

	if (len != 200) {
		log_test(logfd, "ERROR: Reused buffer packet size %zd, expected 200", len);
		TEST_EXIT_CLEAN(FAIL);
	}

	/* Verify new data 'M'+'N', no trace of old 'X' */
	for (i = 0; i < 100; i++) {
		if (recvbuf[i] != 'M') {
			log_test(logfd, "ERROR: Frag 1 corruption at byte %d in reused buffer", i);
			TEST_EXIT_CLEAN(FAIL);
		}
	}
	for (i = 100; i < 200; i++) {
		if (recvbuf[i] != 'N') {
			log_test(logfd, "ERROR: Frag 2 corruption at byte %d in reused buffer", i);
			TEST_EXIT_CLEAN(FAIL);
		}
	}

	log_test(logfd, "        Reused buffer data verified: 'M'+'N' (no trace of old 'X')");

	log_test(logfd, "PASS: Buffer reclamation and reuse verified - no data leakage");
}

/*
 * Test 3: Dynamic buffer shrinking
 *
 * When buffer usage stays below threshold for enough samples, the system should:
 * 1. Detect sustained low usage (< 25% by default)
 * 2. Compact active buffers to the beginning of the array
 * 3. Reallocate the buffer array by halving its size
 * 4. Continue operating correctly with reduced buffer count
 *
 * This test verifies:
 * - Buffer allocation can grow from 32 to 64
 * - When usage drops below threshold, buffers shrink back to 32
 * - Buffer statistics are properly reset after shrinking
 * - Packet reception works correctly after shrinking
 */
static void test_buffer_shrinking(knet_handle_t knet_h[], int datafd, int8_t channel)
{
	char payload_frag1[100];
	char payload_frag2[100];
	char payload_complete[200];
	char recvbuf[KNET_MAX_PACKET_SIZE];
	struct knet_host *host;
	ssize_t len;
	seq_num_t base_seq = 20000;
	int i, initial_buffers, buffers_after_growth, buffers_after_shrink;
	int packets_to_send;

	log_test(logfd, "=== Test 3: Dynamic buffer shrinking ===");

	memset(payload_frag1, 'A', sizeof(payload_frag1));
	memset(payload_frag2, 'B', sizeof(payload_frag2));
	memset(payload_complete, 'C', sizeof(payload_complete));

	host = knet_h[1]->host_index[1];
	if (!host) {
		log_test(logfd, "ERROR: Host 1 not found");
		TEST_EXIT_CLEAN(FAIL);
	}

	initial_buffers = host->allocated_defrag_bufs;
	log_test(logfd, "Initial buffer allocation: %d buffers", initial_buffers);

	/*
	 * Step 1: Ensure we're starting from a known state
	 * We may already have grown buffers from previous tests
	 */
	if (initial_buffers < 64) {
		log_test(logfd, "Step 1: Growing buffers from %d to 64", initial_buffers);

		/* Fill all initial buffers */
		for (i = 0; i < initial_buffers; i++) {
			FAIL_ON_ERR(inject_packet(knet_h[1], KNET_HEADER_TYPE_DATA, 1, 0, 0,
						  2, 1, base_seq + i, 0, payload_frag1, sizeof(payload_frag1)));
			usleep(100);
		}

		/* Trigger growth */
		FAIL_ON_ERR(inject_packet(knet_h[1], KNET_HEADER_TYPE_DATA, 1, 0, 0,
					  2, 1, base_seq + initial_buffers, 0, payload_frag1, sizeof(payload_frag1)));
		FAIL_ON_ERR(inject_packet(knet_h[1], KNET_HEADER_TYPE_DATA, 1, 0, 0,
					  2, 2, base_seq + initial_buffers, 0, payload_frag2, sizeof(payload_frag2)));

		FAIL_ON_ERR(wait_for_packet(knet_h[1], 5, datafd, logfd));
		(void)knet_recv(knet_h[1], recvbuf, sizeof(recvbuf), channel);

		buffers_after_growth = host->allocated_defrag_bufs;
		log_test(logfd, "        Buffers after growth: %d", buffers_after_growth);

		/* Complete all the incomplete packets we just sent */
		for (i = 0; i < initial_buffers; i++) {
			FAIL_ON_ERR(inject_packet(knet_h[1], KNET_HEADER_TYPE_DATA, 1, 0, 0,
						  2, 2, base_seq + i, 0, payload_frag2, sizeof(payload_frag2)));
		}

		/* Drain all completed packets */
		for (i = 0; i < initial_buffers; i++) {
			FAIL_ON_ERR(wait_for_packet(knet_h[1], 5, datafd, logfd));
			(void)knet_recv(knet_h[1], recvbuf, sizeof(recvbuf), channel);
		}
	} else {
		log_test(logfd, "Step 1: Buffers already at %d, skipping growth", initial_buffers);
		buffers_after_growth = initial_buffers;
	}

	/*
	 * Step 2: Ensure buffer usage is low
	 * Send a few complete packets to clear any lingering incomplete ones
	 */
	log_test(logfd, "Step 2: Clearing any incomplete packets to ensure low buffer usage");

	for (i = 0; i < 10; i++) {
		seq_num_t clear_seq = base_seq + 10000 + i;
		FAIL_ON_ERR(inject_packet(knet_h[1], KNET_HEADER_TYPE_DATA, 1, 0, 0,
					  1, 1, clear_seq, 0, payload_complete, sizeof(payload_complete)));
	}

	/* Drain them */
	for (i = 0; i < 10; i++) {
		FAIL_ON_ERR(wait_for_packet(knet_h[1], 5, datafd, logfd));
		(void)knet_recv(knet_h[1], recvbuf, sizeof(recvbuf), channel);
	}

	log_test(logfd, "        Buffer usage should now be near 0%%");

	/*
	 * Step 3: Configure faster shrinking for test purposes
	 * Reduce defrag_bufs_usage_samples to collect samples faster
	 * Default is 255 which would take too long for a test
	 */
	log_test(logfd, "Step 3: Configuring faster shrinking (reducing sample count for test)");

	knet_h[1]->defrag_bufs_usage_samples = 10;  /* Reduced from 255 */
	log_test(logfd, "        Reduced usage_samples to %d for faster testing",
		 knet_h[1]->defrag_bufs_usage_samples);

	/*
	 * Step 4: Send packets to trigger sample collection and shrinking
	 * We need to send enough packets to:
	 * - Collect 10 samples showing low usage
	 * - Keep the RX thread active to call _shrink_defrag_buffers()
	 *
	 * Send one complete packet per sample period
	 */
	log_test(logfd, "Step 4: Sending packets to trigger sample collection and shrinking");

	packets_to_send = knet_h[1]->defrag_bufs_usage_samples + 2;  /* Extra for safety */

	for (i = 0; i < packets_to_send; i++) {
		FAIL_ON_ERR(inject_packet(knet_h[1], KNET_HEADER_TYPE_DATA, 1, 0, 0,
					  1, 1, base_seq + 1000 + i, 0,
					  payload_complete, sizeof(payload_complete)));

		/* Sleep for sample period */
		/* timespan (10s) / samples (10) = 1 second per sample */
		usleep((knet_h[1]->defrag_bufs_usage_samples_timespan * 1000000) /
		       knet_h[1]->defrag_bufs_usage_samples + 50000);
	}

	/* Drain packets */
	for (i = 0; i < packets_to_send; i++) {
		FAIL_ON_ERR(wait_for_packet(knet_h[1], 5, datafd, logfd));
		(void)knet_recv(knet_h[1], recvbuf, sizeof(recvbuf), channel);
	}

	log_test(logfd, "        Sent %d packets to collect usage samples", packets_to_send);

	/*
	 * Step 5: Verify buffer shrinking occurred
	 */
	log_test(logfd, "Step 5: Verifying buffer shrinking occurred");

	buffers_after_shrink = host->allocated_defrag_bufs;
	log_test(logfd, "        Buffers after shrinking: %d (was %d)",
		 buffers_after_shrink, buffers_after_growth);

	if (buffers_after_shrink != buffers_after_growth / 2) {
		log_test(logfd, "ERROR: Shrinking did not occur or incorrect size");
		log_test(logfd, "       Expected %d, got %d", buffers_after_growth / 2, buffers_after_shrink);
		TEST_EXIT_CLEAN(FAIL);
	}

	/*
	 * Step 6: Verify packet reception still works after shrinking
	 */
	log_test(logfd, "Step 6: Verifying packet reception works after shrinking");

	FAIL_ON_ERR(inject_packet(knet_h[1], KNET_HEADER_TYPE_DATA, 1, 0, 0,
				  2, 1, base_seq + 2000, 0, payload_frag1, sizeof(payload_frag1)));
	FAIL_ON_ERR(inject_packet(knet_h[1], KNET_HEADER_TYPE_DATA, 1, 0, 0,
				  2, 2, base_seq + 2000, 0, payload_frag2, sizeof(payload_frag2)));

	FAIL_ON_ERR(wait_for_packet(knet_h[1], 5, datafd, logfd));
	len = knet_recv(knet_h[1], recvbuf, sizeof(recvbuf), channel);

	if (len != 200) {
		log_test(logfd, "ERROR: Packet reception after shrinking failed, got %zd bytes", len);
		TEST_EXIT_CLEAN(FAIL);
	}

	/* Verify data integrity */
	for (i = 0; i < 100; i++) {
		if (recvbuf[i] != 'A' || recvbuf[100 + i] != 'B') {
			log_test(logfd, "ERROR: Data corruption after buffer shrinking");
			TEST_EXIT_CLEAN(FAIL);
		}
	}

	log_test(logfd, "        Packet reception verified: %zd bytes", len);

	log_test(logfd, "PASS: Buffer shrinking from %d to %d verified, system works correctly after shrinking",
		 buffers_after_growth, buffers_after_shrink);
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
	FAIL_ON_ERR(knet_handle_add_datafd(knet_h1, &datafd, &channel, 0));
	FAIL_ON_ERR(knet_host_add(knet_h1, 1));

	/*
	 * Configure UDP link (to ourselves)
	 */
	FAIL_ON_ERR(_ts_knet_link_set_config(knet_h1, 1, 0, KNET_TRANSPORT_UDP, 0, AF_INET, 0, &lo, logfd));
	FAIL_ON_ERR(knet_link_set_enable(knet_h1, 1, 0, 1));
	FAIL_ON_ERR(knet_handle_setfwd(knet_h1, 1));
	FAIL_ON_ERR(wait_for_host(knet_h1, 1, 10, logfd));

	test_sleep(logfd, 1);

	/* Run tests */
	test_buffer_growth(knet_h, datafd, channel);
	test_sleep(logfd, 1);

	test_buffer_reuse_after_reclamation(knet_h, datafd, channel);
	test_sleep(logfd, 1);

	test_buffer_shrinking(knet_h, datafd, channel);
	test_sleep(logfd, 1);

	log_test(logfd, "=== All buffer management tests PASSED ===");

	TEST_EXIT_CLEAN(PASS);
}

int main(int argc, char *argv[])
{
	printf("[TEST] %s: Defragmentation buffer management test\n", TEST_NAME);

	test_buffer_management();

	return PASS;
}
