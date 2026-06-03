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
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "libknet.h"
#include "internals.h"
#include "onwire.h"
#include "onwire_v1.h"
#include "test-common.h"

#define TEST_NAME "int_seq_wraparound_stress"

/*
 * Stress test for sequence number wraparound and circular buffer logic
 *
 * This test exercises the sequence number wraparound handling by:
 * - Injecting packets with sequence numbers near SEQ_MAX boundary
 * - Simulating realistic packet loss (gaps in sequence numbers)
 * - Testing fragmented packets with missing fragments
 * - Verifying buffer reclamation works correctly with gaps
 *
 * Test scenarios:
 * 1. Normal sequential packets with occasional loss
 * 2. Wraparound boundary with packet loss
 * 3. Large sequence number jumps (simulating extended loss)
 * 4. Out-of-order delivery
 * 5. Incomplete fragmented packets (missing fragments)
 */

static int private_data;

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
 * Send a 2-fragment packet with specified sequence number
 * Can optionally skip sending fragment 1 or fragment 2 to simulate loss
 */
static int send_fragmented_packet(knet_handle_t knet_h, seq_num_t seq_num,
				   int send_frag1, int send_frag2, int logfd)
{
	char payload1[100];
	char payload2[100];

	memset(payload1, 'A', sizeof(payload1));
	memset(payload2, 'B', sizeof(payload2));

	log_test(logfd, "Injecting seq %u: frag1=%s frag2=%s",
		 seq_num, send_frag1 ? "yes" : "no", send_frag2 ? "yes" : "no");

	if (send_frag1) {
		if (inject_packet(knet_h, KNET_HEADER_TYPE_DATA, 1, 0, 0, 2, 1, seq_num,
				  0, payload1, sizeof(payload1)) < 0) {
			log_test(logfd, "Failed to inject fragment 1 for seq %u: %s",
				 seq_num, strerror(errno));
			return -1;
		}
	}

	if (send_frag2) {
		if (inject_packet(knet_h, KNET_HEADER_TYPE_DATA, 1, 0, 0, 2, 2, seq_num,
				  0, payload2, sizeof(payload2)) < 0) {
			log_test(logfd, "Failed to inject fragment 2 for seq %u: %s",
				 seq_num, strerror(errno));
			return -1;
		}
	}

	return 0;
}

/*
 * Receive and verify packet count
 * Loops receiving packets until expected_count is reached or timeout
 * Returns received_count on success (which should equal expected_count)
 * Returns -1 if received count doesn't match expected
 */
static int receive_and_verify_count(knet_handle_t knet_h, int expected_count,
				     int datafd, int8_t channel, int logfd,
				     const char *test_name)
{
	char recvbuf[KNET_MAX_PACKET_SIZE];
	ssize_t len;
	int received_count = 0;

	log_test(logfd, "Waiting for %d packets...", expected_count);

	while (received_count < expected_count) {
		if (wait_for_packet(knet_h, 5, datafd, logfd) < 0) {
			break;
		}
		len = knet_recv(knet_h, recvbuf, sizeof(recvbuf), channel);
		if (len > 0) {
			received_count++;
			log_test(logfd, "Received packet %d/%d (size: %zd bytes)",
				 received_count, expected_count, len);
		}
	}

	if (received_count != expected_count) {
		log_test(logfd, "%s: Expected %d packets, received %d",
			 test_name, expected_count, received_count);
		return -1;
	}

	log_test(logfd, "Successfully received all %d packets", received_count);
	return received_count;
}

static void test_normal_with_loss(knet_handle_t knet_h[], int datafd, int8_t channel, int logfd)
{
	log_test(logfd, "=== Test 1: Normal sequential with packet loss ===");

	/*
	 * Send sequence 1000-1010 with some packets lost:
	 * 1000: complete (both fragments)
	 * 1001: lost (neither fragment)
	 * 1002: complete
	 * 1003: incomplete (only fragment 1)
	 * 1004: complete
	 * 1005: lost
	 * 1006: complete
	 */

	FAIL_ON_ERR(send_fragmented_packet(knet_h[1], 1000, 1, 1, logfd)); /* complete */
	FAIL_ON_ERR(send_fragmented_packet(knet_h[1], 1001, 0, 0, logfd)); /* lost */
	FAIL_ON_ERR(send_fragmented_packet(knet_h[1], 1002, 1, 1, logfd)); /* complete */
	FAIL_ON_ERR(send_fragmented_packet(knet_h[1], 1003, 1, 0, logfd)); /* incomplete */
	FAIL_ON_ERR(send_fragmented_packet(knet_h[1], 1004, 1, 1, logfd)); /* complete */
	FAIL_ON_ERR(send_fragmented_packet(knet_h[1], 1005, 0, 0, logfd)); /* lost */
	FAIL_ON_ERR(send_fragmented_packet(knet_h[1], 1006, 1, 1, logfd)); /* complete */

	/* Should receive only complete packets: 1000, 1002, 1004, 1006 */
	FAIL_ON_ERR_ONLY(receive_and_verify_count(knet_h[1], 4, datafd, channel, logfd, "Test 1"));

	log_test(logfd, "PASS: Received 4 complete packets as expected");
}

static void test_wraparound_with_loss(knet_handle_t knet_h[], int datafd, int8_t channel, int logfd)
{
	log_test(logfd, "=== Test 2: Wraparound boundary with packet loss ===");

	/*
	 * Send packets around SEQ_MAX boundary with losses:
	 * 65533: complete
	 * 65534: lost
	 * 65535: complete
	 * 0: incomplete (only frag 1)
	 * 1: complete
	 * 2: lost
	 * 3: complete
	 * 4: complete
	 */

	FAIL_ON_ERR(send_fragmented_packet(knet_h[1], 65533, 1, 1, logfd)); /* complete */
	FAIL_ON_ERR(send_fragmented_packet(knet_h[1], 65534, 0, 0, logfd)); /* lost */
	FAIL_ON_ERR(send_fragmented_packet(knet_h[1], 65535, 1, 1, logfd)); /* complete */
	FAIL_ON_ERR(send_fragmented_packet(knet_h[1], 0, 1, 0, logfd));     /* incomplete */
	FAIL_ON_ERR(send_fragmented_packet(knet_h[1], 1, 1, 1, logfd));     /* complete */
	FAIL_ON_ERR(send_fragmented_packet(knet_h[1], 2, 0, 0, logfd));     /* lost */
	FAIL_ON_ERR(send_fragmented_packet(knet_h[1], 3, 1, 1, logfd));     /* complete */
	FAIL_ON_ERR(send_fragmented_packet(knet_h[1], 4, 1, 1, logfd));     /* complete */

	/* Should receive: 65533, 65535, 1, 3, 4 = 5 packets */
	FAIL_ON_ERR_ONLY(receive_and_verify_count(knet_h[1], 5, datafd, channel, logfd, "Test 2"));

	log_test(logfd, "PASS: Wraparound handled correctly with 5 packets");
}

static void test_large_jump_with_loss(knet_handle_t knet_h[], int datafd, int8_t channel, int logfd)
{
	log_test(logfd, "=== Test 3: Large sequence jump (> KNET_CBUFFER_SIZE) ===");

	/*
	 * Send seq 5000, then jump to 10000 (simulating 5000 lost packets)
	 * This should trigger buffer clearing logic
	 */

	FAIL_ON_ERR(send_fragmented_packet(knet_h[1], 5000, 1, 1, logfd));  /* complete */
	FAIL_ON_ERR(send_fragmented_packet(knet_h[1], 10000, 1, 1, logfd)); /* complete after gap */
	FAIL_ON_ERR(send_fragmented_packet(knet_h[1], 10001, 1, 1, logfd)); /* complete */

	/* Should receive all 3 complete packets */
	FAIL_ON_ERR_ONLY(receive_and_verify_count(knet_h[1], 3, datafd, channel, logfd, "Test 3"));

	log_test(logfd, "PASS: Large jump handled correctly");
}

static void test_out_of_order(knet_handle_t knet_h[], int datafd, int8_t channel, int logfd)
{
	log_test(logfd, "=== Test 4: Out-of-order delivery ===");

	/*
	 * Send fragments out of order:
	 * seq 20003 frag 2, then frag 1 (reversed)
	 * seq 20004 frag 1, then frag 2 (normal)
	 * seq 20005 frag 2, then frag 1 (reversed)
	 */

	/* seq 20003 - reversed order */
	log_test(logfd, "Injecting seq 20003: frag 2 first (reversed)");
	FAIL_ON_ERR(inject_packet(knet_h[1], KNET_HEADER_TYPE_DATA, 1, 0, 0, 2, 2, 20003,
				  0, "BBBB", 4));
	FAIL_ON_ERR(inject_packet(knet_h[1], KNET_HEADER_TYPE_DATA, 1, 0, 0, 2, 1, 20003,
				  0, "AAAA", 4));

	/* seq 20004 - normal order */
	log_test(logfd, "Injecting seq 20004: frag 1, frag 2 (normal)");
	FAIL_ON_ERR(inject_packet(knet_h[1], KNET_HEADER_TYPE_DATA, 1, 0, 0, 2, 1, 20004,
				  0, "CCCC", 4));
	FAIL_ON_ERR(inject_packet(knet_h[1], KNET_HEADER_TYPE_DATA, 1, 0, 0, 2, 2, 20004,
				  0, "DDDD", 4));

	/* seq 20005 - reversed order */
	log_test(logfd, "Injecting seq 20005: frag 2 first (reversed)");
	FAIL_ON_ERR(inject_packet(knet_h[1], KNET_HEADER_TYPE_DATA, 1, 0, 0, 2, 2, 20005,
				  0, "FFFF", 4));
	FAIL_ON_ERR(inject_packet(knet_h[1], KNET_HEADER_TYPE_DATA, 1, 0, 0, 2, 1, 20005,
				  0, "EEEE", 4));

	/* Should receive all 3 complete packets regardless of fragment order */
	FAIL_ON_ERR_ONLY(receive_and_verify_count(knet_h[1], 3, datafd, channel, logfd, "Test 4"));

	log_test(logfd, "PASS: Out-of-order fragments handled correctly");
}

static void test_out_of_order_packets(knet_handle_t knet_h[], int datafd, int8_t channel, int logfd)
{
	log_test(logfd, "=== Test 5: Out-of-order complete packet delivery ===");

	/*
	 * Send complete packets in out-of-order sequence numbers
	 * Send seq 1000, then 1001, then 999
	 * All should be delivered despite arrival order
	 */

	/* seq 1000 - arrives first */
	FAIL_ON_ERR(send_fragmented_packet(knet_h[1], 1000, 1, 1, logfd));

	/* seq 1001 - arrives second */
	FAIL_ON_ERR(send_fragmented_packet(knet_h[1], 1001, 1, 1, logfd));

	/* seq 999 - arrives third (out of order) */
	FAIL_ON_ERR(send_fragmented_packet(knet_h[1], 999, 1, 1, logfd));

	/* Should receive all 3 packets: 999, 1000, 1001 */
	FAIL_ON_ERR_ONLY(receive_and_verify_count(knet_h[1], 3, datafd, channel, logfd, "Test 5"));

	log_test(logfd, "PASS: Out-of-order complete packets handled correctly");
}

static void test_extreme_loss_beyond_window(knet_handle_t knet_h[], int datafd, int8_t channel, int logfd)
{
	log_test(logfd, "=== Test 6: Extreme packet loss beyond receive window ===");

	/*
	 * Test packet loss exceeding KNET_CBUFFER_SIZE (4096)
	 * Start at seq 30000
	 * Send fragmented packets
	 * Simulate massive loss (> 4096 packets)
	 * Send packets at seq 35000 (5000 packet gap)
	 * Verify buffer clearing and recovery works correctly
	 */

	FAIL_ON_ERR(send_fragmented_packet(knet_h[1], 30000, 1, 1, logfd)); /* complete */
	FAIL_ON_ERR(send_fragmented_packet(knet_h[1], 30001, 1, 1, logfd)); /* complete */
	FAIL_ON_ERR(send_fragmented_packet(knet_h[1], 30002, 1, 0, logfd)); /* incomplete - only frag 1 */

	/* Simulate massive packet loss - jump beyond KNET_CBUFFER_SIZE */
	FAIL_ON_ERR(send_fragmented_packet(knet_h[1], 35000, 1, 1, logfd)); /* complete after huge gap */
	FAIL_ON_ERR(send_fragmented_packet(knet_h[1], 35001, 1, 1, logfd)); /* complete */
	FAIL_ON_ERR(send_fragmented_packet(knet_h[1], 35002, 0, 1, logfd)); /* incomplete - only frag 2 */
	FAIL_ON_ERR(send_fragmented_packet(knet_h[1], 35003, 1, 1, logfd)); /* complete */

	/* Should receive: 30000, 30001, 35000, 35001, 35003 = 5 packets */
	FAIL_ON_ERR_ONLY(receive_and_verify_count(knet_h[1], 5, datafd, channel, logfd, "Test 6"));

	log_test(logfd, "PASS: Extreme loss beyond window handled correctly");
}

static void test_wraparound_with_extreme_loss(knet_handle_t knet_h[], int datafd, int8_t channel, int logfd)
{
	log_test(logfd, "=== Test 7: Wraparound with extreme packet loss ===");

	/*
	 * Test wraparound boundary with massive packet loss
	 * Start at 60000
	 * Jump to 100 (wraps around + huge gap)
	 * Gap = (65535 - 60000) + 100 + 1 = 5636 packets (> KNET_CBUFFER_SIZE)
	 */

	FAIL_ON_ERR(send_fragmented_packet(knet_h[1], 60000, 1, 1, logfd)); /* complete */
	FAIL_ON_ERR(send_fragmented_packet(knet_h[1], 60001, 1, 1, logfd)); /* complete */

	/* Massive loss + wraparound */
	FAIL_ON_ERR(send_fragmented_packet(knet_h[1], 100, 1, 1, logfd));   /* complete after wrap + huge gap */
	FAIL_ON_ERR(send_fragmented_packet(knet_h[1], 101, 1, 1, logfd));   /* complete */
	FAIL_ON_ERR(send_fragmented_packet(knet_h[1], 102, 1, 0, logfd));   /* incomplete */
	FAIL_ON_ERR(send_fragmented_packet(knet_h[1], 103, 1, 1, logfd));   /* complete */

	/* Should receive: 60000, 60001, 100, 101, 103 = 5 packets */
	FAIL_ON_ERR_ONLY(receive_and_verify_count(knet_h[1], 5, datafd, channel, logfd, "Test 7"));

	log_test(logfd, "PASS: Wraparound with extreme loss handled correctly");
}

static void test_wraparound_stress(knet_handle_t knet_h[], int datafd, int8_t channel, int logfd)
{
	int seq;
	int received_count;
	int sent_seqs[32] = {0}; /* Track which sequences we've sent (bit array) */
	int expected_count = 0;

	log_test(logfd, "=== Test 8: Wraparound stress (multiple cycles) ===");

	/*
	 * Rapidly cycle through wraparound boundary multiple times
	 * with different packet loss patterns to stress the wraparound logic.
	 * Second cycle uses different filter, sending some duplicates (rejected)
	 * and some new sequence numbers (delivered).
	 */

	/* First cycle: send packets where (seq % 3) != 0 */
	for (seq = 65530; seq <= 65535; seq++) {
		if ((seq % 3) != 0) {
			FAIL_ON_ERR(send_fragmented_packet(knet_h[1], (seq_num_t)seq, 1, 1, logfd));
			sent_seqs[seq - 65530] = 1;
		}
	}

	for (seq = 0; seq <= 10; seq++) {
		if ((seq % 3) != 0) {
			FAIL_ON_ERR(send_fragmented_packet(knet_h[1], (seq_num_t)seq, 1, 1, logfd));
			sent_seqs[6 + seq] = 1;
		}
	}

	/* Second cycle: send packets where (seq % 3) != 1 */
	/* Some will be duplicates (already sent), some will be new */
	for (seq = 65530; seq <= 65535; seq++) {
		if ((seq % 3) != 1) {
			FAIL_ON_ERR(send_fragmented_packet(knet_h[1], (seq_num_t)seq, 1, 1, logfd));
			sent_seqs[seq - 65530] = 1;
		}
	}

	for (seq = 0; seq <= 10; seq++) {
		if ((seq % 3) != 1) {
			FAIL_ON_ERR(send_fragmented_packet(knet_h[1], (seq_num_t)seq, 1, 1, logfd));
			sent_seqs[6 + seq] = 1;
		}
	}

	/* Count unique sequences sent */
	for (seq = 0; seq < 17; seq++) {
		if (sent_seqs[seq]) {
			expected_count++;
		}
	}

	FAIL_ON_ERR_ONLY(received_count = receive_and_verify_count(knet_h[1], expected_count, datafd, channel, logfd, "Test 8"));

	log_test(logfd, "Wraparound stress: received %d packets (expected %d)",
		 received_count, expected_count);
	log_test(logfd, "PASS: Wraparound stress completed");
}

static void test_wraparound_fragment_corruption(knet_handle_t knet_h[], int datafd, int8_t channel, int logfd)
{
	char payload_a[100];
	char payload_b[100];
	seq_num_t test_seq = 5000;
	int i;

	log_test(logfd, "=== Test 9: Fragment corruption across wraparound ===");

	/*
	 * This test verifies protection against a historical bug where:
	 * 1. Sender sends buffer A in 2 fragments (seq 5000), only frag1 arrives
	 * 2. Defrag buffer for 5000 contains: [frag1=A, frag2=empty]
	 * 3. Sequence numbers continue and wrap around
	 * 4. Sender sends buffer B in 2 fragments (seq 5000 again), only frag2 arrives
	 * 5. Without proper clearing, defrag buffer would become: [frag1=A, frag2=B]
	 * 6. This creates data corruption by mixing fragments from different transmissions
	 *
	 * The fix ensures old defrag buffers are invalidated when sequence numbers
	 * wrap around and reuse the same sequence number.
	 */

	memset(payload_a, 'A', sizeof(payload_a));
	memset(payload_b, 'B', sizeof(payload_b));

	log_test(logfd, "Step 1: Send seq %u with fragment 1 only (filled with 'A')", test_seq);
	FAIL_ON_ERR(inject_packet(knet_h[1], KNET_HEADER_TYPE_DATA, 1, 0, 0, 2, 1, test_seq,
				  0, payload_a, sizeof(payload_a)));

	log_test(logfd, "Step 2: Advance through wraparound by sending complete packets");
	/*
	 * Send enough packets to advance sequence numbers through wraparound
	 * We need to go from 5000 → 65535 → 0 → 4999 → 5000
	 * That's approximately 65536 packets
	 * Send packets at intervals to trigger buffer reclamation without overwhelming
	 * We'll send complete packets at key points to verify system stability
	 */

	/* Send some packets to advance past test_seq */
	for (i = 0; i < 10; i++) {
		seq_num_t seq = test_seq + 1000 + (i * 1000);
		FAIL_ON_ERR(send_fragmented_packet(knet_h[1], seq, 1, 1, logfd));
	}

	/* Should receive 10 complete packets */
	log_test(logfd, "Draining 10 complete packets from advancement phase");
	FAIL_ON_ERR_ONLY(receive_and_verify_count(knet_h[1], 10, datafd, channel, logfd, "Test 9 - advancement 1"));

	/* Send packets near wraparound boundary */
	FAIL_ON_ERR(send_fragmented_packet(knet_h[1], 65530, 1, 1, logfd));
	FAIL_ON_ERR(send_fragmented_packet(knet_h[1], 65534, 1, 1, logfd));
	FAIL_ON_ERR(send_fragmented_packet(knet_h[1], 65535, 1, 1, logfd));

	log_test(logfd, "Draining 3 packets from wraparound boundary");
	FAIL_ON_ERR_ONLY(receive_and_verify_count(knet_h[1], 3, datafd, channel, logfd, "Test 9 - wraparound"));

	/* Send packets after wraparound */
	FAIL_ON_ERR(send_fragmented_packet(knet_h[1], 0, 1, 1, logfd));
	FAIL_ON_ERR(send_fragmented_packet(knet_h[1], 1, 1, 1, logfd));
	FAIL_ON_ERR(send_fragmented_packet(knet_h[1], 100, 1, 1, logfd));
	FAIL_ON_ERR(send_fragmented_packet(knet_h[1], 1000, 1, 1, logfd));

	log_test(logfd, "Draining 4 packets after wraparound");
	FAIL_ON_ERR_ONLY(receive_and_verify_count(knet_h[1], 4, datafd, channel, logfd, "Test 9 - post-wrap"));

	/* Continue advancing toward test_seq again */
	for (i = 0; i < 5; i++) {
		seq_num_t seq = 2000 + (i * 500);
		FAIL_ON_ERR(send_fragmented_packet(knet_h[1], seq, 1, 1, logfd));
	}

	log_test(logfd, "Draining 5 complete packets from final advancement");
	FAIL_ON_ERR_ONLY(receive_and_verify_count(knet_h[1], 5, datafd, channel, logfd, "Test 9 - advancement 2"));

	log_test(logfd, "Step 3: Send seq %u again with fragment 2 only (filled with 'B')", test_seq);
	FAIL_ON_ERR(inject_packet(knet_h[1], KNET_HEADER_TYPE_DATA, 1, 0, 0, 2, 2, test_seq,
				  0, payload_b, sizeof(payload_b)));

	log_test(logfd, "Step 4: Verify no packet is delivered (incomplete fragments)");
	/*
	 * The critical check: we should NOT receive a packet for seq 5000
	 * because we only have:
	 * - Fragment 1 from the first transmission (before wraparound) - should be invalidated
	 * - Fragment 2 from the second transmission (after wraparound)
	 *
	 * These fragments are from different packet transmissions and should NOT
	 * be combined into a complete packet.
	 *
	 * If we DO receive a packet here, it indicates the bug is present:
	 * the old fragment 1 was not properly invalidated and got mixed with
	 * the new fragment 2.
	 */

	if (wait_for_packet(knet_h[1], 2, datafd, logfd) == 0) {
		char recvbuf[KNET_MAX_PACKET_SIZE];
		ssize_t len;

		len = knet_recv(knet_h[1], recvbuf, sizeof(recvbuf), channel);
		if (len > 0) {
			log_test(logfd, "ERROR: Received packet for seq %u (size %zd) - fragment corruption bug detected!",
				 test_seq, len);
			log_test(logfd, "This indicates fragments from different transmissions were incorrectly mixed");
			TEST_EXIT_CLEAN(FAIL);
		}
	}

	log_test(logfd, "PASS: No corrupted packet delivered - fragments correctly isolated by wraparound");
}

/*
 * Test 10: Defragmentation buffer reclamation window calculation
 *
 * This test verifies that _reclaim_old_defrag_bufs() correctly reclaims
 * defrag buffers that fall outside the current sequence number window.
 *
 * Tests the fix in commit 03473bb4 which changed reclamation logic to use
 * seq_num instead of dst_seq_num for window calculation.
 */
static void test_defrag_buffer_reclamation_window(knet_handle_t *knet_h, int datafd,
						   int8_t channel, int logfd)
{
	struct knet_host *host;
	int i;
	seq_num_t test_seqs[] = {100, 105, 110, 115, 120};
	int num_test_seqs = sizeof(test_seqs) / sizeof(test_seqs[0]);
	int buffers_found_before[5] = {0};
	int buffers_found_after[5] = {0};

	log_test(logfd, "=== Test 10: Defrag buffer reclamation window calculation ===");

	/* Get access to host internals */
	host = knet_h[1]->host_index[1];
	if (!host) {
		log_test(logfd, "ERROR: Could not access host structure");
		TEST_EXIT_CLEAN(FAIL);
	}

	log_test(logfd, "        Window size = allocated_defrag_bufs (%u entries)",
		 host->allocated_defrag_bufs);

	log_test(logfd, "Step 1: Create incomplete fragments at seq_nums: 100, 105, 110, 115, 120");
	log_test(logfd, "        Each fragment will create a defrag buffer");

	/* Send fragment 1 only (no fragment 2) to create incomplete defrag buffers */
	for (i = 0; i < num_test_seqs; i++) {
		if (send_fragmented_packet(knet_h[1], test_seqs[i], 1, 0, logfd) < 0) {
			log_test(logfd, "ERROR: Failed to send fragment for seq %u", test_seqs[i]);
			TEST_EXIT_CLEAN(FAIL);
		}
	}

	test_sleep(logfd, 1);

	log_test(logfd, "Step 2: Verify all 5 defrag buffers were created");

	/* Scan defrag_bufs array to find our buffers */
	for (i = 0; i < host->allocated_defrag_bufs; i++) {
		if (host->defrag_bufs[i].in_use) {
			int j;
			for (j = 0; j < num_test_seqs; j++) {
				if (host->defrag_bufs[i].pckt_seq == test_seqs[j]) {
					buffers_found_before[j] = 1;
					log_test(logfd, "        Found buffer for seq %u at index %d",
						 test_seqs[j], i);
					break;
				}
			}
		}
	}

	/* Verify all expected buffers exist */
	for (i = 0; i < num_test_seqs; i++) {
		if (!buffers_found_before[i]) {
			log_test(logfd, "ERROR: Buffer for seq %u not found before reclamation",
				 test_seqs[i]);
			TEST_EXIT_CLEAN(FAIL);
		}
	}

	log_test(logfd, "        All 5 defrag buffers confirmed");

	log_test(logfd, "Step 3: Advance sequence window to seq 150");
	log_test(logfd, "        With allocated_defrag_bufs=%u, window calculation:",
		 host->allocated_defrag_bufs);
	log_test(logfd, "        head = seq_num + 1 = 151");
	log_test(logfd, "        tail = seq_num - (allocated + 1) = 150 - %u = %u",
		 host->allocated_defrag_bufs + 1, 150 - (host->allocated_defrag_bufs + 1));
	log_test(logfd, "        Valid window: [%u, 150]",
		 150 - host->allocated_defrag_bufs);
	log_test(logfd, "        Expected: 100, 105, 110, 115 reclaimed (< %u, outside window)",
		 150 - host->allocated_defrag_bufs);
	log_test(logfd, "        Expected: 120 preserved (>= %u, within window)",
		 150 - host->allocated_defrag_bufs);

	/* Send complete packet at seq 150 to advance window and trigger reclamation */
	if (send_fragmented_packet(knet_h[1], 150, 1, 1, logfd) < 0) {
		log_test(logfd, "ERROR: Failed to send advancement packet seq 150");
		TEST_EXIT_CLEAN(FAIL);
	}

	/* Drain the received packet */
	log_test(logfd, "        Draining advancement packet");
	FAIL_ON_ERR_ONLY(receive_and_verify_count(knet_h[1], 1, datafd, channel, logfd,
						   "Test 10 - window advancement"));

	log_test(logfd, "Step 4: Verify buffer reclamation");

	test_sleep(logfd, 1);  /* Give RX thread time to process reclamation */

	/* Scan defrag_bufs array again to see what remains */
	for (i = 0; i < host->allocated_defrag_bufs; i++) {
		if (host->defrag_bufs[i].in_use) {
			int j;
			for (j = 0; j < num_test_seqs; j++) {
				if (host->defrag_bufs[i].pckt_seq == test_seqs[j]) {
					buffers_found_after[j] = 1;
					log_test(logfd, "        Buffer for seq %u still exists at index %d",
						 test_seqs[j], i);
					break;
				}
			}
		}
	}

	/* Verify reclamation results based on window calculation */
	seq_num_t tail = 150 - (host->allocated_defrag_bufs + 1);

	/* Check that buffers outside window were reclaimed */
	for (i = 0; i < 4; i++) {  /* seq 100, 105, 110, 115 */
		if (buffers_found_after[i]) {
			log_test(logfd, "ERROR: Buffer for seq %u should have been reclaimed (< %u, outside window)",
				 test_seqs[i], tail + 1);
			TEST_EXIT_CLEAN(FAIL);
		}
	}

	/* Check that buffer within window still exists */
	if (!buffers_found_after[4]) { /* seq 120 */
		log_test(logfd, "ERROR: Buffer for seq 120 should still exist (>= %u, within window)",
			 tail + 1);
		TEST_EXIT_CLEAN(FAIL);
	}

	log_test(logfd, "PASS: Buffer reclamation window calculation works correctly");
	log_test(logfd, "      Buffers outside window [%u, 150] were reclaimed", tail + 1);
	log_test(logfd, "      Buffer within window was preserved");
}

/*
 * Test 11: Circular buffer clearing at boundaries
 *
 * The _seq_num_lookup function clears ranges in circular_buffer and circular_buffer_defrag
 * when advancing the sequence window. The clearing logic has two branches:
 *
 * 1. tail > head (wraparound case): Clear [tail..SIZE-1] and [0..head]
 * 2. tail <= head (normal case): Clear [tail..head]
 *
 * where:
 *   tail = (dst_seq_num + 1) % KNET_CBUFFER_SIZE
 *   head = seq_num % KNET_CBUFFER_SIZE
 *
 * This test verifies both branches execute correctly and clear the expected ranges.
 */
static void test_circular_buffer_clearing(knet_handle_t *knet_h, int datafd,
					  int8_t channel, int logfd)
{
	struct knet_host *host;
	int i;
	seq_num_t test_seq;

	log_test(logfd, "=== Test 11: Circular buffer clearing at boundaries ===");

	/* Get access to host internals */
	host = knet_h[1]->host_index[1];
	if (!host) {
		log_test(logfd, "ERROR: Could not access host structure");
		TEST_EXIT_CLEAN(FAIL);
	}

	log_test(logfd, "        KNET_CBUFFER_SIZE = %d", KNET_CBUFFER_SIZE);

	/*
	 * Test Case 1: tail > head (wraparound clearing)
	 *
	 * Setup:
	 *   - Send packet at seq 3000 to set dst_seq_num = 3000
	 *   - Then jump to seq 10
	 *   - This creates: tail = 3001 % 4096 = 3001, head = 10 % 4096 = 10
	 *   - Since tail (3001) > head (10), should clear [3001..4095] and [0..10]
	 */
	log_test(logfd, "Test case 1: tail > head (wraparound clearing)");

	test_seq = 3000;
	log_test(logfd, "        Step 1: Send packet at seq %u to establish dst_seq_num", test_seq);
	if (send_fragmented_packet(knet_h[1], test_seq, 1, 1, logfd) < 0) {
		log_test(logfd, "ERROR: Failed to send packet seq %u", test_seq);
		TEST_EXIT_CLEAN(FAIL);
	}
	FAIL_ON_ERR_ONLY(receive_and_verify_count(knet_h[1], 1, datafd, channel, logfd,
						   "Test 11 case 1 setup"));

	/* Mark a known pattern in the circular buffer before the jump */
	log_test(logfd, "        Step 2: Mark circular buffer entries that should be cleared");
	for (i = 3001; i < KNET_CBUFFER_SIZE; i++) {
		host->circular_buffer[i] = 'X';
		host->circular_buffer_defrag[i] = 'X';
	}
	for (i = 0; i <= 10; i++) {
		host->circular_buffer[i] = 'X';
		host->circular_buffer_defrag[i] = 'X';
	}

	test_seq = 10;
	log_test(logfd, "        Step 3: Jump to seq %u", test_seq);
	log_test(logfd, "                tail = (3000 + 1) %% %d = 3001", KNET_CBUFFER_SIZE);
	log_test(logfd, "                head = %u %% %d = %u", test_seq, KNET_CBUFFER_SIZE, test_seq % KNET_CBUFFER_SIZE);
	log_test(logfd, "                tail > head, so should clear [3001..4095] and [0..10]");

	if (send_fragmented_packet(knet_h[1], test_seq, 1, 1, logfd) < 0) {
		log_test(logfd, "ERROR: Failed to send packet seq %u", test_seq);
		TEST_EXIT_CLEAN(FAIL);
	}
	FAIL_ON_ERR_ONLY(receive_and_verify_count(knet_h[1], 1, datafd, channel, logfd,
						   "Test 11 case 1 jump"));

	test_sleep(logfd, 1);  /* Give RX thread time to process */

	log_test(logfd, "        Step 4: Verify circular buffer ranges were cleared");
	/* Check [3001..4095] was cleared */
	for (i = 3001; i < KNET_CBUFFER_SIZE; i++) {
		if (host->circular_buffer[i] != 0 || host->circular_buffer_defrag[i] != 0) {
			log_test(logfd, "ERROR: circular_buffer[%d] not cleared (tail > head case)", i);
			log_test(logfd, "       circular_buffer[%d] = 0x%02x (expected 0)",
				 i, (unsigned char)host->circular_buffer[i]);
			log_test(logfd, "       circular_buffer_defrag[%d] = 0x%02x (expected 0)",
				 i, (unsigned char)host->circular_buffer_defrag[i]);
			TEST_EXIT_CLEAN(FAIL);
		}
	}
	/* Check [0..9] was cleared (exclude position 10 which holds current packet) */
	for (i = 0; i < 10; i++) {
		if (host->circular_buffer[i] != 0 || host->circular_buffer_defrag[i] != 0) {
			log_test(logfd, "ERROR: circular_buffer[%d] not cleared (tail > head case)", i);
			log_test(logfd, "       circular_buffer[%d] = 0x%02x (expected 0)",
				 i, (unsigned char)host->circular_buffer[i]);
			log_test(logfd, "       circular_buffer_defrag[%d] = 0x%02x (expected 0)",
				 i, (unsigned char)host->circular_buffer_defrag[i]);
			TEST_EXIT_CLEAN(FAIL);
		}
	}
	log_test(logfd, "        PASS: Ranges [3001..4095] and [0..9] correctly cleared");

	/*
	 * Test Case 2: tail <= head (normal clearing)
	 *
	 * For tail <= head after a large gap, seq_num % 4096 must equal 4095:
	 *   - Jump to seq 8191 (8191 % 4096 = 4095)
	 *   - tail = (8191 + 1) % 4096 = 0
	 *   - head = 8191 % 4096 = 4095
	 *   - tail (0) <= head (4095), so should clear [0..4095]
	 */
	log_test(logfd, "Test case 2: tail <= head (normal clearing)");

	/* Mark circular buffer */
	log_test(logfd, "        Step 1: Mark circular buffer with pattern");
	for (i = 0; i < KNET_CBUFFER_SIZE; i++) {
		host->circular_buffer[i] = 'Y';
		host->circular_buffer_defrag[i] = 'Y';
	}

	test_seq = 8191;  /* 8191 % 4096 = 4095 */
	log_test(logfd, "        Step 2: Jump to seq %u (%u %% %d = 4095)",
		 test_seq, test_seq, KNET_CBUFFER_SIZE);
	log_test(logfd, "                tail = (%u + 1) %% %d = 0", test_seq, KNET_CBUFFER_SIZE);
	log_test(logfd, "                head = %u %% %d = 4095", test_seq, KNET_CBUFFER_SIZE);
	log_test(logfd, "                tail <= head, so should clear [0..4095]");

	if (send_fragmented_packet(knet_h[1], test_seq, 1, 1, logfd) < 0) {
		log_test(logfd, "ERROR: Failed to send packet seq %u", test_seq);
		TEST_EXIT_CLEAN(FAIL);
	}
	FAIL_ON_ERR_ONLY(receive_and_verify_count(knet_h[1], 1, datafd, channel, logfd,
						   "Test 11 case 2"));

	test_sleep(logfd, 1);

	log_test(logfd, "        Step 3: Verify circular buffer was cleared");
	/* All positions except 4095 (current packet) should be cleared */
	for (i = 0; i < KNET_CBUFFER_SIZE - 1; i++) {
		if (host->circular_buffer[i] != 0 || host->circular_buffer_defrag[i] != 0) {
			log_test(logfd, "ERROR: circular_buffer[%d] not cleared (tail <= head case)", i);
			log_test(logfd, "       circular_buffer[%d] = 0x%02x (expected 0)",
				 i, (unsigned char)host->circular_buffer[i]);
			TEST_EXIT_CLEAN(FAIL);
		}
	}
	log_test(logfd, "        PASS: Range [0..4094] correctly cleared");

	log_test(logfd, "PASS: Circular buffer clearing verified for both tail>head and tail<=head");
}

static void test_seq_wraparound_stress(void)
{
	knet_handle_t knet_h1, knet_h[2] = {0};
	int logfd;
	int datafd = 0;
	int8_t channel = -1;
	struct sockaddr_storage lo;

	logfd = start_logging(stdout);

	knet_h1 = _ts_knet_handle_start(logfd, KNET_LOG_DEBUG, knet_h);

	log_test(logfd, "Setting up sequence number wraparound stress test");

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

	/* Run all test scenarios */
	test_normal_with_loss(knet_h, datafd, channel, logfd);
	test_sleep(logfd, 1);

	test_wraparound_with_loss(knet_h, datafd, channel, logfd);
	test_sleep(logfd, 1);

	test_large_jump_with_loss(knet_h, datafd, channel, logfd);
	test_sleep(logfd, 1);

	test_out_of_order(knet_h, datafd, channel, logfd);
	test_sleep(logfd, 1);

	test_out_of_order_packets(knet_h, datafd, channel, logfd);
	test_sleep(logfd, 1);

	test_extreme_loss_beyond_window(knet_h, datafd, channel, logfd);
	test_sleep(logfd, 1);

	test_wraparound_with_extreme_loss(knet_h, datafd, channel, logfd);
	test_sleep(logfd, 1);

	test_wraparound_stress(knet_h, datafd, channel, logfd);
	test_sleep(logfd, 1);

	test_wraparound_fragment_corruption(knet_h, datafd, channel, logfd);
	test_sleep(logfd, 1);

	test_defrag_buffer_reclamation_window(knet_h, datafd, channel, logfd);
	test_sleep(logfd, 1);

	test_circular_buffer_clearing(knet_h, datafd, channel, logfd);

	log_test(logfd, "=== All sequence wraparound stress tests PASSED ===");

	TEST_EXIT_CLEAN(PASS);
}

int main(int argc, char *argv[])
{
	printf("[TEST] %s: Sequence number wraparound stress test\n", TEST_NAME);

	test_seq_wraparound_stress();

	return PASS;
}
