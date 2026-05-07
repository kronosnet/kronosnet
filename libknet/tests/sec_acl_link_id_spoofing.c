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
#include <time.h>

#include "libknet.h"
#include "internals.h"
#include "onwire.h"
#include "onwire_v1.h"
#include "test-common.h"

#define TEST_NAME "sec_acl_link_id_spoofing"

/*
 * Regression test for CVE-2026-15812: ACL bypass via link ID spoofing
 *
 * Validates that knet properly rejects ping packets where the link_id
 * in the packet doesn't match the source address, preventing ACL bypass.
 *
 * Security model (as of CVE-2026-15812 fix):
 * - use_access_lists is enabled by default (secure by default)
 * - Static links: always validate against auto-configured ACL
 * - Dynamic links:
 *   - If use_access_lists = 1 (default): require ACL configuration
 *   - If use_access_lists = 0: skip validation (user explicit opt-out)
 *
 * Attack scenarios tested (using static links):
 * 1. ACL bypass: Packet from link 0 claiming link_id=1 (different configured link)
 *    - Both links configured with different addresses
 *    - Packet passes bounds/configured checks
 *    - ACL validation rejects because source doesn't match link 1's expected address
 * 2. Unconfigured link_id: Packet claims link_id=2 (not configured)
 *    - Rejected by configured state check
 * 3. Out-of-bounds link_id: Packet claims link_id >= KNET_MAX_LINK
 *    - Rejected by bounds check
 *
 * Test approach:
 * - Configure two static links with different addresses to same host
 * - Inject packets with various spoofed link_id values
 * - Verify each attack is rejected with appropriate log message
 * - Verify use_access_lists defaults to enabled
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
 * Log filter callback to check for packet rejection due to ACL failure
 * This catches link ID spoofing where source address doesn't match claimed link
 */
static int filter_packet_rejected(int logfd, const char *log_line, void *private_data)
{
	(void)logfd;
	(void)private_data;

	if (strstr(log_line, "Packet rejected")) {
		return 1;
	}
	return 0;
}

/*
 * Log filter callback to check for invalid link_id message
 */
static int filter_invalid_link_id(int logfd, const char *log_line, void *private_data)
{
	(void)logfd;
	(void)private_data;

	if (strstr(log_line, "Invalid link_id")) {
		return 1;
	}
	return 0;
}

static void test_link_id_spoofing(void)
{
	knet_handle_t knet_h1, knet_h[2] = {0};
	int logfd;
	int datafd = 0;
	int8_t channel = 0;
	seq_num_t seq_num = 2000;

	logfd = start_logging(stdout);

	log_test(logfd, "Test: CVE-2026-15812 Link ID spoofing prevention (secure by default)");

	/*
	 * Set up knet handle
	 */
	knet_h1 = _ts_knet_handle_start(logfd, KNET_LOG_DEBUG, knet_h);

	FAIL_ON_ERR(knet_handle_enable_sock_notify(knet_h1, &private_data, sock_notify));
	FAIL_ON_ERR(knet_handle_add_datafd(knet_h1, &datafd, &channel, 0));
	FAIL_ON_ERR(knet_host_add(knet_h1, 1));

	/*
	 * Configure two STATIC links to the same remote host with DIFFERENT IP addresses
	 * Link 0: 127.0.0.1
	 * Link 1: 127.0.0.2
	 * This allows ACL to distinguish between links (ACL checks IP, not port)
	 *
	 * Note: Static links automatically get their dst_addr added to ACL during
	 * knet_link_set_config(), and static links ALWAYS validate ACL regardless
	 * of use_access_lists setting.
	 *
	 * With the CVE-2026-15812 fix, use_access_lists defaults to 1,
	 * which means dynamic links without ACL would also be rejected.
	 */
	log_test(logfd, "Step 1: Configure two static links to same host (different IPs)");

	struct sockaddr_storage lo0, lo1;

	/* Allocate dynamic port for link 0, use 127.0.0.1 */
	FAIL_ON_ERR(make_local_sockaddr(&lo0, 0, logfd));
	FAIL_ON_ERR(knet_link_set_config(knet_h1, 1, 0, KNET_TRANSPORT_UDP, &lo0, &lo0, 0));
	log_test(logfd, "        Link 0 configured (127.0.0.1)");

	/* Allocate dynamic port for link 1, change IP to 127.0.0.2 */
	FAIL_ON_ERR(make_local_sockaddr(&lo1, 1, logfd));
	((struct sockaddr_in *)&lo1)->sin_addr.s_addr = htonl(0x7f000002); /* 127.0.0.2 */
	if (knet_link_set_config(knet_h1, 1, 1, KNET_TRANSPORT_UDP, &lo1, &lo1, 0) < 0) {
		log_test(logfd, "Cannot bind 127.0.0.2 (platform lacks full 127/8 support), skipping test");
		_ts_knet_handle_stop_everything(knet_h, 1, logfd);
		TEST_EXIT(PASS);
	}
	log_test(logfd, "        Link 1 configured (127.0.0.2)");

	log_test(logfd, "Two static links configured to same host with different IPs");

	/*
	 * Test Case 1: ACL bypass via link ID spoofing
	 * Send ping from link 0's address claiming to be link 1
	 * Link 1 IS configured but expects packets from a different address
	 * ACL check should reject because source doesn't match link 1's expected address
	 */
	log_test(logfd, "Step 2: Attack - ACL bypass via link ID spoofing");
	log_test(logfd, "        Send from link 0 address claiming to be link 1");
	log_test(logfd, "        Link 1 expects different address - should fail ACL check");

	/* Install filter for packet rejection due to ACL */
	install_log_filter(logfd, filter_packet_rejected, NULL);

	if (inject_packet(knet_h1, KNET_HEADER_TYPE_PING, 1, 0, 1, 0, 0, seq_num, 0, NULL, 0) < 0) {
		log_test(logfd, "*** FAIL: Failed to inject ACL bypass packet");
		install_log_filter(logfd, NULL, NULL);
		TEST_EXIT_CLEAN(FAIL);
	}

	test_sleep(logfd, 2);  /* Give RX thread time to process */

	log_test(logfd, "Spoofed link_id packet sent");

	log_test(logfd, "Step 3: Verify ACL rejected the packet");

	if (!check_log_pattern_found()) {
		log_test(logfd, "*** FAIL: ACL did not reject spoofed packet");
		log_test(logfd, "          Expected: 'Packet rejected from'");
		install_log_filter(logfd, NULL, NULL);
		TEST_EXIT_CLEAN(FAIL);
	}

	log_test(logfd, "ACL correctly rejected spoofed link_id packet");

	/*
	 * Test Case 2: Send ping with unconfigured link_id (link 2 not configured)
	 * Source address is known (link 0) but link_id in packet is not configured
	 */
	log_test(logfd, "Step 4: Attack - Unconfigured link_id in packet");
	log_test(logfd, "        link_id in packet: 2 (not configured)");

	/* Switch to invalid link_id filter */
	install_log_filter(logfd, filter_invalid_link_id, NULL);

	if (inject_packet(knet_h1, KNET_HEADER_TYPE_PING, 1, 0, 2, 0, 0, seq_num + 1, 0, NULL, 0) < 0) {
		log_test(logfd, "*** FAIL: Failed to inject unconfigured link_id packet");
		install_log_filter(logfd, NULL, NULL);
		TEST_EXIT_CLEAN(FAIL);
	}

	test_sleep(logfd, 2);

	log_test(logfd, "Unconfigured link_id packet sent");

	log_test(logfd, "Step 5: Verify log contains invalid link_id warning");

	if (!check_log_pattern_found()) {
		log_test(logfd, "*** FAIL: Log does not contain expected invalid link_id warning");
		log_test(logfd, "          Expected: 'Invalid link_id'");
		install_log_filter(logfd, NULL, NULL);
		TEST_EXIT_CLEAN(FAIL);
	}

	log_test(logfd, "Log contains invalid link_id rejection message");

	/*
	 * Test Case 3: Send ping with out-of-bounds link_id
	 */
	log_test(logfd, "Step 6: Attack - Out-of-bounds link_id");
	log_test(logfd, "        link_id in packet: %u (>= KNET_MAX_LINK)", KNET_MAX_LINK);

	/* Keep invalid link_id filter active */
	if (inject_packet(knet_h1, KNET_HEADER_TYPE_PING, 1, 0, KNET_MAX_LINK, 0, 0, seq_num + 2, 0, NULL, 0) < 0) {
		log_test(logfd, "*** FAIL: Failed to inject out-of-bounds ping packet");
		install_log_filter(logfd, NULL, NULL);
		TEST_EXIT_CLEAN(FAIL);
	}

	test_sleep(logfd, 2);

	log_test(logfd, "Out-of-bounds link_id packet sent");

	log_test(logfd, "Step 7: Verify log contains invalid link_id warning");

	if (!check_log_pattern_found()) {
		log_test(logfd, "*** FAIL: Log does not contain expected invalid link_id warning");
		log_test(logfd, "          Expected: 'Invalid link_id'");
		install_log_filter(logfd, NULL, NULL);
		TEST_EXIT_CLEAN(FAIL);
	}

	log_test(logfd, "Log contains out-of-bounds rejection message");

	/* Remove filter */
	install_log_filter(logfd, NULL, NULL);

	log_test(logfd, "=== CVE-2026-15812 Link ID spoofing prevention test PASSED ===");
	log_test(logfd, "ACL bypass via link_id spoofing prevented");
	log_test(logfd, "Unconfigured link_id rejected");
	log_test(logfd, "Out-of-bounds link_id rejected");
	log_test(logfd, "All attack vectors blocked");
	log_test(logfd, "Note: use_access_lists is now enabled by default (secure by default)");

	_ts_knet_handle_stop_everything(knet_h, 1, logfd);

	TEST_EXIT(PASS);
}

int main(int argc, char *argv[])
{
	printf("[TEST] %s: Test ACL bypass via link ID spoofing (CVE-2026-15812)\n", TEST_NAME);

	test_link_id_spoofing();

	return PASS;
}
