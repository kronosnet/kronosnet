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

#if WITH_COMPRESS_ZLIB > 0
#include <zlib.h>
#endif

#include "libknet.h"
#include "internals.h"
#include "onwire.h"
#include "test-common.h"

#define TEST_NAME "int_decompress_bufsize"

/*
 * Test decompression buffer size validation
 *
 * Verifies that packets with decompressed size exceeding KNET_DATABUFSIZE
 * are properly rejected.
 *
 * Test approach:
 * - Create a large buffer (2x KNET_DATABUFSIZE) of compressible data
 * - Compress it using zlib to create a small payload
 * - Inject packet with compression flag set
 * - Verify packet is rejected
 * - Verify log contains "Rejecting packet"
 */

#if WITH_COMPRESS_ZLIB > 0
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

static int filter_rejecting_packet(int logfd, const char *log_line, void *private_data)
{
	(void)logfd;
	(void)private_data;
	if (strstr(log_line, "rejecting packet")) {
		return 1;
	}
	return 0;
}
#endif

static void test_decompress_bufsize(void)
{
#if WITH_COMPRESS_ZLIB > 0
	knet_handle_t knet_h1, knet_h[2] = {0};
	int logfd;
	int datafd = 0;
	int8_t channel = 0;
	struct sockaddr_storage lo;
	unsigned char *large_payload = NULL;
	unsigned char *compressed_payload = NULL;
	size_t large_payload_size;
	uLongf compressed_size;
	uLongf compressed_bound;
	int compress_result;
	seq_num_t seq_num = 1000;

	/*
	 * Create a large payload (2x KNET_DATABUFSIZE)
	 * Use zeros for maximum compression ratio
	 */
	large_payload_size = KNET_DATABUFSIZE * 2;
	large_payload = calloc(1, large_payload_size);
	if (!large_payload) {
		printf("FAIL: Failed to allocate large payload buffer\n");
		TEST_EXIT(FAIL);
	}

	/*
	 * Compress the large payload using zlib
	 */
	compressed_bound = compressBound(large_payload_size);
	compressed_payload = malloc((size_t)compressed_bound);
	if (!compressed_payload) {
		printf("FAIL: Failed to allocate compressed payload buffer\n");
		free(large_payload);
		TEST_EXIT(FAIL);
	}

	compressed_size = compressed_bound;
	compress_result = compress2(compressed_payload, &compressed_size,
				    large_payload, large_payload_size,
				    Z_BEST_COMPRESSION);

	if (compress_result != Z_OK) {
		printf("FAIL: zlib compress2() failed: %d\n", compress_result);
		free(large_payload);
		free(compressed_payload);
		TEST_EXIT(FAIL);
	}

	free(large_payload);

	/*
	 * Set up knet handle
	 */
	logfd = start_logging(stdout);

	knet_h1 = _ts_knet_handle_start(logfd, KNET_LOG_DEBUG, knet_h);

	log_test(logfd, "Setting up decompression buffer size test");

	install_log_filter(logfd, filter_rejecting_packet, NULL);

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

	log_test(logfd, "Step 1: Inject compressed packet with oversized decompression size");
	log_test(logfd, "        Compressed: %zu bytes, Decompresses to: %zu bytes",
		 (size_t)compressed_size, large_payload_size);
	log_test(logfd, "        KNET_DATABUFSIZE: %zu bytes", (size_t)KNET_DATABUFSIZE);

	/*
	 * Inject the compressed packet from host 1 link 0
	 * compress_type = 1 (KNET_COMPRESS_ZLIB)
	 */
	if (inject_packet(knet_h1, KNET_HEADER_TYPE_DATA, 1, 0, 0, 1, 1, seq_num,
			  1, (const char *)compressed_payload, (size_t)compressed_size) < 0) {
		log_test(logfd, "FAIL: Failed to inject compressed packet: %s", strerror(errno));
		free(compressed_payload);
		TEST_EXIT_CLEAN(FAIL);
	}

	test_sleep(logfd, 2);

	log_test(logfd, "Compressed packet injected");

	log_test(logfd, "Step 2: Verify packet was rejected (not delivered to datafd)");

	/*
	 * Try to read from datafd - should get nothing because packet was rejected
	 */
	char dummy[1];
	ssize_t len = recv(datafd, dummy, sizeof(dummy), MSG_DONTWAIT);
	if (len > 0) {
		log_test(logfd, "FAIL: Packet was delivered despite exceeding KNET_DATABUFSIZE");
		log_test(logfd, "      Buffer size validation FAILED");
		free(compressed_payload);
		TEST_EXIT_CLEAN(FAIL);
	}

	log_test(logfd, "No packet delivered to datafd (correctly rejected)");

	log_test(logfd, "Step 3: Verify log contains rejection message");

	if (!check_log_pattern_found()) {
		log_test(logfd, "FAIL: Log does not contain expected warning message");
		log_test(logfd, "      Expected: 'Rejecting packet'");
		free(compressed_payload);
		TEST_EXIT_CLEAN(FAIL);
	}

	log_test(logfd, "Log contains: 'Rejecting packet'");

	log_test(logfd, "=== Decompression buffer size validation test PASSED ===");
	log_test(logfd, "Packet with decompressed size > KNET_DATABUFSIZE was correctly rejected");

	free(compressed_payload);
	TEST_EXIT_CLEAN(PASS);
#else
	printf("[SKIP] %s: zlib compression not available\n", TEST_NAME);
	TEST_EXIT(SKIP);
#endif
}

int main(int argc, char *argv[])
{
	printf("[TEST] %s: Test decompression buffer size validation\n", TEST_NAME);

	test_decompress_bufsize();

	return PASS;
}
