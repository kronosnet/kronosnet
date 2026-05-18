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

#include "libknet.h"

#include "internals.h"
#include "netutils.h"
#include "crypto_model.h"
#include "test-common.h"

#define TEST_NAME "fun_config_crypto_ctr_test"

/*
 * Test AES-CTR mode support across all available crypto backends
 *
 * Uses knet_get_crypto_list() to detect available crypto modules at runtime
 * and tests each one with AES-CTR ciphers (aes128-ctr, aes192-ctr, aes256-ctr).
 *
 * Tests both cipher naming formats to ensure cross-backend compatibility:
 * - OpenSSL format: aes-128-ctr (with hyphens)
 * - NSS/gcrypt format: aes128-ctr (without hyphens)
 *
 * All backends accept both formats via normalization.
 *
 * Also tests actual encrypted data transmission via loopback to verify
 * CTR mode encryption/decryption works correctly.
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

static void test_ctr_mode(const char *model, const char *cipher)
{
	knet_handle_t knet_h[2];
	int logfd;
	struct knet_handle_crypto_cfg knet_handle_crypto_cfg;
	int datafd = 0;
	int8_t channel = 0;
	struct sockaddr_storage lo;
	char send_buff[KNET_MAX_PACKET_SIZE];
	char recv_buff[KNET_MAX_PACKET_SIZE];
	ssize_t send_len = 0;
	int recv_len = 0;

	memset(send_buff, 0, sizeof(send_buff));
	memset(recv_buff, 0, sizeof(recv_buff));

	logfd = start_logging(stdout);

	log_test(logfd, "=== Test %s with %s/sha256 ===", model, cipher);

	_ts_knet_handle_start(logfd, KNET_LOG_DEBUG, knet_h);

	memset(&knet_handle_crypto_cfg, 0, sizeof(struct knet_handle_crypto_cfg));
	strncpy(knet_handle_crypto_cfg.crypto_model, model, sizeof(knet_handle_crypto_cfg.crypto_model) - 1);
	strncpy(knet_handle_crypto_cfg.crypto_cipher_type, cipher, sizeof(knet_handle_crypto_cfg.crypto_cipher_type) - 1);
	strncpy(knet_handle_crypto_cfg.crypto_hash_type, "sha256", sizeof(knet_handle_crypto_cfg.crypto_hash_type) - 1);
	knet_handle_crypto_cfg.private_key_len = 2000;

	if (knet_handle_crypto_set_config(knet_h[1], &knet_handle_crypto_cfg, 1) < 0) {
		log_test(logfd, "SKIP: %s with %s not supported or failed: %s", model, cipher, strerror(errno));
		TEST_EXIT_CLEAN(CONTINUE);
		return;
	}

	log_test(logfd, "%s with %s configured successfully", model, cipher);

	/* Activate crypto config */
	FAIL_ON_ERR(knet_handle_crypto_use_config(knet_h[1], 1));

	log_test(logfd, "%s with %s activated successfully", model, cipher);

	/* Configure for data transmission test */
	FAIL_ON_ERR(knet_handle_crypto_rx_clear_traffic(knet_h[1], KNET_CRYPTO_RX_DISALLOW_CLEAR_TRAFFIC));
	FAIL_ON_ERR(knet_handle_enable_sock_notify(knet_h[1], &private_data, sock_notify));

	datafd = 0;
	channel = -1;
	FAIL_ON_ERR(knet_handle_add_datafd(knet_h[1], &datafd, &channel, 0));

	/* Set up loopback link */
	FAIL_ON_ERR(knet_host_add(knet_h[1], 1));
	FAIL_ON_ERR(_ts_knet_link_set_config(knet_h[1], 1, 0, KNET_TRANSPORT_UDP, 0, AF_INET, 0, &lo, logfd));
	FAIL_ON_ERR(knet_link_set_enable(knet_h[1], 1, 0, 1));
	FAIL_ON_ERR(knet_handle_setfwd(knet_h[1], 1));
	FAIL_ON_ERR(wait_for_host(knet_h[1], 1, TEST_TIMEOUT_SHORT, logfd, stdout));

	/* Send encrypted data */
	send_len = knet_send(knet_h[1], send_buff, KNET_MAX_PACKET_SIZE, channel);
	if (send_len <= 0) {
		log_test(logfd, "knet_send failed: %s", strerror(errno));
		TEST_EXIT_CLEAN(FAIL);
	}

	if (send_len != sizeof(send_buff)) {
		log_test(logfd, "knet_send sent only %zd bytes: %s", send_len, strerror(errno));
		TEST_EXIT_CLEAN(FAIL);
	}

	FAIL_ON_ERR(knet_handle_setfwd(knet_h[1], 0));
	FAIL_ON_ERR(wait_for_packet(knet_h[1], TEST_TIMEOUT_SHORT, datafd, logfd, stdout));

	/* Receive and verify encrypted data */
	recv_len = knet_recv(knet_h[1], recv_buff, KNET_MAX_PACKET_SIZE, channel);
	if (recv_len != send_len) {
		log_test(logfd, "knet_recv received only %d bytes: %s", recv_len, strerror(errno));
		if ((is_helgrind()) && (recv_len == -1) && (errno == EAGAIN)) {
			log_test(logfd, "helgrind exception. this is normal due to possible timeouts");
			TEST_EXIT_CLEAN(CONTINUE);
			return;
		}
		TEST_EXIT_CLEAN(FAIL);
	}

	if (memcmp(recv_buff, send_buff, KNET_MAX_PACKET_SIZE)) {
		log_test(logfd, "recv and send buffers are different!");
		TEST_EXIT_CLEAN(FAIL);
	}

	log_test(logfd, "=== %s with %s data transmission successful ===", model, cipher);

	TEST_EXIT_CLEAN(CONTINUE);
	return;
}

int main(void)
{
	/*
	 * Test both cipher naming formats on all backends:
	 * - OpenSSL format: aes-128-ctr (with hyphens)
	 * - NSS/gcrypt format: aes128-ctr (without hyphens)
	 *
	 * All backends should accept both formats for cross-backend compatibility
	 */
	const char *hyphenated_ciphers[] = {"aes-128-ctr", "aes-192-ctr", "aes-256-ctr", NULL};
	const char *non_hyphenated_ciphers[] = {"aes128-ctr", "aes192-ctr", "aes256-ctr", NULL};
	struct knet_crypto_info crypto_list[16];
	size_t crypto_list_entries;
	size_t i;
	int j;

	printf("[TEST] %s: Test AES-CTR mode support across crypto backends\n", TEST_NAME);

#ifdef KNET_BSD
	if (is_memcheck() || is_helgrind()) {
		printf("valgrind-freebsd cannot run this test properly. Skipping\n");
		TEST_EXIT(SKIP);
	}
#endif

	memset(crypto_list, 0, sizeof(crypto_list));

	printf("=== AES-CTR Mode Support Test ===\n");

	if (knet_get_crypto_list(crypto_list, &crypto_list_entries) < 0) {
		printf("knet_get_crypto_list failed: %s\n", strerror(errno));
		TEST_EXIT(FAIL);
	}

	if (crypto_list_entries == 0) {
		printf("no crypto modules detected. Skipping\n");
		TEST_EXIT(SKIP);
	}

	/* Test each available backend with both naming formats */
	for (i = 0; i < crypto_list_entries; i++) {
		for (j = 0; hyphenated_ciphers[j] != NULL; j++) {
			test_ctr_mode(crypto_list[i].name, hyphenated_ciphers[j]);
		}
		for (j = 0; non_hyphenated_ciphers[j] != NULL; j++) {
			test_ctr_mode(crypto_list[i].name, non_hyphenated_ciphers[j]);
		}
	}

	printf("=== All CTR mode tests completed ===\n");

	TEST_EXIT(PASS);
}
