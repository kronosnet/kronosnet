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
	knet_handle_t knet_h1, knet_h[2];
	int logfds[2];
	int res;
	struct knet_handle_crypto_cfg knet_handle_crypto_cfg;
	int datafd = 0;
	int8_t channel = 0;
	struct sockaddr_storage lo;
	char send_buff[KNET_MAX_PACKET_SIZE];
	char recv_buff[KNET_MAX_PACKET_SIZE];
	ssize_t send_len = 0;
	int recv_len = 0;

	printf("Test %s with %s/sha256\n", model, cipher);

	memset(send_buff, 0, sizeof(send_buff));
	memset(recv_buff, 0, sizeof(recv_buff));

	setup_logpipes(logfds);
	knet_h1 = knet_handle_start(logfds, KNET_LOG_DEBUG, knet_h);

	memset(&knet_handle_crypto_cfg, 0, sizeof(struct knet_handle_crypto_cfg));
	strncpy(knet_handle_crypto_cfg.crypto_model, model, sizeof(knet_handle_crypto_cfg.crypto_model) - 1);
	strncpy(knet_handle_crypto_cfg.crypto_cipher_type, cipher, sizeof(knet_handle_crypto_cfg.crypto_cipher_type) - 1);
	strncpy(knet_handle_crypto_cfg.crypto_hash_type, "sha256", sizeof(knet_handle_crypto_cfg.crypto_hash_type) - 1);
	knet_handle_crypto_cfg.private_key_len = 2000;

	if (knet_handle_crypto_set_config(knet_h1, &knet_handle_crypto_cfg, 1) < 0) {
		printf("SKIP: %s with %s not supported or failed: %s\n\n", model, cipher, strerror(errno));
		flush_logs(logfds[0], stdout);
		CLEAN_EXIT(CONTINUE);
	}

	printf("%s with %s configured successfully\n", model, cipher);

	/* Activate crypto config */
	FAIL_ON_ERR(knet_handle_crypto_use_config(knet_h1, 1));

	printf("%s with %s activated successfully\n", model, cipher);

	/* Configure for data transmission test */
	FAIL_ON_ERR(knet_handle_crypto_rx_clear_traffic(knet_h1, KNET_CRYPTO_RX_DISALLOW_CLEAR_TRAFFIC));
	FAIL_ON_ERR(knet_handle_enable_sock_notify(knet_h1, &private_data, sock_notify));

	datafd = 0;
	channel = -1;
	FAIL_ON_ERR(knet_handle_add_datafd(knet_h1, &datafd, &channel, 0));

	/* Set up loopback link */
	FAIL_ON_ERR(knet_host_add(knet_h1, 1));
	FAIL_ON_ERR(_knet_link_set_config(knet_h1, 1, 0, KNET_TRANSPORT_UDP, 0, AF_INET, 0, &lo));
	FAIL_ON_ERR(knet_link_set_enable(knet_h1, 1, 0, 1));
	FAIL_ON_ERR(knet_handle_setfwd(knet_h1, 1));
	FAIL_ON_ERR(wait_for_host(knet_h1, 1, 10, logfds[0], stdout));

	/* Send encrypted data */
	send_len = knet_send(knet_h1, send_buff, KNET_MAX_PACKET_SIZE, channel);
	if (send_len <= 0) {
		printf("knet_send failed: %s\n", strerror(errno));
		CLEAN_EXIT(FAIL);
	}

	if (send_len != sizeof(send_buff)) {
		printf("knet_send sent only %zd bytes: %s\n", send_len, strerror(errno));
		CLEAN_EXIT(FAIL);
	}

	FAIL_ON_ERR(knet_handle_setfwd(knet_h1, 0));
	FAIL_ON_ERR(wait_for_packet(knet_h1, 10, datafd, logfds[0], stdout));

	/* Receive and verify encrypted data */
	recv_len = knet_recv(knet_h1, recv_buff, KNET_MAX_PACKET_SIZE, channel);
	if (recv_len != send_len) {
		printf("knet_recv received only %d bytes: %s\n", recv_len, strerror(errno));
		if ((is_helgrind()) && (recv_len == -1) && (errno == EAGAIN)) {
			printf("helgrind exception. this is normal due to possible timeouts\n");
			CLEAN_EXIT(CONTINUE);
		}
		CLEAN_EXIT(FAIL);
	}

	if (memcmp(recv_buff, send_buff, KNET_MAX_PACKET_SIZE)) {
		printf("recv and send buffers are different!\n");
		CLEAN_EXIT(FAIL);
	}

	printf("%s with %s data transmission successful\n\n", model, cipher);

	CLEAN_EXIT(CONTINUE);
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

#ifdef KNET_BSD
	if (is_memcheck() || is_helgrind()) {
		printf("valgrind-freebsd cannot run this test properly. Skipping\n");
		return SKIP;
	}
#endif

	memset(crypto_list, 0, sizeof(crypto_list));

	if (knet_get_crypto_list(crypto_list, &crypto_list_entries) < 0) {
		printf("knet_get_crypto_list failed: %s\n", strerror(errno));
		return FAIL;
	}

	if (crypto_list_entries == 0) {
		printf("no crypto modules detected. Skipping\n");
		return SKIP;
	}

	printf("=== AES-CTR Mode Support Test ===\n\n");

	/* Test each available backend with both naming formats */
	for (i = 0; i < crypto_list_entries; i++) {
		printf("--- Testing %s backend ---\n\n", crypto_list[i].name);

		printf("Testing hyphenated format (aes-NNN-ctr):\n");
		for (j = 0; hyphenated_ciphers[j] != NULL; j++) {
			test_ctr_mode(crypto_list[i].name, hyphenated_ciphers[j]);
		}

		printf("Testing non-hyphenated format (aesNNN-ctr):\n");
		for (j = 0; non_hyphenated_ciphers[j] != NULL; j++) {
			test_ctr_mode(crypto_list[i].name, non_hyphenated_ciphers[j]);
		}

		printf("\n");
	}

	printf("=== All CTR mode tests completed ===\n");

	return PASS;
}
