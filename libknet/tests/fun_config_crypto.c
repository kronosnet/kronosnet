/*
 * Copyright (C) 2020-2026 Red Hat, Inc.  All rights reserved.
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

#include "compress.h"
#include "internals.h"
#include "netutils.h"
#include "test-common.h"

#define TEST_NAME "fun_config_crypto"

#undef TESTNODES
#define TESTNODES 2

static void test(const char *model)
{
	int logfd;
	knet_handle_t knet_h[TESTNODES + 1] = {0};
	struct knet_handle_crypto_cfg knet_handle_crypto_cfg;
	int i,x;
	int seconds = 10;

	logfd = start_logging(stdout);

	_ts_knet_handle_start_nodes(knet_h, TESTNODES, logfd, KNET_LOG_DEBUG);


	/*
	 * config1: aes128/sha256 key1 is all 0s (2000 bytes)
	 */
	memset(&knet_handle_crypto_cfg, 0, sizeof(struct knet_handle_crypto_cfg));
	strncpy(knet_handle_crypto_cfg.crypto_model, model, sizeof(knet_handle_crypto_cfg.crypto_model) - 1);
	strncpy(knet_handle_crypto_cfg.crypto_cipher_type, "aes128", sizeof(knet_handle_crypto_cfg.crypto_cipher_type) - 1);
	strncpy(knet_handle_crypto_cfg.crypto_hash_type, "sha256", sizeof(knet_handle_crypto_cfg.crypto_hash_type) - 1);
	memset(knet_handle_crypto_cfg.private_key, 0, KNET_MAX_KEY_LEN);
	knet_handle_crypto_cfg.private_key_len = 2000;

	for (i = 1; i <= TESTNODES; i++) {
		FAIL_ON_ERR(knet_handle_crypto_set_config(knet_h[i], &knet_handle_crypto_cfg, 1));
		FAIL_ON_ERR(knet_handle_crypto_use_config(knet_h[i], 1));
		FAIL_ON_ERR(knet_handle_crypto_rx_clear_traffic(knet_h[i], KNET_CRYPTO_RX_DISALLOW_CLEAR_TRAFFIC));
	}

	_ts_knet_handle_join_nodes(knet_h, TESTNODES, 1, AF_INET, KNET_TRANSPORT_UDP, logfd);


	/*
	 * config2: aes256/sha512 key1 is all 1s (KNET_MAX_KEY_LEN bytes)
	 */
	memset(&knet_handle_crypto_cfg, 0, sizeof(struct knet_handle_crypto_cfg));
	strncpy(knet_handle_crypto_cfg.crypto_model, model, sizeof(knet_handle_crypto_cfg.crypto_model) - 1);
	strncpy(knet_handle_crypto_cfg.crypto_cipher_type, "aes256", sizeof(knet_handle_crypto_cfg.crypto_cipher_type) - 1);
	strncpy(knet_handle_crypto_cfg.crypto_hash_type, "sha512", sizeof(knet_handle_crypto_cfg.crypto_hash_type) - 1);
	memset(knet_handle_crypto_cfg.private_key, 1, KNET_MAX_KEY_LEN);
	knet_handle_crypto_cfg.private_key_len = KNET_MAX_KEY_LEN;

	for (i = 1; i <= TESTNODES; i++) {
		if (knet_handle_crypto_set_config(knet_h[i], &knet_handle_crypto_cfg, 2) < 0) {
			log_test(logfd, "knet_handle_crypto_set_config (2) failed with correct config: %s", strerror(errno));
			TEST_EXIT_CLEAN(FAIL);
		}
	}


	log_test(logfd, "Testing crypto config switch from 1 to 2");

	for (i = 1; i <= TESTNODES; i++) {
		if (knet_handle_crypto_use_config(knet_h[i], 2) < 0) {
			log_test(logfd, "knet_handle_crypto_use_config (2) failed with correct config: %s", strerror(errno));
			TEST_EXIT_CLEAN(FAIL);
		}
		for (x = 1; x <= TESTNODES; x++) {
			wait_for_nodes_state(knet_h[x], TESTNODES, 1, TEST_TIMEOUT_LONG, knet_h[1]->logfd);
		}
	}


	log_test(logfd, "Testing crypto config switch from 2 to 1");

	for (i = 1; i <= TESTNODES; i++) {
		FAIL_ON_ERR(knet_handle_crypto_use_config(knet_h[i], 1));
		wait_for_nodes_state(knet_h[i], TESTNODES, 1, TEST_TIMEOUT_LONG, knet_h[1]->logfd);
	}

	log_test(logfd, "Testing disable crypto config and allow clear traffic");

	memset(&knet_handle_crypto_cfg, 0, sizeof(struct knet_handle_crypto_cfg));
	strncpy(knet_handle_crypto_cfg.crypto_model, "none", sizeof(knet_handle_crypto_cfg.crypto_model) - 1);
	strncpy(knet_handle_crypto_cfg.crypto_cipher_type, "none", sizeof(knet_handle_crypto_cfg.crypto_cipher_type) - 1);
	strncpy(knet_handle_crypto_cfg.crypto_hash_type, "none", sizeof(knet_handle_crypto_cfg.crypto_hash_type) - 1);
	memset(knet_handle_crypto_cfg.private_key, 0, KNET_MAX_KEY_LEN);
	knet_handle_crypto_cfg.private_key_len = KNET_MAX_KEY_LEN;

	for (i = 1; i <= TESTNODES; i++) {
		/*
		 * config2 is no longer in use
		 */
		FAIL_ON_ERR(knet_handle_crypto_set_config(knet_h[i], &knet_handle_crypto_cfg, 2));
		/*
		 * allow clear traffic on RX on all nodes, before we change config to clear traffic
		 */
		FAIL_ON_ERR(knet_handle_crypto_rx_clear_traffic(knet_h[i], KNET_CRYPTO_RX_ALLOW_CLEAR_TRAFFIC));
	}

	for (i = 1; i <= TESTNODES; i++) {
		/*
		 * switch to clear traffic on RX on all nodes
		 */
		FAIL_ON_ERR(knet_handle_crypto_use_config(knet_h[i], 0));
	}


	for (i = 1; i <= TESTNODES; i++) {
		/*
		 * config1 is no longer in use
		 */
		FAIL_ON_ERR(knet_handle_crypto_set_config(knet_h[i], &knet_handle_crypto_cfg, 1));
	}

	for (i = 1; i <= TESTNODES; i++) {
		for (x = 0; x < seconds; x++){
			test_sleep(knet_h[1]->logfd, 1);
		}
		for (x = 1; x <= TESTNODES; x++) {
			wait_for_nodes_state(knet_h[x], TESTNODES, 1, TEST_TIMEOUT_LONG, knet_h[1]->logfd);
		}
	}

	TEST_EXIT_CLEAN(CONTINUE);
}

int main(int argc, char *argv[])
{
	struct knet_crypto_info crypto_list[16];
	size_t crypto_list_entries;
	size_t i;

	printf("[TEST] %s: Test Config crypto\n", TEST_NAME);

	memset(crypto_list, 0, sizeof(crypto_list));

	if (knet_get_crypto_list(crypto_list, &crypto_list_entries) < 0) {
		printf("knet_get_crypto_list failed: %s\n", strerror(errno));
		TEST_EXIT(FAIL);
	}

	if (crypto_list_entries == 0) {
		printf("no crypto modules detected. Skipping\n");
		TEST_EXIT(SKIP);
	}

	for (i=0; i < crypto_list_entries; i++) {
		test(crypto_list[i].name);
	}

	TEST_EXIT(PASS);
}
