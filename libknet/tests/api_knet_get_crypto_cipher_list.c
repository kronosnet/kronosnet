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
#include "test-common.h"

#define TEST_NAME "api_knet_get_crypto_cipher_list"

static void test(void)
{
	int logfd;
	struct knet_crypto_cipher_info cipher_list[32];
	size_t cipher_list_entries;
	size_t cipher_list_entries1;
	struct knet_crypto_info crypto_list[16];
	size_t crypto_list_entries;
	size_t i, j;
	knet_handle_t knet_h1, knet_h[2] = {0};
	struct knet_handle_crypto_cfg crypto_cfg;
	unsigned char test_key[2000];
	int ret;

	logfd = start_logging(stdout);

	memset(cipher_list, 0, sizeof(cipher_list));

	log_test(logfd, "Test knet_get_crypto_cipher_list with no entries_list");

	FAIL_ON_SUCCESS_NOCLEAN(knet_get_crypto_cipher_list(cipher_list, NULL), EINVAL);

	log_test(logfd, "Test knet_get_crypto_cipher_list with no cipher_list (get number of entries)");

	if (knet_get_crypto_cipher_list(NULL, &cipher_list_entries) < 0) {
		log_test(logfd, "knet_get_crypto_cipher_list returned error instead of number of entries: %s", strerror(errno));
		TEST_EXIT(FAIL);
	}

	log_test(logfd, "Test knet_get_crypto_cipher_list with valid data");

	if (knet_get_crypto_cipher_list(cipher_list, &cipher_list_entries1) < 0) {
		log_test(logfd, "knet_get_crypto_cipher_list failed: %s", strerror(errno));
		TEST_EXIT(FAIL);
	}

	if (cipher_list_entries != cipher_list_entries1) {
		log_test(logfd, "knet_get_crypto_cipher_list returned a different number of entries: %d, %d",
		       (int)cipher_list_entries, (int)cipher_list_entries1);
		TEST_EXIT(FAIL);
	}

	for (i=0; i<cipher_list_entries; i++) {
		log_test(logfd, "Detected cipher: %s (mode: %s, key_bits: %d)",
		       cipher_list[i].name, cipher_list[i].mode, cipher_list[i].key_bits);
	}

	log_test(logfd, "Test that all returned ciphers work with all crypto modules");

	/* Get list of crypto modules */
	if (knet_get_crypto_list(crypto_list, &crypto_list_entries) < 0) {
		log_test(logfd, "knet_get_crypto_list failed: %s", strerror(errno));
		TEST_EXIT(FAIL);
	}

	/* Prepare test key */
	memset(test_key, 0x42, sizeof(test_key));

	/* Test each cipher with each crypto module */
	for (i = 0; i < crypto_list_entries; i++) {
		log_test(logfd, "Testing crypto module: %s", crypto_list[i].name);

		for (j = 0; j < cipher_list_entries; j++) {
			/* Create handle */
			knet_h1 = _ts_knet_handle_start(logfd, KNET_LOG_DEBUG, knet_h);
			if (!knet_h1) {
				log_test(logfd, "  FAIL: %s - couldn't create handle", cipher_list[j].name);
				TEST_EXIT(FAIL);
			}

			/* Configure crypto */
			memset(&crypto_cfg, 0, sizeof(crypto_cfg));
			strncpy(crypto_cfg.crypto_model, crypto_list[i].name, sizeof(crypto_cfg.crypto_model) - 1);
			strncpy(crypto_cfg.crypto_cipher_type, cipher_list[j].name, sizeof(crypto_cfg.crypto_cipher_type) - 1);
			strncpy(crypto_cfg.crypto_hash_type, "sha256", sizeof(crypto_cfg.crypto_hash_type) - 1);
			memcpy(crypto_cfg.private_key, test_key, sizeof(test_key));
			crypto_cfg.private_key_len = sizeof(test_key);

			ret = knet_handle_crypto_set_config(knet_h1, &crypto_cfg, 1);
			if (ret < 0) {
				log_test(logfd, "  FAIL: %s - crypto configuration failed", cipher_list[j].name);
				knet_handle_free(knet_h1);
				TEST_EXIT(FAIL);
			}

			log_test(logfd, "  PASS: %s", cipher_list[j].name);

			knet_handle_free(knet_h1);
		}
	}

	log_test(logfd, "All ciphers successfully configured with all crypto modules");

	stop_logging();
}

int main(int argc, char *argv[])
{
	printf("[TEST] %s: Test knet get crypto cipher list\n", TEST_NAME);

	test();

	TEST_EXIT(PASS);
}
