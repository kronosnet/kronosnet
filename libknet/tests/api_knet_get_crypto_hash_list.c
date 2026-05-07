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

static void test(void)
{
	struct knet_crypto_hash_info hash_list[16];
	size_t hash_list_entries;
	size_t hash_list_entries1;
	struct knet_crypto_info crypto_list[16];
	size_t crypto_list_entries;
	size_t i, j;
	knet_handle_t knet_h1, knet_h[2];
	int logfds[2];
	struct knet_handle_crypto_cfg crypto_cfg;
	unsigned char test_key[2000];
	int ret;

	memset(hash_list, 0, sizeof(hash_list));

	printf("Test knet_get_crypto_hash_list with no entries_list\n");

	if ((!knet_get_crypto_hash_list(hash_list, NULL)) || (errno != EINVAL)) {
		printf("knet_get_crypto_hash_list accepted invalid list_entries or returned incorrect error: %s\n", strerror(errno));
		exit(FAIL);
	}

	printf("Test knet_get_crypto_hash_list with no hash_list (get number of entries)\n");

	if (knet_get_crypto_hash_list(NULL, &hash_list_entries) < 0) {
		printf("knet_get_crypto_hash_list returned error instead of number of entries: %s\n", strerror(errno));
		exit(FAIL);
	}

	printf("Test knet_get_crypto_hash_list with valid data\n");

	if (knet_get_crypto_hash_list(hash_list, &hash_list_entries1) < 0) {
		printf("knet_get_crypto_hash_list failed: %s\n", strerror(errno));
		exit(FAIL);
	}

	if (hash_list_entries != hash_list_entries1) {
		printf("knet_get_crypto_hash_list returned a different number of entries: %d, %d\n",
		       (int)hash_list_entries, (int)hash_list_entries1);
		exit(FAIL);
	}

	for (i=0; i<hash_list_entries; i++) {
		printf("Detected hash: %s (hash_bits: %d)\n",
		       hash_list[i].name, hash_list[i].hash_bits);
	}

	printf("\nTest that all returned hashes work with all crypto modules\n");

	/* Get list of crypto modules */
	if (knet_get_crypto_list(crypto_list, &crypto_list_entries) < 0) {
		printf("knet_get_crypto_list failed: %s\n", strerror(errno));
		exit(FAIL);
	}

	/* Prepare test key */
	memset(test_key, 0x42, sizeof(test_key));

	/* Test each hash with each crypto module */
	for (i = 0; i < crypto_list_entries; i++) {
		printf("\nTesting crypto module: %s\n", crypto_list[i].name);

		for (j = 0; j < hash_list_entries; j++) {
			/* Create handle */
			setup_logpipes(logfds);
			knet_h1 = knet_handle_start(logfds, KNET_LOG_DEBUG, knet_h);
			if (!knet_h1) {
				printf("  FAIL: %s - couldn't create handle\n", hash_list[j].name);
				flush_logs(logfds[0], stdout);
				close_logpipes(logfds);
				exit(FAIL);
			}

			/* Configure crypto */
			memset(&crypto_cfg, 0, sizeof(crypto_cfg));
			strncpy(crypto_cfg.crypto_model, crypto_list[i].name, sizeof(crypto_cfg.crypto_model) - 1);
			strncpy(crypto_cfg.crypto_cipher_type, "aes128", sizeof(crypto_cfg.crypto_cipher_type) - 1);
			strncpy(crypto_cfg.crypto_hash_type, hash_list[j].name, sizeof(crypto_cfg.crypto_hash_type) - 1);
			memcpy(crypto_cfg.private_key, test_key, sizeof(test_key));
			crypto_cfg.private_key_len = sizeof(test_key);

			ret = knet_handle_crypto_set_config(knet_h1, &crypto_cfg, 1);
			if (ret < 0) {
				printf("  FAIL: %s - crypto configuration failed\n", hash_list[j].name);
				flush_logs(logfds[0], stdout);
				knet_handle_free(knet_h1);
				close_logpipes(logfds);
				exit(FAIL);
			}

			printf("  PASS: %s\n", hash_list[j].name);

			knet_handle_free(knet_h1);
			flush_logs(logfds[0], stdout);
			close_logpipes(logfds);
		}
	}

	printf("\nAll hashes successfully configured with all crypto modules\n");
}

int main(int argc, char *argv[])
{
	test();

	return PASS;
}
