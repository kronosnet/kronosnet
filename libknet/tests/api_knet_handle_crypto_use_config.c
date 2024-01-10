/*
 * Copyright (C) 2020-2024 Red Hat, Inc.  All rights reserved.
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
#include "crypto_model.h"
#include "test-common.h"

static void test(const char *model, const char *model2)
{
	knet_handle_t knet_h1, knet_h[2];
	int res;
	int logfds[2];
	struct knet_handle_crypto_cfg knet_handle_crypto_cfg;

	memset(&knet_handle_crypto_cfg, 0, sizeof(struct knet_handle_crypto_cfg));

	printf("Test knet_handle_crypto_use_config incorrect knet_h\n");

	if ((!knet_handle_crypto_use_config(NULL, 1)) || (errno != EINVAL)) {
		printf("knet_handle_crypto_use_config accepted invalid knet_h or returned incorrect error: %s\n", strerror(errno));
		exit(FAIL);
	}

	setup_logpipes(logfds);
	knet_h1 = knet_handle_start(logfds, KNET_LOG_DEBUG, knet_h);

	printf("Test knet_handle_crypto_use_config with invalid config num\n");
	FAIL_ON_SUCCESS(knet_handle_crypto_use_config(knet_h1, KNET_MAX_CRYPTO_INSTANCES + 1), EINVAL);

	printf("Test knet_handle_crypto_use_config with un-initialized cfg\n");
	FAIL_ON_SUCCESS(knet_handle_crypto_use_config(knet_h1, 1), EINVAL);
	FAIL_ON_SUCCESS(knet_handle_crypto_use_config(knet_h1, 2), EINVAL);

	printf("Test knet_handle_crypto_set_config with %s/aes128/sha1 and normal key\n", model);
	memset(&knet_handle_crypto_cfg, 0, sizeof(struct knet_handle_crypto_cfg));
	strncpy(knet_handle_crypto_cfg.crypto_model, model, sizeof(knet_handle_crypto_cfg.crypto_model) - 1);
	strncpy(knet_handle_crypto_cfg.crypto_cipher_type, "aes128", sizeof(knet_handle_crypto_cfg.crypto_cipher_type) - 1);
	strncpy(knet_handle_crypto_cfg.crypto_hash_type, "sha1", sizeof(knet_handle_crypto_cfg.crypto_hash_type) - 1);
	knet_handle_crypto_cfg.private_key_len = 2000;
	FAIL_ON_ERR(knet_handle_crypto_set_config(knet_h1, &knet_handle_crypto_cfg, 1));

	printf("Test knet_handle_crypto_use_config with un-initialized cfg (part 2)\n");
	FAIL_ON_SUCCESS(knet_handle_crypto_use_config(knet_h1, 2), EINVAL);
	FAIL_ON_ERR(knet_handle_crypto_use_config(knet_h1, 1));

	printf("Test knet_handle_crypto_set_config for second config with %s/aes128/sha1 and normal key\n", model);
	memset(&knet_handle_crypto_cfg, 0, sizeof(struct knet_handle_crypto_cfg));
	strncpy(knet_handle_crypto_cfg.crypto_model, model, sizeof(knet_handle_crypto_cfg.crypto_model) - 1);
	strncpy(knet_handle_crypto_cfg.crypto_cipher_type, "aes128", sizeof(knet_handle_crypto_cfg.crypto_cipher_type) - 1);
	strncpy(knet_handle_crypto_cfg.crypto_hash_type, "sha1", sizeof(knet_handle_crypto_cfg.crypto_hash_type) - 1);
	knet_handle_crypto_cfg.private_key_len = 2000;
	FAIL_ON_ERR(knet_handle_crypto_set_config(knet_h1, &knet_handle_crypto_cfg, 2));

	printf("Test knet_handle_crypto_use_config with valid data\n");
	FAIL_ON_ERR(knet_handle_crypto_use_config(knet_h1, 2));
	if (knet_h1->crypto_in_use_config != 2) {
		printf("knet_handle_crypto_set_config failed to set crypto in-use config to 2\n");
		CLEAN_EXIT(FAIL);
	}

	printf("Shutdown crypto\n");

	printf("Test knet_handle_crypto_use_config with valid data\n");

	FAIL_ON_ERR(knet_handle_crypto_use_config(knet_h1, 0));
	if (knet_h1->crypto_in_use_config != 0) {
		printf("knet_handle_crypto_set_config failed to set crypto in-use config to 2\n");
		CLEAN_EXIT(FAIL);
	}

	memset(&knet_handle_crypto_cfg, 0, sizeof(struct knet_handle_crypto_cfg));
	strncpy(knet_handle_crypto_cfg.crypto_model, "none", sizeof(knet_handle_crypto_cfg.crypto_model) - 1);
	strncpy(knet_handle_crypto_cfg.crypto_cipher_type, "none", sizeof(knet_handle_crypto_cfg.crypto_cipher_type) - 1);
	strncpy(knet_handle_crypto_cfg.crypto_hash_type, "none", sizeof(knet_handle_crypto_cfg.crypto_hash_type) - 1);
	knet_handle_crypto_cfg.private_key_len = 2000;

	FAIL_ON_ERR(knet_handle_crypto_set_config(knet_h1, &knet_handle_crypto_cfg, 1));
	if (knet_h1->crypto_instance[1]) {
		printf("knet_handle_crypto_set_config failed to wipe first config but reported success\n");
		CLEAN_EXIT(FAIL);
	}

	FAIL_ON_ERR(knet_handle_crypto_set_config(knet_h1, &knet_handle_crypto_cfg, 2));
	if (knet_h1->crypto_instance[2]) {
		printf("knet_handle_crypto_set_config failed to wipe first config but reported success\n");
		CLEAN_EXIT(FAIL);
	}
	CLEAN_EXIT(CONTINUE);
}

int main(int argc, char *argv[])
{
	struct knet_crypto_info crypto_list[16];
	size_t crypto_list_entries;
	size_t i;

	memset(crypto_list, 0, sizeof(crypto_list));

	if (knet_get_crypto_list(crypto_list, &crypto_list_entries) < 0) {
		printf("knet_get_crypto_list failed: %s\n", strerror(errno));
		return FAIL;
	}

	if (crypto_list_entries == 0) {
		printf("no crypto modules detected. Skipping\n");
		return SKIP;
	}

	for (i=0; i < crypto_list_entries; i++) {
		test(crypto_list[i].name, crypto_list[0].name);
	}

	return PASS;
}
