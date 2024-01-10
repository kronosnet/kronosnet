/*
 * Copyright (C) 2016-2024 Red Hat, Inc.  All rights reserved.
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
	struct crypto_instance *current = NULL;

	memset(&knet_handle_crypto_cfg, 0, sizeof(struct knet_handle_crypto_cfg));

	printf("Test knet_handle_crypto_set_config incorrect knet_h\n");

	if ((!knet_handle_crypto_set_config(NULL, &knet_handle_crypto_cfg, 1)) || (errno != EINVAL)) {
		printf("knet_handle_crypto_set_config accepted invalid knet_h or returned incorrect error: %s\n", strerror(errno));
		exit(FAIL);
	}

	setup_logpipes(logfds);
	knet_h1 = knet_handle_start(logfds, KNET_LOG_DEBUG, knet_h);

	printf("Test knet_handle_crypto_set_config with invalid cfg\n");
	FAIL_ON_SUCCESS(knet_handle_crypto_set_config(knet_h1, NULL, 1), EINVAL);

	printf("Test knet_handle_crypto_set_config with invalid config num\n");
	FAIL_ON_SUCCESS(knet_handle_crypto_set_config(knet_h1, NULL, KNET_MAX_CRYPTO_INSTANCES + 1), EINVAL);

	printf("Test knet_handle_crypto_set_config with un-initialized cfg\n");
	FAIL_ON_SUCCESS(knet_handle_crypto_set_config(knet_h1, &knet_handle_crypto_cfg, 1), EINVAL);

	printf("Test knet_handle_crypto_set_config with none crypto model (disable crypto)\n");
	memset(&knet_handle_crypto_cfg, 0, sizeof(struct knet_handle_crypto_cfg));
	strncpy(knet_handle_crypto_cfg.crypto_model, "none", sizeof(knet_handle_crypto_cfg.crypto_model) - 1);
	strncpy(knet_handle_crypto_cfg.crypto_cipher_type, "aes128", sizeof(knet_handle_crypto_cfg.crypto_cipher_type) - 1);
	strncpy(knet_handle_crypto_cfg.crypto_hash_type, "sha1", sizeof(knet_handle_crypto_cfg.crypto_hash_type) - 1);

	FAIL_ON_ERR(knet_handle_crypto_set_config(knet_h1, &knet_handle_crypto_cfg, 1));

	printf("Test knet_handle_crypto_set_config with none crypto cipher and hash (disable crypto)\n");
	memset(&knet_handle_crypto_cfg, 0, sizeof(struct knet_handle_crypto_cfg));
	strncpy(knet_handle_crypto_cfg.crypto_model, model, sizeof(knet_handle_crypto_cfg.crypto_model) - 1);
	strncpy(knet_handle_crypto_cfg.crypto_cipher_type, "none", sizeof(knet_handle_crypto_cfg.crypto_cipher_type) - 1);
	strncpy(knet_handle_crypto_cfg.crypto_hash_type, "none", sizeof(knet_handle_crypto_cfg.crypto_hash_type) - 1);

	FAIL_ON_ERR(knet_handle_crypto_set_config(knet_h1, &knet_handle_crypto_cfg, 1));

	printf("Test knet_handle_crypto_set_config with %s/aes128/sha1 and too short key\n", model);
	memset(&knet_handle_crypto_cfg, 0, sizeof(struct knet_handle_crypto_cfg));
	strncpy(knet_handle_crypto_cfg.crypto_model, model, sizeof(knet_handle_crypto_cfg.crypto_model) - 1);
	strncpy(knet_handle_crypto_cfg.crypto_cipher_type, "aes128", sizeof(knet_handle_crypto_cfg.crypto_cipher_type) - 1);
	strncpy(knet_handle_crypto_cfg.crypto_hash_type, "sha1", sizeof(knet_handle_crypto_cfg.crypto_hash_type) - 1);
	knet_handle_crypto_cfg.private_key_len = 10;

	FAIL_ON_SUCCESS(knet_handle_crypto_set_config(knet_h1, &knet_handle_crypto_cfg, 1), EINVAL);

	printf("Test knet_handle_crypto_set_config with %s/aes128/sha1 and too long key\n", model);
	memset(&knet_handle_crypto_cfg, 0, sizeof(struct knet_handle_crypto_cfg));
	strncpy(knet_handle_crypto_cfg.crypto_model, model, sizeof(knet_handle_crypto_cfg.crypto_model) - 1);
	strncpy(knet_handle_crypto_cfg.crypto_cipher_type, "aes128", sizeof(knet_handle_crypto_cfg.crypto_cipher_type) - 1);
	strncpy(knet_handle_crypto_cfg.crypto_hash_type, "sha1", sizeof(knet_handle_crypto_cfg.crypto_hash_type) - 1);
	knet_handle_crypto_cfg.private_key_len = 10000;

	FAIL_ON_SUCCESS(knet_handle_crypto_set_config(knet_h1, &knet_handle_crypto_cfg, 1), EINVAL);

	printf("Test knet_handle_crypto_set_config with %s/aes128/sha1 and normal key\n", model);
	memset(&knet_handle_crypto_cfg, 0, sizeof(struct knet_handle_crypto_cfg));
	strncpy(knet_handle_crypto_cfg.crypto_model, model, sizeof(knet_handle_crypto_cfg.crypto_model) - 1);
	strncpy(knet_handle_crypto_cfg.crypto_cipher_type, "aes128", sizeof(knet_handle_crypto_cfg.crypto_cipher_type) - 1);
	strncpy(knet_handle_crypto_cfg.crypto_hash_type, "sha1", sizeof(knet_handle_crypto_cfg.crypto_hash_type) - 1);
	knet_handle_crypto_cfg.private_key_len = 2000;

	FAIL_ON_ERR(knet_handle_crypto_set_config(knet_h1, &knet_handle_crypto_cfg, 1));

	printf("Test knet_handle_crypto_set_config reconfig with %s/aes128/sha1 and normal key\n", model2);
	current = knet_h1->crypto_instance[1];

	memset(&knet_handle_crypto_cfg, 0, sizeof(struct knet_handle_crypto_cfg));
	strncpy(knet_handle_crypto_cfg.crypto_model, model, sizeof(knet_handle_crypto_cfg.crypto_model) - 1);
	strncpy(knet_handle_crypto_cfg.crypto_cipher_type, "aes128", sizeof(knet_handle_crypto_cfg.crypto_cipher_type) - 1);
	strncpy(knet_handle_crypto_cfg.crypto_hash_type, "sha1", sizeof(knet_handle_crypto_cfg.crypto_hash_type) - 1);
	knet_handle_crypto_cfg.private_key_len = 2000;

	FAIL_ON_ERR(knet_handle_crypto_set_config(knet_h1, &knet_handle_crypto_cfg, 1));

	if (current == knet_h1->crypto_instance[1]) {
		printf("knet_handle_crypto_set_config failed to install new correct config: %s\n", strerror(errno));
		CLEAN_EXIT(FAIL);
	}

	printf("Test knet_handle_crypto_set_config reconfig with %s/aes128/sha1 and normal key\n", model);
	current = knet_h1->crypto_instance[1];

	memset(&knet_handle_crypto_cfg, 0, sizeof(struct knet_handle_crypto_cfg));
	strncpy(knet_handle_crypto_cfg.crypto_model, model, sizeof(knet_handle_crypto_cfg.crypto_model) - 1);
	strncpy(knet_handle_crypto_cfg.crypto_cipher_type, "aes128", sizeof(knet_handle_crypto_cfg.crypto_cipher_type) - 1);
	strncpy(knet_handle_crypto_cfg.crypto_hash_type, "sha1", sizeof(knet_handle_crypto_cfg.crypto_hash_type) - 1);
	knet_handle_crypto_cfg.private_key_len = 2000;

	FAIL_ON_ERR(knet_handle_crypto_set_config(knet_h1, &knet_handle_crypto_cfg, 1));

	if (current == knet_h1->crypto_instance[1]) {
		printf("knet_handle_crypto_set_config failed to install new correct config: %s\n", strerror(errno));
		CLEAN_EXIT(FAIL);
	}

	printf("Test knet_handle_crypto_set_config reconfig with %s/aes129/sha1 and normal key\n", model);
	current = knet_h1->crypto_instance[1];

	memset(&knet_handle_crypto_cfg, 0, sizeof(struct knet_handle_crypto_cfg));
	strncpy(knet_handle_crypto_cfg.crypto_model, model, sizeof(knet_handle_crypto_cfg.crypto_model) - 1);
	strncpy(knet_handle_crypto_cfg.crypto_cipher_type, "aes129", sizeof(knet_handle_crypto_cfg.crypto_cipher_type) - 1);
	strncpy(knet_handle_crypto_cfg.crypto_hash_type, "sha1", sizeof(knet_handle_crypto_cfg.crypto_hash_type) - 1);
	knet_handle_crypto_cfg.private_key_len = 2000;

	FAIL_ON_ERR_ONLY(knet_handle_crypto_set_config(knet_h1, &knet_handle_crypto_cfg, 1));
	if (current != knet_h1->crypto_instance[1]) {
		printf("knet_handle_crypto_set_config failed to restore correct config: %s\n", strerror(errno));
		CLEAN_EXIT(FAIL);
	}

	printf("Test knet_handle_crypto_set_config with %s/aes128/none and normal key\n", model);
	memset(&knet_handle_crypto_cfg, 0, sizeof(struct knet_handle_crypto_cfg));
	strncpy(knet_handle_crypto_cfg.crypto_model, model, sizeof(knet_handle_crypto_cfg.crypto_model) - 1);
	strncpy(knet_handle_crypto_cfg.crypto_cipher_type, "aes128", sizeof(knet_handle_crypto_cfg.crypto_cipher_type) - 1);
	strncpy(knet_handle_crypto_cfg.crypto_hash_type, "none", sizeof(knet_handle_crypto_cfg.crypto_hash_type) - 1);
	knet_handle_crypto_cfg.private_key_len = 2000;

	FAIL_ON_SUCCESS(knet_handle_crypto_set_config(knet_h1, &knet_handle_crypto_cfg, 1), EINVAL);

	printf("Test knet_handle_crypto_set_config with %s/aes128/sha1 and key where (key_len %% wrap_key_block_size != 0)\n", model);
	memset(&knet_handle_crypto_cfg, 0, sizeof(struct knet_handle_crypto_cfg));
	strncpy(knet_handle_crypto_cfg.crypto_model, model, sizeof(knet_handle_crypto_cfg.crypto_model) - 1);
	strncpy(knet_handle_crypto_cfg.crypto_cipher_type, "aes128", sizeof(knet_handle_crypto_cfg.crypto_cipher_type) - 1);
	strncpy(knet_handle_crypto_cfg.crypto_hash_type, "sha1", sizeof(knet_handle_crypto_cfg.crypto_hash_type) - 1);
	/*
	 * Prime number so chance that (private_key_len % wrap_key_block_size == 0) is minimalized
	 */
	knet_handle_crypto_cfg.private_key_len = 2003;

	FAIL_ON_ERR(knet_handle_crypto_set_config(knet_h1, &knet_handle_crypto_cfg, 1));

	printf("Test knet_handle_crypto_set_config second with %s/aes128/sha1 and normal key\n", model);
	memset(&knet_handle_crypto_cfg, 0, sizeof(struct knet_handle_crypto_cfg));
	strncpy(knet_handle_crypto_cfg.crypto_model, model, sizeof(knet_handle_crypto_cfg.crypto_model) - 1);
	strncpy(knet_handle_crypto_cfg.crypto_cipher_type, "aes128", sizeof(knet_handle_crypto_cfg.crypto_cipher_type) - 1);
	strncpy(knet_handle_crypto_cfg.crypto_hash_type, "sha1", sizeof(knet_handle_crypto_cfg.crypto_hash_type) - 1);
	knet_handle_crypto_cfg.private_key_len = 2000;

	FAIL_ON_ERR(knet_handle_crypto_set_config(knet_h1, &knet_handle_crypto_cfg, 2));
	if (!knet_h1->crypto_instance[2]) {
		printf("knet_handle_crypto_set_config failed to install second config but reported success\n");
		CLEAN_EXIT(FAIL);
	}

	if (knet_h1->crypto_instance[1] == knet_h1->crypto_instance[2]) {
		printf("knet_handle_crypto_set_config failed to install second config and assigned to first\n");
		CLEAN_EXIT(FAIL);
	}

	printf("Test knet_handle_crypto_set_config second config BUSY test\n");
	FAIL_ON_ERR(knet_handle_crypto_use_config(knet_h1, 2));
	FAIL_ON_SUCCESS(knet_handle_crypto_set_config(knet_h1, &knet_handle_crypto_cfg, 2), EBUSY);
	FAIL_ON_ERR(knet_handle_crypto_use_config(knet_h1, 0));

	printf("Shutdown crypto\n");
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
