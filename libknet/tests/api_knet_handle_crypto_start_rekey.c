/*
 * Copyright (C) 2016-2018 Red Hat, Inc.  All rights reserved.
 *
 * Authors: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *
 * This software licensed under GPL-2.0+, LGPL-2.0+
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

static void test(const char *model)
{
	knet_handle_t knet_h;
	int logfds[2];
	struct knet_handle_crypto_cfg knet_handle_crypto_cfg;

	memset(&knet_handle_crypto_cfg, 0, sizeof(struct knet_handle_crypto_cfg));

	printf("Test knet_handle_crypto_start_rekey incorrect knet_h\n");

	if ((!knet_handle_crypto_start_rekey(NULL, &knet_handle_crypto_cfg)) || (errno != EINVAL)) {
		printf("knet_handle_crypto_start_rekey accepted invalid knet_h or returned incorrect error: %s\n", strerror(errno));
		exit(FAIL);
	}

	setup_logpipes(logfds);

	knet_h = knet_handle_start(logfds, KNET_LOG_DEBUG);

	flush_logs(logfds[0], stdout);

	printf("Test knet_handle_crypto_start_rekey with invalid cfg\n");

	if ((!knet_handle_crypto_start_rekey(knet_h, NULL)) || (errno != EINVAL)) {
		printf("knet_handle_crypto_start_rekey accepted invalid cfg or returned incorrect error: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_handle_crypto_start_rekey with un-initialized cfg\n");

	if ((!knet_handle_crypto_start_rekey(knet_h, &knet_handle_crypto_cfg)) || (errno != EINVAL)) {
		printf("knet_handle_crypto_start_rekey accepted invalid un-initialized cfg\n");
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_handle_crypto_start_rekey with %s/aes128/sha1 and too short key\n", model);

	memset(&knet_handle_crypto_cfg, 0, sizeof(struct knet_handle_crypto_cfg));
	strncpy(knet_handle_crypto_cfg.crypto_model, model, sizeof(knet_handle_crypto_cfg.crypto_model) - 1);
	strncpy(knet_handle_crypto_cfg.crypto_cipher_type, "aes128", sizeof(knet_handle_crypto_cfg.crypto_cipher_type) - 1);
	strncpy(knet_handle_crypto_cfg.crypto_hash_type, "sha1", sizeof(knet_handle_crypto_cfg.crypto_hash_type) - 1);
	knet_handle_crypto_cfg.private_key_len = 10;

	if ((!knet_handle_crypto_start_rekey(knet_h, &knet_handle_crypto_cfg)) || (errno != EINVAL)) {
		printf("knet_handle_crypto_start_rekey accepted too short private key\n");
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_handle_crypto_start_rekey with %s/aes128/sha1 and too long key\n", model);

	memset(&knet_handle_crypto_cfg, 0, sizeof(struct knet_handle_crypto_cfg));
	strncpy(knet_handle_crypto_cfg.crypto_model, model, sizeof(knet_handle_crypto_cfg.crypto_model) - 1);
	strncpy(knet_handle_crypto_cfg.crypto_cipher_type, "aes128", sizeof(knet_handle_crypto_cfg.crypto_cipher_type) - 1);
	strncpy(knet_handle_crypto_cfg.crypto_hash_type, "sha1", sizeof(knet_handle_crypto_cfg.crypto_hash_type) - 1);
	knet_handle_crypto_cfg.private_key_len = 10000;

	if ((!knet_handle_crypto_start_rekey(knet_h, &knet_handle_crypto_cfg)) || (errno != EINVAL)) {
		printf("knet_handle_crypto_start_rekey accepted too long private key\n");
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_handle_crypto_start_rekey with %s/aes128/sha1 and normal key and crypto not configured\n", model);

	memset(&knet_handle_crypto_cfg, 0, sizeof(struct knet_handle_crypto_cfg));
	strncpy(knet_handle_crypto_cfg.crypto_model, model, sizeof(knet_handle_crypto_cfg.crypto_model) - 1);
	strncpy(knet_handle_crypto_cfg.crypto_cipher_type, "aes128", sizeof(knet_handle_crypto_cfg.crypto_cipher_type) - 1);
	strncpy(knet_handle_crypto_cfg.crypto_hash_type, "sha1", sizeof(knet_handle_crypto_cfg.crypto_hash_type) - 1);
	knet_handle_crypto_cfg.private_key_len = 2000;

	if ((!knet_handle_crypto_start_rekey(knet_h, &knet_handle_crypto_cfg)) || (errno != EINVAL)) {
		printf("knet_handle_crypto_start_rekey failed with correct config: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	if (knet_handle_crypto(knet_h, &knet_handle_crypto_cfg) < 0) {
		printf("knet_handle_crypto failed: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	printf("Test knet_handle_crypto_start_rekey with %s/aes128/sha1 and normal key and crypto configured\n", model);

	memset(&knet_handle_crypto_cfg, 0, sizeof(struct knet_handle_crypto_cfg));
	strncpy(knet_handle_crypto_cfg.crypto_model, model, sizeof(knet_handle_crypto_cfg.crypto_model) - 1);
	strncpy(knet_handle_crypto_cfg.crypto_cipher_type, "aes128", sizeof(knet_handle_crypto_cfg.crypto_cipher_type) - 1);
	strncpy(knet_handle_crypto_cfg.crypto_hash_type, "sha1", sizeof(knet_handle_crypto_cfg.crypto_hash_type) - 1);
	knet_handle_crypto_cfg.private_key_len = 2000;

	if (knet_handle_crypto_start_rekey(knet_h, &knet_handle_crypto_cfg) < 0) {
		printf("knet_handle_crypto_start_rekey failed to start: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_handle_crypto_start_rekey with %s/aes128/sha1 and normal key and crypto configured and rekey in progress\n", model);

	memset(&knet_handle_crypto_cfg, 0, sizeof(struct knet_handle_crypto_cfg));
	strncpy(knet_handle_crypto_cfg.crypto_model, model, sizeof(knet_handle_crypto_cfg.crypto_model) - 1);
	strncpy(knet_handle_crypto_cfg.crypto_cipher_type, "aes128", sizeof(knet_handle_crypto_cfg.crypto_cipher_type) - 1);
	strncpy(knet_handle_crypto_cfg.crypto_hash_type, "sha1", sizeof(knet_handle_crypto_cfg.crypto_hash_type) - 1);
	knet_handle_crypto_cfg.private_key_len = 2000;

	if ((!knet_handle_crypto_start_rekey(knet_h, &knet_handle_crypto_cfg)) || (errno != EBUSY)) {
		printf("knet_handle_crypto_start_rekey failed to detect rekey already in progress: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_handle_crypto with %s/aes128/sha1 and normal key and crypto configured and rekey in progress\n", model);

	memset(&knet_handle_crypto_cfg, 0, sizeof(struct knet_handle_crypto_cfg));
	strncpy(knet_handle_crypto_cfg.crypto_model, model, sizeof(knet_handle_crypto_cfg.crypto_model) - 1);
	strncpy(knet_handle_crypto_cfg.crypto_cipher_type, "aes128", sizeof(knet_handle_crypto_cfg.crypto_cipher_type) - 1);
	strncpy(knet_handle_crypto_cfg.crypto_hash_type, "sha1", sizeof(knet_handle_crypto_cfg.crypto_hash_type) - 1);
	knet_handle_crypto_cfg.private_key_len = 2000;

	if ((!knet_handle_crypto(knet_h, &knet_handle_crypto_cfg)) || (errno != EBUSY)) {
		printf("knet_handle_crypto failed to detect rekey in progress: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Shutdown crypto\n");

	memset(&knet_handle_crypto_cfg, 0, sizeof(struct knet_handle_crypto_cfg));
	strncpy(knet_handle_crypto_cfg.crypto_model, "none", sizeof(knet_handle_crypto_cfg.crypto_model) - 1);
	strncpy(knet_handle_crypto_cfg.crypto_cipher_type, "none", sizeof(knet_handle_crypto_cfg.crypto_cipher_type) - 1);
	strncpy(knet_handle_crypto_cfg.crypto_hash_type, "none", sizeof(knet_handle_crypto_cfg.crypto_hash_type) - 1);
	knet_handle_crypto_cfg.private_key_len = 2000;

	if (knet_handle_crypto(knet_h, &knet_handle_crypto_cfg) < 0) {
		printf("Unable to shutdown crypto: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	knet_handle_free(knet_h);
	flush_logs(logfds[0], stdout);
	close_logpipes(logfds);
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
		test(crypto_list[i].name);
	}

	return PASS;
}
