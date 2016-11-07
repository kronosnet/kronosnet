/*
 * Copyright (C) 2016 Red Hat, Inc.  All rights reserved.
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
#include <time.h>

#include "libknet.h"

#include "internals.h"
#include "crypto.h"
#include "threads_common.h"

#include "test-common.h"

static void test(void)
{
	knet_handle_t knet_h;
	int logfds[2];
	struct knet_handle_crypto_cfg knet_handle_crypto_cfg;
	char buf1[1024], buf2[1024], buf3[1024];
	ssize_t outbuf_len;
	int loops;
	struct timespec clock_start, clock_end;
	unsigned long long time_diff;

	memset(&knet_handle_crypto_cfg, 0, sizeof(struct knet_handle_crypto_cfg));

	setup_logpipes(logfds);

	knet_h = knet_handle_new(1, logfds[1], KNET_LOG_DEBUG);

	if (!knet_h) {
		printf("knet_handle_new failed: %s\n", strerror(errno));
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_handle_crypto with nss/aes128/sha1 and normal key\n");

	memset(&knet_handle_crypto_cfg, 0, sizeof(struct knet_handle_crypto_cfg));
	strncpy(knet_handle_crypto_cfg.crypto_model, "nss", sizeof(knet_handle_crypto_cfg.crypto_model) - 1);
	strncpy(knet_handle_crypto_cfg.crypto_cipher_type, "aes128", sizeof(knet_handle_crypto_cfg.crypto_cipher_type) - 1);
	strncpy(knet_handle_crypto_cfg.crypto_hash_type, "sha1", sizeof(knet_handle_crypto_cfg.crypto_hash_type) - 1);
	knet_handle_crypto_cfg.private_key_len = 2000;

	if (knet_handle_crypto(knet_h, &knet_handle_crypto_cfg)) {
		printf("knet_handle_crypto failed with correct config: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	/*
	 * setup source buffer
	 */

	if (clock_gettime(CLOCK_MONOTONIC, &clock_start) != 0) {
		printf("Unable to get start time!\n");
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	for (loops=0; loops<1000000; loops++) {
		memset(buf1, 0, sizeof(buf1));
		memset(buf2, 0, sizeof(buf2));
		memset(buf3, 0, sizeof(buf3));

		strcpy(buf1, "Encrypt me!");

		if (crypto_encrypt_and_sign(knet_h, (unsigned char *)buf1, strlen(buf1)+1, (unsigned char *)buf2, &outbuf_len) < 0) {
			printf("Unable to crypt and sign!\n");
			knet_handle_free(knet_h);
			flush_logs(logfds[0], stdout);
			close_logpipes(logfds);
			exit(FAIL);
		}

		if (crypto_authenticate_and_decrypt(knet_h, (unsigned char *)buf2, outbuf_len, (unsigned char *)buf3, &outbuf_len) < 0) {
			printf("Unable to auth and decrypt!\n");
			knet_handle_free(knet_h);
			flush_logs(logfds[0], stdout);
			close_logpipes(logfds);
			exit(FAIL);
		}


		if (memcmp(buf1, buf3, outbuf_len)) {
			printf("Crypt / Descrypt produced two different data set!\n");
			knet_handle_free(knet_h);
			flush_logs(logfds[0], stdout);
			close_logpipes(logfds);
			exit(FAIL);
		}
	}

	if (clock_gettime(CLOCK_MONOTONIC, &clock_end) != 0) {
		printf("Unable to get end time!\n");
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	timespec_diff(clock_start, clock_end, &time_diff);

	printf("Execution of 1000000 loops: %llu/ns\n", time_diff);

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
	need_root();

	test();

	return PASS;
}
