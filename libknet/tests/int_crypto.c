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

#include "libknet.h"

#include "internals.h"
#include "crypto.h"
#include "test-common.h"

static void test(void)
{
	knet_handle_t knet_h;
	int logfds[2];
	struct knet_handle_crypto_cfg knet_handle_crypto_cfg;
	char *buf1, *buf2, *buf3;
	const char *input = "Encrypt me!\x0";
	ssize_t input_len = strlen(input) + 1;
	ssize_t outbuf_len;
	int i;

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

	buf1=malloc(input_len);
	buf2=malloc(input_len + knet_h->sec_header_size);
	buf3=malloc(input_len + knet_h->sec_header_size);

	memset(buf1, 0, input_len);
	memset(buf2, 0, input_len + knet_h->sec_header_size);
	memset(buf3, 0, input_len + knet_h->sec_header_size);

	/*
	 * setup source buffer
	 */

	strncpy(buf1, input, input_len);
	printf("Source Data: %s\n", buf1);

	if (crypto_encrypt_and_sign(knet_h, (unsigned char *)buf1, strlen(buf1)+1, (unsigned char *)buf2, &outbuf_len) < 0) {
		printf("Unable to crypt and sign!\n");
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	printf("Encrypted Data: ");
	for (i=0; i<outbuf_len; i++) {
		printf("%02x ", (unsigned char)buf2[i]);
	}
	printf("\n");

	if (crypto_authenticate_and_decrypt(knet_h, (unsigned char *)buf2, outbuf_len, (unsigned char *)buf3, &outbuf_len) < 0) {
		printf("Unable to auth and decrypt!\n");
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	printf("Decrypted Data: %s\n", buf3);

	if (memcmp(buf1, buf3, outbuf_len)) {
		printf("Crypt / Descrypt produced two different data set!\n");
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

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

	free(buf1);
	free(buf2);
	free(buf3);
}

int main(int argc, char *argv[])
{
	need_root();

	test();

	return PASS;
}
