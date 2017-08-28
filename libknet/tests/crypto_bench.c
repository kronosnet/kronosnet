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
#include <pthread.h>

#include "libknet.h"

#include "common.h"
#include "internals.h"
#include "crypto.h"
#include "threads_common.h"

#include "test-common.h"

pthread_rwlock_t shlib_rwlock;

static void test(void)
{
	knet_handle_t knet_h;
	int logfd;
	struct knet_handle_crypto_cfg knet_handle_crypto_cfg;
	char *buf1, *buf2, *buf3;
	const char *input = "Encrypt me!\x0";
	ssize_t input_len = strlen(input) + 1;
	ssize_t outbuf_len;
	int loops;
	struct timespec clock_start, clock_end;
	unsigned long long time_diff;
	struct iovec iov_in;
	struct iovec iov_multi[4];
	int err = 0;

	err = pthread_rwlock_init(&shlib_rwlock, NULL);
	if (err) {
		printf("unable to init lock: %s\n", strerror(err));
		exit(FAIL);
	}

	memset(&knet_handle_crypto_cfg, 0, sizeof(struct knet_handle_crypto_cfg));

	logfd = start_logging(stdout);

	knet_h = knet_handle_new(1, logfd, KNET_LOG_DEBUG);

	if (!knet_h) {
		printf("knet_handle_new failed: %s\n", strerror(errno));
		exit(FAIL);
	}

	printf("Test knet_handle_crypto with nss/aes128/sha1 and normal key\n");

	memset(&knet_handle_crypto_cfg, 0, sizeof(struct knet_handle_crypto_cfg));
	strncpy(knet_handle_crypto_cfg.crypto_model, "nss", sizeof(knet_handle_crypto_cfg.crypto_model) - 1);
	strncpy(knet_handle_crypto_cfg.crypto_cipher_type, "aes128", sizeof(knet_handle_crypto_cfg.crypto_cipher_type) - 1);
	strncpy(knet_handle_crypto_cfg.crypto_hash_type, "sha1", sizeof(knet_handle_crypto_cfg.crypto_hash_type) - 1);
	knet_handle_crypto_cfg.private_key_len = 2000;

	if (crypto_init(knet_h, &knet_handle_crypto_cfg) < 0) {
		printf("knet_handle_crypto failed with correct config: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		exit(FAIL);
	}

	buf1=malloc(input_len);
	buf2=malloc(input_len + knet_h->sec_header_size);
	buf3=malloc(input_len + knet_h->sec_header_size);

	memset(buf1, 0, input_len);
	memset(buf2, 0, input_len + knet_h->sec_header_size);
	memset(buf3, 0, input_len + knet_h->sec_header_size);

	/*
	 * setup source buffer
	 */

	if (clock_gettime(CLOCK_MONOTONIC, &clock_start) != 0) {
		printf("Unable to get start time!\n");
		knet_handle_free(knet_h);
		exit(FAIL);
	}

	for (loops=0; loops<1000000; loops++) {
		memset(buf1, 0, input_len);
		memset(buf2, 0, input_len + knet_h->sec_header_size);
		memset(buf3, 0, input_len + knet_h->sec_header_size);

		strncpy(buf1, input, input_len);

		if (crypto_encrypt_and_sign(knet_h, (unsigned char *)buf1, strlen(buf1)+1, (unsigned char *)buf2, &outbuf_len) < 0) {
			printf("Unable to crypt and sign!\n");
			knet_handle_free(knet_h);
			exit(FAIL);
		}

		if (crypto_authenticate_and_decrypt(knet_h, (unsigned char *)buf2, outbuf_len, (unsigned char *)buf3, &outbuf_len) < 0) {
			printf("Unable to auth and decrypt!\n");
			knet_handle_free(knet_h);
			exit(FAIL);
		}


		if (memcmp(buf1, buf3, outbuf_len)) {
			printf("Crypt / Descrypt produced two different data set!\n");
			knet_handle_free(knet_h);
			exit(FAIL);
		}
	}

	if (clock_gettime(CLOCK_MONOTONIC, &clock_end) != 0) {
		printf("Unable to get end time!\n");
		knet_handle_free(knet_h);
		exit(FAIL);
	}

	timespec_diff(clock_start, clock_end, &time_diff);

	printf("Execution of 1000000 loops (buf_in api): %llu/ns\n", time_diff);

	if (clock_gettime(CLOCK_MONOTONIC, &clock_start) != 0) {
		printf("Unable to get start time!\n");
		knet_handle_free(knet_h);
		exit(FAIL);
	}

	memset(buf1, 0, input_len);
	strncpy(buf1, input, input_len);

	for (loops=0; loops<1000000; loops++) {
		memset(buf2, 0, input_len + knet_h->sec_header_size);
		memset(buf3, 0, input_len + knet_h->sec_header_size);
		memset(&iov_in, 0, sizeof(iov_in));

		iov_in.iov_base = (unsigned char *)buf1;
		iov_in.iov_len = strlen(buf1)+1;

		if (crypto_encrypt_and_signv(knet_h, &iov_in, 1, (unsigned char *)buf2, &outbuf_len) < 0) {
			printf("Unable to crypt and sign!\n");
			knet_handle_free(knet_h);
			exit(FAIL);
		}

		if (crypto_authenticate_and_decrypt(knet_h, (unsigned char *)buf2, outbuf_len, (unsigned char *)buf3, &outbuf_len) < 0) {
			printf("Unable to auth and decrypt!\n");
			knet_handle_free(knet_h);
			exit(FAIL);
		}


		if (memcmp(buf1, buf3, outbuf_len)) {
			printf("Crypt / Descrypt produced two different data set!\n");
			knet_handle_free(knet_h);
			exit(FAIL);
		}
	}

	if (clock_gettime(CLOCK_MONOTONIC, &clock_end) != 0) {
		printf("Unable to get end time!\n");
		knet_handle_free(knet_h);
		exit(FAIL);
	}

	timespec_diff(clock_start, clock_end, &time_diff);

	printf("Execution of 1000000 loops (iov_in api): %llu/ns\n", time_diff);

	if (clock_gettime(CLOCK_MONOTONIC, &clock_start) != 0) {
		printf("Unable to get start time!\n");
		knet_handle_free(knet_h);
		exit(FAIL);
	}

	memset(buf1, 0, input_len);
	strncpy(buf1, input, input_len);

	for (loops=0; loops<1000000; loops++) {
		memset(buf2, 0, input_len + knet_h->sec_header_size);
		memset(buf3, 0, input_len + knet_h->sec_header_size);
		memset(&iov_multi, 0, sizeof(iov_multi));

		/*
		 * "Encrypt me!\n" = 12 bytes
		 */

		iov_multi[0].iov_base = (unsigned char *)buf1;
		iov_multi[0].iov_len = 3;
		iov_multi[1].iov_base = (unsigned char *)buf1 + 3;
		iov_multi[1].iov_len = 3;
		iov_multi[2].iov_base = (unsigned char *)buf1 + 6;
		iov_multi[2].iov_len = 3;
		iov_multi[3].iov_base = (unsigned char *)buf1 + 9;
		iov_multi[3].iov_len = 3;

		if (crypto_encrypt_and_signv(knet_h, iov_multi, 4, (unsigned char *)buf2, &outbuf_len) < 0) {
			printf("Unable to crypt and sign!\n");
			knet_handle_free(knet_h);
			exit(FAIL);
		}

		if (crypto_authenticate_and_decrypt(knet_h, (unsigned char *)buf2, outbuf_len, (unsigned char *)buf3, &outbuf_len) < 0) {
			printf("Unable to auth and decrypt!\n");
			knet_handle_free(knet_h);
			exit(FAIL);
		}


		if (memcmp(buf1, buf3, outbuf_len)) {
			printf("Crypt / Descrypt produced two different data set!\n");
			knet_handle_free(knet_h);
			exit(FAIL);
		}
	}

	if (clock_gettime(CLOCK_MONOTONIC, &clock_end) != 0) {
		printf("Unable to get end time!\n");
		knet_handle_free(knet_h);
		exit(FAIL);
	}

	timespec_diff(clock_start, clock_end, &time_diff);

	printf("Execution of 1000000 loops (iov_in multi api): %llu/ns\n", time_diff);

	printf("Shutdown crypto\n");

	crypto_fini(knet_h);

	knet_handle_free(knet_h);
	free(buf1);
	free(buf2);
	free(buf3);
	pthread_rwlock_destroy(&shlib_rwlock);
}

int main(int argc, char *argv[])
{
	need_root();

	printf("Testing with default scheduler\n");

	set_scheduler(SCHED_OTHER);

	test();

	printf("Testing with SCHED_RR scheduler\n");

	set_scheduler(SCHED_RR);

	test();

	printf("Testing with SCHED_FIFO scheduler\n");

	set_scheduler(SCHED_FIFO);

	test();

	return PASS;
}
