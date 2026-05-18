/*
 * Copyright (C) 2017-2026 Red Hat, Inc.  All rights reserved.
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

#define TEST_NAME "api_knet_get_crypto_list"

static void test(void)
{
	int logfd;
	struct knet_crypto_info crypto_list[16];
	size_t crypto_list_entries;
	size_t crypto_list_entries1;
	size_t i;

	logfd = start_logging(stdout);

	memset(crypto_list, 0, sizeof(crypto_list));

	log_test(logfd, "Test knet_handle_get_crypto_list with no entries_list");

	if ((!knet_get_crypto_list(crypto_list, NULL)) || (errno != EINVAL)) {
		log_test(logfd, "knet_get_crypto_list accepted invalid list_entries or returned incorrect error: %s", strerror(errno));
		TEST_EXIT(FAIL);
	}

	log_test(logfd, "Test knet_get_crypto_list with no crypto_list (get number of entries)");

	if (knet_get_crypto_list(NULL, &crypto_list_entries) < 0) {
		log_test(logfd, "knet_handle_get_crypto_list returned error instead of number of entries: %s", strerror(errno));
		TEST_EXIT(FAIL);
	}

	log_test(logfd, "Test knet_get_crypto_list with valid data");

	if (knet_get_crypto_list(crypto_list, &crypto_list_entries1) < 0) {
		log_test(logfd, "knet_get_crypto_list failed: %s", strerror(errno));
		TEST_EXIT(FAIL);
	}

	if (crypto_list_entries != crypto_list_entries1) {
		log_test(logfd, "knet_get_crypto_list returned a different number of entries: %d, %d",
		       (int)crypto_list_entries, (int)crypto_list_entries1);
		TEST_EXIT(FAIL);
	}

	for (i=0; i<crypto_list_entries; i++) {
		log_test(logfd, "Detected crypto: %s", crypto_list[i].name);
	}

	stop_logging();
}

int main(int argc, char *argv[])
{
	printf("[TEST] %s: Test knet get crypto list\n", TEST_NAME);

	test();

	TEST_EXIT(PASS);
}
