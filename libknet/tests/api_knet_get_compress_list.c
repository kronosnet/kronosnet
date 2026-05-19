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

#define TEST_NAME "api_knet_get_compress_list"

static void test(void)
{
	int logfd;
	struct knet_compress_info compress_list[16];
	size_t compress_list_entries;
	size_t compress_list_entries1;
	size_t i;

	logfd = start_logging(stdout);

	memset(compress_list, 0, sizeof(compress_list));

	log_test(logfd, "Test knet_get_compress_list with no entries_list");

	FAIL_ON_SUCCESS_NOCLEAN(knet_get_compress_list(compress_list, NULL), EINVAL);

	log_test(logfd, "Test knet_get_compress_list with no compress_list (get number of entries)");

	if (knet_get_compress_list(NULL, &compress_list_entries) < 0) {
		log_test(logfd, "knet_handle_get_compress_list returned error instead of number of entries: %s", strerror(errno));
		TEST_EXIT(FAIL);
	}

	log_test(logfd, "Test knet_get_compress_list with valid data");

	if (knet_get_compress_list(compress_list, &compress_list_entries1) < 0) {
		log_test(logfd, "knet_get_compress_list failed: %s", strerror(errno));
		TEST_EXIT(FAIL);
	}

	if (compress_list_entries != compress_list_entries1) {
		log_test(logfd, "knet_get_compress_list returned a different number of entries: %d, %d",
		       (int)compress_list_entries, (int)compress_list_entries1);
		TEST_EXIT(FAIL);
	}

	for (i=0; i<compress_list_entries; i++) {
		log_test(logfd, "Detected compress: %s", compress_list[i].name);
	}

	stop_logging();
}

int main(int argc, char *argv[])
{
	printf("[TEST] %s: Test knet get compress list\n", TEST_NAME);

	test();

	TEST_EXIT(PASS);
}
