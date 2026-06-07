/*
 * Copyright (C) 2016-2026 Red Hat, Inc.  All rights reserved.
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

#include "test-common.h"

#define TEST_NAME "api_knet_host_get_host_list"

static void test(void)
{
	int logfd;
	knet_handle_t knet_h1, knet_h[2] = {0};
	knet_node_id_t host_ids[KNET_MAX_HOST];
	size_t host_ids_entries;

	logfd = start_logging(stdout);

	log_test(logfd, "Test knet_host_get_host_list incorrect knet_h");

	FAIL_ON_SUCCESS(knet_host_get_host_list(NULL, host_ids, &host_ids_entries), EINVAL);


	knet_h1 = _ts_knet_handle_start(logfd, KNET_LOG_DEBUG, knet_h);


	log_test(logfd, "Test knet_host_get_host_list incorrect host_ids");
	FAIL_ON_SUCCESS(knet_host_get_host_list(knet_h1, NULL, &host_ids_entries), EINVAL);

	log_test(logfd, "Test knet_host_get_host_list incorrect host_ids_entries");
	FAIL_ON_SUCCESS(knet_host_get_host_list(knet_h1, host_ids, NULL), EINVAL);

	log_test(logfd, "Test knet_host_get_host_list with one host");
	FAIL_ON_ERR(knet_host_add(knet_h1, 1));
	FAIL_ON_ERR(knet_host_get_host_list(knet_h1, host_ids, &host_ids_entries));
	if (host_ids_entries != 1) {
		log_test(logfd, "Too many hosts?");
		TEST_EXIT_CLEAN(FAIL);
	}
	if (host_ids[0] != 1) {
		log_test(logfd, "Unable to find host id 1 in host list");
		TEST_EXIT_CLEAN(FAIL);
	}

	log_test(logfd, "Test knet_host_get_host_list with zero hosts");
	FAIL_ON_ERR(knet_host_remove(knet_h1, 1));
	FAIL_ON_ERR(knet_host_get_host_list(knet_h1, host_ids, &host_ids_entries));

	if (host_ids_entries != 0) {
		log_test(logfd, "Too many hosts?");
		TEST_EXIT_CLEAN(FAIL);
	}
	TEST_EXIT_CLEAN(CONTINUE);
}

int main(int argc, char *argv[])
{
	printf("[TEST] %s: Test knet host get host list\n", TEST_NAME);

	test();

	TEST_EXIT(PASS);
}
