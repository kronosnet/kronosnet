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

#include "internals.h"
#include "test-common.h"

#define TEST_NAME "api_knet_host_get_name_by_host_id"

static void test(void)
{
	int logfd;
	knet_handle_t knet_h1, knet_h[2] = {0};
	char name[KNET_MAX_HOST_LEN];

	logfd = start_logging(stdout);

	log_test(logfd, "Test knet_host_get_name_by_host_id incorrect knet_h");

	FAIL_ON_SUCCESS(knet_host_get_name_by_host_id(NULL, 1, name), EINVAL);


	knet_h1 = _ts_knet_handle_start(logfd, KNET_LOG_DEBUG, knet_h);


	log_test(logfd, "Test knet_host_get_name_by_host_id with incorrect hostid 1");
	FAIL_ON_SUCCESS(knet_host_get_name_by_host_id(knet_h1, 1, name), EINVAL);

	log_test(logfd, "Test knet_host_get_name_by_host_id with incorrect name");
	FAIL_ON_SUCCESS(knet_host_get_name_by_host_id(knet_h1, 1, NULL), EINVAL);

	log_test(logfd, "Test knet_host_get_name_by_host_id with correct values for hostid 1");
	FAIL_ON_ERR(knet_host_add(knet_h1, 1));
	FAIL_ON_ERR(knet_host_get_name_by_host_id(knet_h1, 1, name));

	log_test(logfd, "Retrieved hostname:");
	log_test(logfd, "%.253s", name);

	TEST_EXIT_CLEAN(CONTINUE);
}

int main(int argc, char *argv[])
{
	printf("[TEST] %s: Test knet host get name by host id\n", TEST_NAME);

	test();

	TEST_EXIT(PASS);
}
