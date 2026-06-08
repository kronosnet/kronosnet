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

#define TEST_NAME "api_knet_host_get_id_by_host_name"

static void test(void)
{
	int logfd;
	knet_handle_t knet_h1, knet_h[2] = {0};
	knet_node_id_t host_id;

	logfd = start_logging(stdout);

	log_test(logfd, "Test knet_host_get_id_by_host_name incorrect knet_h");

	FAIL_ON_SUCCESS(knet_host_get_id_by_host_name(NULL, "1", &host_id), EINVAL);


	knet_h1 = _ts_knet_handle_start(logfd, KNET_LOG_DEBUG, knet_h);


	log_test(logfd, "Test knet_host_get_id_by_host_name with incorrect name 1");
	FAIL_ON_SUCCESS(knet_host_get_id_by_host_name(knet_h1, NULL, &host_id), EINVAL);

	log_test(logfd, "Test knet_host_get_id_by_host_name with incorrect host_id");
	FAIL_ON_SUCCESS(knet_host_get_id_by_host_name(knet_h1, "1", NULL), EINVAL);

	log_test(logfd, "Test knet_host_get_id_by_host_name with incorrect values for name");
	FAIL_ON_ERR(knet_host_add(knet_h1, 1));
	FAIL_ON_SUCCESS(knet_host_get_id_by_host_name(knet_h1, "test", &host_id), ENOENT);

	log_test(logfd, "Test knet_host_get_id_by_host_name with correct values");
	FAIL_ON_ERR(knet_host_get_id_by_host_name(knet_h1, "1", &host_id));

	TEST_EXIT_CLEAN(CONTINUE);
}

int main(int argc, char *argv[])
{
	printf("[TEST] %s: Test knet host get id by host name\n", TEST_NAME);

	test();

	TEST_EXIT(PASS);
}
