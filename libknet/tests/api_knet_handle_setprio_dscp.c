/*
 * Copyright (C) 2016-2026 Red Hat, Inc.  All rights reserved.
 *
 * Authors: David Hanisch <hanisch@strato.de>
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

#define TEST_NAME "api_knet_handle_setprio_dscp"

static void test(void)
{
	int logfd;
	knet_handle_t knet_h1, knet_h[2] = {0};

	logfd = start_logging(stdout);

	log_test(logfd, "Test knet_handle_setprio_dscp incorrect knet_h");

	FAIL_ON_SUCCESS(knet_handle_setprio_dscp(NULL, 1), EINVAL);


	knet_h1 = _ts_knet_handle_start(logfd, KNET_LOG_DEBUG, knet_h);


	log_test(logfd, "Test knet_handle_setprio_dscp with 100 (incorrect)");
	FAIL_ON_SUCCESS(knet_handle_setprio_dscp(knet_h1, 100), EINVAL);

	log_test(logfd, "Test knet_handle_setprio_dscp with 40 (correct)");
	FAIL_ON_ERR(knet_handle_setprio_dscp(knet_h1, 40));

	if (knet_h1->prio_dscp != 40) {
		log_test(logfd, "knet_handle_setprio_dscp failed to set the value");
		TEST_EXIT_CLEAN(FAIL);
	}
	TEST_EXIT_CLEAN(CONTINUE);
}

int main(int argc, char *argv[])
{
	printf("[TEST] %s: Test knet handle setprio dscp\n", TEST_NAME);

	test();

	TEST_EXIT(PASS);
}
