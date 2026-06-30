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
#include <sys/time.h>
#include <sys/resource.h>

#include "libknet.h"
#include "internals.h"

#include "test-common.h"

#define TEST_NAME "api_knet_log_get_loglevel"

static void test(void)
{
	int logfd;
	knet_handle_t knet_h1, knet_h[2] = {0};
	uint8_t level;

	logfd = start_logging(stdout);

	log_test(logfd, "Test knet_log_get_loglevel incorrect knet_h");

	FAIL_ON_SUCCESS(knet_log_get_loglevel(NULL, KNET_SUB_UNKNOWN, &level), EINVAL);

	knet_h1 = _ts_knet_handle_start(logfd, KNET_LOG_INFO, knet_h);

	log_test(logfd, "Test knet_log_get_loglevel incorrect subsystem");
	FAIL_ON_SUCCESS(knet_log_get_loglevel(knet_h1, KNET_SUB_UNKNOWN - 1, &level), EINVAL);

	log_test(logfd, "Test knet_log_get_loglevel incorrect log level");
	FAIL_ON_SUCCESS(knet_log_get_loglevel(knet_h1, KNET_SUB_UNKNOWN, NULL), EINVAL);

	log_test(logfd, "Test knet_log_get_loglevel with valid parameters");
	FAIL_ON_ERR(knet_log_get_loglevel(knet_h1, KNET_SUB_UNKNOWN, &level));
	if (knet_h1->log_levels[KNET_SUB_UNKNOWN] != level) {
		log_test(logfd, "knet_log_get_loglevel failed to get the right value");
		TEST_EXIT_CLEAN(FAIL);
	}

	TEST_EXIT_CLEAN(CONTINUE);
}

int main(int argc, char *argv[])
{
	printf("[TEST] %s: Test knet log get loglevel\n", TEST_NAME);

	test();

	TEST_EXIT(PASS);
}
