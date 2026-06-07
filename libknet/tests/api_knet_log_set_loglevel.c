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

#define TEST_NAME "api_knet_log_set_loglevel"

static void test(void)
{
	int logfd;
	knet_handle_t knet_h1, knet_h[2] = {0};

	logfd = start_logging(stdout);

	log_test(logfd, "Test knet_log_set_loglevel incorrect knet_h");

	FAIL_ON_SUCCESS(knet_log_set_loglevel(NULL, KNET_SUB_COMMON, KNET_LOG_DEBUG), EINVAL);

	knet_h1 = _ts_knet_handle_start(logfd, KNET_LOG_INFO, knet_h);

	log_test(logfd, "Test knet_log_set_loglevel incorrect subsystem");
	FAIL_ON_SUCCESS(knet_log_set_loglevel(knet_h1, KNET_SUB_UNKNOWN - 1, KNET_LOG_DEBUG), EINVAL);

	log_test(logfd, "Test knet_log_set_loglevel incorrect log level");
	FAIL_ON_SUCCESS(knet_log_set_loglevel(knet_h1, KNET_SUB_UNKNOWN, KNET_LOG_TRACE + 1), EINVAL);

	log_test(logfd, "Test knet_log_set_loglevel with valid parameters");
	if (knet_h1->log_levels[KNET_SUB_UNKNOWN] != KNET_LOG_INFO) {
		log_test(logfd, "knet_handle_new did not init log_levels correctly?");
		TEST_EXIT_CLEAN(FAIL);
	}
	FAIL_ON_ERR(knet_log_set_loglevel(knet_h1, KNET_SUB_UNKNOWN, KNET_LOG_DEBUG));
	if (knet_h1->log_levels[KNET_SUB_UNKNOWN] != KNET_LOG_DEBUG) {
		log_test(logfd, "knet_log_set_loglevel did not set log level to DEBUG correctly");
		TEST_EXIT_CLEAN(FAIL);
	}
	FAIL_ON_ERR(knet_log_set_loglevel(knet_h1, KNET_SUB_UNKNOWN, KNET_LOG_TRACE));
	if (knet_h1->log_levels[KNET_SUB_UNKNOWN] != KNET_LOG_TRACE) {
		log_test(logfd, "knet_log_set_loglevel did not set log level to TRACE correctly");
		TEST_EXIT_CLEAN(FAIL);
	}
	TEST_EXIT_CLEAN(CONTINUE);
}

int main(int argc, char *argv[])
{
	printf("[TEST] %s: Test knet log set loglevel\n", TEST_NAME);

	test();

	TEST_EXIT(PASS);
}
