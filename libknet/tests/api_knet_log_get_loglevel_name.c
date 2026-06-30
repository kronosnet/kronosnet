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

#define TEST_NAME "api_knet_log_get_loglevel_name"

static void test(void)
{
	int logfd;
	const char *res;

	logfd = start_logging(stdout);

	log_test(logfd, "Testing knet_log_get_loglevel_name normal lookup");
	res = knet_log_get_loglevel_name(KNET_LOG_DEBUG);
	if (strcmp(res, "debug")) {
		log_test(logfd, "knet_log_get_loglevel_name failed to get correct log level name. got: %s expected: debug",
		       res);
		TEST_EXIT(FAIL);
	}

	res = knet_log_get_loglevel_name(KNET_LOG_TRACE);
	if (strcmp(res, "trace")) {
		log_test(logfd, "knet_log_get_loglevel_name failed to get correct log level name. got: %s expected: debug",
		       res);
		TEST_EXIT(FAIL);
	}

	log_test(logfd, "Testing knet_log_get_loglevel_name bad lookup");
	res = knet_log_get_loglevel_name(KNET_LOG_TRACE+1);
	if (strcmp(res, "ERROR")) {
		log_test(logfd, "knet_log_get_loglevel_name failed to get correct log level name. got: %s expected: ERROR",
		       res);
		TEST_EXIT(FAIL);
	}

	stop_logging();
}

int main(int argc, char *argv[])
{
	printf("[TEST] %s: Test knet log get loglevel name\n", TEST_NAME);

	test();

	TEST_EXIT(PASS);
}
