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

#define TEST_NAME "api_knet_log_get_loglevel_id"

static void test(void)
{
	int logfd;

	logfd = start_logging(stdout);
	uint8_t res;

	log_test(logfd, "Testing knet_log_get_loglevel_id normal lookup");
	res = knet_log_get_loglevel_id("debug");
	if (res != KNET_LOG_DEBUG) {
		log_test(logfd, "knet_log_get_loglevel_id failed to get correct log level id. got: %u expected: %d",
		       res, KNET_LOG_DEBUG);
		TEST_EXIT(FAIL);
	}

	log_test(logfd, "Testing knet_log_get_loglevel_id bad lookup");
	res = knet_log_get_loglevel_id("whatever");
	if (res != KNET_LOG_ERR) {
		log_test(logfd, "knet_log_get_loglevel_id failed to get correct log level id. got: %u expected: %d",
		       res, KNET_LOG_ERR);
		TEST_EXIT(FAIL);
	}

	stop_logging();
}

int main(int argc, char *argv[])
{
	printf("[TEST] %s: Test knet log get loglevel id\n", TEST_NAME);

	test();

	TEST_EXIT(PASS);
}
