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

#define TEST_NAME "api_knet_log_get_subsystem_name"

static void test(void)
{
	int logfd;
	const char *res;

	logfd = start_logging(stdout);

	log_test(logfd, "Testing knet_log_get_subsystem_name normal lookup");
	res = knet_log_get_subsystem_name(KNET_SUB_NSSCRYPTO);
	if (strcmp(res, "nsscrypto")) {
		log_test(logfd, "knet_log_get_subsystem_name failed to get correct log subsystem name. got: %s expected: nsscrypto",
		       res);
		TEST_EXIT(FAIL);
	}

	log_test(logfd, "Testing knet_log_get_subsystem_name bad lookup (within boundaries)");
	res = knet_log_get_subsystem_name(KNET_SUB_UNKNOWN - 1);
	if (strcmp(res, "unknown")) {
		log_test(logfd, "knet_log_get_subsystem_name failed to get correct log subsystem name. got: %s expected: common",
		       res);
		TEST_EXIT(FAIL);
	}

	log_test(logfd, "Testing knet_log_get_subsystem_name bad lookup (outside boundaries)");
	res = knet_log_get_subsystem_name(KNET_MAX_SUBSYSTEMS);
	if (strcmp(res, "unknown")) {
		log_test(logfd, "knet_log_get_subsystem_name failed to get correct log subsystem name. got: %s expected: common",
		       res);
		TEST_EXIT(FAIL);
	}

	stop_logging();
}

int main(int argc, char *argv[])
{
	printf("[TEST] %s: Test knet log get subsystem name\n", TEST_NAME);

	test();

	TEST_EXIT(PASS);
}
