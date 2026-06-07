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

#define TEST_NAME "api_knet_handle_setfwd"

static void test(void)
{
	int logfd;
	knet_handle_t knet_h1, knet_h[2] = {0};

	logfd = start_logging(stdout);

	log_test(logfd, "Test knet_handle_setfwd with invalid knet_h");

	FAIL_ON_SUCCESS(knet_handle_setfwd(NULL, 0), EINVAL);


	log_test(logfd, "Test knet_handle_setfwd with invalid param (2) ");
	knet_h1 = _ts_knet_handle_start(logfd, KNET_LOG_DEBUG, knet_h);
	FAIL_ON_SUCCESS(knet_handle_setfwd(knet_h1, 2), EINVAL);

	log_test(logfd, "Test knet_handle_setfwd with valid param (1) ");
	FAIL_ON_ERR(knet_handle_setfwd(knet_h1, 1));

	if (knet_h1->enabled != 1) {
		log_test(logfd, "knet_handle_setfwd failed to set correct value");
		TEST_EXIT_CLEAN(FAIL);
	}

	log_test(logfd, "Test knet_handle_setfwd with valid param (0) ");
	FAIL_ON_ERR(knet_handle_setfwd(knet_h1, 0));

	if (knet_h1->enabled != 0) {
		log_test(logfd, "knet_handle_setfwd failed to set correct value");
		TEST_EXIT_CLEAN(FAIL);
	}

	TEST_EXIT_CLEAN(CONTINUE);
}

int main(int argc, char *argv[])
{
	printf("[TEST] %s: Test knet handle setfwd\n", TEST_NAME);

	test();

	TEST_EXIT(PASS);
}
