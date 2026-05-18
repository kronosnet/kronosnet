/*
 * Copyright (C) 2020-2026 Red Hat, Inc.  All rights reserved.
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

#define TEST_NAME "api_knet_handle_set_onwire_ver"

static void test(void)
{
	int logfd;

	logfd = start_logging(stdout);
	knet_handle_t knet_h1, knet_h[2] = {0};

	log_test(logfd, "Test knet_handle_set_onwire_ver incorrect knet_h");

	FAIL_ON_SUCCESS(knet_handle_set_onwire_ver(NULL, 1), EINVAL);


	knet_h1 = _ts_knet_handle_start(logfd, KNET_LOG_DEBUG, knet_h);

	knet_h1->onwire_min_ver = 2;
	knet_h1->onwire_max_ver = 3;

	log_test(logfd, "Test knet_handle_set_onwire_ver with invalid onwire_ver (1)");
	FAIL_ON_SUCCESS(knet_handle_set_onwire_ver(knet_h1, 1), EINVAL);

	log_test(logfd, "Test knet_handle_set_onwire_ver with invalid onwire_ver (4)");
	FAIL_ON_SUCCESS(knet_handle_set_onwire_ver(knet_h1, 4), EINVAL);

	log_test(logfd, "Test knet_handle_set_onwire_ver with valid onwire_ver (2)");
	if (knet_handle_set_onwire_ver(knet_h1, 2) < 0) {
		log_test(logfd, "knet_handle_set_onwire_ver did not accepted valid onwire_ver");
		TEST_EXIT_CLEAN(FAIL);
	}

	if (knet_h1->onwire_force_ver != 2) {
		log_test(logfd, "knet_handle_set_onwire_ver did not set correct onwire_ver");
		TEST_EXIT_CLEAN(FAIL);
	}


	log_test(logfd, "Test knet_handle_set_onwire_ver reset (0)");
	FAIL_ON_ERR(knet_handle_set_onwire_ver(knet_h1, 0));

	if (knet_h1->onwire_force_ver != 0) {
		log_test(logfd, "knet_handle_set_onwire_ver did not set correct onwire_ver");
		TEST_EXIT_CLEAN(FAIL);
	}
	TEST_EXIT_CLEAN(CONTINUE);
}

int main(int argc, char *argv[])
{
	printf("[TEST] %s: Test knet handle set onwire ver\n", TEST_NAME);

	test();

	TEST_EXIT(PASS);
}
