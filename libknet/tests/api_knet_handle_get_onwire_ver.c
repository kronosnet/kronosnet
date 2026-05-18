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

#define TEST_NAME "api_knet_handle_get_onwire_ver"

static void test(void)
{
	int logfd;

	logfd = start_logging(stdout);
	knet_handle_t knet_h1, knet_h[2];
	uint8_t onwire_min_ver, onwire_max_ver, onwire_ver;

	log_test(logfd, "Test knet_handle_get_onwire_ver incorrect knet_h");

	if ((!knet_handle_get_onwire_ver(NULL, 1, &onwire_min_ver, &onwire_max_ver, &onwire_ver)) || (errno != EINVAL)) {
		log_test(logfd, "knet_handle_get_onwire_ver accepted invalid knet_h or returned incorrect error: %s", strerror(errno));
		TEST_EXIT(FAIL);
	}

	knet_h1 = knet_handle_start(logfd, KNET_LOG_DEBUG, knet_h);

	log_test(logfd, "Test knet_handle_get_onwire_ver with invalid host_id");
	FAIL_ON_SUCCESS(knet_handle_get_onwire_ver(knet_h1, 199, &onwire_min_ver, &onwire_max_ver, &onwire_ver), EINVAL);

	log_test(logfd, "Test knet_handle_get_onwire_ver with invalid onwire_min_ver");
	FAIL_ON_SUCCESS(knet_handle_get_onwire_ver(knet_h1, knet_h1->host_id, NULL, &onwire_max_ver, &onwire_ver), EINVAL);

	log_test(logfd, "Test knet_handle_get_onwire_ver with invalid onwire_max_ver");
	FAIL_ON_SUCCESS(knet_handle_get_onwire_ver(knet_h1, knet_h1->host_id, &onwire_min_ver, NULL, &onwire_ver), EINVAL);

	log_test(logfd, "Test knet_handle_get_onwire_ver with invalid onwire_ver");
	FAIL_ON_SUCCESS(knet_handle_get_onwire_ver(knet_h1, knet_h1->host_id, &onwire_min_ver, &onwire_max_ver, NULL), EINVAL);

	log_test(logfd, "Test knet_handle_get_onwire_ver with valid data");
	FAIL_ON_ERR(knet_handle_get_onwire_ver(knet_h1, knet_h1->host_id, &onwire_min_ver, &onwire_max_ver, &onwire_ver));

	if (onwire_min_ver != knet_h1->onwire_min_ver) {
		log_test(logfd, "knet_handle_get_onwire_ver returned invalid onwire_min_ver");
		TEST_EXIT_CLEAN(FAIL);
	}

	if (onwire_max_ver != knet_h1->onwire_max_ver) {
		log_test(logfd, "knet_handle_get_onwire_ver returned invalid onwire_max_ver");
		TEST_EXIT_CLEAN(FAIL);
	}

	if (onwire_ver != knet_h1->onwire_ver) {
		log_test(logfd, "knet_handle_get_onwire_ver returned invalid onwire_ver");
		TEST_EXIT_CLEAN(FAIL);
	}
	TEST_EXIT_CLEAN(CONTINUE);
}

int main(int argc, char *argv[])
{
	printf("[TEST] %s: Test knet handle get onwire ver\n", TEST_NAME);

	test();

	TEST_EXIT(PASS);
}
