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
#include "host.h"
#include "test-common.h"

#define TEST_NAME "api_knet_host_get_status"

static void test(void)
{
	int logfd;

	logfd = start_logging(stdout);
	knet_handle_t knet_h1, knet_h[2];
	struct knet_host_status status;

	log_test(logfd, "Test knet_host_get_status incorrect knet_h");

	memset(&status, 0, sizeof(struct knet_host_status));

	if ((!knet_host_get_status(NULL, 1, &status)) || (errno != EINVAL)) {
		log_test(logfd, "knet_host_get_status accepted invalid knet_h or returned incorrect error: %s", strerror(errno));
		TEST_EXIT(FAIL);
	}


	knet_h1 = _ts_knet_handle_start(logfd, KNET_LOG_DEBUG, knet_h);

	log_test(logfd, "Test knet_host_get_status with unconfigured host_id");
	FAIL_ON_SUCCESS(knet_host_get_status(knet_h1, 1, &status), EINVAL);

	log_test(logfd, "Test knet_host_get_status with incorrect status");
	FAIL_ON_ERR(knet_host_add(knet_h1, 1));
	FAIL_ON_SUCCESS(knet_host_get_status(knet_h1, 1, NULL), EINVAL);

	log_test(logfd, "Test knet_host_get_status with correct values");
	FAIL_ON_ERR(knet_host_get_status(knet_h1, 1, &status));

	TEST_EXIT_CLEAN(CONTINUE);
}

int main(int argc, char *argv[])
{
	printf("[TEST] %s: Test knet host get status\n", TEST_NAME);

	test();

	TEST_EXIT(PASS);
}
