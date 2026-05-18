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

#define TEST_NAME "api_knet_handle_set_transport_reconnect_interval"

static void test(void)
{
	int logfd;

	logfd = start_logging(stdout);
	knet_handle_t knet_h1, knet_h[2] = {0};

	log_test(logfd, "Test knet_handle_set_transport_reconnect_interval with incorrect knet_h");

	FAIL_ON_SUCCESS(knet_handle_set_transport_reconnect_interval(NULL, 1000), EINVAL);


	knet_h1 = _ts_knet_handle_start(logfd, KNET_LOG_DEBUG, knet_h);

	log_test(logfd, "Test knet_handle_set_transport_reconnect_interval with incorrect msecs");
	FAIL_ON_SUCCESS(knet_handle_set_transport_reconnect_interval(knet_h1, 0), EINVAL);

	log_test(logfd, "Test knet_handle_set_transport_reconnect_interval with correct values");
	FAIL_ON_ERR(knet_handle_set_transport_reconnect_interval(knet_h1, 2000));

	// coverity[MISSING_LOCK:SUPPRESS] use out of the main library is 'OK' here. ish
	if (knet_h1->reconnect_int != 2000) {
		log_test(logfd, "knet_handle_set_transport_reconnect_interval failed to set correct value");
		TEST_EXIT_CLEAN(FAIL);
	}

	TEST_EXIT_CLEAN(CONTINUE);
}

int main(int argc, char *argv[])
{
	printf("[TEST] %s: Test knet handle set transport reconnect interval\n", TEST_NAME);

	test();

	TEST_EXIT(PASS);
}
