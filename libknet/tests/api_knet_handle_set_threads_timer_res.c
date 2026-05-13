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

#define TEST_NAME "api_knet_handle_set_threads_timer_res"

static void test(void)
{
	int logfd;

	logfd = start_logging(stdout);
	knet_handle_t knet_h1, knet_h[2];
	struct sockaddr_storage src, dst;

	if (make_local_sockaddr(&src, 0, logfd) < 0) {
		log_test(logfd, "Unable to convert src to sockaddr: %s", strerror(errno));
		TEST_EXIT(FAIL);
	}

	if (make_local_sockaddr(&dst, 1, logfd) < 0) {
		log_test(logfd, "Unable to convert dst to sockaddr: %s", strerror(errno));
		TEST_EXIT(FAIL);
	}

	log_test(logfd, "Test knet_handle_set_threads_timer_res incorrect knet_h");

	if ((!knet_handle_set_threads_timer_res(NULL, 0)) || (errno != EINVAL)) {
		log_test(logfd, "knet_handle_set_threads_timer_res accepted invalid knet_h or returned incorrect error: %s", strerror(errno));
		TEST_EXIT(FAIL);
	}

	knet_h1 = _ts_knet_handle_start(logfd, KNET_LOG_DEBUG, knet_h);

	log_test(logfd, "Test knet_handle_set_threads_timer_res with invalid timeres");
	FAIL_ON_SUCCESS(knet_handle_set_threads_timer_res(knet_h1, 999), EINVAL);

	log_test(logfd, "Configuring host and link");
	FAIL_ON_ERR(knet_host_add(knet_h1, 1));
	FAIL_ON_ERR(knet_link_set_config(knet_h1, 1, 0, KNET_TRANSPORT_UDP, &src, &dst, 0));
	FAIL_ON_ERR(knet_link_set_ping_timers(knet_h1, 1, 0, 1000, 300, 2048));

	log_test(logfd, "Test knet_handle_set_threads_timer_res with too high timeres");
	FAIL_ON_SUCCESS(knet_handle_set_threads_timer_res(knet_h1, 300001), EINVAL);

	log_test(logfd, "Test knet_handle_set_threads_timer_res with valid timeres");
	FAIL_ON_ERR(knet_handle_set_threads_timer_res(knet_h1, 20000));
	if (knet_h1->threads_timer_res != 20000) {
		log_test(logfd, "knet_handle_set_threads_timer_res did not set timeres to correct value: %s", strerror(errno));
		TEST_EXIT_CLEAN(FAIL);
	}
	TEST_EXIT_CLEAN(CONTINUE);
}

int main(int argc, char *argv[])
{
	printf("[TEST] %s: Test knet handle set threads timer res\n", TEST_NAME);

	test();

	TEST_EXIT(PASS);
}
