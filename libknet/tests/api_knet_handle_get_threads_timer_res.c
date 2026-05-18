/*
 * Copyright (C) 2019-2026 Red Hat, Inc.  All rights reserved.
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

#define TEST_NAME "api_knet_handle_get_threads_timer_res"

static void test(void)
{
	int logfd;

	logfd = start_logging(stdout);
	knet_handle_t knet_h1, knet_h[2] = {0};
	useconds_t timeres;

	log_test(logfd, "Test knet_handle_get_threads_timer_res incorrect knet_h");

	FAIL_ON_SUCCESS(knet_handle_get_threads_timer_res(NULL, &timeres), EINVAL);

	knet_h1 = _ts_knet_handle_start(logfd, KNET_LOG_DEBUG, knet_h);

	log_test(logfd, "Test knet_handle_get_threads_timer_res with invalid timeres");
	FAIL_ON_SUCCESS(knet_handle_get_threads_timer_res(knet_h1, NULL), EINVAL);

	log_test(logfd, "Test knet_handle_get_threads_timer_res with valid timeres");
	FAIL_ON_ERR(knet_handle_get_threads_timer_res(knet_h1, &timeres));
	if (timeres != knet_h1->threads_timer_res) {
		log_test(logfd, "knet_handle_get_threads_timer_res did not get timeres correct value: %s", strerror(errno));
		TEST_EXIT_CLEAN(FAIL);
	}

	log_test(logfd, "Test knet_handle_get_threads_timer_res with valid timeres");
	FAIL_ON_ERR(knet_handle_set_threads_timer_res(knet_h1, 1000));
	FAIL_ON_ERR(knet_handle_get_threads_timer_res(knet_h1, &timeres));
	if (timeres != knet_h1->threads_timer_res) {
		log_test(logfd, "knet_handle_get_threads_timer_res did not get timeres correct value: %s", strerror(errno));
		TEST_EXIT_CLEAN(FAIL);
	}

	TEST_EXIT_CLEAN(CONTINUE);
}

int main(int argc, char *argv[])
{
	printf("[TEST] %s: Test knet handle get threads timer res\n", TEST_NAME);

	test();

	TEST_EXIT(PASS);
}
