/*
 * Copyright (C) 2019-2025 Red Hat, Inc.  All rights reserved.
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

static void test(void)
{
	knet_handle_t knet_h1, knet_h[2];
	int res;
	int logfds[2];
	useconds_t timeres;

	printf("Test knet_handle_get_threads_timer_res incorrect knet_h\n");

	if ((!knet_handle_get_threads_timer_res(NULL, &timeres)) || (errno != EINVAL)) {
		printf("knet_handle_get_threads_timer_res accepted invalid knet_h or returned incorrect error: %s\n", strerror(errno));
		exit(FAIL);
	}

	setup_logpipes(logfds);
	knet_h1 = knet_handle_start(logfds, KNET_LOG_DEBUG, knet_h);

	printf("Test knet_handle_get_threads_timer_res with invalid timeres\n");
	FAIL_ON_SUCCESS(knet_handle_get_threads_timer_res(knet_h1, NULL), EINVAL);

	printf("Test knet_handle_get_threads_timer_res with valid timeres\n");
	FAIL_ON_ERR(knet_handle_get_threads_timer_res(knet_h1, &timeres));
	if (timeres != knet_h1->threads_timer_res) {
		printf("knet_handle_get_threads_timer_res did not get timeres correct value: %s\n", strerror(errno));
		CLEAN_EXIT(FAIL);
	}

	printf("Test knet_handle_get_threads_timer_res with valid timeres\n");
	FAIL_ON_ERR(knet_handle_set_threads_timer_res(knet_h1, 1000));
	FAIL_ON_ERR(knet_handle_get_threads_timer_res(knet_h1, &timeres));
	if (timeres != knet_h1->threads_timer_res) {
		printf("knet_handle_get_threads_timer_res did not get timeres correct value: %s\n", strerror(errno));
		CLEAN_EXIT(FAIL);
	}

	CLEAN_EXIT(CONTINUE);
}

int main(int argc, char *argv[])
{
	test();

	return PASS;
}
