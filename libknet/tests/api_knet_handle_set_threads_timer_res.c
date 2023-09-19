/*
 * Copyright (C) 2016-2023 Red Hat, Inc.  All rights reserved.
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
	struct sockaddr_storage src, dst;

	if (make_local_sockaddr(&src, 0) < 0) {
		printf("Unable to convert src to sockaddr: %s\n", strerror(errno));
		exit(FAIL);
	}

	if (make_local_sockaddr(&dst, 1) < 0) {
		printf("Unable to convert dst to sockaddr: %s\n", strerror(errno));
		exit(FAIL);
	}

	printf("Test knet_handle_set_threads_timer_res incorrect knet_h\n");

	if ((!knet_handle_set_threads_timer_res(NULL, 0)) || (errno != EINVAL)) {
		printf("knet_handle_set_threads_timer_res accepted invalid knet_h or returned incorrect error: %s\n", strerror(errno));
		exit(FAIL);
	}

	setup_logpipes(logfds);
	knet_h1 = knet_handle_start(logfds, KNET_LOG_DEBUG, knet_h);

	printf("Test knet_handle_set_threads_timer_res with invalid timeres\n");
	FAIL_ON_SUCCESS(knet_handle_set_threads_timer_res(knet_h1, 999), EINVAL);

	printf("Configuring host and link");
	FAIL_ON_ERR(knet_host_add(knet_h1, 1));
	FAIL_ON_ERR(knet_link_set_config(knet_h1, 1, 0, KNET_TRANSPORT_UDP, &src, &dst, 0));
	FAIL_ON_ERR(knet_link_set_ping_timers(knet_h1, 1, 0, 1000, 300, 2048));

	printf("Test knet_handle_set_threads_timer_res with too high timeres\n");
	FAIL_ON_SUCCESS(knet_handle_set_threads_timer_res(knet_h1, 300001), EINVAL);

	printf("Test knet_handle_set_threads_timer_res with valid timeres\n");
	FAIL_ON_ERR(knet_handle_set_threads_timer_res(knet_h1, 20000));
	if (knet_h1->threads_timer_res != 20000) {
		printf("knet_handle_set_threads_timer_res did not set timeres to correct value: %s\n", strerror(errno));
		CLEAN_EXIT(FAIL);
	}
	CLEAN_EXIT(CONTINUE);
}

int main(int argc, char *argv[])
{
	test();

	return PASS;
}
