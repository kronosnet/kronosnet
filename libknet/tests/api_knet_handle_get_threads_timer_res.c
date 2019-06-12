/*
 * Copyright (C) 2019 Red Hat, Inc.  All rights reserved.
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
	knet_handle_t knet_h;
	int logfds[2];
	useconds_t timeres;

	printf("Test knet_handle_get_threads_timer_res incorrect knet_h\n");

	if ((!knet_handle_get_threads_timer_res(NULL, &timeres)) || (errno != EINVAL)) {
		printf("knet_handle_get_threads_timer_res accepted invalid knet_h or returned incorrect error: %s\n", strerror(errno));
		exit(FAIL);
	}

	setup_logpipes(logfds);

	knet_h = knet_handle_start(logfds, KNET_LOG_DEBUG);

	printf("Test knet_handle_get_threads_timer_res with invalid timeres\n");

	if ((!knet_handle_get_threads_timer_res(knet_h, NULL)) || (errno != EINVAL)) {
		printf("knet_handle_get_threads_timer_res accepted invalid timeres or returned incorrect error: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_handle_get_threads_timer_res with valid timeres\n");

	if (knet_handle_get_threads_timer_res(knet_h, &timeres)) {
		printf("knet_handle_get_threads_timer_res did not accept valid timeres: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	if (timeres != knet_h->threads_timer_res) {
		printf("knet_handle_get_threads_timer_res did not get timeres correct value: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_handle_get_threads_timer_res with valid timeres\n");

	if (knet_handle_set_threads_timer_res(knet_h, 1000)) {
		printf("knet_handle_set_threads_timer_res did not accept valid timeres: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	if (knet_handle_get_threads_timer_res(knet_h, &timeres)) {
		printf("knet_handle_get_threads_timer_res did not accept valid timeres: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	if (timeres != knet_h->threads_timer_res) {
		printf("knet_handle_get_threads_timer_res did not get timeres correct value: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	knet_handle_free(knet_h);
	flush_logs(logfds[0], stdout);
	close_logpipes(logfds);
}

int main(int argc, char *argv[])
{
	test();

	return PASS;
}
