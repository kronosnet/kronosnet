/*
 * Copyright (C) 2016-2020 Red Hat, Inc.  All rights reserved.
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

	printf("Test knet_handle_setfwd with invalid knet_h\n");

	if ((!knet_handle_setfwd(NULL, 0)) || (errno != EINVAL)) {
		printf("knet_handle_setfwd accepted invalid knet_h parameter\n");
		exit(FAIL);
	}

	setup_logpipes(logfds);

	printf("Test knet_handle_setfwd with invalid param (2) \n");

	knet_h = knet_handle_start(logfds, KNET_LOG_DEBUG);

	if ((!knet_handle_setfwd(knet_h, 2)) || (errno != EINVAL)) {
		printf("knet_handle_setfwd accepted invalid param for enabled: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_handle_setfwd with valid param (1) \n");

	if (knet_handle_setfwd(knet_h, 1) < 0) {
		printf("knet_handle_setfwd failed: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	if (knet_h->enabled != 1) {
		printf("knet_handle_setfwd failed to set correct value");
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_handle_setfwd with valid param (0) \n");

	if (knet_handle_setfwd(knet_h, 0) < 0) {
		printf("knet_handle_setfwd failed: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	if (knet_h->enabled != 0) {
		printf("knet_handle_setfwd failed to set correct value");
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
