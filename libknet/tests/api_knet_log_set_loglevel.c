/*
 * Copyright (C) 2016-2017 Red Hat, Inc.  All rights reserved.
 *
 * Authors: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *
 * This software licensed under GPL-2.0+, LGPL-2.0+
 */

#include "config.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/resource.h>

#include "libknet.h"
#include "internals.h"

#include "test-common.h"

static void test(void)
{
	knet_handle_t knet_h;
	int logfds[2];

	printf("Test knet_log_set_loglevel incorrect knet_h\n");

	if ((!knet_log_set_loglevel(NULL, KNET_SUB_COMMON, KNET_LOG_DEBUG)) || (errno != EINVAL)) {
		printf("knet_log_set_loglevel accepted invalid knet_h or returned incorrect error: %s\n", strerror(errno));
		exit(FAIL);
	}

	setup_logpipes(logfds);

	printf("Test knet_log_set_loglevel incorrect subsystem\n");

	knet_h = knet_handle_start(logfds, KNET_LOG_INFO);

	if ((!knet_log_set_loglevel(knet_h, KNET_SUB_UNKNOWN - 1, KNET_LOG_DEBUG)) || (errno != EINVAL)) {
		printf("knet_log_set_loglevel accepted invalid subsystem or returned incorrect error: %s\n", strerror(errno));
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		knet_handle_free(knet_h);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_log_set_loglevel incorrect log level\n");

	if ((!knet_log_set_loglevel(knet_h, KNET_SUB_UNKNOWN, KNET_LOG_DEBUG + 1)) || (errno != EINVAL)) {
		printf("knet_log_set_loglevel accepted invalid log level or returned incorrect error: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_log_set_loglevel with valid parameters\n");

	if (knet_h->log_levels[KNET_SUB_UNKNOWN] != KNET_LOG_INFO) {
		printf("knet_handle_new did not init log_levels correctly?\n");
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	if (knet_log_set_loglevel(knet_h, KNET_SUB_UNKNOWN, KNET_LOG_DEBUG) < 0) {
		printf("knet_log_set_loglevel failed: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	if (knet_h->log_levels[KNET_SUB_UNKNOWN] != KNET_LOG_DEBUG) {
		printf("knet_log_set_loglevel did not set log level correctly\n");
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	knet_handle_free(knet_h);
	flush_logs(logfds[0], stdout);
	close_logpipes(logfds);
}

int main(int argc, char *argv[])
{
	test();

	return PASS;
}
