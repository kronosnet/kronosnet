/*
 * Copyright (C) 2016-2018 Red Hat, Inc.  All rights reserved.
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
	uint8_t level;
	int logfds[2];

	printf("Test knet_log_get_loglevel incorrect knet_h\n");

	if ((!knet_log_get_loglevel(NULL, KNET_SUB_UNKNOWN, &level)) || (errno != EINVAL)) {
		printf("knet_log_get_loglevel accepted invalid knet_h or returned incorrect error: %s\n", strerror(errno));
		exit(FAIL);
	}

	setup_logpipes(logfds);

	printf("Test knet_log_get_loglevel incorrect subsystem\n");

	knet_h = knet_handle_start(logfds, KNET_LOG_INFO);

	if ((!knet_log_get_loglevel(knet_h, KNET_SUB_UNKNOWN - 1, &level)) || (errno != EINVAL)) {
		printf("knet_log_get_loglevel accepted invalid subsystem or returned incorrect error: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_log_get_loglevel incorrect log level\n");

	if ((!knet_log_get_loglevel(knet_h, KNET_SUB_UNKNOWN, NULL)) || (errno != EINVAL)) {
		printf("knet_log_get_loglevel accepted invalid log level or returned incorrect error: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_log_get_loglevel with valid parameters\n");

	if (knet_log_get_loglevel(knet_h, KNET_SUB_UNKNOWN, &level ) < 0) {
		printf("knet_log_get_loglevel failed: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	if (knet_h->log_levels[KNET_SUB_UNKNOWN] != level) {
		printf("knet_log_get_loglevel failed to get the right value\n");
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
