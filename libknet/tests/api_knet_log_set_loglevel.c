/*
 * Copyright (C) 2016-2022 Red Hat, Inc.  All rights reserved.
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
#include <sys/time.h>
#include <sys/resource.h>

#include "libknet.h"
#include "internals.h"

#include "test-common.h"

static void test(void)
{
	knet_handle_t knet_h1, knet_h[2];
	int res;
	int logfds[2];

	printf("Test knet_log_set_loglevel incorrect knet_h\n");

	if ((!knet_log_set_loglevel(NULL, KNET_SUB_COMMON, KNET_LOG_DEBUG)) || (errno != EINVAL)) {
		printf("knet_log_set_loglevel accepted invalid knet_h or returned incorrect error: %s\n", strerror(errno));
		exit(FAIL);
	}

	setup_logpipes(logfds);
	knet_h1 = knet_handle_start(logfds, KNET_LOG_INFO, knet_h);

	printf("Test knet_log_set_loglevel incorrect subsystem\n");
	FAIL_ON_SUCCESS(knet_log_set_loglevel(knet_h1, KNET_SUB_UNKNOWN - 1, KNET_LOG_DEBUG), EINVAL);

	printf("Test knet_log_set_loglevel incorrect log level\n");
	FAIL_ON_SUCCESS(knet_log_set_loglevel(knet_h1, KNET_SUB_UNKNOWN, KNET_LOG_DEBUG + 1), EINVAL);

	printf("Test knet_log_set_loglevel with valid parameters\n");
	if (knet_h1->log_levels[KNET_SUB_UNKNOWN] != KNET_LOG_INFO) {
		printf("knet_handle_new did not init log_levels correctly?\n");
		CLEAN_EXIT(FAIL);
	}
	FAIL_ON_ERR(knet_log_set_loglevel(knet_h1, KNET_SUB_UNKNOWN, KNET_LOG_DEBUG));
	if (knet_h1->log_levels[KNET_SUB_UNKNOWN] != KNET_LOG_DEBUG) {
		printf("knet_log_set_loglevel did not set log level correctly\n");
		CLEAN_EXIT(FAIL);
	}
	CLEAN_EXIT(CONTINUE);
}

int main(int argc, char *argv[])
{
	test();

	return PASS;
}
