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
#include "link.h"
#include "netutils.h"
#include "test-common.h"

#define TEST_NAME "api_knet_link_get_enable"

static void test(void)
{
	int logfd;

	logfd = start_logging(stdout);
	knet_handle_t knet_h1, knet_h[2];
	unsigned int enabled;
	struct sockaddr_storage lo;

	log_test(logfd, "Test knet_link_get_enable incorrect knet_h");

	if ((!knet_link_get_enable(NULL, 1, 0, &enabled)) || (errno != EINVAL)) {
		log_test(logfd, "knet_link_get_enable accepted invalid knet_h or returned incorrect error: %s", strerror(errno));
		TEST_EXIT(FAIL);
	}

	knet_h1 = _ts_knet_handle_start(logfd, KNET_LOG_DEBUG, knet_h);

	log_test(logfd, "Test knet_link_get_enable with unconfigured host_id");
	FAIL_ON_SUCCESS(knet_link_get_enable(knet_h1, 1, 0, &enabled), EINVAL);

	log_test(logfd, "Test knet_link_get_enable with incorrect linkid");
	FAIL_ON_ERR(knet_host_add(knet_h1, 1));
	FAIL_ON_SUCCESS(knet_link_get_enable(knet_h1, 1, KNET_MAX_LINK, &enabled), EINVAL);

	log_test(logfd, "Test knet_link_get_enable with unconfigured link");
	FAIL_ON_SUCCESS(knet_link_get_enable(knet_h1, 1, 0, &enabled), EINVAL);

	log_test(logfd, "Test knet_link_get_enable without enabled");
	FAIL_ON_SUCCESS(knet_link_get_enable(knet_h1, 1, 0, NULL), EINVAL);

	log_test(logfd, "Test knet_link_get_enable with disabled link");
	FAIL_ON_ERR(_ts_knet_link_set_config(knet_h1, 1, 0, KNET_TRANSPORT_UDP, 0, AF_INET, 0, &lo, logfd));
	FAIL_ON_ERR(knet_link_get_enable(knet_h1, 1, 0, &enabled));
	if (enabled) {
		log_test(logfd, "knet_link_get_enable returned incorrect value");
		TEST_EXIT_CLEAN(FAIL);
	}

	log_test(logfd, "Test knet_link_get_enable with enabled link");
	FAIL_ON_ERR(knet_link_set_enable(knet_h1, 1, 0, 1));
	FAIL_ON_ERR(knet_link_get_enable(knet_h1, 1, 0, &enabled));
	if (!enabled) {
		log_test(logfd, "knet_link_get_enable returned incorrect value");
		TEST_EXIT_CLEAN(FAIL);
	}
	TEST_EXIT_CLEAN(CONTINUE);
}

int main(int argc, char *argv[])
{
	printf("[TEST] %s: Test knet link get enable\n", TEST_NAME);

	test();

	TEST_EXIT(PASS);
}
