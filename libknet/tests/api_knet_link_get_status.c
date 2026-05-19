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

#define TEST_NAME "api_knet_link_get_status"

static void test(void)
{
	int logfd;

	logfd = start_logging(stdout);
	knet_handle_t knet_h1, knet_h[2] = {0};
	struct knet_link_status status;
	struct sockaddr_storage lo;

	log_test(logfd, "Test knet_link_get_status incorrect knet_h");

	memset(&status, 0, sizeof(struct knet_link_status));

	FAIL_ON_SUCCESS(knet_link_get_status(NULL, 1, 0, &status, sizeof(struct knet_link_status)), EINVAL);

	knet_h1 = _ts_knet_handle_start(logfd, KNET_LOG_DEBUG, knet_h);

	log_test(logfd, "Test knet_link_get_status with unconfigured host_id");
	FAIL_ON_SUCCESS(knet_link_get_status(knet_h1, 1, 0, &status, sizeof(struct knet_link_status)), EINVAL);

	log_test(logfd, "Test knet_link_get_status with incorrect linkid");
	FAIL_ON_ERR(knet_host_add(knet_h1, 1));
	FAIL_ON_SUCCESS(knet_link_get_status(knet_h1, 1, KNET_MAX_LINK, &status, sizeof(struct knet_link_status)), EINVAL);

	log_test(logfd, "Test knet_link_get_status with incorrect status");
	FAIL_ON_SUCCESS(knet_link_get_status(knet_h1, 1, 0, NULL, 0), EINVAL);

	log_test(logfd, "Test knet_link_get_status with unconfigured link");
	FAIL_ON_SUCCESS(knet_link_get_status(knet_h1, 1, 0, &status, sizeof(struct knet_link_status)), EINVAL);

	log_test(logfd, "Test knet_link_get_status with correct values");
	FAIL_ON_ERR(_ts_knet_link_set_config(knet_h1, 1, 0, KNET_TRANSPORT_UDP, 0, AF_INET, 0, &lo, logfd));
	FAIL_ON_ERR(knet_link_get_status(knet_h1, 1, 0, &status, sizeof(struct knet_link_status)));

	TEST_EXIT_CLEAN(CONTINUE);
}

int main(int argc, char *argv[])
{
	printf("[TEST] %s: Test knet link get status\n", TEST_NAME);

	test();

	TEST_EXIT(PASS);
}
