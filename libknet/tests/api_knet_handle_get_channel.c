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
#include "test-common.h"

#define TEST_NAME "api_knet_handle_get_channel"

static int private_data;

static void sock_notify(void *pvt_data,
			int datafd,
			int8_t channel,
			uint8_t tx_rx,
			int error,
			int errorno)
{
	return;
}

static void test(void)
{
	int logfd;
	knet_handle_t knet_h1, knet_h[2] = {0};
	int datafd = 0;
	int8_t channel = 0, old_channel = 0;

	logfd = start_logging(stdout);

	log_test(logfd, "Test knet_handle_get_channel incorrect knet_h");
	FAIL_ON_SUCCESS(knet_handle_get_channel(NULL, datafd, &channel), EINVAL);


	knet_h1 = _ts_knet_handle_start(logfd, KNET_LOG_DEBUG, knet_h);

	log_test(logfd, "Test knet_handle_get_channel with invalid datafd");
	datafd = 0;
	FAIL_ON_SUCCESS(knet_handle_get_channel(knet_h1, datafd, &channel), EINVAL);

	log_test(logfd, "Test knet_handle_get_channel with invalid channel");
	datafd = 10;
	FAIL_ON_SUCCESS(knet_handle_get_channel(knet_h1, datafd, NULL), EINVAL);

	log_test(logfd, "Test knet_handle_get_channel with unconfigured datafd/channel");
	datafd = 10;
	FAIL_ON_SUCCESS(knet_handle_get_channel(knet_h1, datafd, &channel), EINVAL);

	log_test(logfd, "Test knet_handle_get_channel with valid datafd");
	FAIL_ON_ERR(knet_handle_enable_sock_notify(knet_h1, &private_data, sock_notify));

	datafd = 0;
	old_channel = -1;

	FAIL_ON_ERR(knet_handle_add_datafd(knet_h1, &datafd, &old_channel));

	FAIL_ON_ERR(knet_handle_get_channel(knet_h1, datafd, &channel));
	if (old_channel != channel) {
		TEST_EXIT_CLEAN(FAIL);
	}
	TEST_EXIT_CLEAN(CONTINUE);
}

int main(int argc, char *argv[])
{
	printf("[TEST] %s: Test knet handle get channel\n", TEST_NAME);

	test();

	TEST_EXIT(PASS);
}
