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

#define TEST_NAME "api_knet_handle_add_datafd"

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

	logfd = start_logging(stdout);
	knet_handle_t knet_h[2] = {0};
	knet_handle_t knet_h1;
	int datafd = 0, i;
	int8_t channel = 0;
	int datafdmax[KNET_DATAFD_MAX];
	int8_t channels[KNET_DATAFD_MAX];

	log_test(logfd, "Test knet_handle_add_datafd incorrect knet_h");

	FAIL_ON_SUCCESS(knet_handle_add_datafd(NULL, &datafd, &channel, 0), EINVAL);


	knet_h1 = _ts_knet_handle_start(logfd, KNET_LOG_DEBUG, knet_h);

	log_test(logfd, "Test knet_handle_add_datafd with no datafd");
	FAIL_ON_SUCCESS(knet_handle_add_datafd(knet_h1, NULL, &channel, 0), EINVAL);

	log_test(logfd, "Test knet_handle_add_datafd with no channel");
	FAIL_ON_SUCCESS(knet_handle_add_datafd(knet_h1, &datafd, NULL, 0), EINVAL);

	log_test(logfd, "Test knet_handle_add_datafd with invalid channel");
	channel = KNET_DATAFD_MAX;

	FAIL_ON_SUCCESS(knet_handle_add_datafd(knet_h1, &datafd, &channel, 0), EINVAL);


	log_test(logfd, "Test knet_handle_add_datafd with no socknotify");
	datafd = 0;
	channel = -1;
	FAIL_ON_SUCCESS(knet_handle_add_datafd(knet_h1, &datafd, &channel, 0), EINVAL);

	log_test(logfd, "Test knet_handle_add_datafd with automatic config values");
	FAIL_ON_ERR(knet_handle_enable_sock_notify(knet_h1, &private_data, sock_notify));

	datafd = 0;
	channel = -1;

	FAIL_ON_ERR(knet_handle_add_datafd(knet_h1, &datafd, &channel, 0));
	log_test(logfd, "got datafd: %d channel: %d", datafd, channel);

	log_test(logfd, "Test knet_handle_add_datafd with duplicated datafd");
	FAIL_ON_SUCCESS(knet_handle_add_datafd(knet_h1, &datafd, &channel, 0), EEXIST);

	log_test(logfd, "Test knet_handle_add_datafd with busy channel");
	datafd = datafd + 1;
	FAIL_ON_SUCCESS(knet_handle_add_datafd(knet_h1, &datafd, &channel, 0), EBUSY);

	datafd = datafd - 1;

	FAIL_ON_ERR(knet_handle_remove_datafd(knet_h1, datafd));

	log_test(logfd, "Test knet_handle_add_datafd with no available channels");
	for (i = 0; i < KNET_DATAFD_MAX; i++) {
		datafdmax[i] = 0;
		channels[i] = -1;
		FAIL_ON_ERR(knet_handle_add_datafd(knet_h1, &datafdmax[i], &channels[i], 0));
	}

	datafd = 0;
	channel = -1;

	FAIL_ON_SUCCESS(knet_handle_add_datafd(knet_h1, &datafd, &channel, 0), EBUSY);

	for (i = 0; i < KNET_DATAFD_MAX; i++) {
		FAIL_ON_ERR(knet_handle_remove_datafd(knet_h1, datafdmax[i]));
	}

	TEST_EXIT_CLEAN(CONTINUE);
}

int main(int argc, char *argv[])
{
	printf("[TEST] %s: Test knet handle add datafd\n", TEST_NAME);

	test();

	TEST_EXIT(PASS);
}
