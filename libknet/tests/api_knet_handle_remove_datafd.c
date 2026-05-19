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

#define TEST_NAME "api_knet_handle_remove_datafd"

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
	knet_handle_t knet_h1, knet_h[2] = {0};
	int datafd = 0;
	int8_t channel = 0;

	log_test(logfd, "Test knet_handle_remove_datafd incorrect knet_h");

	FAIL_ON_SUCCESS(knet_handle_remove_datafd(NULL, datafd), EINVAL);


	knet_h1 = _ts_knet_handle_start(logfd, KNET_LOG_DEBUG, knet_h);

	log_test(logfd, "Test knet_handle_remove_datafd with no datafd");
	datafd = 0;
	FAIL_ON_SUCCESS(knet_handle_remove_datafd(knet_h1, datafd), EINVAL);

	log_test(logfd, "Test knet_handle_remove_datafd with invalid datafd");
	datafd = 10;
	FAIL_ON_SUCCESS(knet_handle_remove_datafd(knet_h1, datafd), EINVAL);

	log_test(logfd, "Test knet_handle_remove_datafd with valid datafd");
	FAIL_ON_ERR(knet_handle_enable_sock_notify(knet_h1, &private_data, sock_notify));
	datafd = 0;
	channel = -1;
	FAIL_ON_ERR(knet_handle_add_datafd(knet_h1, &datafd, &channel, 0));

	FAIL_ON_ERR(knet_handle_remove_datafd(knet_h1, datafd));

	TEST_EXIT_CLEAN(CONTINUE);
}

int main(int argc, char *argv[])
{
	printf("[TEST] %s: Test knet handle remove datafd\n", TEST_NAME);

	test();

	TEST_EXIT(PASS);
}
