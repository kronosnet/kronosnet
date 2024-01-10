/*
 * Copyright (C) 2016-2024 Red Hat, Inc.  All rights reserved.
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
	knet_handle_t knet_h1, knet_h[2];
	int res;
	int logfds[2];
	int datafd = 0;
	int8_t channel = 0, old_channel = 0;

	printf("Test knet_handle_get_channel incorrect knet_h\n");
	if ((!knet_handle_get_channel(NULL, datafd, &channel)) || (errno != EINVAL)) {
		printf("knet_handle_get_channel accepted invalid knet_h or returned incorrect error: %s\n", strerror(errno));
		exit(FAIL);
	}

	setup_logpipes(logfds);

	knet_h1 = knet_handle_start(logfds, KNET_LOG_DEBUG, knet_h);

	printf("Test knet_handle_get_channel with invalid datafd\n");
	datafd = 0;
	FAIL_ON_SUCCESS(knet_handle_get_channel(knet_h1, datafd, &channel), EINVAL);

	printf("Test knet_handle_get_channel with invalid channel\n");
	datafd = 10;
	FAIL_ON_SUCCESS(knet_handle_get_channel(knet_h1, datafd, NULL), EINVAL);

	printf("Test knet_handle_get_channel with unconfigured datafd/channel\n");
	datafd = 10;
	FAIL_ON_SUCCESS(knet_handle_get_channel(knet_h1, datafd, &channel), EINVAL);

	printf("Test knet_handle_get_channel with valid datafd\n");
	FAIL_ON_ERR(knet_handle_enable_sock_notify(knet_h1, &private_data, sock_notify));

	datafd = 0;
	old_channel = -1;

	FAIL_ON_ERR(knet_handle_add_datafd(knet_h1, &datafd, &old_channel));

	FAIL_ON_ERR(knet_handle_get_channel(knet_h1, datafd, &channel));
	if (old_channel != channel) {
		CLEAN_EXIT(FAIL);
	}
	CLEAN_EXIT(CONTINUE);
}

int main(int argc, char *argv[])
{
	test();

	return PASS;
}
