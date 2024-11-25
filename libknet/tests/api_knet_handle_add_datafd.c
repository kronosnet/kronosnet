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
	knet_handle_t knet_h[2];
	knet_handle_t knet_h1;
	int res;
	int logfds[2];
	int datafd = 0, i;
	int8_t channel = 0;
	int datafdmax[KNET_DATAFD_MAX];
	int8_t channels[KNET_DATAFD_MAX];

	printf("Test knet_handle_add_datafd incorrect knet_h\n");

	if ((!knet_handle_add_datafd(NULL, &datafd, &channel, 0)) || (errno != EINVAL)) {
		printf("knet_handle_add_datafd accepted invalid knet_h or returned incorrect error: %s\n", strerror(errno));
		exit(FAIL);
	}

	setup_logpipes(logfds);

	knet_h1 = knet_handle_start(logfds, KNET_LOG_DEBUG, knet_h);

	printf("Test knet_handle_add_datafd with no datafd\n");
	FAIL_ON_SUCCESS(knet_handle_add_datafd(knet_h1, NULL, &channel, 0), EINVAL);

	printf("Test knet_handle_add_datafd with no channel\n");
	FAIL_ON_SUCCESS(knet_handle_add_datafd(knet_h1, &datafd, NULL, 0), EINVAL);

	printf("Test knet_handle_add_datafd with invalid channel\n");
	channel = KNET_DATAFD_MAX;

	FAIL_ON_SUCCESS(knet_handle_add_datafd(knet_h1, &datafd, &channel, 0), EINVAL);


	printf("Test knet_handle_add_datafd with no socknotify\n");
	datafd = 0;
	channel = -1;
	FAIL_ON_SUCCESS(knet_handle_add_datafd(knet_h1, &datafd, &channel, 0), EINVAL);

	printf("Test knet_handle_add_datafd with automatic config values\n");
	FAIL_ON_ERR(knet_handle_enable_sock_notify(knet_h1, &private_data, sock_notify));

	datafd = 0;
	channel = -1;

	FAIL_ON_ERR(knet_handle_add_datafd(knet_h1, &datafd, &channel, 0));
	printf("got datafd: %d channel: %d\n", datafd, channel);

	printf("Test knet_handle_add_datafd with duplicated datafd\n");
	FAIL_ON_SUCCESS(knet_handle_add_datafd(knet_h1, &datafd, &channel, 0), EEXIST);

	printf("Test knet_handle_add_datafd with busy channel\n");
	datafd = datafd + 1;
	FAIL_ON_SUCCESS(knet_handle_add_datafd(knet_h1, &datafd, &channel, 0), EBUSY);

	datafd = datafd - 1;

	FAIL_ON_ERR(knet_handle_remove_datafd(knet_h1, datafd));

	printf("Test knet_handle_add_datafd with no available channels\n");
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

	CLEAN_EXIT(CONTINUE);
}

int main(int argc, char *argv[])
{
	test();

	return PASS;
}
