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
	knet_handle_t knet_h;
	int logfds[2];
	int datafd = 0;
	int8_t channel = 0, old_channel = 0;

	printf("Test knet_handle_get_channel incorrect knet_h\n");

	if ((!knet_handle_get_channel(NULL, datafd, &channel)) || (errno != EINVAL)) {
		printf("knet_handle_get_channel accepted invalid knet_h or returned incorrect error: %s\n", strerror(errno));
		exit(FAIL);
	}

	setup_logpipes(logfds);

	knet_h = knet_handle_start(logfds, KNET_LOG_DEBUG);

	printf("Test knet_handle_get_channel with invalid datafd\n");

	datafd = 0;

	if ((!knet_handle_get_channel(knet_h, datafd, &channel)) || (errno != EINVAL)) {
		printf("knet_handle_get_channel accepted invalid datafd or returned incorrect error: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_handle_get_channel with invalid channel\n");

	datafd = 10;

	if ((!knet_handle_get_channel(knet_h, datafd, NULL)) || (errno != EINVAL)) {
		printf("knet_handle_get_channel accepted invalid channel or returned incorrect error: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_handle_get_channel with unconfigured datafd/channel\n");

	datafd = 10;

	if ((!knet_handle_get_channel(knet_h, datafd, &channel)) || (errno != EINVAL)) {
		printf("knet_handle_get_channel accepted invalid channel or returned incorrect error: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_handle_get_channel with valid datafd\n");

	if (knet_handle_enable_sock_notify(knet_h, &private_data, sock_notify) < 0) {
		printf("knet_handle_enable_sock_notify failed: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
        }

	datafd = 0;
	old_channel = -1;

	if (knet_handle_add_datafd(knet_h, &datafd, &old_channel) < 0) {
		printf("knet_handle_add_datafd failed: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	if (knet_handle_get_channel(knet_h, datafd, &channel) < 0) {
		printf("knet_handle_get_channel failed: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	if (old_channel != channel) {
		printf("knet_handle_get_channel got incorrect channel\n");
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	knet_handle_free(knet_h);
	flush_logs(logfds[0], stdout);
	close_logpipes(logfds);
}

int main(int argc, char *argv[])
{
	test();

	return PASS;
}
