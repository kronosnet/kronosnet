/*
 * Copyright (C) 2016-2020 Red Hat, Inc.  All rights reserved.
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
	knet_handle_t knet_h;
	int logfds[2];
	int datafd = 0, i;
	int8_t channel = 0;
	int datafdmax[KNET_DATAFD_MAX];
	int8_t channels[KNET_DATAFD_MAX];

	printf("Test knet_handle_add_datafd incorrect knet_h\n");

	if ((!knet_handle_add_datafd(NULL, &datafd, &channel)) || (errno != EINVAL)) {
		printf("knet_handle_add_datafd accepted invalid knet_h or returned incorrect error: %s\n", strerror(errno));
		exit(FAIL);
	}

	setup_logpipes(logfds);

	knet_h = knet_handle_start(logfds, KNET_LOG_DEBUG);

	printf("Test knet_handle_add_datafd with no datafd\n");

	if ((!knet_handle_add_datafd(knet_h, NULL, &channel)) || (errno != EINVAL)) {
		printf("knet_handle_add_datafd accepted invalid datafd or returned incorrect error: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_handle_add_datafd with no channel\n");

	if ((!knet_handle_add_datafd(knet_h, &datafd, NULL)) || (errno != EINVAL)) {
		printf("knet_handle_add_datafd accepted invalid channel or returned incorrect error: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_handle_add_datafd with invalid channel\n");

	channel = KNET_DATAFD_MAX;

	if ((!knet_handle_add_datafd(knet_h, &datafd, &channel)) || (errno != EINVAL)) {
		printf("knet_handle_add_datafd accepted invalid channel or returned incorrect error: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_handle_add_datafd with no socknotify\n");

	datafd = 0;
	channel = -1;

	if ((!knet_handle_add_datafd(knet_h, &datafd, &channel)) || (errno != EINVAL)) {
		printf("knet_handle_add_datafd accepted invalid channel or returned incorrect error: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_handle_add_datafd with automatic config values\n");

	if (knet_handle_enable_sock_notify(knet_h, &private_data, sock_notify) < 0) {
		printf("knet_handle_enable_sock_notify failed: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	datafd = 0;
	channel = -1;

	if (knet_handle_add_datafd(knet_h, &datafd, &channel) < 0) {
		printf("knet_handle_add_datafd failed: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	printf("got datafd: %d channel: %d\n", datafd, channel);

	flush_logs(logfds[0], stdout);

	printf("Test knet_handle_add_datafd with duplicated datafd\n");

	if ((!knet_handle_add_datafd(knet_h, &datafd, &channel)) || (errno != EEXIST)) {
		printf("knet_handle_add_datafd accepted duplicated datafd or returned incorrect error: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_handle_add_datafd with busy channel\n");

	datafd = datafd + 1;

	if ((!knet_handle_add_datafd(knet_h, &datafd, &channel)) || (errno != EBUSY)) {
		printf("knet_handle_add_datafd accepted duplicated datafd or returned incorrect error: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	datafd = datafd - 1;

	if (knet_handle_remove_datafd(knet_h, datafd) < 0) {
		printf("knet_handle_remove_datafd failed: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_handle_add_datafd with no available channels\n");

	for (i = 0; i < KNET_DATAFD_MAX; i++) {
		datafdmax[i] = 0;
		channels[i] = -1;
		if (knet_handle_add_datafd(knet_h, &datafdmax[i], &channels[i]) < 0) {
			printf("knet_handle_add_datafd failed: %s\n", strerror(errno));
			knet_handle_free(knet_h);
			flush_logs(logfds[0], stdout);
			close_logpipes(logfds);
			exit(FAIL);
		}
	}

	datafd = 0;
	channel = -1;

	if ((!knet_handle_add_datafd(knet_h, &datafd, &channel)) || (errno != EBUSY)) {
		printf("knet_handle_add_datafd accepted entry with no available channels or returned incorrect error: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	for (i = 0; i < KNET_DATAFD_MAX; i++) {
		if (knet_handle_remove_datafd(knet_h, datafdmax[i]) < 0) {
			printf("knet_handle_remove_datafd failed: %s\n", strerror(errno));
			knet_handle_free(knet_h);
			flush_logs(logfds[0], stdout);
			close_logpipes(logfds);
			exit(FAIL);
		}
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
