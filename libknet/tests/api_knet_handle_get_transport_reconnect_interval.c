/*
 * Copyright (C) 2016-2019 Red Hat, Inc.  All rights reserved.
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

static void test(void)
{
	knet_handle_t knet_h;
	int logfds[2];
	uint32_t msecs = 0;

	printf("Test knet_handle_get_transport_reconnect_interval with incorrect knet_h\n");

	if ((!knet_handle_get_transport_reconnect_interval(NULL, &msecs)) || (errno != EINVAL)) {
		printf("knet_handle_get_transport_reconnect_interval accepted invalid knet_h or returned incorrect error: %s\n", strerror(errno));
		exit(FAIL);
	}

	setup_logpipes(logfds);

	knet_h = knet_handle_start(logfds, KNET_LOG_DEBUG);

	printf("Test knet_handle_get_transport_reconnect_interval with incorrect msecs\n");

	if ((!knet_handle_get_transport_reconnect_interval(knet_h, NULL)) || (errno != EINVAL)) {
		printf("knet_handle_get_transport_reconnect_interval accepted invalid msecs or returned incorrect error: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_handle_get_transport_reconnect_interval with correct values\n");

	if (knet_handle_get_transport_reconnect_interval(knet_h, &msecs) < 0) {
		printf("knet_handle_get_transport_reconnect_interval failed: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	if (msecs != KNET_TRANSPORT_DEFAULT_RECONNECT_INTERVAL) {
		printf("knet_handle_get_transport_reconnect_interval failed to set correct value\n");
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	knet_handle_free(knet_h);
	flush_logs(logfds[0], stdout);
	close_logpipes(logfds);
}

int main(int argc, char *argv[])
{
	test();

	return PASS;
}
