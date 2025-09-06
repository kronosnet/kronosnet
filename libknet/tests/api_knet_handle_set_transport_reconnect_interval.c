/*
 * Copyright (C) 2016-2025 Red Hat, Inc.  All rights reserved.
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
	knet_handle_t knet_h1, knet_h[2];
	int res;
	int logfds[2];

	printf("Test knet_handle_set_transport_reconnect_interval with incorrect knet_h\n");

	if ((!knet_handle_set_transport_reconnect_interval(NULL, 1000)) || (errno != EINVAL)) {
		printf("knet_handle_set_transport_reconnect_interval accepted invalid knet_h or returned incorrect error: %s\n", strerror(errno));
		exit(FAIL);
	}

	setup_logpipes(logfds);

	knet_h1 = knet_handle_start(logfds, KNET_LOG_DEBUG, knet_h);

	printf("Test knet_handle_set_transport_reconnect_interval with incorrect msecs\n");
	FAIL_ON_SUCCESS(knet_handle_set_transport_reconnect_interval(knet_h1, 0), EINVAL);

	printf("Test knet_handle_set_transport_reconnect_interval with correct values\n");
	FAIL_ON_ERR(knet_handle_set_transport_reconnect_interval(knet_h1, 2000));

	// coverity[MISSING_LOCK:SUPPRESS] use out of the main library is 'OK' here. ish
	if (knet_h1->reconnect_int != 2000) {
		printf("knet_handle_set_transport_reconnect_interval failed to set correct value\n");
		CLEAN_EXIT(FAIL);
	}

	CLEAN_EXIT(CONTINUE);
}

int main(int argc, char *argv[])
{
	test();

	return PASS;
}
