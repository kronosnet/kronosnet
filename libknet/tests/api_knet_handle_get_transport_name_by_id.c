/*
 * Copyright (C) 2016 Red Hat, Inc.  All rights reserved.
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

static void test(void)
{
	knet_handle_t knet_h;
	int logfds[2];
	const char *name = NULL;

	printf("Test knet_handle_get_transport_name_by_id with incorrect knet_h\n");

	if ((knet_handle_get_transport_name_by_id(NULL, KNET_TRANSPORT_UDP) != NULL) || (errno != EINVAL)) {
		printf("knet_handle_get_transport_name_by_id accepted invalid knet_h or returned incorrect error: %s\n", strerror(errno));
		exit(FAIL);
	}

	setup_logpipes(logfds);

	knet_h = knet_handle_new(1, logfds[1], KNET_LOG_DEBUG);

	if (!knet_h) {
		printf("knet_handle_new failed: %s\n", strerror(errno));
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	printf("Test knet_handle_get_transport_name_by_id with incorrect transport\n");

	if ((knet_handle_get_transport_name_by_id(knet_h, KNET_MAX_TRANSPORTS) != NULL) || (errno != EINVAL)) {
		printf("knet_handle_get_transport_name_by_id accepted invalid transport or returned incorrect error: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_handle_get_transport_name_by_id with correct values\n");

	name = knet_handle_get_transport_name_by_id(knet_h, KNET_TRANSPORT_UDP);
	if (!name) {
		printf("knet_handle_get_transport_name_by_id failed: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	if (strcmp(name, "UDP")) {
		printf("knet_handle_get_transport_name_by_id failed to get UDP transport name\n");
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
	need_root();

	test();

	return PASS;
}
