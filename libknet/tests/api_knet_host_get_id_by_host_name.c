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

static void test(void)
{
	knet_handle_t knet_h;
	int logfds[2];
	knet_node_id_t host_id;

	printf("Test knet_host_get_id_by_host_name incorrect knet_h\n");

	if ((!knet_host_get_id_by_host_name(NULL, "1", &host_id)) || (errno != EINVAL)) {
		printf("knet_host_get_id_by_host_name accepted invalid knet_h or returned incorrect error: %s\n", strerror(errno));
		exit(FAIL);
	}

	setup_logpipes(logfds);

	knet_h = knet_handle_start(logfds, KNET_LOG_DEBUG);

	flush_logs(logfds[0], stdout);

	printf("Test knet_host_get_id_by_host_name with incorrect name 1\n");

	if ((!knet_host_get_id_by_host_name(knet_h, NULL, &host_id)) || (errno != EINVAL)) {
		printf("knet_host_get_id_by_host_name accepted invalid name or returned incorrect error: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_host_get_id_by_host_name with incorrect host_id\n");

	if ((!knet_host_get_id_by_host_name(knet_h, "1", NULL)) || (errno != EINVAL)) {
		printf("knet_host_get_id_by_host_name accepted invalid host_id or returned incorrect error: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_host_get_id_by_host_name with incorrect values for name\n");

	if (knet_host_add(knet_h, 1) < 0) {
		printf("knet_host_add failed error: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	if ((!knet_host_get_id_by_host_name(knet_h, "test", &host_id)) || (errno != ENOENT)) {
		printf("knet_host_get_id_by_host_name returned invalid host_id or returned incorrect error: %s\n", strerror(errno));
		knet_host_remove(knet_h, 1);
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_host_get_id_by_host_name with correct values\n");

	if (knet_host_get_id_by_host_name(knet_h, "1", &host_id) < 0) {
		printf("knet_host_get_id_by_host_name could not get id for known name: %s\n", strerror(errno));
		knet_host_remove(knet_h, 1);
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	knet_host_remove(knet_h, 1);

	knet_handle_free(knet_h);
	flush_logs(logfds[0], stdout);
	close_logpipes(logfds);
}

int main(int argc, char *argv[])
{
	test();

	return PASS;
}
