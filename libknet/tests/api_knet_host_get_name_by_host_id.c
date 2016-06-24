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
	char name[KNET_MAX_HOST_LEN];

	printf("Test knet_host_get_name_by_host_id incorrect knet_h\n");

	if ((!knet_host_get_name_by_host_id(NULL, 1, name)) || (errno != EINVAL)) {
		printf("knet_host_get_name_by_host_id accepted invalid knet_h or returned incorrect error: %s\n", strerror(errno));
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

	flush_logs(logfds[0], stdout);

	printf("Test knet_host_get_name_by_host_id with incorrect hostid 1\n");

	if ((!knet_host_get_name_by_host_id(knet_h, 1, name)) || (errno != EINVAL)) {
		printf("knet_host_get_name_by_host_id accepted invalid host_id or returned incorrect error: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_host_get_name_by_host_id with incorrect name\n");

	if ((!knet_host_get_name_by_host_id(knet_h, 1, NULL)) || (errno != EINVAL)) {
		printf("knet_host_get_name_by_host_id accepted invalid name or returned incorrect error: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_host_get_name_by_host_id with correct values for hostid 1: ");

	if (knet_host_add(knet_h, 1) < 0) {
		printf("knet_host_add failed error: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	if (knet_host_get_name_by_host_id(knet_h, 1, name) < 0) {
		printf("knet_host_get_name_by_host_id faild to retrive name: %s\n", strerror(errno));
		knet_host_remove(knet_h, 1);
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	printf("%s\n", name);

	flush_logs(logfds[0], stdout);

	knet_host_remove(knet_h, 1);

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
