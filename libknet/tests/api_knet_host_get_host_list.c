/*
 * Copyright (C) 2016-2019 Red Hat, Inc.  All rights reserved.
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

#include "test-common.h"

static void test(void)
{
	knet_handle_t knet_h;
	int logfds[2];
	knet_node_id_t host_ids[KNET_MAX_HOST];
	size_t host_ids_entries;

	printf("Test knet_host_get_host_list incorrect knet_h\n");

	if ((!knet_host_get_host_list(NULL, host_ids, &host_ids_entries)) || (errno != EINVAL)) {
		printf("knet_host_get_host_list accepted invalid knet_h or returned incorrect error: %s\n", strerror(errno));
		exit(FAIL);
	}

	setup_logpipes(logfds);

	knet_h = knet_handle_start(logfds, KNET_LOG_DEBUG);

	flush_logs(logfds[0], stdout);

	printf("Test knet_host_get_host_list incorrect host_ids\n");

	if ((!knet_host_get_host_list(knet_h, NULL, &host_ids_entries)) || (errno != EINVAL)) {
		printf("knet_host_get_host_list accepted invalid host_ids or returned incorrect error: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_host_get_host_list incorrect host_ids_entries\n");

	if ((!knet_host_get_host_list(knet_h, host_ids, NULL)) || (errno != EINVAL)) {
		printf("knet_host_get_host_list accepted invalid host_ids or returned incorrect error: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_host_get_host_list with one host\n");

	if (knet_host_add(knet_h, 1) < 0) {
		printf("knet_host_add failed error: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	if (knet_host_get_host_list(knet_h, host_ids, &host_ids_entries) < 0) {
		printf("Unable to get host list: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	if (host_ids_entries != 1) {
		printf("Too many hosts?\n");
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	if (host_ids[0] != 1) {
		printf("Unable to find host id 1 in host list\n");
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_host_get_host_list with zero hosts\n");

	if (knet_host_remove(knet_h, 1) < 0) {
		printf("knet_host_remove failed error: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	if (knet_host_get_host_list(knet_h, host_ids, &host_ids_entries) < 0) {
		printf("Unable to get host list: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	if (host_ids_entries != 0) {
		printf("Too many hosts?\n");
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
