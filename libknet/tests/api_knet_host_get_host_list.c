/*
 * Copyright (C) 2016-2023 Red Hat, Inc.  All rights reserved.
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

#include "test-common.h"

static void test(void)
{
	knet_handle_t knet_h1, knet_h[2];
	int res;
	int logfds[2];
	knet_node_id_t host_ids[KNET_MAX_HOST];
	size_t host_ids_entries;

	printf("Test knet_host_get_host_list incorrect knet_h\n");

	if ((!knet_host_get_host_list(NULL, host_ids, &host_ids_entries)) || (errno != EINVAL)) {
		printf("knet_host_get_host_list accepted invalid knet_h or returned incorrect error: %s\n", strerror(errno));
		exit(FAIL);
	}

	setup_logpipes(logfds);

	knet_h1 = knet_handle_start(logfds, KNET_LOG_DEBUG, knet_h);

	flush_logs(logfds[0], stdout);

	printf("Test knet_host_get_host_list incorrect host_ids\n");
	FAIL_ON_SUCCESS(knet_host_get_host_list(knet_h1, NULL, &host_ids_entries), EINVAL);

	printf("Test knet_host_get_host_list incorrect host_ids_entries\n");
	FAIL_ON_SUCCESS(knet_host_get_host_list(knet_h1, host_ids, NULL), EINVAL);

	printf("Test knet_host_get_host_list with one host\n");
	FAIL_ON_ERR(knet_host_add(knet_h1, 1));
	FAIL_ON_ERR(knet_host_get_host_list(knet_h1, host_ids, &host_ids_entries));
	if (host_ids_entries != 1) {
		printf("Too many hosts?\n");
		CLEAN_EXIT(FAIL);
	}
	if (host_ids[0] != 1) {
		printf("Unable to find host id 1 in host list\n");
		CLEAN_EXIT(FAIL);
	}

	printf("Test knet_host_get_host_list with zero hosts\n");
	FAIL_ON_ERR(knet_host_remove(knet_h1, 1));
	FAIL_ON_ERR(knet_host_get_host_list(knet_h1, host_ids, &host_ids_entries));

	if (host_ids_entries != 0) {
		printf("Too many hosts?\n");
		CLEAN_EXIT(FAIL);
	}
	CLEAN_EXIT(CONTINUE);
}

int main(int argc, char *argv[])
{
	test();

	return PASS;
}
