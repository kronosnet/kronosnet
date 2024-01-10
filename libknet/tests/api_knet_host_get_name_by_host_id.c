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

static void test(void)
{
	knet_handle_t knet_h1, knet_h[2];
	int res;
	int logfds[2];
	char name[KNET_MAX_HOST_LEN];

	printf("Test knet_host_get_name_by_host_id incorrect knet_h\n");

	if ((!knet_host_get_name_by_host_id(NULL, 1, name)) || (errno != EINVAL)) {
		printf("knet_host_get_name_by_host_id accepted invalid knet_h or returned incorrect error: %s\n", strerror(errno));
		exit(FAIL);
	}

	setup_logpipes(logfds);

	knet_h1 = knet_handle_start(logfds, KNET_LOG_DEBUG, knet_h);

	flush_logs(logfds[0], stdout);

	printf("Test knet_host_get_name_by_host_id with incorrect hostid 1\n");
	FAIL_ON_SUCCESS(knet_host_get_name_by_host_id(knet_h1, 1, name), EINVAL);

	printf("Test knet_host_get_name_by_host_id with incorrect name\n");
	FAIL_ON_SUCCESS(knet_host_get_name_by_host_id(knet_h1, 1, NULL), EINVAL);

	printf("Test knet_host_get_name_by_host_id with correct values for hostid 1: ");
	FAIL_ON_ERR(knet_host_add(knet_h1, 1));
	FAIL_ON_ERR(knet_host_get_name_by_host_id(knet_h1, 1, name));

	printf("%s\n", name);

	CLEAN_EXIT(CONTINUE);
}

int main(int argc, char *argv[])
{
	test();

	return PASS;
}
