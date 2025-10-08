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
	int logfds[2];
	int res;
	char longhostname[KNET_MAX_HOST_LEN+2];

	printf("Test knet_host_set_name incorrect knet_h\n");

	// coverity[CHECKED_RETURN:SUPPRESS] - it's a test , get over it
	if ((!knet_host_set_name(NULL, 1, "test")) || (errno != EINVAL)) {
		printf("knet_host_set_name accepted invalid knet_h or returned incorrect error: %s\n", strerror(errno));
		exit(FAIL);
	}

	setup_logpipes(logfds);

	knet_h1 = knet_handle_start(logfds, KNET_LOG_DEBUG, knet_h);

	flush_logs(logfds[0], stdout);

	printf("Test knet_host_set_name with incorrect hostid 1\n");
	FAIL_ON_SUCCESS(knet_host_set_name(knet_h1, 2, "test"), EINVAL);

	printf("Test knet_host_set_name with correct values\n");
	FAIL_ON_ERR(knet_host_add(knet_h1, 1));
	FAIL_ON_ERR(knet_host_set_name(knet_h1, 1, "test"));
	if (strcmp("test", knet_h1->host_index[1]->name)) {
		printf("knet_host_set_name failed to copy name\n");
		CLEAN_EXIT(FAIL);
	}

	printf("Test knet_host_set_name with correct values (name change)\n");
	FAIL_ON_ERR(knet_host_set_name(knet_h1, 1, "tes"));
	if (strcmp("tes", knet_h1->host_index[1]->name)) {
		printf("knet_host_set_name failed to change name\n");
		CLEAN_EXIT(FAIL);
	}

	printf("Test knet_host_set_name with NULL name\n");
	FAIL_ON_SUCCESS(knet_host_set_name(knet_h1, 1, NULL), EINVAL);

	printf("Test knet_host_set_name with duplicate name\n");
	FAIL_ON_ERR(knet_host_add(knet_h1, 2));

	if ((!knet_host_set_name(knet_h1, 2, "tes")) || (errno != EEXIST)) {
		printf("knet_host_set_name accepted duplicated name or returned incorrect error: %s\n", strerror(errno));
		CLEAN_EXIT(FAIL);
	}

	knet_host_remove(knet_h1, 2);
	flush_logs(logfds[0], stdout);

	printf("Test knet_host_set_name with (too) long name\n");

	memset(longhostname, 'a', sizeof(longhostname));
	longhostname[KNET_MAX_HOST_LEN] = '\0';

	if ((!knet_host_set_name(knet_h1, 1, longhostname)) || (errno != EINVAL)) {
		printf("knet_host_set_name accepted invalid (too long) name or returned incorrect error: %s\n", strerror(errno));
		CLEAN_EXIT(FAIL);
	}

	CLEAN_EXIT(CONTINUE);
}

int main(int argc, char *argv[])
{
	test();

	return PASS;
}
