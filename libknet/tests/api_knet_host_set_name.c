/*
 * Copyright (C) 2016-2026 Red Hat, Inc.  All rights reserved.
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

#define TEST_NAME "api_knet_host_set_name"

static void test(void)
{
	int logfd;

	logfd = start_logging(stdout);
	knet_handle_t knet_h1, knet_h[2];
	char longhostname[KNET_MAX_HOST_LEN+2];

	log_test(logfd, "Test knet_host_set_name incorrect knet_h");

	// coverity[CHECKED_RETURN:SUPPRESS] - it's a test , get over it
	if ((!knet_host_set_name(NULL, 1, "test")) || (errno != EINVAL)) {
		log_test(logfd, "knet_host_set_name accepted invalid knet_h or returned incorrect error: %s", strerror(errno));
		TEST_EXIT(FAIL);
	}


	knet_h1 = knet_handle_start(logfd, KNET_LOG_DEBUG, knet_h);


	log_test(logfd, "Test knet_host_set_name with incorrect hostid 1");
	FAIL_ON_SUCCESS(knet_host_set_name(knet_h1, 2, "test"), EINVAL);

	log_test(logfd, "Test knet_host_set_name with correct values");
	FAIL_ON_ERR(knet_host_add(knet_h1, 1));
	FAIL_ON_ERR(knet_host_set_name(knet_h1, 1, "test"));
	if (strcmp("test", knet_h1->host_index[1]->name)) {
		log_test(logfd, "knet_host_set_name failed to copy name");
		TEST_EXIT_CLEAN(FAIL);
	}

	log_test(logfd, "Test knet_host_set_name with correct values (name change)");
	FAIL_ON_ERR(knet_host_set_name(knet_h1, 1, "tes"));
	if (strcmp("tes", knet_h1->host_index[1]->name)) {
		log_test(logfd, "knet_host_set_name failed to change name");
		TEST_EXIT_CLEAN(FAIL);
	}

	log_test(logfd, "Test knet_host_set_name with NULL name");
	FAIL_ON_SUCCESS(knet_host_set_name(knet_h1, 1, NULL), EINVAL);

	log_test(logfd, "Test knet_host_set_name with duplicate name");
	FAIL_ON_ERR(knet_host_add(knet_h1, 2));

	if ((!knet_host_set_name(knet_h1, 2, "tes")) || (errno != EEXIST)) {
		log_test(logfd, "knet_host_set_name accepted duplicated name or returned incorrect error: %s", strerror(errno));
		TEST_EXIT_CLEAN(FAIL);
	}

	knet_host_remove(knet_h1, 2);

	log_test(logfd, "Test knet_host_set_name with (too) long name");

	memset(longhostname, 'a', sizeof(longhostname));
	longhostname[KNET_MAX_HOST_LEN] = '\0';

	if ((!knet_host_set_name(knet_h1, 1, longhostname)) || (errno != EINVAL)) {
		log_test(logfd, "knet_host_set_name accepted invalid (too long) name or returned incorrect error: %s", strerror(errno));
		TEST_EXIT_CLEAN(FAIL);
	}

	TEST_EXIT_CLEAN(CONTINUE);
}

int main(int argc, char *argv[])
{
	printf("[TEST] %s: Test knet host set name\n", TEST_NAME);

	test();

	TEST_EXIT(PASS);
}
