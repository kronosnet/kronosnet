/*
 * Copyright (C) 2017-2026 Red Hat, Inc.  All rights reserved.
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

#define TEST_NAME "api_knet_get_transport_name_by_id"

static void test(void)
{
	int logfd;
	const char *name = NULL;

	logfd = start_logging(stdout);

	log_test(logfd, "Test knet_get_transport_name_by_id with incorrect transport");

	if ((knet_get_transport_name_by_id(KNET_MAX_TRANSPORTS) != NULL) || (errno != EINVAL)) {
		log_test(logfd, "knet_get_transport_name_by_id accepted invalid transport or returned incorrect error: %s", strerror(errno));
		TEST_EXIT(FAIL);
	}

	log_test(logfd, "Test knet_get_transport_name_by_id with correct values");

	name = knet_get_transport_name_by_id(KNET_TRANSPORT_UDP);
	if (!name) {
		log_test(logfd, "knet_get_transport_name_by_id failed: %s", strerror(errno));
		TEST_EXIT(FAIL);
	}

	if (strcmp(name, "UDP")) {
		log_test(logfd, "knet_get_transport_name_by_id failed to get UDP transport name");
		TEST_EXIT(FAIL);
	}

	stop_logging();
}

int main(int argc, char *argv[])
{
	printf("[TEST] %s: Test knet get transport name by id\n", TEST_NAME);

	test();

	TEST_EXIT(PASS);
}
