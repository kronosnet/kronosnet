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

#define TEST_NAME "api_knet_get_transport_list"

static void test(void)
{
	int logfd;
	struct knet_transport_info transport_list[KNET_MAX_TRANSPORTS];
	size_t transport_list_entries;
	size_t transport_list_entries1;
	size_t i;

	logfd = start_logging(stdout);

	memset(transport_list, 0, sizeof(transport_list));

	log_test(logfd, "Test knet_get_transport_list with no entries_list");

	FAIL_ON_SUCCESS_NOCLEAN(knet_get_transport_list(transport_list, NULL), EINVAL);

	log_test(logfd, "Test knet_get_transport_list with no transport_list (get number of entries)");

	if (knet_get_transport_list(NULL, &transport_list_entries) < 0) {
		log_test(logfd, "knet_get_transport_list returned error instead of number of entries: %s", strerror(errno));
		TEST_EXIT(FAIL);
	}

	log_test(logfd, "Test knet_get_transport_list with valid data");

	if (knet_get_transport_list(transport_list, &transport_list_entries1) < 0) {
		log_test(logfd, "knet_get_transport_list failed: %s", strerror(errno));
		TEST_EXIT(FAIL);
	}

	if (transport_list_entries != transport_list_entries1) {
		log_test(logfd, "knet_get_transport_list returned a different number of entries: %d, %d",
		       (int)transport_list_entries, (int)transport_list_entries1);
		TEST_EXIT(FAIL);
	}

	for (i=0; i<transport_list_entries; i++) {
		log_test(logfd, "Detected transport: %s id: %d properties: %u",
			transport_list[i].name, transport_list[i].id, transport_list[i].properties);
	}

	stop_logging();
}

int main(int argc, char *argv[])
{
	printf("[TEST] %s: Test knet get transport list\n", TEST_NAME);

	test();

	TEST_EXIT(PASS);
}
