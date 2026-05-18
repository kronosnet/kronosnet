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

#include "test-common.h"

static void test(void)
{
	int logfd;

	logfd = start_logging(stdout);
	knet_handle_t knet_h1, knet_h[2];
	knet_node_id_t host_ids[KNET_MAX_HOST];
	size_t host_ids_entries;

	log_test(logfd, "Test knet_host_add incorrect knet_h");

	if ((!knet_host_add(NULL, 1)) || (errno != EINVAL)) {
		log_test(logfd, "knet_host_add accepted invalid knet_h or returned incorrect error: %s", strerror(errno));
		exit(FAIL);
	}


	knet_h1 = knet_handle_start(logfd, KNET_LOG_DEBUG, knet_h);


	log_test(logfd, "Test knet_host_add with hostid 1");
	FAIL_ON_ERR(knet_host_add(knet_h1, 1));

	log_test(logfd, "Test verify host_id 1 is in the host list");
	FAIL_ON_ERR(knet_host_get_host_list(knet_h1, host_ids, &host_ids_entries));
	if (host_ids_entries != 1) {
		log_test(logfd, "Too many hosts?");
		CLEAN_EXIT(FAIL);
	}
	if (host_ids[0] != 1) {
		log_test(logfd, "Unable to find host id 1 in host list");
		CLEAN_EXIT(FAIL);
	}

	log_test(logfd, "Test knet_host_add adding host 1 again");
	FAIL_ON_SUCCESS(knet_host_add(knet_h1, 1), EEXIST);

	CLEAN_EXIT(CONTINUE);
}

int main(int argc, char *argv[])
{
	test();

	return PASS;
}
