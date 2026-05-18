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
#include "link.h"
#include "netutils.h"
#include "test-common.h"

static void test(void)
{
	int logfd;

	logfd = start_logging(stdout);
	knet_handle_t knet_h1, knet_h[2];
	uint8_t priority = 0;
	struct sockaddr_storage lo;

	log_test(logfd, "Test knet_link_get_priority incorrect knet_h");

	if ((!knet_link_get_priority(NULL, 1, 0, &priority)) || (errno != EINVAL)) {
		log_test(logfd, "knet_link_get_priority accepted invalid knet_h or returned incorrect error: %s", strerror(errno));
		exit(FAIL);
	}

	knet_h1 = knet_handle_start(logfd, KNET_LOG_DEBUG, knet_h);

	log_test(logfd, "Test knet_link_get_priority with unconfigured host_id");
	FAIL_ON_SUCCESS(knet_link_get_priority(knet_h1, 1, 0, &priority), EINVAL);

	log_test(logfd, "Test knet_link_get_priority with incorrect linkid");
	FAIL_ON_ERR(knet_host_add(knet_h1, 1));
	FAIL_ON_SUCCESS(knet_link_get_priority(knet_h1, 1, KNET_MAX_LINK, &priority), EINVAL);

	log_test(logfd, "Test knet_link_get_priority with unconfigured link");
	FAIL_ON_SUCCESS(knet_link_get_priority(knet_h1, 1, 0, &priority), EINVAL);

	log_test(logfd, "Test knet_link_get_priority with incorrect priority");
	FAIL_ON_SUCCESS(knet_link_get_priority(knet_h1, 1, 0, NULL), EINVAL);

	log_test(logfd, "Test knet_link_get_priority with correct values");
	FAIL_ON_ERR(_knet_link_set_config(knet_h1, 1, 0, KNET_TRANSPORT_UDP, 0, AF_INET, 0, &lo, logfd));
	FAIL_ON_ERR(knet_link_set_priority(knet_h1, 1, 0, 1));
	FAIL_ON_ERR(knet_link_get_priority(knet_h1, 1, 0, &priority));
	if (priority != 1) {
		log_test(logfd, "knet_link_get_priority failed to get correct values");
		CLEAN_EXIT(FAIL);
	}

	CLEAN_EXIT(CONTINUE);
}

int main(int argc, char *argv[])
{
	test();

	return PASS;
}
