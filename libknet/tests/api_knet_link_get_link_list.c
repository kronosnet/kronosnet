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
	uint8_t link_ids[KNET_MAX_LINK];
	size_t link_ids_entries = 0;
	struct sockaddr_storage lo;

	memset(&link_ids, 1, sizeof(link_ids));

	log_test(logfd, "Test knet_link_get_link_list incorrect knet_h");

	if ((!knet_link_get_link_list(NULL, 1, link_ids, &link_ids_entries)) || (errno != EINVAL)) {
		log_test(logfd, "knet_link_get_link_list accepted invalid knet_h or returned incorrect error: %s", strerror(errno));
		exit(FAIL);
	}

	knet_h1 = knet_handle_start(logfd, KNET_LOG_DEBUG, knet_h);

	log_test(logfd, "Test knet_link_get_link_list with unconfigured host_id");
	FAIL_ON_SUCCESS(knet_link_get_link_list(knet_h1, 1, link_ids, &link_ids_entries), EINVAL);

	log_test(logfd, "Test knet_link_get_link_list with incorrect link_id");
	FAIL_ON_ERR(knet_host_add(knet_h1, 1));
	FAIL_ON_SUCCESS(knet_link_get_link_list(knet_h1, 1, NULL, &link_ids_entries), EINVAL);

	log_test(logfd, "Test knet_link_get_link_list with incorrect link_ids_entries");
	FAIL_ON_SUCCESS(knet_link_get_link_list(knet_h1, 1, link_ids, NULL), EINVAL);

	log_test(logfd, "Test knet_link_get_link_list with no links");
	FAIL_ON_ERR(knet_link_get_link_list(knet_h1, 1, link_ids, &link_ids_entries));
	if (link_ids_entries != 0) {
		log_test(logfd, "knet_link_get_link_list returned incorrect number of links");
		CLEAN_EXIT(FAIL);
	}

	log_test(logfd, "Test knet_link_get_link_list with 1 link");
	FAIL_ON_ERR(_knet_link_set_config(knet_h1, 1, 0, KNET_TRANSPORT_UDP, 0, AF_INET, 0, &lo, logfd));
	FAIL_ON_ERR(knet_link_get_link_list(knet_h1, 1, link_ids, &link_ids_entries));
	if ((link_ids_entries != 1) || (link_ids[0] != 0)) {
		log_test(logfd, "knet_link_get_link_list returned incorrect values");
		CLEAN_EXIT(FAIL);
	}
	CLEAN_EXIT(CONTINUE);
}

int main(int argc, char *argv[])
{
	test();

	return PASS;
}
