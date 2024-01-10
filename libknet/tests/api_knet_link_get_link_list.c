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
#include "link.h"
#include "netutils.h"
#include "test-common.h"

static void test(void)
{
	knet_handle_t knet_h1, knet_h[2];
	int res;
	int logfds[2];
	uint8_t link_ids[KNET_MAX_LINK];
	size_t link_ids_entries = 0;
	struct sockaddr_storage lo;

	memset(&link_ids, 1, sizeof(link_ids));

	printf("Test knet_link_get_link_list incorrect knet_h\n");

	if ((!knet_link_get_link_list(NULL, 1, link_ids, &link_ids_entries)) || (errno != EINVAL)) {
		printf("knet_link_get_link_list accepted invalid knet_h or returned incorrect error: %s\n", strerror(errno));
		exit(FAIL);
	}

	setup_logpipes(logfds);
	knet_h1 = knet_handle_start(logfds, KNET_LOG_DEBUG, knet_h);

	printf("Test knet_link_get_link_list with unconfigured host_id\n");
	FAIL_ON_SUCCESS(knet_link_get_link_list(knet_h1, 1, link_ids, &link_ids_entries), EINVAL);

	printf("Test knet_link_get_link_list with incorrect link_id\n");
	FAIL_ON_ERR(knet_host_add(knet_h1, 1));
	FAIL_ON_SUCCESS(knet_link_get_link_list(knet_h1, 1, NULL, &link_ids_entries), EINVAL);

	printf("Test knet_link_get_link_list with incorrect link_ids_entries\n");
	FAIL_ON_SUCCESS(knet_link_get_link_list(knet_h1, 1, link_ids, NULL), EINVAL);

	printf("Test knet_link_get_link_list with no links\n");
	FAIL_ON_ERR(knet_link_get_link_list(knet_h1, 1, link_ids, &link_ids_entries));
	if (link_ids_entries != 0) {
		printf("knet_link_get_link_list returned incorrect number of links");
		CLEAN_EXIT(FAIL);
	}

	printf("Test knet_link_get_link_list with 1 link\n");
	FAIL_ON_ERR(_knet_link_set_config(knet_h1, 1, 0, KNET_TRANSPORT_UDP, 0, AF_INET, 0, &lo));
	FAIL_ON_ERR(knet_link_get_link_list(knet_h1, 1, link_ids, &link_ids_entries));
	if ((link_ids_entries != 1) || (link_ids[0] != 0)) {
		printf("knet_link_get_link_list returned incorrect values");
		CLEAN_EXIT(FAIL);
	}
	CLEAN_EXIT(CONTINUE);
}

int main(int argc, char *argv[])
{
	test();

	return PASS;
}
