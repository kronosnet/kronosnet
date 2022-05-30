/*
 * Copyright (C) 2016-2022 Red Hat, Inc.  All rights reserved.
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

#include "netutils.h"
#include "test-common.h"

static void test(void)
{
	knet_handle_t knet_h1, knet_h[2];
	int logfds[2];
	int res;
	knet_node_id_t host_ids[KNET_MAX_HOST];
	size_t host_ids_entries;
	struct sockaddr_storage lo;

	printf("Test knet_host_add incorrect knet_h\n");

	if ((!knet_host_remove(NULL, 1)) || (errno != EINVAL)) {
		printf("knet_host_remove accepted invalid knet_h or returned incorrect error: %s\n", strerror(errno));
		exit(FAIL);
	}

	setup_logpipes(logfds);

	knet_h1 = knet_handle_start(logfds, KNET_LOG_DEBUG, knet_h);

	flush_logs(logfds[0], stdout);

	printf("Test knet_host_remove with unconfigured host_id\n");
	FAIL_ON_SUCCESS(knet_host_remove(knet_h1, 1), EINVAL);
	FAIL_ON_ERR(knet_host_add(knet_h1, 1));

	printf("Test knet_host_remove with configured host_id and links\n");
	FAIL_ON_ERR(_knet_link_set_config(knet_h1, 1, 0, KNET_TRANSPORT_UDP, 0, AF_INET, 1, &lo));
	FAIL_ON_ERR(knet_link_set_enable(knet_h1, 1, 0, 1));

	if ((!knet_host_remove(knet_h1, 1)) || (errno != EBUSY)) {
		printf("knet_host_remove accepted invalid request to remove host with link enabled or returned incorrect error: %s\n", strerror(errno));
		CLEAN_EXIT(FAIL);
	}

	FAIL_ON_ERR(knet_link_set_enable(knet_h1, 1, 0, 0));
	FAIL_ON_ERR(knet_link_clear_config(knet_h1, 1, 0));

	printf("Test knet_host_remove with configured host_id (no links)\n");
	FAIL_ON_ERR(knet_host_remove(knet_h1, 1));

	FAIL_ON_ERR(knet_host_get_host_list(knet_h1, host_ids, &host_ids_entries));

	if (host_ids_entries) {
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
