/*
 * Copyright (C) 2019-2024 Red Hat, Inc.  All rights reserved.
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
#include <inttypes.h>

#include "libknet.h"

#include "internals.h"
#include "netutils.h"
#include "test-common.h"

static void test(void)
{
	knet_handle_t knet_h1, knet_h[2];
	int res;
	int logfds[2];
	struct knet_host *host;
	struct knet_link *link;
	struct sockaddr_storage lo;

	printf("Test knet_link_clear_acl incorrect knet_h\n");

	if ((!knet_link_clear_acl(NULL, 1, 0)) || (errno != EINVAL)) {
		printf("knet_link_clear_acl accepted invalid knet_h or returned incorrect error: %s\n", strerror(errno));
		exit(FAIL);
	}

	setup_logpipes(logfds);
	knet_h1 = knet_handle_start(logfds, KNET_LOG_DEBUG, knet_h);

	printf("Test knet_link_clear_acl with unconfigured host\n");
	FAIL_ON_SUCCESS(knet_link_clear_acl(knet_h1, 1, 0), EINVAL);

	printf("Test knet_link_clear_acl with unconfigured link\n");
	FAIL_ON_ERR(knet_host_add(knet_h1, 1));
	FAIL_ON_SUCCESS(knet_link_clear_acl(knet_h1, 1, 0), EINVAL);

	printf("Test knet_link_clear_acl with invalid link\n");
	FAIL_ON_SUCCESS(knet_link_clear_acl(knet_h1, 1, KNET_MAX_LINK), EINVAL);

	printf("Test knet_link_clear_acl with point to point link\n");
	FAIL_ON_ERR(_knet_link_set_config(knet_h1, 1, 0, KNET_TRANSPORT_UDP, 0, AF_INET, 0, &lo));
	FAIL_ON_SUCCESS(knet_link_clear_acl(knet_h1, 1, 0), EINVAL);
	FAIL_ON_ERR(knet_link_clear_config(knet_h1, 1, 0));

	printf("Test knet_link_clear_acl with dynamic link\n");
	FAIL_ON_ERR(_knet_link_set_config(knet_h1, 1, 0, KNET_TRANSPORT_UDP, 0, AF_INET, 1, &lo));

	host = knet_h1->host_index[1];
	link = &host->link[0];

	if (link->access_list_match_entry_head) {
		printf("match list NOT empty!");
		CLEAN_EXIT(FAIL);
	}

	FAIL_ON_ERR(knet_link_add_acl(knet_h1, 1, 0, &lo, &lo, CHECK_TYPE_ADDRESS, CHECK_ACCEPT));
	if (!link->access_list_match_entry_head) {
		printf("match list empty!");
		CLEAN_EXIT(FAIL);
	}

	FAIL_ON_ERR(knet_link_clear_acl(knet_h1, 1, 0));
	if (link->access_list_match_entry_head) {
		printf("match list NOT empty!");
		CLEAN_EXIT(FAIL);
	}
	CLEAN_EXIT(CONTINUE);
}

int main(int argc, char *argv[])
{
	test();

	return PASS;
}
