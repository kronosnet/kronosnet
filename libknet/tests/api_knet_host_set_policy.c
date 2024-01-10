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
#include "test-common.h"

static void test(void)
{
	knet_handle_t knet_h1, knet_h[2];
	int res;
	int logfds[2];

	printf("Test knet_host_set_policy incorrect knet_h\n");

	if ((!knet_host_set_policy(NULL, 1, KNET_LINK_POLICY_PASSIVE)) || (errno != EINVAL)) {
		printf("knet_host_set_policy accepted invalid knet_h or returned incorrect error: %s\n", strerror(errno));
		exit(FAIL);
	}

	setup_logpipes(logfds);

	knet_h1 = knet_handle_start(logfds, KNET_LOG_DEBUG, knet_h);

	flush_logs(logfds[0], stdout);

	printf("Test knet_host_set_policy incorrect host_id\n");
	FAIL_ON_SUCCESS(knet_host_set_policy(knet_h1, 1, KNET_LINK_POLICY_PASSIVE), EINVAL);

	printf("Test knet_host_set_policy incorrect policy\n");
	FAIL_ON_SUCCESS(knet_host_set_policy(knet_h1, 1, KNET_LINK_POLICY_RR + 1), EINVAL);

	printf("Test knet_host_set_policy correct policy\n");
	FAIL_ON_ERR(knet_host_add(knet_h1, 1));
	FAIL_ON_ERR(knet_host_set_policy(knet_h1, 1, KNET_LINK_POLICY_RR));
	if (knet_h1->host_index[1]->link_handler_policy != KNET_LINK_POLICY_RR) {
		printf("knet_host_set_policy failed to set RR policy for host 1: %s\n", strerror(errno));
		CLEAN_EXIT(FAIL);
	}
	CLEAN_EXIT(CONTINUE);
}

int main(int argc, char *argv[])
{
	test();

	return PASS;
}
