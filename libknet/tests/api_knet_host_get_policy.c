/*
 * Copyright (C) 2016-2023 Red Hat, Inc.  All rights reserved.
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
	uint8_t policy;

	printf("Test knet_host_get_policy incorrect knet_h\n");

	if ((!knet_host_get_policy(NULL, 1, &policy)) || (errno != EINVAL)) {
		printf("knet_host_get_policy accepted invalid knet_h or returned incorrect error: %s\n", strerror(errno));
		exit(FAIL);
	}

	setup_logpipes(logfds);

	knet_h1 = knet_handle_start(logfds, KNET_LOG_DEBUG, knet_h);

	flush_logs(logfds[0], stdout);

	printf("Test knet_host_get_policy incorrect host_id\n");
	FAIL_ON_SUCCESS(knet_host_get_policy(knet_h1, 1, &policy), EINVAL);

	printf("Test knet_host_get_policy incorrect policy\n");
	FAIL_ON_SUCCESS(knet_host_get_policy(knet_h1, 1, NULL), EINVAL);

	printf("Test knet_host_get_policy correct policy\n");
	FAIL_ON_ERR(knet_host_add(knet_h1, 1));
	FAIL_ON_ERR(knet_host_set_policy(knet_h1, 1, KNET_LINK_POLICY_RR));
	FAIL_ON_ERR(knet_host_get_policy(knet_h1, 1, &policy));
	if (policy != KNET_LINK_POLICY_RR) {
		printf("knet_host_get_policy policy for host 1 does not appear to be correct\n");
		CLEAN_EXIT(FAIL);
	}
	CLEAN_EXIT(CONTINUE);
}

int main(int argc, char *argv[])
{
	test();

	return PASS;
}
