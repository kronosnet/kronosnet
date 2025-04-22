/*
 * Copyright (C) 2016-2025 Red Hat, Inc.  All rights reserved.
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

static int private_data;

static void link_notify(void *priv_data,
			knet_node_id_t host_id,
			uint8_t link_id,
			uint8_t connected,
			uint8_t remote,
			uint8_t external)
{
	return;
}

static void test(void)
{
	knet_handle_t knet_h1, knet_h[2];
	int res;
	int logfds[2];

	printf("Test knet_link_enable_status_change_notify incorrect knet_h\n");

	if ((!knet_link_enable_status_change_notify(NULL, NULL, link_notify)) || (errno != EINVAL)) {
		printf("knet_link_enable_status_change_notify accepted invalid knet_h or returned incorrect error: %s\n", strerror(errno));
		exit(FAIL);
	}

	setup_logpipes(logfds);
	knet_h1 = knet_handle_start(logfds, KNET_LOG_DEBUG, knet_h);

	printf("Test knet_link_enable_status_change_notify with no private_data\n");
	FAIL_ON_ERR(knet_link_enable_status_change_notify(knet_h1, NULL, link_notify));
	if (knet_h1->link_status_change_notify_fn_private_data != NULL) {
		printf("knet_link_enable_status_change_notify failed to unset private_data");
		CLEAN_EXIT(FAIL);
	}
	printf("Test knet_link_enable_status_change_notify with private_data\n");

	FAIL_ON_ERR(knet_link_enable_status_change_notify(knet_h1, &private_data, NULL));
	if (knet_h1->link_status_change_notify_fn_private_data != &private_data) {
		printf("knet_link_enable_status_change_notify failed to set private_data");
		CLEAN_EXIT(FAIL);
	}

	printf("Test knet_link_enable_status_change_notify with no link_notify fn\n");
	FAIL_ON_ERR(knet_link_enable_status_change_notify(knet_h1, NULL, NULL));
	if (knet_h1->link_status_change_notify_fn != NULL) {
		printf("knet_link_enable_status_change_notify failed to unset link_notify fn");
		CLEAN_EXIT(FAIL);
	}

	printf("Test knet_link_enable_status_change_notify with link_notify fn\n");
	FAIL_ON_ERR(knet_link_enable_status_change_notify(knet_h1, NULL, link_notify));
	if (knet_h1->link_status_change_notify_fn != &link_notify) {
		printf("knet_link_enable_status_change_notify failed to set link_notify fn");
		CLEAN_EXIT(FAIL);
	}
	CLEAN_EXIT(CONTINUE);
}

int main(int argc, char *argv[])
{
	test();

	return PASS;
}
