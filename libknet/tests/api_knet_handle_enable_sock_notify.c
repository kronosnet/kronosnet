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
#include "test-common.h"

static int private_data;

static void sock_notify(void *pvt_data,
			int datafd,
			int8_t channel,
			uint8_t tx_rx,
			int error,
			int errorno)
{
	return;
}

static void test(void)
{
	int logfd;

	logfd = start_logging(stdout);
	knet_handle_t knet_h1, knet_h[2];

	log_test(logfd, "Test knet_handle_enable_sock_notify incorrect knet_h");

	if ((!knet_handle_enable_sock_notify(NULL, NULL, sock_notify)) || (errno != EINVAL)) {
		log_test(logfd, "knet_handle_enable_sock_notify accepted invalid knet_h or returned incorrect error: %s", strerror(errno));
		exit(FAIL);
	}


	knet_h1 = knet_handle_start(logfd, KNET_LOG_DEBUG, knet_h);

	log_test(logfd, "Test knet_handle_enable_sock_notify with no private_data");
	FAIL_ON_ERR(knet_handle_enable_sock_notify(knet_h1, NULL, sock_notify));

	if (knet_h1->sock_notify_fn_private_data != NULL) {
		log_test(logfd, "knet_handle_enable_sock_notify failed to unset private_data");
		CLEAN_EXIT(FAIL);
	}

	log_test(logfd, "Test knet_handle_enable_sock_notify with private_data");
	FAIL_ON_ERR(knet_handle_enable_sock_notify(knet_h1, &private_data, sock_notify));

	if (knet_h1->sock_notify_fn_private_data != &private_data) {
		log_test(logfd, "knet_handle_enable_sock_notify failed to set private_data");
		CLEAN_EXIT(FAIL);
	}

	log_test(logfd, "Test knet_handle_enable_sock_notify with no sock_notify fn");
	FAIL_ON_SUCCESS(knet_handle_enable_sock_notify(knet_h1, NULL, NULL), EINVAL);

	log_test(logfd, "Test knet_handle_enable_sock_notify with sock_notify fn");
	FAIL_ON_ERR(knet_handle_enable_sock_notify(knet_h1, NULL, sock_notify));

	if (knet_h1->sock_notify_fn != &sock_notify) {
		CLEAN_EXIT(FAIL);
	}

	CLEAN_EXIT(CONTINUE);
}

int main(int argc, char *argv[])
{
	test();

	return PASS;
}
