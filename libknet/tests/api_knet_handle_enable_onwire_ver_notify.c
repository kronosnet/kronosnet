/*
 * Copyright (C) 2020-2026 Red Hat, Inc.  All rights reserved.
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

#define TEST_NAME "api_knet_handle_enable_onwire_ver_notify"

static int private_data;

static void onwire_ver_notify(void *priv_data,
			      uint8_t onwire_min_ver,
			      uint8_t onwire_max_ver,
			      uint8_t onwire_ver)
{
	return;
}

static void test(void)
{
	int logfd;

	logfd = start_logging(stdout);
	knet_handle_t knet_h1, knet_h[2];

	log_test(logfd, "Test knet_handle_enable_onwire_ver_notify incorrect knet_h");

	if ((!knet_handle_enable_onwire_ver_notify(NULL, NULL, onwire_ver_notify)) || (errno != EINVAL)) {
		log_test(logfd, "knet_handle_enable_onwire_ver_notify accepted invalid knet_h or returned incorrect error: %s", strerror(errno));
		TEST_EXIT(FAIL);
	}


	knet_h1 = knet_handle_start(logfd, KNET_LOG_DEBUG, knet_h);

	log_test(logfd, "Test knet_handle_enable_onwire_ver_notify with no private_data");
	FAIL_ON_ERR(knet_handle_enable_onwire_ver_notify(knet_h1, NULL, onwire_ver_notify));
	if (knet_h1->onwire_ver_notify_fn_private_data != NULL) {
		log_test(logfd, "knet_handle_enable_onwire_ver_notify failed to unset private_data");
		TEST_EXIT_CLEAN(FAIL);
	}

	log_test(logfd, "Test knet_handle_enable_onwire_ver_notify with private_data");
	FAIL_ON_ERR(knet_handle_enable_onwire_ver_notify(knet_h1, &private_data, NULL));
	if (knet_h1->onwire_ver_notify_fn_private_data != &private_data) {
		log_test(logfd, "knet_handle_enable_onwire_ver_notify failed to set private_data");
		TEST_EXIT_CLEAN(FAIL);
	}

	log_test(logfd, "Test knet_handle_enable_onwire_ver_notify with no onwire_ver_notify fn");
	FAIL_ON_ERR(knet_handle_enable_onwire_ver_notify(knet_h1, NULL, NULL));
	if (knet_h1->onwire_ver_notify_fn != NULL) {
		log_test(logfd, "knet_handle_enable_onwire_ver_notify failed to unset onwire_ver_notify fn");
		TEST_EXIT_CLEAN(FAIL);
	}

	log_test(logfd, "Test knet_handle_enable_onwire_ver_notify with onwire_ver_notify fn");
	FAIL_ON_ERR(knet_handle_enable_onwire_ver_notify(knet_h1, NULL, onwire_ver_notify));
	if (knet_h1->onwire_ver_notify_fn != &onwire_ver_notify) {
		log_test(logfd, "knet_handle_enable_onwire_ver_notify failed to set onwire_ver_notify fn");
		TEST_EXIT_CLEAN(FAIL);
	}
	TEST_EXIT_CLEAN(CONTINUE);
}

int main(int argc, char *argv[])
{
	printf("[TEST] %s: Test knet handle enable onwire ver notify\n", TEST_NAME);

	test();

	TEST_EXIT(PASS);
}
