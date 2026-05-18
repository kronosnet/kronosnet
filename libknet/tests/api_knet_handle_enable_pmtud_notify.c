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

static void pmtud_notify(void *priv_data,
			 unsigned int data_mtu)
{
	return;
}

static void test(void)
{
	int logfd;

	logfd = start_logging(stdout);
	knet_handle_t knet_h1, knet_h[2];

	log_test(logfd, "Test knet_handle_enable_pmtud_notify incorrect knet_h");

	if ((!knet_handle_enable_pmtud_notify(NULL, NULL, pmtud_notify)) || (errno != EINVAL)) {
		log_test(logfd, "knet_handle_enable_pmtud_notify accepted invalid knet_h or returned incorrect error: %s", strerror(errno));
		exit(FAIL);
	}


	knet_h1 = knet_handle_start(logfd, KNET_LOG_DEBUG, knet_h);

	log_test(logfd, "Test knet_handle_enable_pmtud_notify with no private_data");
	FAIL_ON_ERR(knet_handle_enable_pmtud_notify(knet_h1, NULL, pmtud_notify));
	if (knet_h1->pmtud_notify_fn_private_data != NULL) {
		log_test(logfd, "knet_handle_enable_pmtud_notify failed to unset private_data");
		CLEAN_EXIT(FAIL);
	}

	log_test(logfd, "Test knet_handle_enable_pmtud_notify with private_data");
	FAIL_ON_ERR(knet_handle_enable_pmtud_notify(knet_h1, &private_data, NULL));
	if (knet_h1->pmtud_notify_fn_private_data != &private_data) {
		log_test(logfd, "knet_handle_enable_pmtud_notify failed to set private_data");
		CLEAN_EXIT(FAIL);
	}

	log_test(logfd, "Test knet_handle_enable_pmtud_notify with no pmtud_notify fn");
	FAIL_ON_ERR(knet_handle_enable_pmtud_notify(knet_h1, NULL, NULL));
	if (knet_h1->pmtud_notify_fn != NULL) {
		log_test(logfd, "knet_handle_enable_pmtud_notify failed to unset pmtud_notify fn");
		CLEAN_EXIT(FAIL);
	}

	log_test(logfd, "Test knet_handle_enable_pmtud_notify with pmtud_notify fn");
	FAIL_ON_ERR(knet_handle_enable_pmtud_notify(knet_h1, NULL, pmtud_notify));

	if (knet_h1->pmtud_notify_fn != &pmtud_notify) {
		log_test(logfd, "knet_handle_enable_pmtud_notify failed to set pmtud_notify fn");
		CLEAN_EXIT(FAIL);
	}
	CLEAN_EXIT(CONTINUE);
}

int main(int argc, char *argv[])
{
	test();

	return PASS;
}
