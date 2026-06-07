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
#include <sys/time.h>
#include <sys/resource.h>

#include "libknet.h"
#include "internals.h"

#include "test-common.h"

#define TEST_NAME "api_knet_handle_new"

static void test(void)
{
	int logfd;
	knet_handle_t knet_h1, knet_h[2] = {0};
	struct rlimit cur;

	logfd = start_logging(stdout);

	log_test(logfd, "Test knet_handle_new hostid 1, no logging");

	knet_h1 = knet_handle_new(1, 0, 0, 0);
	if (!knet_h1) {
		log_test(logfd, "Unable to init knet_handle! err: %s", strerror(errno));
		TEST_EXIT(FAIL);
	}

	if (knet_handle_free(knet_h1) != 0) {
		log_test(logfd, "Unable to free knet_handle");
		TEST_EXIT(FAIL);
	}

	log_test(logfd, "Test knet_handle_new hostid -1, no logging");

	knet_h1 = knet_handle_new(-1, 0, 0, 0);
	if (!knet_h1) {
		log_test(logfd, "Unable to init knet_handle! err: %s", strerror(errno));
		TEST_EXIT(FAIL);
	}

	/*
	 * -1 == knet_node_id_t 65535
	 */

	if (knet_h1->host_id != 65535) {
		log_test(logfd, "host_id size might have changed!");
		knet_handle_free(knet_h1);
		TEST_EXIT(FAIL);
	}

	if (knet_handle_free(knet_h1) != 0) {
		log_test(logfd, "Unable to free knet_handle");
		TEST_EXIT(FAIL);
	}

	if (getrlimit(RLIMIT_NOFILE, &cur) < 0) {
		log_test(logfd, "Unable to get current fd limit: %s", strerror(errno));
		TEST_EXIT(SKIP);
	}

	/*
	 * passing a bad fd and it should fail
	 */
	log_test(logfd, "Test knet_handle_new hostid 1, incorrect log_fd (-1)");

	knet_h1 = knet_handle_new(1, -1, 0, 0);

	if ((!knet_h1) && (errno != EINVAL)) {
		log_test(logfd, "knet_handle_new returned incorrect errno on incorrect log_fd");
		TEST_EXIT(FAIL);
	}

	if (knet_h1) {
		log_test(logfd, "knet_handle_new accepted an incorrect (-1) log_fd");
		knet_handle_free(knet_h1);
		TEST_EXIT(FAIL);
	}

	/*
	 * passing a bad fd and it should fail
	 */
	log_test(logfd, "Test knet_handle_new hostid 1, incorrect log_fd (max_fd + 1)");

	knet_h1 = knet_handle_new(1, (int) cur.rlim_max, 0, 0);

	if ((knet_h1) || (errno != EINVAL)) {
		log_test(logfd, "knet_handle_new accepted an incorrect (max_fd + 1) log_fd or returned incorrect errno on incorrect log_fd: %s", strerror(errno));
		knet_handle_free(knet_h1);
		TEST_EXIT(FAIL);
	}


	log_test(logfd, "Test knet_handle_new hostid 1, proper log_fd, invalid log level (DEBUG + 1)");

	knet_h1 = knet_handle_new(1, logfd, KNET_LOG_DEBUG + 1 ,0);
	if ((knet_h1) || (errno != EINVAL)) {
		log_test(logfd, "knet_handle_new accepted an incorrect log level or returned incorrect errno on incorrect log level: %s", strerror(errno));
		knet_h[1] = knet_h1;
		TEST_EXIT_CLEAN(FAIL);
	}

	log_test(logfd, "Test knet_handle_new hostid 1, proper log_fd, proper log level (DEBUG)");

	(void)_ts_knet_handle_start(logfd, KNET_LOG_DEBUG, knet_h);
	TEST_EXIT_CLEAN(CONTINUE);
}

int main(int argc, char *argv[])
{
	printf("[TEST] %s: Create and free knet handle with various parameters\n", TEST_NAME);

	test();

	TEST_EXIT(PASS);
}
