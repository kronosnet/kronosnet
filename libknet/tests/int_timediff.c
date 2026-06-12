/*
 * Copyright (C) 2010-2026 Red Hat, Inc.  All rights reserved.
 *
 * Authors: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *          Federico Simoncelli <fsimon@kronosnet.org>
 *
 * This software licensed under GPL-2.0+
 */

#include "config.h"

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <pthread.h>

#include "test-common.h"

#define TEST_NAME "int_timediff"

#define timespec_set(x, sec, nsec) \
do { \
	x.tv_sec = sec; \
	x.tv_nsec = nsec; \
} while (0);

static void check_timespec_diff(void)
{
	int logfd;
	unsigned long long diff;
	struct timespec start, end;

	logfd = start_logging(stdout);

	timespec_set(start, 1, 30000);

	timespec_set(end, start.tv_sec, start.tv_nsec + 10000);
	timespec_diff(start, end, &diff);

	log_test(logfd, "Checking 10000 == %llu", diff);

	if (diff != 10000) {
		log_test(logfd, "Failure!");
		TEST_EXIT(FAIL);
	}

	timespec_set(end, start.tv_sec + 5, start.tv_nsec - 5000);
	timespec_diff(start, end, &diff);

	log_test(logfd, "Checking 4999995000 == %llu", diff);

	if (diff != 4999995000llu) {
		log_test(logfd, "Failure!");
		TEST_EXIT(FAIL);
	}

	stop_logging();
}

int main(int argc, char *argv[])
{
	printf("[TEST] %s: Test Timediff\n", TEST_NAME);

	check_timespec_diff();

	TEST_EXIT(PASS);
}
