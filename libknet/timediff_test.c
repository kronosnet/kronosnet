/*
 * Copyright (C) 2010-2012 Red Hat, Inc.  All rights reserved.
 *
 * Authors: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *          Federico Simoncelli <fsimon@kronosnet.org>
 *
 * This software licensed under GPL-2.0+, LGPL-2.0+
 */

#include "config.h"

#include <stdio.h>
#include <time.h>
#include <stdlib.h>

#include "threads_common.h"

#define timespec_set(x, sec, nsec) \
do { \
	x.tv_sec = sec; \
	x.tv_nsec = nsec; \
} while (0);

static void check_timespec_diff(void)
{
	unsigned long long diff;
	struct timespec start, end;

	timespec_set(start, 1, 30000);

	timespec_set(end, start.tv_sec, start.tv_nsec + 10000);
	timespec_diff(start, end, &diff);

	printf("Checking 10000 == %llu\n", diff);

	if (diff != 10000) {
		printf("Failure!\n");
		exit(EXIT_FAILURE);
	}

	timespec_set(end, start.tv_sec + 5, start.tv_nsec - 5000);
	timespec_diff(start, end, &diff);

	printf("Checking 4999995000 == %llu\n", diff);

	if (diff != 4999995000llu) {
		printf("Failure!\n");
		exit(EXIT_FAILURE);
	}
}

int main(int argc, char *argv[])
{
	check_timespec_diff();

	return 0;
}
