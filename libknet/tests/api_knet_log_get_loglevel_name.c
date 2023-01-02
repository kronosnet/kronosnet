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

#include "test-common.h"

static void test(void)
{
	const char *res;

	printf("Testing knet_log_get_loglevel_name normal lookup\n");
	res = knet_log_get_loglevel_name(KNET_LOG_DEBUG);
	if (strcmp(res, "debug")) {
		printf("knet_log_get_loglevel_name failed to get correct log level name. got: %s expected: debug\n",
		       res);
		exit(FAIL);
	}

	printf("Testing knet_log_get_loglevel_name bad lookup\n");
	res = knet_log_get_loglevel_name(KNET_LOG_DEBUG+1);
	if (strcmp(res, "ERROR")) {
		printf("knet_log_get_loglevel_name failed to get correct log level name. got: %s expected: ERROR\n",
		       res);
		exit(FAIL);
	}
}

int main(int argc, char *argv[])
{
	test();

	return PASS;
}
