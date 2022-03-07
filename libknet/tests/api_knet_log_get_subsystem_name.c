/*
 * Copyright (C) 2016-2022 Red Hat, Inc.  All rights reserved.
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

	printf("Testing knet_log_get_subsystem_name normal lookup\n");
	res = knet_log_get_subsystem_name(KNET_SUB_NSSCRYPTO);
	if (strcmp(res, "nsscrypto")) {
		printf("knet_log_get_subsystem_name failed to get correct log subsystem name. got: %s expected: nsscrypto\n",
		       res);
		exit(FAIL);
	}

	printf("Testing knet_log_get_subsystem_name bad lookup (within boundaries)\n");
	res = knet_log_get_subsystem_name(KNET_SUB_UNKNOWN - 1);
	if (strcmp(res, "unknown")) {
		printf("knet_log_get_subsystem_name failed to get correct log subsystem name. got: %s expected: common\n",
		       res);
		exit(FAIL);
	}

	printf("Testing knet_log_get_subsystem_name bad lookup (outside boundaries)\n");
	res = knet_log_get_subsystem_name(KNET_MAX_SUBSYSTEMS);
	if (strcmp(res, "unknown")) {
		printf("knet_log_get_subsystem_name failed to get correct log subsystem name. got: %s expected: common\n",
		       res);
		exit(FAIL);
	}
}

int main(int argc, char *argv[])
{
	test();

	return PASS;
}
