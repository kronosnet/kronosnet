/*
 * Copyright (C) 2016-2019 Red Hat, Inc.  All rights reserved.
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
	uint8_t res;

	printf("Testing knet_log_get_subsystem_id normal lookup\n");
	res = knet_log_get_subsystem_id("nsscrypto");
	if (res != KNET_SUB_NSSCRYPTO) {
		printf("knet_log_get_subsystem_id failed to get correct log subsystem id. got: %u expected: %d\n",
		       res, KNET_SUB_NSSCRYPTO);
		exit(FAIL);
	}

	printf("Testing knet_log_get_subsystem_id bad lookup\n");
	res = knet_log_get_subsystem_id("whatever");
	if (res != KNET_SUB_UNKNOWN) {
		printf("knet_log_get_subsystem_id failed to get correct log subsystem id. got: %u expected: %d\n",
		       res, KNET_SUB_UNKNOWN);
		exit(FAIL);
	}
}

int main(int argc, char *argv[])
{
	test();

	return PASS;
}
