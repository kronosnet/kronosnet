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

#include "test-common.h"

static void test(void)
{
	int logfd;

	logfd = start_logging(stdout);
	uint8_t res;

	log_test(logfd, "Testing knet_log_get_subsystem_id normal lookup");
	res = knet_log_get_subsystem_id("nsscrypto");
	if (res != KNET_SUB_NSSCRYPTO) {
		log_test(logfd, "knet_log_get_subsystem_id failed to get correct log subsystem id. got: %u expected: %d",
		       res, KNET_SUB_NSSCRYPTO);
		stop_logging();
		exit(FAIL);
	}

	log_test(logfd, "Testing knet_log_get_subsystem_id bad lookup");
	res = knet_log_get_subsystem_id("whatever");
	if (res != KNET_SUB_UNKNOWN) {
		log_test(logfd, "knet_log_get_subsystem_id failed to get correct log subsystem id. got: %u expected: %d",
		       res, KNET_SUB_UNKNOWN);
		stop_logging();
		exit(FAIL);
	}

	stop_logging();
}

int main(int argc, char *argv[])
{
	test();

	return PASS;
}
