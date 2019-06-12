/*
 * Copyright (C) 2017-2019 Red Hat, Inc.  All rights reserved.
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

static void test(void)
{
	const char *name = NULL;

	printf("Test knet_get_transport_name_by_id with incorrect transport\n");

	if ((knet_get_transport_name_by_id(KNET_MAX_TRANSPORTS) != NULL) || (errno != EINVAL)) {
		printf("knet_get_transport_name_by_id accepted invalid transport or returned incorrect error: %s\n", strerror(errno));
		exit(FAIL);
	}

	printf("Test knet_get_transport_name_by_id with correct values\n");

	name = knet_get_transport_name_by_id(KNET_TRANSPORT_UDP);
	if (!name) {
		printf("knet_get_transport_name_by_id failed: %s\n", strerror(errno));
		exit(FAIL);
	}

	if (strcmp(name, "UDP")) {
		printf("knet_get_transport_name_by_id failed to get UDP transport name\n");
		exit(FAIL);
	}
}

int main(int argc, char *argv[])
{
	test();

	return PASS;
}
