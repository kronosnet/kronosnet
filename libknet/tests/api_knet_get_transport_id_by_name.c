/*
 * Copyright (C) 2017-2023 Red Hat, Inc.  All rights reserved.
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
	uint8_t id;

	printf("Test knet_get_transport_id_by_name with no name\n");

	if ((knet_get_transport_id_by_name(NULL) != KNET_MAX_TRANSPORTS) || (errno != EINVAL)) {
		printf("knet_get_transport_id_by_name accepted invalid transport or returned incorrect error: %s\n", strerror(errno));
		exit(FAIL);
	}

	printf("Test knet_get_transport_id_by_name with incorrect name\n");

	if ((knet_get_transport_id_by_name("ARP") != KNET_MAX_TRANSPORTS) || (errno != EINVAL)) {
		printf("knet_get_transport_id_by_name accepted invalid transport or returned incorrect error: %s\n", strerror(errno));
		exit(FAIL);
	}

	printf("Test knet_get_transport_id_by_name with correct values\n");

	id = knet_get_transport_id_by_name("UDP");
	if (id != KNET_TRANSPORT_UDP) {
		printf("knet_get_transport_id_by_name failed: %s\n", strerror(errno));
		exit(FAIL);
	}
}

int main(int argc, char *argv[])
{
	test();

	return PASS;
}
