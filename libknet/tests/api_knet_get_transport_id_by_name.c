/*
 * Copyright (C) 2017-2026 Red Hat, Inc.  All rights reserved.
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
	int logfd;
	uint8_t id;

	logfd = start_logging(stdout);

	log_test(logfd, "Test knet_get_transport_id_by_name with no name");

	if ((knet_get_transport_id_by_name(NULL) != KNET_MAX_TRANSPORTS) || (errno != EINVAL)) {
		log_test(logfd, "knet_get_transport_id_by_name accepted invalid transport or returned incorrect error: %s", strerror(errno));
		stop_logging();
		exit(FAIL);
	}

	log_test(logfd, "Test knet_get_transport_id_by_name with incorrect name");

	if ((knet_get_transport_id_by_name("ARP") != KNET_MAX_TRANSPORTS) || (errno != EINVAL)) {
		log_test(logfd, "knet_get_transport_id_by_name accepted invalid transport or returned incorrect error: %s", strerror(errno));
		stop_logging();
		exit(FAIL);
	}

	log_test(logfd, "Test knet_get_transport_id_by_name with correct values");

	id = knet_get_transport_id_by_name("UDP");
	if (id != KNET_TRANSPORT_UDP) {
		log_test(logfd, "knet_get_transport_id_by_name failed: %s", strerror(errno));
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
