/*
 * Copyright (C) 2017-2018 Red Hat, Inc.  All rights reserved.
 *
 * Authors: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *
 * This software licensed under GPL-2.0+, LGPL-2.0+
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
	struct knet_transport_info transport_list[KNET_MAX_TRANSPORTS];
	size_t transport_list_entries;
	size_t transport_list_entries1;
	size_t i;

	memset(transport_list, 0, sizeof(transport_list));

	printf("Test knet_handle_get_transport_list with no entries_list\n");

	if ((!knet_get_transport_list(transport_list, NULL)) || (errno != EINVAL)) {
		printf("knet_get_transport_list accepted invalid list_entries or returned incorrect error: %s\n", strerror(errno));
		exit(FAIL);
	}

	printf("Test knet_get_transport_list with no transport_list (get number of entries)\n");

	if (knet_get_transport_list(NULL, &transport_list_entries) < 0) {
		printf("knet_get_transport_list returned error instead of number of entries: %s\n", strerror(errno));
		exit(FAIL);
	}

	printf("Test knet_get_transport_list with valid data\n");

	if (knet_get_transport_list(transport_list, &transport_list_entries1) < 0) {
		printf("knet_get_transport_list failed: %s\n", strerror(errno));
		exit(FAIL);
	}

	if (transport_list_entries != transport_list_entries1) {
		printf("knet_get_transport_list returned a different number of entries: %d, %d\n",
		       (int)transport_list_entries, (int)transport_list_entries1);
		exit(FAIL);
	}

	for (i=0; i<transport_list_entries; i++) {
		printf("Detected transport: %s id: %d properties: %u\n",
			transport_list[i].name, transport_list[i].id, transport_list[i].properties);
	}
}

int main(int argc, char *argv[])
{
	test();

	return PASS;
}
