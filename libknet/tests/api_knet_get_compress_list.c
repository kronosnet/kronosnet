/*
 * Copyright (C) 2017-2025 Red Hat, Inc.  All rights reserved.
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
	struct knet_compress_info compress_list[16];
	size_t compress_list_entries;
	size_t compress_list_entries1;
	size_t i;

	memset(compress_list, 0, sizeof(compress_list));

	printf("Test knet_get_compress_list with no entries_list\n");

	if ((!knet_get_compress_list(compress_list, NULL)) || (errno != EINVAL)) {
		printf("knet_get_compress_list accepted invalid list_entries or returned incorrect error: %s\n", strerror(errno));
		exit(FAIL);
	}

	printf("Test knet_get_compress_list with no compress_list (get number of entries)\n");

	if (knet_get_compress_list(NULL, &compress_list_entries) < 0) {
		printf("knet_handle_get_compress_list returned error instead of number of entries: %s\n", strerror(errno));
		exit(FAIL);
	}

	printf("Test knet_get_compress_list with valid data\n");

	if (knet_get_compress_list(compress_list, &compress_list_entries1) < 0) {
		printf("knet_get_compress_list failed: %s\n", strerror(errno));
		exit(FAIL);
	}

	if (compress_list_entries != compress_list_entries1) {
		printf("knet_get_compress_list returned a different number of entries: %d, %d\n",
		       (int)compress_list_entries, (int)compress_list_entries1);
		exit(FAIL);
	}

	for (i=0; i<compress_list_entries; i++) {
		printf("Detected compress: %s\n", compress_list[i].name);
	}
}

int main(int argc, char *argv[])
{
	test();

	return PASS;
}
