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
	struct knet_crypto_info crypto_list[16];
	size_t crypto_list_entries;
	size_t crypto_list_entries1;
	size_t i;

	memset(crypto_list, 0, sizeof(crypto_list));

	printf("Test knet_handle_get_crypto_list with no entries_list\n");

	if ((!knet_get_crypto_list(crypto_list, NULL)) || (errno != EINVAL)) {
		printf("knet_get_crypto_list accepted invalid list_entries or returned incorrect error: %s\n", strerror(errno));
		exit(FAIL);
	}

	printf("Test knet_get_crypto_list with no crypto_list (get number of entries)\n");

	if (knet_get_crypto_list(NULL, &crypto_list_entries) < 0) {
		printf("knet_handle_get_crypto_list returned error instead of number of entries: %s\n", strerror(errno));
		exit(FAIL);
	}

	printf("Test knet_get_crypto_list with valid data\n");

	if (knet_get_crypto_list(crypto_list, &crypto_list_entries1) < 0) {
		printf("knet_get_crypto_list failed: %s\n", strerror(errno));
		exit(FAIL);
	}

	if (crypto_list_entries != crypto_list_entries1) {
		printf("knet_get_crypto_list returned a different number of entries: %d, %d\n",
		       (int)crypto_list_entries, (int)crypto_list_entries1);
		exit(FAIL);
	}

	for (i=0; i<crypto_list_entries; i++) {
		printf("Detected crypto: %s\n", crypto_list[i].name);
	}
}

int main(int argc, char *argv[])
{
	test();

	return PASS;
}
