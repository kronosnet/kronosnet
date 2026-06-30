/*
 * Copyright (C) 2018-2026 Red Hat, Inc.  All rights reserved.
 *
 * Author: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *
 * This software licensed under GPL-2.0+
 */

#include "config.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <limits.h>

#include "test-common.h"

static int test(void)
{
	char device_name[2*IFNAMSIZ];
	const char *device_name_tmp;
	size_t size = IFNAMSIZ;
	nozzle_t nozzle = NULL;
	int err = 0;

	printf("Testing get name by handle\n");

	memset(device_name, 0, size);

	printf("Creating nozzle interface\n");
	FAIL_ON_NULL(nozzle, nozzle_open(device_name, size, NULL));

	printf("Getting name by handle\n");
	FAIL_ON_NULL(device_name_tmp, nozzle_get_name_by_handle(nozzle));

	printf("Verifying name matches\n");
	FAIL_ON_NONZERO(strcmp(device_name, device_name_tmp), "get name by handle returned different names for the same handle");

	printf("Testing error conditions\n");

	printf("Testing NULL handle\n");
	FAIL_ON_NOT_NULL(device_name_tmp, nozzle_get_name_by_handle(NULL), ENOENT);

out_clean:

	if (nozzle) {
		nozzle_close(nozzle);
	}

	return err;
}

int main(void)
{
	need_root();
	need_tun();

	if (test() < 0)
		return FAIL;

	return PASS;
}
