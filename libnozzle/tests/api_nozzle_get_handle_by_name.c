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
	size_t size = IFNAMSIZ;
	nozzle_t nozzle = NULL, nozzle_tmp;
	int err = 0;

	printf("Testing get handle by name\n");

	memset(device_name, 0, size);

	printf("Creating nozzle interface\n");
	FAIL_ON_NULL(nozzle, nozzle_open(device_name, size, NULL));

	printf("Getting handle by name\n");
	FAIL_ON_NULL(nozzle_tmp, nozzle_get_handle_by_name(device_name));

	printf("Verifying handle matches\n");
	if (nozzle != nozzle_tmp) {
		printf("*** FAIL on line %d. get handle by name returned wrong handle!\n", __LINE__);
		err = -1;
		goto out_clean;
	}

	printf("Testing error conditions\n");

	printf("Testing with NULL device name\n");
	FAIL_ON_NOT_NULL(nozzle_tmp, nozzle_get_handle_by_name(NULL), EINVAL);

	printf("Testing with device name longer than IFNAMSIZ\n");
	FAIL_ON_NOT_NULL(nozzle_tmp, nozzle_get_handle_by_name("antanisupercazzolaunpotapioca"), EINVAL);

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
