/*
 * Copyright (C) 2018-2024 Red Hat, Inc.  All rights reserved.
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
	nozzle_t nozzle, nozzle_tmp;
	int err = 0;

	printf("Testing get handle by name\n");

	memset(device_name, 0, size);
	nozzle = nozzle_open(device_name, size, NULL);
	if (!nozzle) {
		printf("Unable to init %s\n", device_name);
		return -1;
	}

	nozzle_tmp = nozzle_get_handle_by_name(device_name);
	if ((!nozzle_tmp) && (errno != ENOENT)) {
		printf("Unable to get handle by name\n");
		err = -1;
		goto out_clean;
	}

	if (nozzle != nozzle_tmp) {
		printf("get handle by name returned wrong handle!\n");
		err = -1;
		goto out_clean;
	}

	printf("Testing error conditions\n");

	printf("Testing with NULL device name\n");

	nozzle_tmp = nozzle_get_handle_by_name(NULL);

	if ((nozzle_tmp) || (errno != EINVAL)) {
		printf("get handle by name returned wrong error\n");
		err = -1;
		goto out_clean;
	}

	printf("Testing with device name longer than IFNAMSIZ\n");

	nozzle_tmp = nozzle_get_handle_by_name("antanisupercazzolaunpotapioca");
	if ((nozzle_tmp) || (errno != EINVAL)) {
		printf("get handle by name returned wrong error\n");
		err = -1;
		goto out_clean;
	}

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
