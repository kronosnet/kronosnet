/*
 * Copyright (C) 2018-2020 Red Hat, Inc.  All rights reserved.
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
	nozzle_t nozzle;
	int err = 0;

	printf("Testing get name by handle\n");

	memset(device_name, 0, size);
	nozzle = nozzle_open(device_name, size, NULL);
	if (!nozzle) {
		printf("Unable to init %s\n", device_name);
		return -1;
	}

	device_name_tmp = nozzle_get_name_by_handle(nozzle);
	if (!device_name_tmp) {
		if (errno != ENOENT) {
			printf("Unable to get name by handle\n");
		} else {
			printf("received incorrect errno!\n");
		}
		err = -1;
		goto out_clean;
	}

	if (strcmp(device_name, device_name_tmp)) {
		printf("get name by handle returned different names for the same handle\n");
		err = -1;
		goto out_clean;
	}

	printf("Testing error conditions\n");

	device_name_tmp = nozzle_get_name_by_handle(NULL);
	if ((device_name_tmp) || (errno != ENOENT)) {
		printf("get name by handle returned wrong error\n");
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

	if (test() < 0)
		return FAIL;

	return PASS;
}
