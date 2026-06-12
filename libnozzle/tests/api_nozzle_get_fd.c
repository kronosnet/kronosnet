/*
 * Copyright (C) 2018-2026 Red Hat, Inc.  All rights reserved.
 *
 * Author: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *
 * This software licensed under GPL-2.0+
 */

#include "config.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <limits.h>
#include <fcntl.h>

#include "test-common.h"

static int test(void)
{
	char device_name[IFNAMSIZ];
	size_t size = IFNAMSIZ;
	int err=0;
	nozzle_t nozzle = NULL;
	int fd;

	printf("Testing get fd\n");

	memset(device_name, 0, size);

	printf("Creating nozzle interface\n");
	FAIL_ON_NULL(nozzle, nozzle_open(device_name, size, NULL));

	printf("Getting file descriptor\n");
	FAIL_ON_ERR_ONLY(fd = nozzle_get_fd(nozzle), "nozzle_get_fd failed");

	printf("Verifying file descriptor is valid\n");
	FAIL_ON_ERR_ONLY(fcntl(fd, F_GETFD), "fcntl failed, invalid fd");

	printf("Testing ERROR conditions\n");

	printf("Passing empty struct to get_fd\n");
	FAIL_ON_NOT_ERR_ONLY(nozzle_get_fd(NULL), ENOENT, "nozzle_get_fd(NULL) should have failed with ENOENT");

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
