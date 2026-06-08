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
	fd = nozzle_get_fd(nozzle);
	if (fd < 0) {
		printf("*** FAIL on line %d. nozzle_get_fd failed: %s\n", __LINE__, strerror(errno));
		err = -1;
		goto out_clean;
	}

	printf("Verifying file descriptor is valid\n");
	if (fcntl(fd, F_GETFD) < 0) {
		printf("*** FAIL on line %d. fcntl failed, invalid fd: %s\n", __LINE__, strerror(errno));
		err = -1;
		goto out_clean;
	}

	printf("Testing ERROR conditions\n");

	printf("Passing empty struct to get_fd\n");
	fd = nozzle_get_fd(NULL);
	if ((fd >= 0) || (errno != ENOENT)) {
		printf("*** FAIL on line %d. nozzle_get_fd(NULL) should have failed with ENOENT: %s\n", __LINE__, strerror(errno));
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
