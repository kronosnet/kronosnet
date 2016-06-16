/*
 * Copyright (C) 2010-2015 Red Hat, Inc.  All rights reserved.
 *
 * Authors: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *          Federico Simoncelli <fsimon@kronosnet.org>
 *
 * This software licensed under GPL-2.0+, LGPL-2.0+
 */

#include "config.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "libknet.h"

#include "test-common.h"

int main(int argc, char *argv[])
{
	int i;
	knet_handle_t knet_h;

	need_root();

	knet_h = knet_handle_new(1, 0, 0);
	if (!knet_h) {
		printf("Unable to init knet_handle! err: %s\n", strerror(errno));
		exit(FAIL);
	}

	for (i = 0; i < 24; i++) {
		printf("add host: %d\n", i);
		if (knet_host_add(knet_h, i) < 0) {
			printf("Unable to add hosts! err: %s\n", strerror(errno));
			exit(FAIL);
		}
	}

	for (i = 0; i < 24; i++) {
		printf("del host: %d\n", i);
		if (knet_host_remove(knet_h, i) < 0) {
			printf("Unable to del hosts! err: %s\n", strerror(errno));
			exit(FAIL);
		}
	}

	if (knet_handle_free(knet_h) != 0) {
		printf("Unable to free knet_handle\n");
		exit(FAIL);
	}

	return PASS;
}
