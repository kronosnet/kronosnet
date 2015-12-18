/*
 * Copyright (C) 2010-2015 Red Hat, Inc.  All rights reserved.
 *
 * Authors: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *          Federico Simoncelli <fsimon@kronosnet.org>
 *
 * This software licensed under GPL-2.0+, LGPL-2.0+
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "libknet.h"

int main(int argc, char *argv[])
{
	int i;
	knet_handle_t knet_h;

	knet_h = knet_handle_new(1, 0, 0);

	for (i = 0; i < KNET_MAX_HOST; i++) {
		printf("add host: %d\n", i);
		knet_host_add(knet_h, i);
	}

	for (i = 0; i < KNET_MAX_HOST; i++) {
		printf("del host: %d\n", i);
		knet_host_remove(knet_h, i);
	}

	if (knet_handle_free(knet_h) != 0) {
		printf("Unable to free knet_handle\n");
		exit(EXIT_FAILURE);
	}

	return 0;
}
