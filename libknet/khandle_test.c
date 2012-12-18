/*
 * Copyright (C) 2010-2012 Red Hat, Inc.  All rights reserved.
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
	int sock, i;
	knet_handle_t knet_h;

	sock = socket(AF_UNIX, SOCK_STREAM, 0);

	if (sock < 0) {
		printf("Unable to create new socket\n");
		exit(EXIT_FAILURE);
	}

	knet_h = knet_handle_new(1, sock, 0, 0);

	for (i = 0; i < KNET_MAX_HOST; i++)
		knet_host_add(knet_h, i);

	for (i = 0; i < KNET_MAX_HOST; i++)
		knet_host_remove(knet_h, i);

	if (knet_handle_free(knet_h) != 0) {
		printf("Unable to free knet_handle\n");
		exit(EXIT_FAILURE);
	}

	return 0;
}
