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

#define HOST_LIST_SIZE 8192
#define HOST_LIST_LOOP 64

static int host_loop(knet_handle_t knet_h, struct knet_host *host, struct knet_host_search *search)
{
	host->link_handler_policy = KNET_LINK_POLICY_ACTIVE;
	search->param1++;
	return KNET_HOST_FOREACH_NEXT;
}

int main(int argc, char *argv[])
{
	int sock, i, j;
	knet_handle_t knet_h;
	struct knet_host_search search;
	struct knet_handle_cfg knet_handle_cfg;

	sock = socket(AF_UNIX, SOCK_STREAM, 0);

	if (sock < 0) {
		printf("Unable to create new socket\n");
		exit(EXIT_FAILURE);
	}

	memset(&knet_handle_cfg, 0, sizeof(struct knet_handle_cfg));
	knet_handle_cfg.to_net_fd = sock;
	knet_handle_cfg.node_id = 1;

	knet_h = knet_handle_new(&knet_handle_cfg);

	for (i = 0; i < HOST_LIST_SIZE; i++)
		knet_host_add(knet_h, i);

	search.param1 = 0;

	for (i = 0; i < HOST_LIST_SIZE; i++) {
		for (j = 0; j < HOST_LIST_LOOP; j++) {
			knet_host_foreach(knet_h, host_loop, &search);
		}
		knet_host_remove(knet_h, i);
	}

	printf("Loop count: %u times\n", (unsigned int) search.param1);

	if (knet_handle_free(knet_h) != 0) {
		printf("Unable to free knet_handle\n");
		exit(EXIT_FAILURE);
	}

	return 0;
}
