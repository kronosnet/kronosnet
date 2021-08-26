/*
 * Copyright (C) 2020-2021 Red Hat, Inc.  All rights reserved.
 *
 * Authors: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *
 * This software licensed under GPL-2.0+
 */

#include "config.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <pthread.h>

#include "libknet.h"

#include "compress.h"
#include "internals.h"
#include "netutils.h"
#include "test-common.h"

#define TESTNODES 3

static int upgrade_onwire_max_ver(knet_handle_t knet_h, int nodes, uint8_t min, uint8_t max, int seconds, int logfd, FILE *std)
{
	if (knet_handle_disconnect_links(knet_h) < 0) {
		return -1;
	}

	if (wait_for_nodes_state(knet_h, TESTNODES, 0, seconds, logfd, std) < 0) {
		printf("Failed waiting for nodes 0\n");
		return -1;
	}

	knet_h->onwire_min_ver = min;
	knet_h->onwire_max_ver = max;
	if (knet_handle_reconnect_links(knet_h) < 0) {
		return -1;
	}

	if (nodes) {
		if (wait_for_nodes_state(knet_h, nodes, 1, seconds, logfd, std) < 0) {
			printf("Failed waiting for nodes 1\n");
			return -1;
		}
	}

	return 0;
}

static void onwire_ver_callback_fn(void *private_data, uint8_t onwire_min_ver, uint8_t onwire_max_ver, uint8_t onwire_ver)
{
	knet_handle_t knet_h = (knet_handle_t)private_data;

	printf("Received callback from %p: min: %u max: %u current: %u\n", knet_h, onwire_min_ver, onwire_max_ver, onwire_ver);
}

static void test(void)
{
	knet_handle_t knet_h[TESTNODES + 1];
	int logfds[2];
	int i,j;
	int seconds = 10;

	if (is_memcheck() || is_helgrind()) {
		printf("Test suite is running under valgrind, adjusting wait_for_host timeout\n");
		seconds = seconds * 16;
	}

	setup_logpipes(logfds);

	knet_handle_start_nodes(knet_h, TESTNODES, logfds, KNET_LOG_DEBUG);

	flush_logs(logfds[0], stdout);

	for (i = 1; i <= TESTNODES; i++) {
		knet_h[i]->onwire_ver_remap = 1;
		if (knet_handle_enable_onwire_ver_notify(knet_h[i], (void *)&knet_h[i], onwire_ver_callback_fn) < 0) {
			printf("Failed to install onwire ver callback\n");
				knet_handle_stop_nodes(knet_h, TESTNODES);
				flush_logs(logfds[0], stdout);
				close_logpipes(logfds);
				exit(FAIL);
		}
	}

	flush_logs(logfds[0], stdout);

	knet_handle_join_nodes(knet_h, TESTNODES, 1, AF_INET, KNET_TRANSPORT_UDP);

	flush_logs(logfds[0], stdout);

	printf("Test normal onwire upgrade from %u to %u\n", knet_h[1]->onwire_ver, knet_h[1]->onwire_ver + 1);

	for (i = 1; i <= TESTNODES; i++) {
		if (upgrade_onwire_max_ver(knet_h[i], TESTNODES, knet_h[1]->onwire_ver, knet_h[1]->onwire_ver + 1, seconds,
					   logfds[0], stdout) < 0) {
			knet_handle_stop_nodes(knet_h, TESTNODES);
			flush_logs(logfds[0], stdout);
			close_logpipes(logfds);
			exit(FAIL);
		}
		flush_logs(logfds[0], stdout);
	}

	flush_logs(logfds[0], stdout);
	sleep(seconds);
	flush_logs(logfds[0], stdout);

	for (i = 1; i <= TESTNODES; i++) {
		printf("node %u, onwire: %u min: %u max: %u\n", i, knet_h[i]->onwire_ver, knet_h[i]->onwire_min_ver, knet_h[i]->onwire_max_ver);
	}

	flush_logs(logfds[0], stdout);
	sleep(seconds);
	flush_logs(logfds[0], stdout);

	printf("Test onwire upgrade from %u to %u (all but one node)\n", knet_h[1]->onwire_ver, knet_h[1]->onwire_ver + 1);

	for (i = 1; i < TESTNODES; i++) {
		if (upgrade_onwire_max_ver(knet_h[i], TESTNODES, knet_h[i]->onwire_ver, knet_h[i]->onwire_ver + 1, seconds,
					   logfds[0], stdout) < 0) {
			knet_handle_stop_nodes(knet_h, TESTNODES);
			flush_logs(logfds[0], stdout);
			close_logpipes(logfds);
			exit(FAIL);
		}
		flush_logs(logfds[0], stdout);
	}

	flush_logs(logfds[0], stdout);
	sleep(seconds);
	flush_logs(logfds[0], stdout);

	for (i = 1; i <= TESTNODES; i++) {
		printf("node %u, onwire: %u min: %u max: %u\n", i, knet_h[i]->onwire_ver, knet_h[i]->onwire_min_ver, knet_h[i]->onwire_max_ver);
	}

	flush_logs(logfds[0], stdout);
	sleep(seconds);
	flush_logs(logfds[0], stdout);

	printf("Test onwire upgrade from %u to %u (all but one node - phase 2, node should be kicked out and remaining nodes should upgrade)\n", knet_h[1]->onwire_max_ver, knet_h[1]->onwire_max_ver + 1);

	for (i = 1; i < TESTNODES; i++) {
		if (upgrade_onwire_max_ver(knet_h[i], TESTNODES - 1, knet_h[i]->onwire_max_ver, knet_h[i]->onwire_max_ver + 1, seconds,
					   logfds[0], stdout) < 0) {
			knet_handle_stop_nodes(knet_h, TESTNODES);
			flush_logs(logfds[0], stdout);
			close_logpipes(logfds);
			exit(FAIL);
		}
		flush_logs(logfds[0], stdout);
	}

	flush_logs(logfds[0], stdout);
	sleep(seconds);
	flush_logs(logfds[0], stdout);

	for (i = 1; i <= TESTNODES; i++) {
		printf("node %u, onwire: %u min: %u max: %u\n", i, knet_h[i]->onwire_ver, knet_h[i]->onwire_min_ver, knet_h[i]->onwire_max_ver);
		for (j = 1; j <= TESTNODES; j++) {
			if (j == i) {
				continue;
			}

			if (i == TESTNODES) {
				/*
				 * highset node has been kicked out and should not
				 * be able to reach any other node
				 */
				if (knet_h[i]->host_index[j]->status.reachable != 0) {
					knet_handle_stop_nodes(knet_h, TESTNODES);
					flush_logs(logfds[0], stdout);
					close_logpipes(logfds);
					exit(FAIL);
				}
			} else {
				/*
				 * all other nodes should detect the highest node unreachable
				 * and all the remaining nodes reachable
				 */
				if (j == TESTNODES) {
					if (knet_h[i]->host_index[j]->status.reachable != 0) {
						knet_handle_stop_nodes(knet_h, TESTNODES);
						flush_logs(logfds[0], stdout);
						close_logpipes(logfds);
						exit(FAIL);
					}
				} else {
					if (knet_h[i]->host_index[j]->status.reachable != 1) {
						knet_handle_stop_nodes(knet_h, TESTNODES);
						flush_logs(logfds[0], stdout);
						close_logpipes(logfds);
						exit(FAIL);
					}
				}
			}
		}
	}

	flush_logs(logfds[0], stdout);
	sleep(seconds);
	flush_logs(logfds[0], stdout);

	/*
	 * CHANGE THIS TEST if we decide to support downgrades
	 */
	printf("Testing node rejoining one version lower (cluster should reject the node)\n");

	if (upgrade_onwire_max_ver(knet_h[TESTNODES], 0, knet_h[1]->onwire_min_ver - 1, knet_h[1]->onwire_max_ver - 1, seconds,
				   logfds[0], stdout) < 0) {
		knet_handle_stop_nodes(knet_h, TESTNODES);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	/*
	 * need more time here for membership to settle
	 */
	flush_logs(logfds[0], stdout);
	sleep(seconds);
	flush_logs(logfds[0], stdout);
	sleep(seconds);
	flush_logs(logfds[0], stdout);

	for (i = 1; i <= TESTNODES; i++) {
		printf("node %u, onwire: %u min: %u max: %u\n", i, knet_h[i]->onwire_ver, knet_h[i]->onwire_min_ver, knet_h[i]->onwire_max_ver);
		for (j = 1; j <= TESTNODES; j++) {
			if (j == i) {
				continue;
			}

			if (i == TESTNODES) {
				/*
				 * highset node has been kicked out and should not
				 * be able to reach any other node
				 */
				if (knet_h[i]->host_index[j]->status.reachable != 0) {
					knet_handle_stop_nodes(knet_h, TESTNODES);
					flush_logs(logfds[0], stdout);
					close_logpipes(logfds);
					exit(FAIL);
				}
			} else {
				/*
				 * all other nodes should detect the highest node unreachable
				 * and all the remaining nodes reachable
				 */
				if (j == TESTNODES) {
					if (knet_h[i]->host_index[j]->status.reachable != 0) {
						knet_handle_stop_nodes(knet_h, TESTNODES);
						flush_logs(logfds[0], stdout);
						close_logpipes(logfds);
						exit(FAIL);
					}
				} else {
					if (knet_h[i]->host_index[j]->status.reachable != 1) {
						knet_handle_stop_nodes(knet_h, TESTNODES);
						flush_logs(logfds[0], stdout);
						close_logpipes(logfds);
						exit(FAIL);
					}
				}
			}
		}
	}

	printf("Testing node rejoining with proper version (cluster should reform)\n");

	if (upgrade_onwire_max_ver(knet_h[TESTNODES], TESTNODES, knet_h[1]->onwire_min_ver, knet_h[1]->onwire_max_ver, seconds,
				   logfds[0], stdout) < 0) {
		knet_handle_stop_nodes(knet_h, TESTNODES);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	/*
	 * need more time here for membership to settle
	 */
	flush_logs(logfds[0], stdout);
	sleep(seconds);
	flush_logs(logfds[0], stdout);
	sleep(seconds);
	flush_logs(logfds[0], stdout);

	for (i = 1; i <= TESTNODES; i++) {
		printf("node %u, onwire: %u min: %u max: %u\n", i, knet_h[i]->onwire_ver, knet_h[i]->onwire_min_ver, knet_h[i]->onwire_max_ver);
		for (j = 1; j <= TESTNODES; j++) {
			if (j == i) {
				continue;
			}
			if ((knet_h[i]->host_index[j]->status.reachable != 1) || (knet_h[i]->onwire_ver != knet_h[1]->onwire_max_ver)) {
				knet_handle_stop_nodes(knet_h, TESTNODES);
				flush_logs(logfds[0], stdout);
				close_logpipes(logfds);
				exit(FAIL);
			}
		}
	}

	printf("Testing node force onwire version\n");

	for (i = 1; i <= TESTNODES; i++) {
		if (knet_handle_set_onwire_ver(knet_h[i], knet_h[i]->onwire_min_ver) < 0) {
			knet_handle_stop_nodes(knet_h, TESTNODES);
			flush_logs(logfds[0], stdout);
			close_logpipes(logfds);
			exit(FAIL);
		}
	}

	/*
	 * need more time here for membership to settle
	 */
	flush_logs(logfds[0], stdout);
	sleep(seconds);
	flush_logs(logfds[0], stdout);
	sleep(seconds);
	flush_logs(logfds[0], stdout);

	for (i = 1; i <= TESTNODES; i++) {
		printf("node %u, onwire: %u min: %u max: %u\n", i, knet_h[i]->onwire_ver, knet_h[i]->onwire_min_ver, knet_h[i]->onwire_max_ver);
		for (j = 1; j <= TESTNODES; j++) {
			if (j == i) {
				continue;
			}
			if ((knet_h[i]->host_index[j]->status.reachable != 1) || (knet_h[i]->onwire_ver != knet_h[1]->onwire_min_ver)) {
				knet_handle_stop_nodes(knet_h, TESTNODES);
				flush_logs(logfds[0], stdout);
				close_logpipes(logfds);
				exit(FAIL);
			}
		}
	}

	flush_logs(logfds[0], stdout);
	close_logpipes(logfds);
	knet_handle_stop_nodes(knet_h, TESTNODES);
}

int main(int argc, char *argv[])
{
	test();

	return PASS;
}
