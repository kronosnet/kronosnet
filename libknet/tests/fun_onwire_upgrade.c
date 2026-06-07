/*
 * Copyright (C) 2020-2026 Red Hat, Inc.  All rights reserved.
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

#define TEST_NAME "fun_onwire_upgrade"

#undef TESTNODES
#define TESTNODES 3

static int test_logfd;

static int upgrade_onwire_max_ver(knet_handle_t knet_h, int nodes, uint8_t min, uint8_t max, int seconds, int logfd)
{
	if (_ts_knet_handle_disconnect_links(knet_h, logfd) < 0) {
		return -1;
	}

	if (wait_for_nodes_state(knet_h, TESTNODES, 0, seconds, logfd) < 0) {
		log_test(logfd, "Failed waiting for nodes 0");
		return -1;
	}

	/*
	 * Acquire write lock to ensure RX threads (which hold read lock during
	 * packet processing at threads_rx.c:1035) are not reading onwire version
	 * fields while we modify them. This prevents the race where RX threads
	 * see stale values and reject packets as "higher than maximum version".
	 */
	if (pthread_rwlock_wrlock(&knet_h->global_rwlock) != 0) {
		printf("Failed to acquire global write lock\n");
		return -1;
	}

	knet_h->onwire_min_ver = min;
	knet_h->onwire_max_ver = max;

	pthread_rwlock_unlock(&knet_h->global_rwlock);

	if (_ts_knet_handle_reconnect_links(knet_h, logfd) < 0) {
		return -1;
	}

	if (nodes) {
		if (wait_for_nodes_state(knet_h, nodes, 1, seconds, logfd) < 0) {
			log_test(logfd, "Failed waiting for nodes 1");
			return -1;
		}
	}

	return 0;
}

static void onwire_ver_callback_fn(void *private_data, uint8_t onwire_min_ver, uint8_t onwire_max_ver, uint8_t onwire_ver)
{
	knet_handle_t knet_h = (knet_handle_t)private_data;

	log_test(test_logfd, "Received callback from %p: min: %u max: %u current: %u", knet_h, onwire_min_ver, onwire_max_ver, onwire_ver);
}

static void test(void)
{
	int logfd;
	knet_handle_t knet_h[TESTNODES + 1] = {0};
	int i,j;
	int seconds = 10;

	logfd = start_logging(stdout);
	test_logfd = logfd;

	_ts_knet_handle_start_nodes(knet_h, TESTNODES, logfd, KNET_LOG_DEBUG);


	for (i = 1; i <= TESTNODES; i++) {
		knet_h[i]->onwire_ver_remap = 1;
		FAIL_ON_ERR(knet_handle_enable_onwire_ver_notify(knet_h[i], (void *)&knet_h[i], onwire_ver_callback_fn));
	}


	_ts_knet_handle_join_nodes(knet_h, TESTNODES, 1, AF_INET, KNET_TRANSPORT_UDP, logfd);


	log_test(logfd, "Test normal onwire upgrade from %u to %u", knet_h[1]->onwire_ver, knet_h[1]->onwire_ver + 1);

	for (i = 1; i <= TESTNODES; i++) {
		FAIL_ON_ERR(upgrade_onwire_max_ver(knet_h[i], TESTNODES, knet_h[1]->onwire_ver, knet_h[1]->onwire_ver + 1, seconds,
						   logfd));
	}

	test_sleep(logfd, seconds);

	for (i = 1; i <= TESTNODES; i++) {
		log_test(logfd, "node %u, onwire: %u min: %u max: %u", i, knet_h[i]->onwire_ver, knet_h[i]->onwire_min_ver, knet_h[i]->onwire_max_ver);
	}

	test_sleep(logfd, seconds);

	log_test(logfd, "Test onwire upgrade from %u to %u (all but one node)", knet_h[1]->onwire_ver, knet_h[1]->onwire_ver + 1);

	for (i = 1; i < TESTNODES; i++) {
		FAIL_ON_ERR(upgrade_onwire_max_ver(knet_h[i], TESTNODES, knet_h[i]->onwire_ver, knet_h[i]->onwire_ver + 1, seconds,
						   logfd));
	}

	test_sleep(logfd, seconds);

	for (i = 1; i <= TESTNODES; i++) {
		log_test(logfd, "node %u, onwire: %u min: %u max: %u", i, knet_h[i]->onwire_ver, knet_h[i]->onwire_min_ver, knet_h[i]->onwire_max_ver);
	}

	test_sleep(logfd, seconds * 2);

	log_test(logfd, "Test onwire upgrade from %u to %u (all but one node - phase 2, node should be kicked out and remaining nodes should upgrade)", knet_h[1]->onwire_max_ver, knet_h[1]->onwire_max_ver + 1);

	for (i = 1; i < TESTNODES; i++) {
		FAIL_ON_ERR(upgrade_onwire_max_ver(knet_h[i], TESTNODES - 1, knet_h[i]->onwire_max_ver, knet_h[i]->onwire_max_ver + 1, seconds,
						   logfd));
	}

	test_sleep(logfd, seconds);

	for (i = 1; i <= TESTNODES; i++) {
		log_test(logfd, "node %u, onwire: %u min: %u max: %u", i, knet_h[i]->onwire_ver, knet_h[i]->onwire_min_ver, knet_h[i]->onwire_max_ver);
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
					TEST_EXIT_CLEAN(FAIL);
				}
			} else {
				/*
				 * all other nodes should detect the highest node unreachable
				 * and all the remaining nodes reachable
				 */
				if (j == TESTNODES) {
					if (knet_h[i]->host_index[j]->status.reachable != 0) {
						TEST_EXIT_CLEAN(FAIL);
					}
				} else {
					if (knet_h[i]->host_index[j]->status.reachable != 1) {
						TEST_EXIT_CLEAN(FAIL);
					}
				}
			}
		}
	}

	test_sleep(logfd, seconds);

	/*
	 * CHANGE THIS TEST if we decide to support downgrades
	 */
	log_test(logfd, "Testing node rejoining one version lower (cluster should reject the node)");

	FAIL_ON_ERR(upgrade_onwire_max_ver(knet_h[TESTNODES], 0, knet_h[1]->onwire_min_ver - 1, knet_h[1]->onwire_max_ver - 1, seconds,
					   logfd));

	/*
	 * need more time here for membership to settle
	 */
	test_sleep(logfd, seconds * 2);

	for (i = 1; i <= TESTNODES; i++) {
		log_test(logfd, "node %u, onwire: %u min: %u max: %u", i, knet_h[i]->onwire_ver, knet_h[i]->onwire_min_ver, knet_h[i]->onwire_max_ver);
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
					TEST_EXIT_CLEAN(FAIL);
				}
			} else {
				/*
				 * all other nodes should detect the highest node unreachable
				 * and all the remaining nodes reachable
				 */
				if (j == TESTNODES) {
					if (knet_h[i]->host_index[j]->status.reachable != 0) {
						TEST_EXIT_CLEAN(FAIL);
					}
				} else {
					if (knet_h[i]->host_index[j]->status.reachable != 1) {
						TEST_EXIT_CLEAN(FAIL);
					}
				}
			}
		}
	}

	log_test(logfd, "Testing node rejoining with proper version (cluster should reform)");

	FAIL_ON_ERR(upgrade_onwire_max_ver(knet_h[TESTNODES], TESTNODES, knet_h[1]->onwire_min_ver, knet_h[1]->onwire_max_ver, seconds,
					   logfd));

        /*
	 * need more time here for membership to settle
	 */
	test_sleep(logfd, seconds * 2);

	for (i = 1; i <= TESTNODES; i++) {
		log_test(logfd, "node %u, onwire: %u min: %u max: %u", i, knet_h[i]->onwire_ver, knet_h[i]->onwire_min_ver, knet_h[i]->onwire_max_ver);
		for (j = 1; j <= TESTNODES; j++) {
			if (j == i) {
				continue;
			}
			if ((knet_h[i]->host_index[j]->status.reachable != 1) || (knet_h[i]->onwire_ver != knet_h[1]->onwire_max_ver)) {
				TEST_EXIT_CLEAN(FAIL);
			}
		}
	}

	log_test(logfd, "Testing node force onwire version");

	for (i = 1; i <= TESTNODES; i++) {
		if (knet_handle_set_onwire_ver(knet_h[i], knet_h[i]->onwire_min_ver) < 0) {
			TEST_EXIT_CLEAN(FAIL);
		}
	}

	/*
	 * need more time here for membership to settle
	 */
	test_sleep(logfd, seconds * 2);

	for (i = 1; i <= TESTNODES; i++) {
		log_test(logfd, "node %u, onwire: %u min: %u max: %u", i, knet_h[i]->onwire_ver, knet_h[i]->onwire_min_ver, knet_h[i]->onwire_max_ver);
		for (j = 1; j <= TESTNODES; j++) {
			if (j == i) {
				continue;
			}
			if ((knet_h[i]->host_index[j]->status.reachable != 1) || (knet_h[i]->onwire_ver != knet_h[1]->onwire_min_ver)) {
				TEST_EXIT_CLEAN(FAIL);
			}
		}
	}

	TEST_EXIT_CLEAN(CONTINUE);
}

int main(int argc, char *argv[])
{
	printf("[TEST] %s: Test Onwire upgrade\n", TEST_NAME);

	test();

	TEST_EXIT(PASS);
}
