/*
 * Copyright (C) 2016-2019 Red Hat, Inc.  All rights reserved.
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

#include "libknet.h"

#include "compress.h"
#include "internals.h"
#include "netutils.h"
#include "test-common.h"

#define TESTNODES 2

static void test(const char *model)
{
	knet_handle_t knet_h[TESTNODES + 1];
	int logfds[2];
	struct knet_handle_crypto_cfg knet_handle_crypto_cfg;
	int i,x,j;
	int seconds = 5;

	if (is_memcheck() || is_helgrind()) {
		printf("Test suite is running under valgrind, adjusting wait_for_host timeout\n");
		seconds = seconds * 16;
	}

	setup_logpipes(logfds);

	knet_handle_start_nodes(knet_h, TESTNODES, logfds, KNET_LOG_DEBUG);

	flush_logs(logfds[0], stdout);

	/*
	 * config1: aes128/sha256 key1 is all 0s (2000 bytes)
	 */
	memset(&knet_handle_crypto_cfg, 0, sizeof(struct knet_handle_crypto_cfg));
	strncpy(knet_handle_crypto_cfg.crypto_model, model, sizeof(knet_handle_crypto_cfg.crypto_model) - 1);
	strncpy(knet_handle_crypto_cfg.crypto_cipher_type, "aes128", sizeof(knet_handle_crypto_cfg.crypto_cipher_type) - 1);
	strncpy(knet_handle_crypto_cfg.crypto_hash_type, "sha256", sizeof(knet_handle_crypto_cfg.crypto_hash_type) - 1);
	memset(knet_handle_crypto_cfg.private_key, 0, KNET_MAX_KEY_LEN);
	knet_handle_crypto_cfg.private_key_len = 2000;

	for (i = 1; i <= TESTNODES; i++) {
		if (knet_handle_crypto_set_config(knet_h[i], &knet_handle_crypto_cfg, 1) < 0) {
			printf("knet_handle_crypto_set_config (1) failed with correct config: %s\n", strerror(errno));
			knet_handle_stop_nodes(knet_h, TESTNODES);
			flush_logs(logfds[0], stdout);
			close_logpipes(logfds);
			exit(FAIL);
		}
		if (knet_handle_crypto_use_config(knet_h[i], 1) < 0) {
			printf("knet_handle_crypto_use_config (1) failed with correct config: %s\n", strerror(errno));
			knet_handle_stop_nodes(knet_h, TESTNODES);
			flush_logs(logfds[0], stdout);
			close_logpipes(logfds);
			exit(FAIL);
		}
		if (knet_handle_crypto_rx_clear_traffic(knet_h[i], KNET_CRYPTO_RX_DISALLOW_CLEAR_TRAFFIC)) {
			printf("knet_handle_crypto_rx_clear_traffic failed: %s\n", strerror(errno));
			knet_handle_stop_nodes(knet_h, TESTNODES);
			flush_logs(logfds[0], stdout);
			close_logpipes(logfds);
			exit(FAIL);
		}
	}

	flush_logs(logfds[0], stdout);

	knet_handle_join_nodes(knet_h, TESTNODES, 1, AF_INET, KNET_TRANSPORT_UDP);

	flush_logs(logfds[0], stdout);

	/*
	 * config2: aes256/sha512 key1 is all 1s (KNET_MAX_KEY_LEN bytes)
	 */
	memset(&knet_handle_crypto_cfg, 0, sizeof(struct knet_handle_crypto_cfg));
	strncpy(knet_handle_crypto_cfg.crypto_model, model, sizeof(knet_handle_crypto_cfg.crypto_model) - 1);
	strncpy(knet_handle_crypto_cfg.crypto_cipher_type, "aes256", sizeof(knet_handle_crypto_cfg.crypto_cipher_type) - 1);
	strncpy(knet_handle_crypto_cfg.crypto_hash_type, "sha512", sizeof(knet_handle_crypto_cfg.crypto_hash_type) - 1);
	memset(knet_handle_crypto_cfg.private_key, 1, KNET_MAX_KEY_LEN);
	knet_handle_crypto_cfg.private_key_len = KNET_MAX_KEY_LEN;

	for (i = 1; i <= TESTNODES; i++) {
		if (knet_handle_crypto_set_config(knet_h[i], &knet_handle_crypto_cfg, 2) < 0) {
			printf("knet_handle_crypto_set_config (2) failed with correct config: %s\n", strerror(errno));
			knet_handle_stop_nodes(knet_h, TESTNODES);
			flush_logs(logfds[0], stdout);
			close_logpipes(logfds);
			exit(FAIL);
		}
	}

	flush_logs(logfds[0], stdout);

	printf("Testing crypto config switch from 1 to 2\n");

	for (i = 1; i <= TESTNODES; i++) {
		if (knet_handle_crypto_use_config(knet_h[i], 2) < 0) {
			printf("knet_handle_crypto_use_config (2) failed with correct config: %s\n", strerror(errno));
			knet_handle_stop_nodes(knet_h, TESTNODES);
			flush_logs(logfds[0], stdout);
			close_logpipes(logfds);
			exit(FAIL);
		}
		for (x = 0; x < seconds; x++){
			flush_logs(logfds[0], stdout);
			sleep(1);
		}
		for (x = 1; x <= TESTNODES; x++) {
			for (j = 1; j <= TESTNODES; j++) {
				if (j == x) {
					continue;
				}
				if (knet_h[x]->host_index[j]->status.reachable != 1) {
					printf("knet failed to switch config for host %d\n", x);
					knet_handle_stop_nodes(knet_h, TESTNODES);
					flush_logs(logfds[0], stdout);
					close_logpipes(logfds);
					exit(FAIL);
				}
			}
		}
	}

	flush_logs(logfds[0], stdout);

	printf("Testing crypto config switch from 2 to 1\n");

	for (i = 1; i <= TESTNODES; i++) {
		if (knet_handle_crypto_use_config(knet_h[i], 1) < 0) {
			printf("knet_handle_crypto_use_config (1) failed with correct config: %s\n", strerror(errno));
			knet_handle_stop_nodes(knet_h, TESTNODES);
			flush_logs(logfds[0], stdout);
			close_logpipes(logfds);
			exit(FAIL);
		}
		for (x = 0; x < seconds; x++){
			flush_logs(logfds[0], stdout);
			sleep(1);
		}
		for (x = 1; x <= TESTNODES; x++) {
			for (j = 1; j <= TESTNODES; j++) {
				if (j == x) {
					continue;
				}
				if (knet_h[x]->host_index[j]->status.reachable != 1) {
					printf("knet failed to switch config for host %d\n", x);
					knet_handle_stop_nodes(knet_h, TESTNODES);
					flush_logs(logfds[0], stdout);
					close_logpipes(logfds);
					exit(FAIL);
				}
			}
		}
	}

	printf("Testing disable crypto config and allow clear traffic\n");

	memset(&knet_handle_crypto_cfg, 0, sizeof(struct knet_handle_crypto_cfg));
	strncpy(knet_handle_crypto_cfg.crypto_model, "none", sizeof(knet_handle_crypto_cfg.crypto_model) - 1);
	strncpy(knet_handle_crypto_cfg.crypto_cipher_type, "none", sizeof(knet_handle_crypto_cfg.crypto_cipher_type) - 1);
	strncpy(knet_handle_crypto_cfg.crypto_hash_type, "none", sizeof(knet_handle_crypto_cfg.crypto_hash_type) - 1);
	memset(knet_handle_crypto_cfg.private_key, 0, KNET_MAX_KEY_LEN);
	knet_handle_crypto_cfg.private_key_len = KNET_MAX_KEY_LEN;

	for (i = 1; i <= TESTNODES; i++) {
		/*
		 * config2 is no longer in use
		 */
		if (knet_handle_crypto_set_config(knet_h[i], &knet_handle_crypto_cfg, 2) < 0) {
			printf("knet_handle_crypto_set_config (2) failed with correct config: %s\n", strerror(errno));
			knet_handle_stop_nodes(knet_h, TESTNODES);
			flush_logs(logfds[0], stdout);
			close_logpipes(logfds);
			exit(FAIL);
		}
		/*
		 * allow clear traffic on RX on all nodes, before we change config to clear traffic
		 */
		if (knet_handle_crypto_rx_clear_traffic(knet_h[i], KNET_CRYPTO_RX_ALLOW_CLEAR_TRAFFIC)) {
			printf("knet_handle_crypto_rx_clear_traffic failed: %s\n", strerror(errno));
			knet_handle_stop_nodes(knet_h, TESTNODES);
			flush_logs(logfds[0], stdout);
			close_logpipes(logfds);
			exit(FAIL);
		}
	}

	for (i = 1; i <= TESTNODES; i++) {
		/*
		 * switch to clear traffic on RX on all nodes
		 */
		if (knet_handle_crypto_use_config(knet_h[i], 0) < 0) {
			printf("knet_handle_crypto_use_config (0) failed with correct config: %s\n", strerror(errno));
			knet_handle_stop_nodes(knet_h, TESTNODES);
			flush_logs(logfds[0], stdout);
			close_logpipes(logfds);
			exit(FAIL);
		}
	}


	for (i = 1; i <= TESTNODES; i++) {
		/*
		 * config1 is no longer in use
		 */
		if (knet_handle_crypto_set_config(knet_h[i], &knet_handle_crypto_cfg, 1) < 0) {
			printf("knet_handle_crypto_set_config (2) failed with correct config: %s\n", strerror(errno));
			knet_handle_stop_nodes(knet_h, TESTNODES);
			flush_logs(logfds[0], stdout);
			close_logpipes(logfds);
			exit(FAIL);
		}
	}

	for (i = 1; i <= TESTNODES; i++) {
		for (x = 0; x < seconds; x++){
			flush_logs(logfds[0], stdout);
			sleep(1);
		}
		for (x = 1; x <= TESTNODES; x++) {
			for (j = 1; j <= TESTNODES; j++) {
				if (j == x) {
					continue;
				}
				if (knet_h[x]->host_index[j]->status.reachable != 1) {
					printf("knet failed to switch config for host %d\n", x);
					knet_handle_stop_nodes(knet_h, TESTNODES);
					flush_logs(logfds[0], stdout);
					close_logpipes(logfds);
					exit(FAIL);
				}
			}
		}
	}

	flush_logs(logfds[0], stdout);
	close_logpipes(logfds);
	knet_handle_stop_nodes(knet_h, TESTNODES);
}

int main(int argc, char *argv[])
{
	struct knet_crypto_info crypto_list[16];
	size_t crypto_list_entries;
	size_t i;

	memset(crypto_list, 0, sizeof(crypto_list));

	if (knet_get_crypto_list(crypto_list, &crypto_list_entries) < 0) {
		printf("knet_get_crypto_list failed: %s\n", strerror(errno));
		return FAIL;
	}

	if (crypto_list_entries == 0) {
		printf("no crypto modules detected. Skipping\n");
		return SKIP;
	}

	for (i=0; i < crypto_list_entries; i++) {
		test(crypto_list[i].name);
	}

	return PASS;
}
