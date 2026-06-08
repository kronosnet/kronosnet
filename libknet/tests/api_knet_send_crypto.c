/*
 * Copyright (C) 2016-2026 Red Hat, Inc.  All rights reserved.
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

#define TEST_NAME "api_knet_send_crypto"

static int private_data;

static void sock_notify(void *pvt_data,
			int datafd,
			int8_t channel,
			uint8_t tx_rx,
			int error,
			int errorno)
{
	return;
}

static void test(const char *model)
{
	int logfd;
	knet_handle_t knet_h1, knet_h[2] = {0};
	int datafd = 0;
	int8_t channel = 0;
	struct knet_handle_stats stats;
	char send_buff[KNET_MAX_PACKET_SIZE];
	char recv_buff[KNET_MAX_PACKET_SIZE];
	ssize_t send_len = 0;
	int recv_len = 0;
	int savederrno;
	struct sockaddr_storage lo;
	struct knet_handle_crypto_cfg knet_handle_crypto_cfg;

	logfd = start_logging(stdout);

	memset(send_buff, 0, sizeof(send_buff));


	knet_h1 = _ts_knet_handle_start(logfd, KNET_LOG_DEBUG, knet_h);


	log_test(logfd, "Test knet_send with %s and valid data", model);

	memset(&knet_handle_crypto_cfg, 0, sizeof(struct knet_handle_crypto_cfg));
	strncpy(knet_handle_crypto_cfg.crypto_model, model, sizeof(knet_handle_crypto_cfg.crypto_model) - 1);
	strncpy(knet_handle_crypto_cfg.crypto_cipher_type, "aes128", sizeof(knet_handle_crypto_cfg.crypto_cipher_type) - 1);
	strncpy(knet_handle_crypto_cfg.crypto_hash_type, "sha256", sizeof(knet_handle_crypto_cfg.crypto_hash_type) - 1);
	knet_handle_crypto_cfg.private_key_len = 2000;

	FAIL_ON_ERR(knet_handle_crypto_set_config(knet_h1, &knet_handle_crypto_cfg, 1));

	FAIL_ON_ERR(knet_handle_crypto_use_config(knet_h1, 1));

	FAIL_ON_ERR(knet_handle_crypto_rx_clear_traffic(knet_h1, KNET_CRYPTO_RX_DISALLOW_CLEAR_TRAFFIC));

	FAIL_ON_ERR(knet_handle_enable_sock_notify(knet_h1, &private_data, sock_notify));

	datafd = 0;
	channel = -1;

	FAIL_ON_ERR(knet_handle_add_datafd(knet_h1, &datafd, &channel, 0));

	FAIL_ON_ERR(knet_host_add(knet_h1, 1));

	FAIL_ON_ERR(_ts_knet_link_set_config(knet_h1, 1, 0, KNET_TRANSPORT_UDP, 0, AF_INET, 0, &lo, logfd));

	FAIL_ON_ERR(knet_link_set_enable(knet_h1, 1, 0, 1));

	FAIL_ON_ERR(knet_handle_setfwd(knet_h1, 1));

	FAIL_ON_ERR(wait_for_host(knet_h1, 1, TEST_TIMEOUT_SHORT, logfd));

	send_len = knet_send(knet_h1, send_buff, KNET_MAX_PACKET_SIZE, channel);
	if (send_len <= 0) {
		log_test(logfd, "knet_send failed: %s", strerror(errno));
		TEST_EXIT_CLEAN(FAIL);
	}

	if (send_len != sizeof(send_buff)) {
		log_test(logfd, "knet_send sent only %zd bytes: %s", send_len, strerror(errno));
		TEST_EXIT_CLEAN(FAIL);
	}

	FAIL_ON_ERR(knet_handle_setfwd(knet_h1, 0));

	FAIL_ON_ERR(wait_for_packet(knet_h1, TEST_TIMEOUT_SHORT, datafd, logfd));

	recv_len = knet_recv(knet_h1, recv_buff, KNET_MAX_PACKET_SIZE, channel);
	savederrno = errno;
	if (recv_len != send_len) {
		log_test(logfd, "knet_recv received only %d bytes: %s (errno: %d)", recv_len, strerror(errno), errno);
		if ((is_helgrind()) && (recv_len == -1) && (savederrno == EAGAIN)) {
			log_test(logfd, "helgrind exception. this is normal due to possible timeouts");
			TEST_EXIT_CLEAN(PASS);
		}
		TEST_EXIT_CLEAN(FAIL);
	}

	if (memcmp(recv_buff, send_buff, KNET_MAX_PACKET_SIZE)) {
		log_test(logfd, "recv and send buffers are different!");
		TEST_EXIT_CLEAN(FAIL);
	}

	/* A sanity check on the stats */
	if (knet_handle_get_stats(knet_h1, &stats, sizeof(stats)) < 0) {
		log_test(logfd, "knet_handle_get_stats failed: %s", strerror(errno));
		TEST_EXIT_CLEAN(FAIL);
	}

	if (stats.tx_crypt_packets >= 1 ||
	    stats.rx_crypt_packets < 1) {
		log_test(logfd, "stats look wrong: tx_packets: %" PRIu64 ", rx_packets: %" PRIu64 "",
		       stats.tx_crypt_packets,
		       stats.rx_crypt_packets);
	}
	TEST_EXIT_CLEAN(CONTINUE);
}

int main(int argc, char *argv[])
{
	struct knet_crypto_info crypto_list[16];
	size_t crypto_list_entries;
	size_t i;

	printf("[TEST] %s: Test knet send crypto\n", TEST_NAME);

#ifdef KNET_BSD
	if (is_memcheck() || is_helgrind()) {
		printf("valgrind-freebsd cannot run this test properly. Skipping\n");
		TEST_EXIT(SKIP);
	}
#endif

	memset(crypto_list, 0, sizeof(crypto_list));

	if (knet_get_crypto_list(crypto_list, &crypto_list_entries) < 0) {
		printf("knet_get_crypto_list failed: %s\n", strerror(errno));
		TEST_EXIT(FAIL);
	}

	if (crypto_list_entries == 0) {
		printf("no crypto modules detected. Skipping\n");
		TEST_EXIT(SKIP);
	}

	for (i=0; i < crypto_list_entries; i++) {
		test(crypto_list[i].name);
	}

	TEST_EXIT(PASS);
}
