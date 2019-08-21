/*
 * Copyright (C) 2019 Red Hat, Inc.  All rights reserved.
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
#include <sys/ioctl.h>
#include <net/ethernet.h>
#include <ifaddrs.h>
#include <net/if.h>

#include "libknet.h"

#include "compress.h"
#include "internals.h"
#include "netutils.h"
#include "onwire.h"
#include "test-common.h"

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

static int iface_fd = 0;
static int default_mtu = 0;

#ifdef KNET_LINUX
const char *loopback = "lo";
#endif
#ifdef KNET_BSD
const char *loopback = "lo0";
#endif

static int fd_init(void)
{
#ifdef KNET_LINUX
	return socket(AF_INET, SOCK_STREAM, 0);
#endif
#ifdef KNET_BSD
	return socket(AF_LOCAL, SOCK_DGRAM, 0);
#endif
	return -1;
}

static int set_iface_mtu(uint32_t mtu)
{
	int err = 0;
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(struct ifreq));
	strncpy(ifr.ifr_name, loopback, IFNAMSIZ - 1);
	ifr.ifr_mtu = mtu;

	err = ioctl(iface_fd, SIOCSIFMTU, &ifr);

	return err;
}

static int get_iface_mtu(void)
{
	int err = 0, savederrno = 0;
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(struct ifreq));
	strncpy(ifr.ifr_name, loopback, IFNAMSIZ - 1);

	err = ioctl(iface_fd, SIOCGIFMTU, &ifr);
	if (err) {
		savederrno = errno;
		goto out_clean;
	}

	err = ifr.ifr_mtu;

out_clean:
	errno = savederrno;
	return err;
}

static int exit_local(int code)
{
	set_iface_mtu(default_mtu);
	close(iface_fd);
	iface_fd = 0;
	exit(code);
}

static void test_mtu(const char *model, const char *crypto, const char *hash)
{
	knet_handle_t knet_h;
	int logfds[2];
	int datafd = 0;
	int8_t channel = 0;
	struct sockaddr_storage lo;
	struct knet_handle_crypto_cfg knet_handle_crypto_cfg;
	unsigned int data_mtu, expected_mtu;
	size_t calculated_iface_mtu = 0, detected_iface_mtu = 0;

	if (make_local_sockaddr(&lo, 0) < 0) {
		printf("Unable to convert loopback to sockaddr: %s\n", strerror(errno));
		exit_local(FAIL);
	}

	setup_logpipes(logfds);

	knet_h = knet_handle_start(logfds, KNET_LOG_DEBUG);

	flush_logs(logfds[0], stdout);

	printf("Test knet_send with %s and valid data\n", model);

	memset(&knet_handle_crypto_cfg, 0, sizeof(struct knet_handle_crypto_cfg));
	strncpy(knet_handle_crypto_cfg.crypto_model, model, sizeof(knet_handle_crypto_cfg.crypto_model) - 1);
	strncpy(knet_handle_crypto_cfg.crypto_cipher_type, crypto, sizeof(knet_handle_crypto_cfg.crypto_cipher_type) - 1);
	strncpy(knet_handle_crypto_cfg.crypto_hash_type, hash, sizeof(knet_handle_crypto_cfg.crypto_hash_type) - 1);
	knet_handle_crypto_cfg.private_key_len = 2000;

	if (knet_handle_crypto(knet_h, &knet_handle_crypto_cfg)) {
		printf("knet_handle_crypto failed with correct config: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit_local(FAIL);
        }

	if (knet_handle_enable_sock_notify(knet_h, &private_data, sock_notify) < 0) {
		printf("knet_handle_enable_sock_notify failed: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit_local(FAIL);
        }

	datafd = 0;
	channel = -1;

	if (knet_handle_add_datafd(knet_h, &datafd, &channel) < 0) {
		printf("knet_handle_add_datafd failed: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit_local(FAIL);
	}

	if (knet_host_add(knet_h, 1) < 0) {
		printf("knet_host_add failed: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit_local(FAIL);
	}

	if (knet_link_set_config(knet_h, 1, 0, KNET_TRANSPORT_UDP, &lo, &lo, 0) < 0) {
		printf("Unable to configure link: %s\n", strerror(errno));
		knet_host_remove(knet_h, 1);
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit_local(FAIL);
	}

	if (knet_link_set_pong_count(knet_h, 1, 0, 1) < 0) {
		printf("knet_link_set_pong_count failed: %s\n", strerror(errno));
		knet_host_remove(knet_h, 1);
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit_local(FAIL);
	}

	if (knet_link_set_enable(knet_h, 1, 0, 1) < 0) {
		printf("knet_link_set_enable failed: %s\n", strerror(errno));
		knet_link_clear_config(knet_h, 1, 0);
		knet_host_remove(knet_h, 1);
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit_local(FAIL);
	}

	if (wait_for_host(knet_h, 1, 4, logfds[0], stdout) < 0) {
		printf("timeout waiting for host to be reachable");
		knet_link_set_enable(knet_h, 1, 0, 0);
		knet_link_clear_config(knet_h, 1, 0);
		knet_host_remove(knet_h, 1);
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit_local(FAIL);
	}

	flush_logs(logfds[0], stdout);

	if (knet_handle_pmtud_get(knet_h, &data_mtu) < 0) {
		printf("knet_handle_pmtud_get failed error: %s\n", strerror(errno));
		knet_link_set_enable(knet_h, 1, 0, 0);
		knet_link_clear_config(knet_h, 1, 0);
		knet_host_remove(knet_h, 1);
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit_local(FAIL);
	}

	calculated_iface_mtu = calc_data_outlen(knet_h, data_mtu + KNET_HEADER_ALL_SIZE) + 28;
	detected_iface_mtu = get_iface_mtu();
	/*
	 * 28 = 20 IP header + 8 UDP header
	 */
	expected_mtu = calc_max_data_outlen(knet_h, detected_iface_mtu - 28);

	if (expected_mtu != data_mtu) {
		printf("Wrong MTU detected! interface mtu: %zu knet mtu: %u expected mtu: %u\n", detected_iface_mtu, data_mtu, expected_mtu);
		knet_link_set_enable(knet_h, 1, 0, 0);
		knet_link_clear_config(knet_h, 1, 0);
		knet_host_remove(knet_h, 1);
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit_local(FAIL);
	}

	if ((detected_iface_mtu - calculated_iface_mtu) >= knet_h->sec_block_size) {
		printf("Wrong MTU detected! real iface mtu: %zu calculated: %zu\n", detected_iface_mtu, calculated_iface_mtu);
		knet_link_set_enable(knet_h, 1, 0, 0);
		knet_link_clear_config(knet_h, 1, 0);
		knet_host_remove(knet_h, 1);
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit_local(FAIL);
	}

	knet_link_set_enable(knet_h, 1, 0, 0);
	knet_link_clear_config(knet_h, 1, 0);
	knet_host_remove(knet_h, 1);
	knet_handle_free(knet_h);
	flush_logs(logfds[0], stdout);
	close_logpipes(logfds);
}

static void test(const char *model, const char *crypto, const char *hash)
{
	int i = 576;
	int max = 65535;

	while (i <= max) {
		printf("Setting interface MTU to: %i\n", i);
		set_iface_mtu(i);
		test_mtu(model, crypto, hash);
		if (i == max) {
			break;
		}
		i = i + 15;
		if (i > max) {
			i = max;
		}
	}
}

int main(int argc, char *argv[])
{
	struct knet_crypto_info crypto_list[16];
	size_t crypto_list_entries;

#ifdef KNET_BSD
	if (is_memcheck() || is_helgrind()) {
		printf("valgrind-freebsd cannot run this test properly. Skipping\n");
		return SKIP;
	}
#endif

	if (geteuid() != 0) {
		printf("This test requires root privileges\n");
		return SKIP;
	}

	iface_fd = fd_init();
	if (iface_fd < 0) {
		printf("fd_init failed: %s\n", strerror(errno));
		return FAIL;
	}

	default_mtu = get_iface_mtu();
	if (default_mtu < 0) {
		printf("get_iface_mtu failed: %s\n", strerror(errno));
		return FAIL;
	}

	memset(crypto_list, 0, sizeof(crypto_list));

	if (knet_get_crypto_list(crypto_list, &crypto_list_entries) < 0) {
		printf("knet_get_crypto_list failed: %s\n", strerror(errno));
		return FAIL;
	}

	if (crypto_list_entries == 0) {
		printf("no crypto modules detected. Skipping\n");
		return SKIP;
	}

	test(crypto_list[0].name, "aes128", "sha1");
	test(crypto_list[0].name, "aes128", "sha256");
	test(crypto_list[0].name, "aes256", "sha1");
	test(crypto_list[0].name, "aes256", "sha256");

	exit_local(PASS);
}
