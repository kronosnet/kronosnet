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
#include <alloca.h>
#include <signal.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/uio.h>

#include "libknet.h"

#define KNET_RING_DEFPORT 50000

static int knet_sock[2];
static knet_handle_t knet_h;
static struct knet_handle_crypto_cfg knet_handle_crypto_cfg;
static uint8_t loglevel = KNET_LOG_INFO;
static uint8_t use_stdout = 0;
static char *src_host = NULL;
static char *src_port = NULL;

static in_port_t tok_inport(char *str)
{
	int value = atoi(str);

	if ((value < 0) || (value > UINT16_MAX))
		return 0;

	return (in_port_t) value;
}

static int tok_inaddrport(char *strin, struct sockaddr_in *addr)
{
	char *strhost, *strport, *tmp = NULL;
	char *str;

	str = strdup(strin);
	if (!str) {
		printf("no mem?\n");
		exit(1);
	}

	strhost = strtok_r(str, ":", &tmp);
	if (inet_aton(strhost, &addr->sin_addr) == 0) {
		printf("inet_aton error\n");
		exit(1);
	}

	if (!src_host)
		src_host = strdup(strhost);
	strport = strtok_r(NULL, ":", &tmp);

	addr->sin_family = AF_INET;

	if (strport == NULL) {
		src_port = malloc(KNET_MAX_PORT_LEN);
		if (!src_port) {
			printf("no mem?\n");
			exit(1);
		}
		snprintf(src_port, KNET_MAX_PORT_LEN, "%d", KNET_RING_DEFPORT);
		addr->sin_port = htons(KNET_RING_DEFPORT);
	} else {
		src_port = strdup(strport);
		addr->sin_port = htons(tok_inport(strport));
	}
	free(str);
	return 0;
}

static void print_usage(char *name)
{
	printf("usage: %s <localip>[:<port>] <remoteip>[:port] [...]\n", name);
	printf("example: %s 0.0.0.0 192.168.0.2\n", name);
	printf("example: %s 127.0.0.1:50000 127.0.0.1:50000 crypto:nss,aes256,sha1\n", name);
	printf("example: %s 127.0.0.1:50000 127.0.0.1:50000 debug\n", name);
}

static void set_log(int argc, char *argv[])
{
	int i;

	for (i = 0; i < argc; i++) {
		if (!strncmp(argv[i], "stdout", 6)) {
			use_stdout = 1;
			break;
		}
	}
}

static void set_debug(int argc, char *argv[])
{
	int i;

	for (i = 0; i < argc; i++) {
		if (!strncmp(argv[i], "debug", 5)) {
			loglevel = KNET_LOG_DEBUG;
			break;
		}
	}
}

static int set_crypto(int argc, char *argv[])
{
	int i, found = 0;

	for (i = 0; i < argc; i++) {
		if (!strncmp(argv[i], "crypto", 6)) {
			found = 1;
			break;
		}
	}

	if (found) {
		char *tmp = NULL;
		strtok_r(argv[i], ":", &tmp);
		strncpy(knet_handle_crypto_cfg.crypto_model,
			strtok_r(NULL, ",", &tmp),
			sizeof(knet_handle_crypto_cfg.crypto_model) - 1);
		strncpy(knet_handle_crypto_cfg.crypto_cipher_type,
			strtok_r(NULL, ",", &tmp),
			sizeof(knet_handle_crypto_cfg.crypto_cipher_type) - 1);
		strncpy(knet_handle_crypto_cfg.crypto_hash_type,
			strtok_r(NULL, ",", &tmp),
			sizeof(knet_handle_crypto_cfg.crypto_hash_type) - 1);
		printf("Setting up encryption: model: %s crypto: %s hmac: %s\n",
			knet_handle_crypto_cfg.crypto_model,
			knet_handle_crypto_cfg.crypto_cipher_type,
			knet_handle_crypto_cfg.crypto_hash_type);
		return 1;
	}

	return 0;
}

static void argv_to_hosts(int argc, char *argv[])
{
	int err, i;
	uint16_t node_id;
	struct sockaddr_storage src_addr;
	struct sockaddr_storage dst_addr;

	for (i = 2; i < argc; i++) {
		if (!strncmp(argv[i], "crypto", 6))
			continue;
		if (!strncmp(argv[i], "debug", 5))
			continue;
		if (!strncmp(argv[i], "stdout", 6))
			continue;

		node_id = i - 1;

		if (knet_host_add(knet_h, node_id) != 0) {
			printf("Unable to add new knet_host\n");
			exit(EXIT_FAILURE);
		}

		knet_host_set_name(knet_h, node_id, argv[i]);

		err = tok_inaddrport(argv[1], (struct sockaddr_in *) &src_addr);
		if (err < 0) {
			printf("Unable to convert ip address: %s", argv[i]);
			exit(EXIT_FAILURE);
		}

		err = tok_inaddrport(argv[i],
				(struct sockaddr_in *) &dst_addr);
		if (err < 0) {
			printf("Unable to convert ip address: %s", argv[i]);
			exit(EXIT_FAILURE);
		}

		knet_link_set_config(knet_h, node_id, 0, &src_addr, &dst_addr);
		knet_link_set_timeout(knet_h, node_id, 0, 1000, 5000, 2048);
		//knet_link_set_pong_count(knet_h, node_id, 0, 10);
		knet_link_set_enable(knet_h, node_id, 0, 1);
	}
}

/* Testing the latency/timeout:
 *   # tc qdisc add dev lo root handle 1:0 netem delay 1s limit 1000
 *   # tc -d qdisc show dev lo
 *   # tc qdisc del dev lo root
 */
static int print_link(knet_handle_t khandle, uint16_t host_id)
{
	int i;
	struct knet_link_status status;
	uint8_t link_ids[KNET_MAX_LINK];
	size_t link_ids_entries;

	if (knet_link_get_link_list(khandle, host_id, link_ids, &link_ids_entries)) {
		printf("unable to get list of configured links\n");
		return -1;
	}

	for (i = 0; i < link_ids_entries; i++) {
		if (knet_link_get_status(knet_h, host_id, link_ids[i], &status) < 0)
			return -1;

		if (status.enabled != 1) continue;

		printf("host %u, link %u latency is %llu us, status: %s\n",
			host_id, i, status.latency,
			(status.connected == 0) ? "disconnected" : "connected");
	}

	return 0;
}

static void sigint_handler(int signum)
{
	int i, j;
	uint16_t host_ids[KNET_MAX_HOST];
	uint8_t link_ids[KNET_MAX_LINK];
	size_t host_ids_entries = 0, link_ids_entries = 0;
	struct knet_link_status status;

	printf("Cleaning up... got signal: %d\n", signum);

	if (knet_h != NULL) {
		if (knet_host_get_host_list(knet_h, host_ids, &host_ids_entries))
			printf("Unable to get host list: %s\n",strerror(errno));

		for (i = 0; i < host_ids_entries; i++) {
			if (knet_link_get_link_list(knet_h, host_ids[i], link_ids, &link_ids_entries)) {
				printf("Unable to get link list: %s\n",strerror(errno));
			}
			for (j = 0; j < link_ids_entries; j++) {
				if (knet_link_get_status(knet_h, host_ids[i], link_ids[j], &status)) {
					if (errno != EINVAL) {
						printf("Unable to get link data: %s\n",strerror(errno));
					}
					continue;
				}
				if (status.enabled != 1) {
					continue;
				}

				if (knet_link_set_enable(knet_h, host_ids[i], j, 0))
					printf("Unable to remove link: %s\n",strerror(errno));
			}
			if (knet_host_remove(knet_h, host_ids[i]))
				printf("Unable to remove host: %s\n",strerror(errno));
		}

		if (knet_handle_free(knet_h)) {
			printf("Unable to cleanup before exit: %s\n",strerror(errno));
			exit(EXIT_FAILURE);
		}
	}

	exit(EXIT_SUCCESS);
}

static void pmtud_notify(void *private_data, unsigned int link_mtu, unsigned int data_mtu)
{
	printf("New mtu change notification: data: %p link %u data %u\n", private_data, link_mtu, data_mtu);
	return;
}

int main(int argc, char *argv[])
{
	char out_big_buff[65000], out_big_frag[64000], hello_world[16];
	char recvbuff[65000];
	size_t len;
	fd_set rfds;
	struct timeval tv;
	int logpipefd[2];
	uint16_t host_ids[KNET_MAX_HOST];
	size_t host_ids_entries = 0;
	int has_crypto = 0;
	int logfd;
	unsigned int link_mtu = 0, data_mtu = 0;
	int big = 0;

	if (argc < 3) {
		print_usage(argv[0]);
		exit(EXIT_FAILURE);
	}

	if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, knet_sock) != 0) {
		printf("Unable to create socket\n");
		exit(EXIT_FAILURE);
	}

	if (pipe(logpipefd)) {
		printf("Unable to create log pipe\n");
		exit(EXIT_FAILURE);
	}

	knet_h = NULL;

	if (signal(SIGINT, sigint_handler) == SIG_ERR) {
		printf("Unable to configure SIGINT handler\n");
		exit(EXIT_FAILURE);
	}

	set_log(argc, argv);
	if (use_stdout) {
		logfd = 1;
	} else {
		logfd = logpipefd[1];
	}

	set_debug(argc, argv);

	if ((knet_h = knet_handle_new(1, knet_sock[0], logfd, loglevel)) == NULL) {
		printf("Unable to create new knet_handle_t\n");
		exit(EXIT_FAILURE);
	}

	if (knet_handle_pmtud_get(knet_h, &link_mtu, &data_mtu)) {
		printf("Unable to get PMTUd current values\n");
		exit(EXIT_FAILURE);
	} else {
		printf("Current PMTUd: link %u data %u\n", link_mtu, data_mtu);
	}

	if (knet_handle_enable_pmtud_notify(knet_h, NULL, pmtud_notify)) {
		printf("Unable to install PMTUd notification callback\n");
		exit(EXIT_FAILURE);
	}

	if (knet_handle_pmtud_setfreq(knet_h, 5)) {
		printf("Unable to set PMTUd interval\n");
		exit(EXIT_FAILURE);
	}

	if (set_crypto(argc, argv)) {
		memset(knet_handle_crypto_cfg.private_key, 0, KNET_MAX_KEY_LEN);
		knet_handle_crypto_cfg.private_key_len = KNET_MAX_KEY_LEN;	
		if (knet_handle_crypto(knet_h, &knet_handle_crypto_cfg)) {
			printf("Unable to init crypto\n");
			exit(EXIT_FAILURE);
		}
		has_crypto = 1;
	} else {
		printf("Crypto not activated\n");
	}

	argv_to_hosts(argc, argv);
	knet_handle_setfwd(knet_h, 1);	

	while (1) {
		ssize_t wlen;
		size_t i;
		struct iovec iov_out[1];

		knet_host_get_host_list(knet_h, host_ids, &host_ids_entries);
		for (i = 0; i < host_ids_entries; i++) {
			print_link(knet_h, host_ids[i]);
		}

		memset(iov_out, 0, sizeof(iov_out));

		memset(&out_big_frag, 0, sizeof(out_big_frag));
		memset(&out_big_buff, 0, sizeof(out_big_buff));
		memset(&hello_world, 0, sizeof(hello_world));

		snprintf(hello_world, sizeof(hello_world), "Hello world!");

		if (big) {
			iov_out[0].iov_base = (void *)out_big_frag;
			iov_out[0].iov_len = sizeof(out_big_frag);
			big = 0;
		} else {
			iov_out[0].iov_base = (void *)hello_world;
			iov_out[0].iov_len = 13;
			big = 1;
		}

		wlen = writev(knet_sock[1], iov_out, 1);
		if (wlen != iov_out[0].iov_len) {
			printf("Unable to send messages to socket\n");
			exit(1);
		}

		tv.tv_sec = 0;
		tv.tv_usec = 5000;

 select_loop:
		FD_ZERO(&rfds);
		FD_SET(knet_sock[1], &rfds);
		FD_SET(logpipefd[0], &rfds);

		len = select(FD_SETSIZE, &rfds, NULL, NULL, &tv);

		/* uncomment this to replicate the one-message problem */
		/* usleep(500000); */

		if (len < 0) {
			printf("Unable select over knet_handle_t\n");
			exit(EXIT_FAILURE);
		} else if (FD_ISSET(knet_sock[1], &rfds)) {
			struct iovec iov_in;
			ssize_t rlen = 0;

			memset(&iov_in, 0, sizeof(iov_in));

			iov_in.iov_base = (void *)recvbuff;
			iov_in.iov_len = sizeof(recvbuff);

			rlen = readv(knet_sock[1], &iov_in, 1);

			if (!rlen) {
				printf("EOF\n");
				break;
			}
			if ((rlen < 0) && ((errno = EAGAIN) || (errno = EWOULDBLOCK))) {
				printf("NO MORE DATA TO READ\n");
				break;
			}

			printf("Received data (%zu bytes): '%s'\n", rlen, (char *)iov_in.iov_base);

			if (has_crypto) {
				printf("changing crypto key\n");
				memset(knet_handle_crypto_cfg.private_key, has_crypto, KNET_MAX_KEY_LEN);
				if (knet_handle_crypto(knet_h, &knet_handle_crypto_cfg)) {
					printf("Unable to change key on the fly\n");
					has_crypto++;
				}
			}

		} else if (FD_ISSET(logpipefd[0], &rfds)) {
			struct knet_log_msg msg;
			size_t bytes_read = 0;

			while (bytes_read < sizeof(struct knet_log_msg)) {
				len = read(logpipefd[0], &msg + bytes_read,
					   sizeof(struct knet_log_msg) - bytes_read);
				if (len <= 0) {
					printf("Error from log fd, unable to read data\n");
					exit(EXIT_FAILURE);
				}
				bytes_read += len;
			}

			printf("[%s] %s: %s\n",
			       knet_log_get_loglevel_name(msg.msglevel),
			       knet_log_get_subsystem_name(msg.subsystem),
			       msg.msg);
		}

		if ((tv.tv_sec > 0) || (tv.tv_usec > 0))
			goto select_loop;
	}

	/* FIXME: allocated hosts should be free'd */

	return 0;
}
