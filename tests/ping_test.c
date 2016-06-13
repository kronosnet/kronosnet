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
#include <alloca.h>
#include <signal.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>

#include "libknet.h"

#define KNET_RING_DEFPORT 50000

static int knet_sock[4];
static int8_t channel[4];
static knet_handle_t knet_h;
static struct knet_handle_crypto_cfg knet_handle_crypto_cfg;
static uint8_t loglevel = KNET_LOG_INFO;
static uint8_t use_stdout = 0;
static char *src_host = NULL;
static char *src_port = NULL;
static int can_use_sync = 0;
static int max_nodeid = 0;

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

		max_nodeid = node_id;

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
		knet_link_set_pong_count(knet_h, node_id, 0, 3);
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

		printf("host %u, link %u latency is %llu us, status: %s mtu: %u overhead: %u\n",
			host_id, i, status.latency,
			(status.connected == 0) ? "disconnected" : "connected",
			status.mtu, status.proto_overhead);
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

		for (j = 0; j < 4; j++) {
			if (knet_handle_remove_datafd(knet_h, knet_sock[j]) < 0) {
				printf("Unable to delete datafd!!!: %s\n",strerror(errno));
				exit(EXIT_FAILURE);
			}
		}

		if (knet_handle_free(knet_h)) {
			printf("Unable to cleanup before exit: %s\n",strerror(errno));
			exit(EXIT_FAILURE);
		}
	}

	exit(EXIT_SUCCESS);
}

static void pmtud_notify(void *private_data, unsigned int data_mtu)
{
	printf("New mtu change notification: private_data: %p PMTUd data %u\n", private_data, data_mtu);
	return;
}

static void host_notify(void *private_data, uint16_t host_id, uint8_t reachable, uint8_t remote, uint8_t external)
{
	struct knet_host_status status;

	printf("Received host_id (%u) status change notification. reachable: %u remote: %u external: %u\n",
		host_id, reachable, remote, external);

	if (reachable) {
		can_use_sync = 1;
	} else {
		can_use_sync = 0;
	}

	if (knet_host_get_status(knet_h, host_id, &status)) {
		printf("Unable to get host status\n");
		exit(EXIT_FAILURE);
	}

	printf("Recorded host_id (%u) status change notification. reachable: %u remote: %u external: %u\n",
		host_id, status.reachable, status.remote, status.external);

	return;
}

static void sock_notify(void *private_data, int datafd, int8_t chan, uint8_t tx_rx, int error, int errorno)
{
	printf("Received sock notify, datafd: %d channel: %d direction: %u error: %d errno: %d (%s)\n",
	       datafd, chan, tx_rx, error, errorno, strerror(errorno));

	printf("Something went wrong with our sockets!\n");
	exit(EXIT_FAILURE);
}

static void recv_data(knet_handle_t khandle, int inchannel, int has_crypto)
{
	char recvbuff[66000];
	ssize_t rlen = 0;
	uint16_t nodeid;

	rlen = knet_recv(knet_h, recvbuff, sizeof(recvbuff), inchannel);

	if (!rlen) {
		printf("EOF\n");
		return;
	}

	if ((rlen < 0) && ((errno == EAGAIN) || (errno == EWOULDBLOCK))) {
		printf("NO MORE DATA TO READ: %s\n", strerror(errno));
		return;
	}

	memmove(&nodeid, recvbuff, 2);

	printf("Received data (%zu bytes): '%s' on channel: %d for nodeid %u\n", rlen, recvbuff+2, inchannel, nodeid);

	if (has_crypto) {
#if 0
		printf("changing crypto key\n");
		memset(knet_handle_crypto_cfg.private_key, has_crypto, KNET_MAX_KEY_LEN);
		if (knet_handle_crypto(knet_h, &knet_handle_crypto_cfg)) {
			printf("Unable to change key on the fly\n");
			has_crypto++;
		}
#endif
	}
}

static int ping_dst_host_filter(void *private_data,
				const unsigned char *outdata,
				ssize_t outdata_len,
				uint8_t tx_rx,
				uint16_t this_host_id,
				uint16_t src_host_id,
				int8_t *dst_channel,
				uint16_t *dst_host_ids,
				size_t *dst_host_ids_entries)
{
	if (tx_rx == KNET_NOTIFY_TX) {
		memmove(&dst_host_ids[0], outdata, 2);
	} else {
		dst_host_ids[0] = this_host_id;
	}
	*dst_host_ids_entries = 1;
	return 0;
}

int main(int argc, char *argv[])
{
	char out_big_buff[64000], out_big_frag[65536], hello_world[16];
	ssize_t len;
	fd_set rfds;
	struct timeval tv;
	int logpipefd[2];
	uint16_t host_ids[KNET_MAX_HOST];
	size_t host_ids_entries = 0;
	int has_crypto = 0;
	int logfd;
	unsigned int data_mtu = 0;
	int big = 0;
	int j;
	int8_t chan;
	int use_sync = 0;
	uint16_t dst_nodeid;

	if (argc < 3) {
		print_usage(argv[0]);
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

	if ((knet_h = knet_handle_new(1, logfd, loglevel)) == NULL) {
		printf("Unable to create new knet_handle_t\n");
		exit(EXIT_FAILURE);
	}

	if (knet_handle_pmtud_get(knet_h, &data_mtu)) {
		printf("Unable to get PMTUd current values\n");
		exit(EXIT_FAILURE);
	} else {
		printf("Current data PMTUd %u\n", data_mtu);
	}

	if (knet_handle_enable_pmtud_notify(knet_h, NULL, pmtud_notify)) {
		printf("Unable to install PMTUd notification callback\n");
		exit(EXIT_FAILURE);
	}

	if (knet_host_enable_status_change_notify(knet_h, NULL, host_notify)) {
		printf("Unable to install host status notification callback\n");
		exit(EXIT_FAILURE);
	}

	if (knet_handle_enable_sock_notify(knet_h, NULL, sock_notify)) {
		printf("Unable to install sock notification callback\n");
		exit(EXIT_FAILURE);
	}

	if (knet_handle_pmtud_setfreq(knet_h, 5)) {
		printf("Unable to set PMTUd interval\n");
		exit(EXIT_FAILURE);
	}

	if (knet_handle_enable_filter(knet_h, NULL, ping_dst_host_filter)) {
		printf("Unable to enable filter\n");
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

	for (j = 0; j < 4; j++) {
		knet_sock[j] = 0;
		channel[j] = -1;
		if (knet_handle_add_datafd(knet_h, &knet_sock[j], &channel[j]) < 0) {
			printf("Unable to add datafd!!!\n");
			exit(EXIT_FAILURE);
		}
	}

	if (knet_handle_get_datafd(knet_h, 1, &j)) {
		printf("Unable to get data fd from chan\n");
		exit(EXIT_FAILURE);
	}
	printf("get datafd[%d] from chan[1]; %d\n", knet_sock[1], j);

	if (knet_handle_get_channel(knet_h, knet_sock[1], &chan)) {
		printf("Unable to get chan from data fd\n");
		exit(EXIT_FAILURE);
	}
	printf("get chan[1] from sock[%d]: %d\n", knet_sock[1], chan);

	while (1) {
		ssize_t wlen;
		size_t i, buff_len;
		char *buff;
		int outchan;

		knet_host_get_host_list(knet_h, host_ids, &host_ids_entries);
		for (i = 0; i < host_ids_entries; i++) {
			print_link(knet_h, host_ids[i]);
		}

		memset(&out_big_frag, 0, sizeof(out_big_frag));
		memset(&out_big_buff, 0, sizeof(out_big_buff));
		memset(&hello_world, 0, sizeof(hello_world));

		snprintf(hello_world+2, sizeof(hello_world)-2, "Hello world!");
		snprintf(out_big_buff+2, sizeof(out_big_buff)-2, "%zu", sizeof(out_big_buff));
		snprintf(out_big_frag+2, sizeof(out_big_frag)-2, "%zu", sizeof(out_big_frag));

		switch(big) {
			case 0: /* hello world */
				buff = hello_world;
				buff_len = 13;
				big = 1;
				outchan = channel[0];
				break;
			case 1: /* big but does not require frag */
				buff = out_big_buff;
				buff_len = sizeof(out_big_buff);
				big = 2;
				outchan = channel[1];
				use_sync = 0;
				break;
			case 2: /* big and requires frag */
				buff = out_big_frag;
				buff_len = sizeof(out_big_frag);
				big = 0;
				outchan = channel[2];
				use_sync = 1;
				break;
			default:
				printf("unknown packet size?\n");
				exit(1);
				break;
		}

		printf("Sending '%zu' bytes on channel: %d\n", buff_len, outchan);
		if ((can_use_sync) && (use_sync)) {
			for (j = 1; j <= max_nodeid; j++) {
				dst_nodeid = j;
				memmove(buff, &dst_nodeid, 2);
				printf("Using sync send\n");
				wlen = knet_send_sync(knet_h, buff, buff_len, outchan);
				if (wlen < 0) {
					printf("Unable to send messages to socket: %s\n", strerror(errno));
					exit(1);
				}
			}
		} else {
			/* clear node id */
			memset(buff, 0, 2);
			printf("Using async send\n");
			wlen = knet_send(knet_h, buff, buff_len, outchan);
			if (wlen != buff_len) {
				printf("Unable to send messages to socket: %s\n", strerror(errno));
				exit(1);
			}
		}

		tv.tv_sec = 1;
		tv.tv_usec = 0;

select_loop:
		FD_ZERO(&rfds);
		for (j = 0; j < 4; j++) {
			FD_SET(knet_sock[j], &rfds);
		}
		FD_SET(logpipefd[0], &rfds);

		len = select(FD_SETSIZE, &rfds, NULL, NULL, &tv);

		/* uncomment this to replicate the one-message problem */
		/* usleep(500000); */

		if (len < 0) {
			printf("Unable select over knet_handle_t\n");
			exit(EXIT_FAILURE);
		} else if (FD_ISSET(knet_sock[0], &rfds)) {
			recv_data(knet_h, channel[0], has_crypto);
		} else if (FD_ISSET(knet_sock[1], &rfds)) {
			recv_data(knet_h, channel[1], has_crypto);
		} else if (FD_ISSET(knet_sock[2], &rfds)) {
			recv_data(knet_h, channel[2], has_crypto);
		} else if (FD_ISSET(knet_sock[3], &rfds)) {
			recv_data(knet_h, channel[3], has_crypto);
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
