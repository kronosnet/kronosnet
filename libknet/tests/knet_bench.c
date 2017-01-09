/*
 * Copyright (C) 2016 Red Hat, Inc.  All rights reserved.
 *
 * Authors: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *
 * This software licensed under GPL-2.0+, LGPL-2.0+
 */

#include "config.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>

#include "libknet.h"

#include "internals.h"
#include "netutils.h"
#include "test-common.h"

#define MAX_NODES 128

static int senderid = -1;
static knet_handle_t knet_h;
static int datafd = 0;
static int8_t channel = 0;
static int globallistener = 0;
static int continous = 0;
static struct sockaddr_storage allv4;
static struct sockaddr_storage allv6;
static int broadcast_test = 1;
static pthread_t rx_thread = NULL;
static char *rx_buf[PCKT_FRAG_MAX];
static int shutdown_in_progress = 0;
static pthread_mutex_t shutdown_mutex = PTHREAD_MUTEX_INITIALIZER;

#define TEST_PING 0
#define TEST_PING_AND_DATA 1
#define TEST_PERF 2

static int test_type = TEST_PING;

struct node {
	int nodeid;
	int links;
	struct sockaddr_storage address[KNET_MAX_LINK];
};

static void print_help(void)
{
	printf("knet_bench usage:\n");
	printf(" -h                                        print this help (no really)\n");
	printf(" -d                                        enable debug logs (default INFO)\n");
	printf(" -c [implementation]:[crypto]:[hashing]    crypto configuration. (default disabled)\n");
	printf("                                           Example: -c nss:aes128:sha1\n");
	printf(" -p [active|passive|rr]                    (default: passive)\n");
	printf(" -P [udp|sctp]                             (default: udp) protocol (transport) to use\n");
	printf(" -t [nodeid]                               This nodeid (required)\n");
	printf(" -n [nodeid],[link1_ip_addr],[link2_..]    Other nodes information (at least one required)\n");
	printf("                                           Example: -t 1,192.168.8.1,3ffe::8:1,..\n");
	printf("                                           can be repeated up to %d and should contain also the localnode info\n", MAX_NODES);
	printf(" -b [port]                                 baseport (default: 50000)\n");
	printf(" -l                                        enable global listener on 0.0.0.0/:: (default: off, incompatible with -o)\n");
	printf(" -o                                        enable baseport offset per nodeid\n");
	printf(" -w                                        dont wait for all nodes to be up before starting the test (default: wait)\n");
	printf(" -T [ping|ping_data|perf]                  test type (default: ping)\n");
	printf("                                           ping: will wait for all hosts to join the knet network, sleep 5 seconds and quit\n");
	printf("                                           ping_data: will wait for all hosts to join the knet network, sends some data to all nodes and quit\n");
	printf("                                           perf: will wait for all hosts to join the knet network, perform a series of benchmarks and quit\n");
	printf(" -s                                        nodeid that will generate traffic for benchmarks\n");
	printf(" -C                                        repeat the test continously (default: off)\n");
}

static void parse_nodes(char *nodesinfo[MAX_NODES], int onidx, int port, struct node nodes[MAX_NODES], int thisnodeid, int *thisidx)
{
	int i;
	char *temp = NULL;
	char port_str[10];

	memset(port_str, 0, sizeof(port_str));
	sprintf(port_str, "%d", port);

	for (i = 0; i < onidx; i++) {
		nodes[i].nodeid = atoi(strtok(nodesinfo[i], ","));
		if ((nodes[i].nodeid < 0) || (nodes[i].nodeid > KNET_MAX_HOST)) {
			printf("Invalid nodeid: %d (0 - %d)\n", nodes[i].nodeid, KNET_MAX_HOST);
			exit(FAIL);
		}
		if (thisnodeid == nodes[i].nodeid) {
			*thisidx = i;
		}
		while((temp = strtok(NULL, ","))) {
			if (nodes[i].links == KNET_MAX_LINK) {
				printf("Too many links configured. Max %d\n", KNET_MAX_LINK);
				exit(FAIL);
			}
			if (strtoaddr(temp, port_str,
				      (struct sockaddr *)&nodes[i].address[nodes[i].links],
				      sizeof(struct sockaddr_storage)) < 0) {
				printf("Unable to convert %s to sockaddress\n", temp);
				exit(FAIL);
			}
			nodes[i].links++;
		}
	}

	if (strtoaddr("0.0.0.0", port_str, (struct sockaddr *)&allv4, sizeof(struct sockaddr_storage)) < 0) {
		printf("Unable to convert 0.0.0.0 to sockaddress\n");
		exit(FAIL);
	}

	if (strtoaddr("::", port_str, (struct sockaddr *)&allv6, sizeof(struct sockaddr_storage)) < 0) {
		printf("Unable to convert :: to sockaddress\n");
		exit(FAIL);
	}

	for (i = 1; i < onidx; i++) {
		if (nodes[0].links != nodes[i].links) {
			printf("knet_bench does not support unbalanced link configuration\n");
			exit(FAIL);
		}
	}

	return;
}

static int private_data;

static void sock_notify(void *pvt_data,
			int local_datafd,
			int8_t local_channel,
			uint8_t tx_rx,
			int error,
			int errorno)
{
	printf("Error (%d - %d - %s) from socket: %d\n", error, errorno, strerror(errno), local_datafd);
	return;
}

static void setup_knet(int argc, char *argv[])
{
	int logfd;
	int rv;
	char *cryptocfg = NULL, *policystr = NULL, *protostr = NULL;
	char *othernodeinfo[MAX_NODES];
	struct node nodes[MAX_NODES];
	int thisnodeid = -1;
	int thisidx = -1;
	int onidx = 0;
	int debug = KNET_LOG_INFO;
	int port = 50000, portoffset = 0;
	int thisport = 0, otherport = 0;
	int thisnewport = 0, othernewport = 0;
	struct sockaddr_in *so_in;
	struct sockaddr_in6 *so_in6;
	struct sockaddr_storage *src;
	int i, link_idx, allnodesup = 0;
	int policy = KNET_LINK_POLICY_PASSIVE, policyfound = 0;
	int protocol = KNET_TRANSPORT_UDP, protofound = 0;
	int wait = 1;
	struct knet_handle_crypto_cfg knet_handle_crypto_cfg;
	char *cryptomodel = NULL, *cryptotype = NULL, *cryptohash = NULL;

	memset(nodes, 0, sizeof(nodes));

	optind = 0;
	while ((rv = getopt(argc, argv, "CT:s:ldowb:t:n:c:p:P:h")) != EOF) {
		switch(rv) {
			case 'h':
				print_help();
				exit(PASS);
				break;
			case 'd':
				debug = KNET_LOG_DEBUG;
				break;
			case 'c':
				if (cryptocfg) {
					printf("Error: -c can only be specified once\n");
					exit(FAIL);
				}
				cryptocfg = optarg;
				break;
			case 'p':
				if (policystr) {
					printf("Error: -p can only be specified once\n");
					exit(FAIL);
				}
				policystr = optarg;
				if (!strcmp(policystr, "active")) {
					policy = KNET_LINK_POLICY_ACTIVE;
					policyfound = 1;
				}
				if (!strcmp(policystr, "rr")) {
					policy = KNET_LINK_POLICY_RR;
					policyfound = 1;
				}
				if (!strcmp(policystr, "passive")) {
					policy = KNET_LINK_POLICY_PASSIVE;
					policyfound = 1;
				}
				if (!policyfound) {
					printf("Error: invalid policy %s specified. -p accepts active|passive|rr\n", policystr);
					exit(FAIL);
				}
				break;
		        case 'P':
				if (protostr) {
					printf("Error: -P can only be specified once\n");
					exit(FAIL);
				}
				protostr = optarg;
				if (!strcmp(protostr, "udp")) {
					protocol = KNET_TRANSPORT_UDP;
					protofound = 1;
				}
				if (!strcmp(protostr, "sctp")) {
					protocol = KNET_TRANSPORT_SCTP;
					protofound = 1;
				}
				if (!protofound) {
					printf("Error: invalid protocol %s specified. -P accepts udp|sctp\n", policystr);
					exit(FAIL);
				}
				break;
			case 't':
				if (thisnodeid >= 0) {
					printf("Error: -t can only be specified once\n");
					exit(FAIL);
				}
				thisnodeid = atoi(optarg);
				if ((thisnodeid < 0) || (thisnodeid > 65536)) {
					printf("Error: -t nodeid out of range %d (1 - 65536)\n", thisnodeid);
                                        exit(FAIL);
				}
				break;
			case 'n':
				if (onidx == MAX_NODES) {
					printf("Error: too many other nodes. Max %d\n", MAX_NODES);
					exit(FAIL);
				}
				othernodeinfo[onidx] = optarg;
				onidx++;
				break;
			case 'b':
				port = atoi(optarg);
				if ((port < 1) || (port > 65536)) {
					printf("Error: port %d out of range (1 - 65536)\n", port);
					exit(FAIL);
				}
			case 'o':
				if (globallistener) {
					printf("Error: -l cannot be used with -o\n");
					exit(FAIL);
				}
				portoffset = 1;
				break;
			case 'l':
				if (portoffset) {
					printf("Error: -o cannot be used with -l\n");
					exit(FAIL);
				}
				globallistener = 1;
				break;
			case 'w':
				wait = 0;
				break;
			case 's':
				if (senderid >= 0) {
					printf("Error: -s can only be specified once\n");
					exit(FAIL);
				}
				senderid = atoi(optarg);
				if ((senderid < 0) || (senderid > 65536)) {
					printf("Error: -s nodeid out of range %d (1 - 65536)\n", senderid);
                                        exit(FAIL);
				}
				break;
			case 'T':
				if (!strcmp("ping", optarg)) {
					test_type = TEST_PING;
				}
				if (!strcmp("ping_data", optarg)) {
					test_type = TEST_PING_AND_DATA;
				}
				if (!strcmp("perf", optarg)) {
					test_type = TEST_PERF;
				}
				break;
			case 'C':
				continous = 1;
				break;
			default:
				break;
		}
	}

	if (thisnodeid < 0) {
		printf("Who am I?!? missing -t from command line?\n");
		exit(FAIL);
	}

	if (onidx < 1) {
		printf("no other nodes configured?!? missing -n from command line\n");
		exit(FAIL);
	}

	parse_nodes(othernodeinfo, onidx, port, nodes, thisnodeid, &thisidx);

	if (thisidx < 0) {
		printf("no config for this node found\n");
		exit(FAIL);
	}

	if (senderid >= 0) {
		for (i=0; i < onidx; i++) {
			if (senderid == nodes[i].nodeid) {
				break;
			}
		}
		if (i == onidx) {
			printf("Unable to find senderid in nodelist\n");
			exit(FAIL);
		}
	}

	if ((test_type == TEST_PERF) && (senderid < 0)) {
		printf("Error: performance test requires -s to be set (for now)\n");
		exit(FAIL);
	}

	logfd = start_logging(stdout);

	knet_h = knet_handle_new(thisnodeid, logfd, debug);
	if (!knet_h) {
		printf("Unable to knet_handle_new: %s\n", strerror(errno));
		exit(FAIL);
	}

	if (cryptocfg) {
		memset(&knet_handle_crypto_cfg, 0, sizeof(knet_handle_crypto_cfg));
		cryptomodel = strtok(cryptocfg, ":");
		cryptotype = strtok(NULL, ":");
		cryptohash = strtok(NULL, ":");
		if (cryptomodel) {
			strncpy(knet_handle_crypto_cfg.crypto_model, cryptomodel, sizeof(knet_handle_crypto_cfg.crypto_model) - 1);
		}
		if (cryptotype) {
			strncpy(knet_handle_crypto_cfg.crypto_cipher_type, cryptotype, sizeof(knet_handle_crypto_cfg.crypto_cipher_type) - 1);
		}
		if (cryptohash) {
			strncpy(knet_handle_crypto_cfg.crypto_hash_type, cryptohash, sizeof(knet_handle_crypto_cfg.crypto_hash_type) - 1);
		}
		knet_handle_crypto_cfg.private_key_len = KNET_MAX_KEY_LEN;
		if (knet_handle_crypto(knet_h, &knet_handle_crypto_cfg)) {
			printf("Unable to init crypto\n");
			exit(FAIL);
		}
	}

	if (knet_handle_enable_sock_notify(knet_h, &private_data, sock_notify) < 0) {
		printf("knet_handle_enable_sock_notify failed: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		exit(FAIL);
        }

	datafd = 0;
	channel = -1;

	if (knet_handle_add_datafd(knet_h, &datafd, &channel) < 0) {
		printf("knet_handle_add_datafd failed: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		exit(FAIL);
	}

	for (i=0; i < onidx; i++) {
		if (i == thisidx) {
			continue;
		}

		if (knet_host_add(knet_h, nodes[i].nodeid) < 0) {
			printf("knet_host_add failed: %s\n", strerror(errno));
			exit(FAIL);
		}

		if (knet_host_set_policy(knet_h, nodes[i].nodeid, policy) < 0) {
			printf("knet_host_set_policy failed: %s\n", strerror(errno));
			exit(FAIL);
		}

		for (link_idx = 0; link_idx < nodes[i].links; link_idx++) {
			if (portoffset) {
				if (nodes[thisidx].address[link_idx].ss_family == AF_INET) {
					so_in = (struct sockaddr_in *)&nodes[thisidx].address[link_idx];
					thisport = ntohs(so_in->sin_port);
					thisnewport = thisport + nodes[i].nodeid;
					so_in->sin_port = (htons(thisnewport));
					so_in = (struct sockaddr_in *)&nodes[i].address[link_idx];
					otherport = ntohs(so_in->sin_port);
					othernewport = otherport + nodes[thisidx].nodeid;
					so_in->sin_port = (htons(othernewport));
				} else {
					so_in6 = (struct sockaddr_in6 *)&nodes[thisidx].address[link_idx];
					thisport = ntohs(so_in6->sin6_port);
					thisnewport = thisport + nodes[i].nodeid;
					so_in6->sin6_port = (htons(thisnewport));
					so_in6 = (struct sockaddr_in6 *)&nodes[i].address[link_idx];
					otherport = ntohs(so_in6->sin6_port);
					othernewport = otherport + nodes[thisidx].nodeid;
					so_in6->sin6_port = (htons(othernewport));
				}
			}
			if (!globallistener) {
				src = &nodes[thisidx].address[link_idx];
			} else {
				if (nodes[thisidx].address[link_idx].ss_family == AF_INET) {
					src = &allv4;
				} else {
					src = &allv6;
				}
			}
			if (knet_link_set_config(knet_h, nodes[i].nodeid, link_idx,
						 protocol, src,
						 &nodes[i].address[link_idx]) < 0) {
				printf("Unable to configure link: %s\n", strerror(errno));
				exit(FAIL);
			}
			if (portoffset) {
				if (nodes[thisidx].address[link_idx].ss_family == AF_INET) {
					so_in = (struct sockaddr_in *)&nodes[thisidx].address[link_idx];
					so_in->sin_port = (htons(thisport));
					so_in = (struct sockaddr_in *)&nodes[i].address[link_idx];
					so_in->sin_port = (htons(otherport));
				} else {
					so_in6 = (struct sockaddr_in6 *)&nodes[thisidx].address[link_idx];
					so_in6->sin6_port = (htons(thisport));
					so_in6 = (struct sockaddr_in6 *)&nodes[i].address[link_idx];
					so_in6->sin6_port = (htons(otherport));
				}
			}
			if (knet_link_set_enable(knet_h, nodes[i].nodeid, link_idx, 1) < 0) {
				printf("knet_link_set_enable failed: %s\n", strerror(errno));
				exit(FAIL);
			}
		}
	}

	if (knet_handle_setfwd(knet_h, 1) < 0) {
		printf("knet_handle_setfwd failed: %s\n", strerror(errno));
		exit(FAIL);
	}

	if (wait) {
		while(!allnodesup) {
			allnodesup = 1;
			for (i=0; i < onidx; i++) {
				if (i == thisidx) {
					continue;
				}
				if(knet_h->host_index[nodes[i].nodeid]->status.reachable != 1) {
					printf("waiting host %d to be reachable\n", nodes[i].nodeid);
					allnodesup = 0;
				}
			}
			if (!allnodesup) {
				sleep(1);
			}
		}
		sleep(1);
	}
}

static int ping_dst_host_filter(void *pvt_data,
				const unsigned char *outdata,
				ssize_t outdata_len,
				uint8_t tx_rx,
				uint16_t this_host_id,
				uint16_t src_host_id,
				int8_t *dst_channel,
				uint16_t *dst_host_ids,
				size_t *dst_host_ids_entries)
{
	if (broadcast_test) {
		return 1;
	}

	if (tx_rx == KNET_NOTIFY_TX) {
		memmove(&dst_host_ids[0], outdata, 2);
	} else {
		dst_host_ids[0] = this_host_id;
	}
	*dst_host_ids_entries = 1;
	return 0;
}

static void *_rx_thread(void *args)
{
	fd_set rfds;
	ssize_t len;
	struct timeval tv;
	struct sockaddr_storage address[PCKT_FRAG_MAX];
	struct mmsghdr msg[PCKT_FRAG_MAX];
	struct iovec iov_in[PCKT_FRAG_MAX];
	int i, msg_recv;

	for (i = 0; i < PCKT_FRAG_MAX; i++) {
		rx_buf[i] = malloc(KNET_MAX_PACKET_SIZE);
		if (!rx_buf[i]) {
			printf("RXT: Unable to malloc!\n");
			return NULL;
		}
		memset(rx_buf[i], 0, KNET_MAX_PACKET_SIZE);
		iov_in[i].iov_base = (void *)rx_buf[i];
		iov_in[i].iov_len = KNET_MAX_PACKET_SIZE;
		memset(&msg[i].msg_hdr, 0, sizeof(struct msghdr));
		msg[i].msg_hdr.msg_name = &address[i];
		msg[i].msg_hdr.msg_namelen = sizeof(struct sockaddr_storage);
		msg[i].msg_hdr.msg_iov = &iov_in[i];
		msg[i].msg_hdr.msg_iovlen = 1;
	}

select_loop:
	tv.tv_sec = 5;
	tv.tv_usec = 0;

	FD_ZERO(&rfds);
	FD_SET(datafd, &rfds);

	len = select(FD_SETSIZE, &rfds, NULL, NULL, &tv);
	if (len < 0) {
		printf("RXT: Unable select over datafd\nHALTING RX THREAD!\n");
		return NULL;
	}
	if (!len) {
		printf("RXT: No data for the past 5 seconds\n");
	}
	if (FD_ISSET(datafd, &rfds)) {
		msg_recv = recvmmsg(datafd, msg, PCKT_FRAG_MAX, MSG_DONTWAIT | MSG_NOSIGNAL, NULL);
		if (msg_recv < 0) {
			printf("RXT: error from recvmmsg: %s\n", strerror(errno));
		}
		for (i = 0; i < msg_recv; i++) {
			if (msg[i].msg_len == 0) {
				printf("RXT: received 0 bytes message?\n");
			}
			if (test_type == TEST_PING_AND_DATA) {
				printf("received %u bytes message: %s\n", msg[i].msg_len, (char *)msg[i].msg_hdr.msg_iov->iov_base);
			}
			/*
			 * do stats here
			 */
		}
	}

	goto select_loop;

	return NULL;
}

static void setup_data_txrx_common(void)
{
	if (!rx_thread) {
		if (knet_handle_enable_filter(knet_h, NULL, ping_dst_host_filter)) {
			printf("Unable to enable dst_host_filter: %s\n", strerror(errno));
			exit(FAIL);
		}
		printf("Setting up rx thread\n");
		if (pthread_create(&rx_thread, 0, _rx_thread, NULL)) {
			printf("Unable to start rx thread\n");
			exit(FAIL);
		}
	}
}

static void stop_rx_thread(void)
{
	void *retval;
	int i;

	if (rx_thread) {
		printf("Shutting down rx thread\n");
		pthread_cancel(rx_thread);
		pthread_join(rx_thread, &retval);
		for (i = 0; i < PCKT_FRAG_MAX; i ++) {
			free(rx_buf[i]);
		}
	}
}

static void send_ping_data(void)
{
	const char *buf = "Hello world!\x0";
	ssize_t len = strlen(buf);

	if (knet_send(knet_h, buf, len, channel) != len) {
		printf("Error sending hello world: %s\n", strerror(errno));
	}
	sleep(1);
}

static void cleanup_all(void)
{
	if (pthread_mutex_lock(&shutdown_mutex)) {
		return;
	}

	if (shutdown_in_progress) {
		pthread_mutex_unlock(&shutdown_mutex);
		return;
	}

	shutdown_in_progress = 1;

	pthread_mutex_unlock(&shutdown_mutex);

	if (rx_thread) {
		stop_rx_thread();
	}
	knet_handle_stop(knet_h);
}

static void sigint_handler(int signum)
{
	printf("Cleaning up... got signal: %d\n", signum);
	cleanup_all();
	exit(PASS);
}

int main(int argc, char *argv[])
{
	if (signal(SIGINT, sigint_handler) == SIG_ERR) {
		printf("Unable to configure SIGINT handler\n");
		exit(FAIL);
	}

	need_root();

	setup_knet(argc, argv);

restart:
	switch(test_type) {
		default:
		case TEST_PING: /* basic ping, no data */
			sleep(5);
			break;
		case TEST_PING_AND_DATA:
			setup_data_txrx_common();
			send_ping_data();
			break;
		case TEST_PERF:
			setup_data_txrx_common();
			break;
	}
	if (continous) {
		goto restart;
	}

	cleanup_all();

	return PASS;
}
