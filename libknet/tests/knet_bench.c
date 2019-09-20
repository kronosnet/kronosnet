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
#include <signal.h>
#include <pthread.h>
#include <sys/types.h>
#include <inttypes.h>

#include "libknet.h"

#include "compat.h"
#include "internals.h"
#include "netutils.h"
#include "transport_common.h"
#include "threads_common.h"
#include "test-common.h"

#define MAX_NODES 128

static int senderid = -1;
static int thisnodeid = -1;
static knet_handle_t knet_h;
static int datafd = 0;
static int8_t channel = 0;
static int globallistener = 0;
static int continous = 0;
static int show_stats = 0;
static struct sockaddr_storage allv4;
static struct sockaddr_storage allv6;
static int broadcast_test = 1;
static pthread_t rx_thread = (pthread_t)NULL;
static char *rx_buf[PCKT_FRAG_MAX];
static int wait_for_perf_rx = 0;
static char *compresscfg = NULL;
static char *cryptocfg = NULL;
static int machine_output = 0;
static int use_access_lists = 0;

static int bench_shutdown_in_progress = 0;
static pthread_mutex_t shutdown_mutex = PTHREAD_MUTEX_INITIALIZER;

#define TEST_PING 0
#define TEST_PING_AND_DATA 1
#define TEST_PERF_BY_SIZE 2
#define TEST_PERF_BY_TIME 3

static int test_type = TEST_PING;

#define TEST_START 2
#define TEST_STOP 4
#define TEST_COMPLETE 6

#define ONE_GIGABYTE 1073741824

static uint64_t perf_by_size_size = 1 * ONE_GIGABYTE;
static uint64_t perf_by_time_secs = 10;

struct node {
	int nodeid;
	int links;
	uint8_t transport[KNET_MAX_LINK];
	struct sockaddr_storage address[KNET_MAX_LINK];
};

static void print_help(void)
{
	printf("knet_bench usage:\n");
	printf(" -h                                        print this help (no really)\n");
	printf(" -d                                        enable debug logs (default INFO)\n");
	printf(" -f                                        enable use of access lists (default: off)\n");
	printf(" -c [implementation]:[crypto]:[hashing]    crypto configuration. (default disabled)\n");
	printf("                                           Example: -c nss:aes128:sha1\n");
	printf(" -z [implementation]:[level]:[threshold]   compress configuration. (default disabled)\n");
	printf("                                           Example: -z zlib:5:100\n");
	printf(" -p [active|passive|rr]                    (default: passive)\n");
	printf(" -P [UDP|SCTP]                             (default: UDP) protocol (transport) to use for all links\n");
	printf(" -t [nodeid]                               This nodeid (required)\n");
	printf(" -n [nodeid],[proto]/[link1_ip],[link2_..] Other nodes information (at least one required)\n");
	printf("                                           Example: -n 1,192.168.8.1,SCTP/3ffe::8:1,UDP/172...\n");
	printf("                                           can be repeated up to %d and should contain also the localnode info\n", MAX_NODES);
	printf(" -b [port]                                 baseport (default: 50000)\n");
	printf(" -l                                        enable global listener on 0.0.0.0/:: (default: off, incompatible with -o)\n");
	printf(" -o                                        enable baseport offset per nodeid\n");
	printf(" -m                                        change PMTUd interval in seconds (default: 60)\n");
	printf(" -w                                        dont wait for all nodes to be up before starting the test (default: wait)\n");
	printf(" -T [ping|ping_data|perf-by-size|perf-by-time]\n");
	printf("                                           test type (default: ping)\n");
	printf("                                           ping: will wait for all hosts to join the knet network, sleep 5 seconds and quit\n");
	printf("                                           ping_data: will wait for all hosts to join the knet network, sends some data to all nodes and quit\n");
	printf("                                           perf-by-size: will wait for all hosts to join the knet network,\n");
	printf("                                                         perform a series of benchmarks by transmitting a known\n");
	printf("                                                         size/quantity of packets and measuring the time, then quit\n");
	printf("                                           perf-by-time: will wait for all hosts to join the knet network,\n");
	printf("                                                         perform a series of benchmarks by transmitting a known\n");
	printf("                                                         size of packets for a given amount of time (10 seconds)\n");
	printf("                                                         and measuring the quantity of data transmitted, then quit\n");
	printf(" -s                                        nodeid that will generate traffic for benchmarks\n");
	printf(" -S [size|seconds]                         when used in combination with -T perf-by-size it indicates how many GB of traffic to generate for the test. (default: 1GB)\n");
	printf("                                           when used in combination with -T perf-by-time it indicates how many Seconds of traffic to generate for the test. (default: 10 seconds)\n");
	printf(" -C                                        repeat the test continously (default: off)\n");
	printf(" -X[XX]                                    show stats at the end of the run (default: 1)\n");
	printf("                                           1: show handle stats, 2: show summary link stats\n");
	printf("                                           3: show detailed link stats\n");
	printf(" -a                                        enable machine parsable output (default: off).\n");
}

static void parse_nodes(char *nodesinfo[MAX_NODES], int onidx, int port, struct node nodes[MAX_NODES], int *thisidx)
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
			char *slash = NULL;
			uint8_t transport;

			if (nodes[i].links == KNET_MAX_LINK) {
				printf("Too many links configured. Max %d\n", KNET_MAX_LINK);
				exit(FAIL);
			}

			slash = strstr(temp, "/");
			if (slash) {
				memset(slash, 0, 1);
				transport = knet_get_transport_id_by_name(temp);
				if (transport == KNET_MAX_TRANSPORTS) {
					printf("Unknown transport: %s\n", temp);
					exit(FAIL);
				}
				nodes[i].transport[nodes[i].links] = transport;
				temp = slash + 1;
			} else {
				nodes[i].transport[nodes[i].links] = KNET_TRANSPORT_UDP;
			}

			if (knet_strtoaddr(temp, port_str,
					   &nodes[i].address[nodes[i].links],
					   sizeof(struct sockaddr_storage)) < 0) {
				printf("Unable to convert %s to sockaddress\n", temp);
				exit(FAIL);
			}
			nodes[i].links++;
		}
	}

	if (knet_strtoaddr("0.0.0.0", port_str, &allv4, sizeof(struct sockaddr_storage)) < 0) {
		printf("Unable to convert 0.0.0.0 to sockaddress\n");
		exit(FAIL);
	}

	if (knet_strtoaddr("::", port_str, &allv6, sizeof(struct sockaddr_storage)) < 0) {
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
	printf("[info]: error (%d - %d - %s) from socket: %d\n", error, errorno, strerror(errno), local_datafd);
	return;
}

static int ping_dst_host_filter(void *pvt_data,
				const unsigned char *outdata,
				ssize_t outdata_len,
				uint8_t tx_rx,
				knet_node_id_t this_host_id,
				knet_node_id_t src_host_id,
				int8_t *dst_channel,
				knet_node_id_t *dst_host_ids,
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

static void setup_knet(int argc, char *argv[])
{
	int logfd = 0;
	int rv;
	char *policystr = NULL, *protostr = NULL;
	char *othernodeinfo[MAX_NODES];
	struct node nodes[MAX_NODES];
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
	int pmtud_interval = 60;
	struct knet_handle_crypto_cfg knet_handle_crypto_cfg;
	char *cryptomodel = NULL, *cryptotype = NULL, *cryptohash = NULL;
	struct knet_handle_compress_cfg knet_handle_compress_cfg;

	memset(nodes, 0, sizeof(nodes));

	while ((rv = getopt(argc, argv, "aCT:S:s:ldfom:wb:t:n:c:p:X::P:z:h")) != EOF) {
		switch(rv) {
			case 'h':
				print_help();
				exit(PASS);
				break;
			case 'a':
				machine_output = 1;
				break;
			case 'd':
				debug = KNET_LOG_DEBUG;
				break;
			case 'f':
				use_access_lists = 1;
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
				if (optarg) {
					policystr = optarg;
					if (!strcmp(policystr, "active")) {
						policy = KNET_LINK_POLICY_ACTIVE;
						policyfound = 1;
					}
					/*
					 * we can't use rr because clangs can't compile
					 * an array of 3 strings, one of which is 2 bytes long
					 */
					if (!strcmp(policystr, "round-robin")) {
						policy = KNET_LINK_POLICY_RR;
						policyfound = 1;
					}
					if (!strcmp(policystr, "passive")) {
						policy = KNET_LINK_POLICY_PASSIVE;
						policyfound = 1;
					}
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
				if (optarg) {
					protostr = optarg;
					if (!strcmp(protostr, "UDP")) {
						protocol = KNET_TRANSPORT_UDP;
						protofound = 1;
					}
					if (!strcmp(protostr, "SCTP")) {
						protocol = KNET_TRANSPORT_SCTP;
						protofound = 1;
					}
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
				break;
			case 'o':
				if (globallistener) {
					printf("Error: -l cannot be used with -o\n");
					exit(FAIL);
				}
				portoffset = 1;
				break;
			case 'm':
				pmtud_interval = atoi(optarg);
				if (pmtud_interval < 1) {
					printf("Error: pmtud interval %d out of range (> 0)\n", pmtud_interval);
					exit(FAIL);
				}
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
				if (optarg) {
					if (!strcmp("ping", optarg)) {
						test_type = TEST_PING;
					}
					if (!strcmp("ping_data", optarg)) {
						test_type = TEST_PING_AND_DATA;
					}
					if (!strcmp("perf-by-size", optarg)) {
						test_type = TEST_PERF_BY_SIZE;
					}
					if (!strcmp("perf-by-time", optarg)) {
						test_type = TEST_PERF_BY_TIME;
					}
				} else {
					printf("Error: -T requires an option\n");
					exit(FAIL);
				}
				break;
			case 'S':
				perf_by_size_size = (uint64_t)atoi(optarg) * ONE_GIGABYTE;
				perf_by_time_secs = (uint64_t)atoi(optarg);
				break;
			case 'C':
				continous = 1;
				break;
			case 'X':
				if (optarg) {
					show_stats = atoi(optarg);
				} else {
					show_stats = 1;
				}
				break;
			case 'z':
				if (compresscfg) {
					printf("Error: -c can only be specified once\n");
					exit(FAIL);
				}
				compresscfg = optarg;
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

	parse_nodes(othernodeinfo, onidx, port, nodes, &thisidx);

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

	if (((test_type == TEST_PERF_BY_SIZE) || (test_type == TEST_PERF_BY_TIME)) && (senderid < 0)) {
		printf("Error: performance test requires -s to be set (for now)\n");
		exit(FAIL);
	}

	logfd = start_logging(stdout);

	knet_h = knet_handle_new(thisnodeid, logfd, debug);
	if (!knet_h) {
		printf("Unable to knet_handle_new: %s\n", strerror(errno));
		exit(FAIL);
	}

	if (knet_handle_enable_access_lists(knet_h, use_access_lists) < 0) {
		printf("Unable to knet_handle_enable_access_lists: %s\n", strerror(errno));
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

	if (compresscfg) {
		memset(&knet_handle_compress_cfg, 0, sizeof(struct knet_handle_compress_cfg));
		snprintf(knet_handle_compress_cfg.compress_model, 16, "%s", strtok(compresscfg, ":"));
		knet_handle_compress_cfg.compress_level = atoi(strtok(NULL, ":"));
		knet_handle_compress_cfg.compress_threshold = atoi(strtok(NULL, ":"));
		if (knet_handle_compress(knet_h, &knet_handle_compress_cfg)) {
			printf("Unable to configure compress\n");
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

	if (knet_handle_pmtud_setfreq(knet_h, pmtud_interval) < 0) {
		printf("knet_handle_pmtud_setfreq failed: %s\n", strerror(errno));
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
			/*
			 * -P overrides per link protocol configuration
			 */
			if (protofound) {
				nodes[i].transport[link_idx] = protocol;
			}
			if (knet_link_set_config(knet_h, nodes[i].nodeid, link_idx,
						 nodes[i].transport[link_idx], src,
						 &nodes[i].address[link_idx], 0) < 0) {
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
			if (knet_link_set_ping_timers(knet_h, nodes[i].nodeid, link_idx, 1000, 10000, 2048) < 0) {
				printf("knet_link_set_ping_timers failed: %s\n", strerror(errno));
				exit(FAIL);
			}
			if (knet_link_set_pong_count(knet_h, nodes[i].nodeid, link_idx, 2) < 0) {
				printf("knet_link_set_pong_count failed: %s\n", strerror(errno));
				exit(FAIL);
			}
		}
	}

	if (knet_handle_enable_filter(knet_h, NULL, ping_dst_host_filter)) {
		printf("Unable to enable dst_host_filter: %s\n", strerror(errno));
		exit(FAIL);
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
				if (knet_h->host_index[nodes[i].nodeid]->status.reachable != 1) {
					printf("[info]: waiting host %d to be reachable\n", nodes[i].nodeid);
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

static void *_rx_thread(void *args)
{
	int rx_epoll;
	struct epoll_event ev;
	struct epoll_event events[KNET_EPOLL_MAX_EVENTS];

	struct sockaddr_storage address[PCKT_FRAG_MAX];
	struct knet_mmsghdr msg[PCKT_FRAG_MAX];
	struct iovec iov_in[PCKT_FRAG_MAX];
	int i, msg_recv;
	struct timespec clock_start, clock_end;
	unsigned long long time_diff = 0;
	uint64_t rx_pkts = 0;
	uint64_t rx_bytes = 0;
	unsigned int current_pckt_size = 0;

	for (i = 0; i < PCKT_FRAG_MAX; i++) {
		rx_buf[i] = malloc(KNET_MAX_PACKET_SIZE);
		if (!rx_buf[i]) {
			printf("RXT: Unable to malloc!\nHALTING RX THREAD!\n");
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

	rx_epoll = epoll_create(KNET_EPOLL_MAX_EVENTS + 1);
	if (rx_epoll < 0) {
		printf("RXT: Unable to create epoll!\nHALTING RX THREAD!\n");
		return NULL;
	}

	memset(&ev, 0, sizeof(struct epoll_event));
	ev.events = EPOLLIN;
	ev.data.fd = datafd;

	if (epoll_ctl(rx_epoll, EPOLL_CTL_ADD, datafd, &ev)) {
		printf("RXT: Unable to add datafd to epoll\nHALTING RX THREAD!\n");
		return NULL;
	}

	memset(&clock_start, 0, sizeof(clock_start));
	memset(&clock_end, 0, sizeof(clock_start));

	while (!bench_shutdown_in_progress) {
		if (epoll_wait(rx_epoll, events, KNET_EPOLL_MAX_EVENTS, 1) >= 1) {
			msg_recv = _recvmmsg(datafd, &msg[0], PCKT_FRAG_MAX, MSG_DONTWAIT | MSG_NOSIGNAL);
			if (msg_recv < 0) {
				printf("[info]: RXT: error from recvmmsg: %s\n", strerror(errno));
			}
			switch(test_type) {
				case TEST_PING_AND_DATA:
					for (i = 0; i < msg_recv; i++) {
						if (msg[i].msg_len == 0) {
							printf("[info]: RXT: received 0 bytes message?\n");
						}
						printf("[info]: received %u bytes message: %s\n", msg[i].msg_len, (char *)msg[i].msg_hdr.msg_iov->iov_base);
					}
					break;
				case TEST_PERF_BY_TIME:
				case TEST_PERF_BY_SIZE:
					for (i = 0; i < msg_recv; i++) {
						if (msg[i].msg_len < 64) {
							if (msg[i].msg_len == 0) {
								printf("[info]: RXT: received 0 bytes message?\n");
							}
							if (msg[i].msg_len == TEST_START) {
								if (clock_gettime(CLOCK_MONOTONIC, &clock_start) != 0) {
									printf("[info]: unable to get start time!\n");
								}
							}
							if (msg[i].msg_len == TEST_STOP) {
								double average_rx_mbytes;
								double average_rx_pkts;
								double time_diff_sec;
								if (clock_gettime(CLOCK_MONOTONIC, &clock_end) != 0) {
									printf("[info]: unable to get end time!\n");
								}
								timespec_diff(clock_start, clock_end, &time_diff);
								/*
								 * adjust for sleep(2) between sending the last data and TEST_STOP
								 */
								time_diff = time_diff - 2000000000llu;

								/*
								 * convert to seconds
								 */
								time_diff_sec = (double)time_diff / 1000000000llu;

								average_rx_mbytes = (double)((rx_bytes / time_diff_sec) / (1024 * 1024));
								average_rx_pkts = (double)(rx_pkts / time_diff_sec);
								if (!machine_output) {
									printf("[perf] execution time: %8.4f secs Average speed: %8.4f MB/sec %8.4f pckts/sec (size: %u total: %" PRIu64 ")\n",
									       time_diff_sec, average_rx_mbytes, average_rx_pkts, current_pckt_size, rx_pkts);
								} else {
									printf("[perf],%.4f,%u,%" PRIu64 ",%.4f,%.4f\n", time_diff_sec, current_pckt_size, rx_pkts, average_rx_mbytes, average_rx_pkts);
								}
								rx_pkts = 0;
								rx_bytes = 0;
								current_pckt_size = 0;
							}
							if (msg[i].msg_len == TEST_COMPLETE) {
								wait_for_perf_rx = 1;
							}
							continue;
						}
						rx_pkts++;
						rx_bytes = rx_bytes + msg[i].msg_len;
						current_pckt_size = msg[i].msg_len;
					}
					break;
			}
		}
	}

	epoll_ctl(rx_epoll, EPOLL_CTL_DEL, datafd, &ev);
	close(rx_epoll);

	return NULL;
}

static void setup_data_txrx_common(void)
{
	if (!rx_thread) {
		if (knet_handle_enable_filter(knet_h, NULL, ping_dst_host_filter)) {
			printf("Unable to enable dst_host_filter: %s\n", strerror(errno));
			exit(FAIL);
		}
		printf("[info]: setting up rx thread\n");
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
		printf("[info]: shutting down rx thread\n");
		sleep(2);
		pthread_cancel(rx_thread);
		pthread_join(rx_thread, &retval);
		for (i = 0; i < PCKT_FRAG_MAX; i ++) {
			free(rx_buf[i]);
		}
	}
}

static void send_ping_data(void)
{
	char buf[65535];
	ssize_t len;

	memset(&buf, 0, sizeof(buf));
	snprintf(buf, sizeof(buf), "Hello world!");

	if (compresscfg) {
		len = sizeof(buf);
	} else {
		len = strlen(buf);
	}

	if (knet_send(knet_h, buf, len, channel) != len) {
		printf("[info]: Error sending hello world: %s\n", strerror(errno));
	}
	sleep(1);
}

static int send_messages(struct knet_mmsghdr *msg, int msgs_to_send)
{
	int sent_msgs, prev_sent, progress, total_sent;

	total_sent = 0;
	sent_msgs = 0;
	prev_sent = 0;
	progress = 1;

retry:
	errno = 0;
	sent_msgs = _sendmmsg(datafd, 0, &msg[0], msgs_to_send, MSG_NOSIGNAL);

	if (sent_msgs < 0) {
		if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) {
			usleep(KNET_THREADS_TIMERES / 16);
			goto retry;
		}
		printf("[info]: Unable to send messages: %s\n", strerror(errno));
		return -1;
	}

	total_sent = total_sent + sent_msgs;

	if ((sent_msgs >= 0) && (sent_msgs < msgs_to_send)) {
		if ((sent_msgs) || (progress)) {
			msgs_to_send = msgs_to_send - sent_msgs;
			prev_sent = prev_sent + sent_msgs;
			if (sent_msgs) {
				progress = 1;
			} else {
				progress = 0;
			}
			goto retry;
		}
		if (!progress) {
			printf("[info]: Unable to send more messages after retry\n");
		}
	}
	return total_sent;
}

static int setup_send_buffers_common(struct knet_mmsghdr *msg, struct iovec *iov_out, char *tx_buf[])
{
	int i;

	for (i = 0; i < PCKT_FRAG_MAX; i++) {
		tx_buf[i] = malloc(KNET_MAX_PACKET_SIZE);
		if (!tx_buf[i]) {
			printf("TXT: Unable to malloc!\n");
			return -1;
		}
		memset(tx_buf[i], 0, KNET_MAX_PACKET_SIZE);
		iov_out[i].iov_base = (void *)tx_buf[i];
		memset(&msg[i].msg_hdr, 0, sizeof(struct msghdr));
		msg[i].msg_hdr.msg_iov = &iov_out[i];
		msg[i].msg_hdr.msg_iovlen = 1;
	}
	return 0;
}

static void send_perf_data_by_size(void)
{
	char *tx_buf[PCKT_FRAG_MAX];
	struct knet_mmsghdr msg[PCKT_FRAG_MAX];
	struct iovec iov_out[PCKT_FRAG_MAX];
	char ctrl_message[16];
	int sent_msgs;
	int i;
	uint64_t total_pkts_to_tx;
	uint64_t packets_to_send;
	uint32_t packetsize = 64;

	setup_send_buffers_common(msg, iov_out, tx_buf);

	while (packetsize <= KNET_MAX_PACKET_SIZE) {
		for (i = 0; i < PCKT_FRAG_MAX; i++) {
			iov_out[i].iov_len = packetsize;
		}

		total_pkts_to_tx = perf_by_size_size / packetsize;
		printf("[info]: testing with %u packet size. total bytes to transfer: %" PRIu64 " (%" PRIu64 " packets)\n", packetsize, perf_by_size_size, total_pkts_to_tx);

		memset(ctrl_message, 0, sizeof(ctrl_message));
		knet_send(knet_h, ctrl_message, TEST_START, channel);

		while (total_pkts_to_tx > 0) {
			if (total_pkts_to_tx >= PCKT_FRAG_MAX) {
				packets_to_send = PCKT_FRAG_MAX;
			} else {
				packets_to_send = total_pkts_to_tx;
			}
			sent_msgs = send_messages(&msg[0], packets_to_send);
			if (sent_msgs < 0) {
				printf("Something went wrong, aborting\n");
				exit(FAIL);
			}
			total_pkts_to_tx = total_pkts_to_tx - sent_msgs;
		}

		sleep(2);

		knet_send(knet_h, ctrl_message, TEST_STOP, channel);

		if (packetsize == KNET_MAX_PACKET_SIZE) {
			break;
		}

		/*
		 * Use a multiplier that can always divide properly a GB
		 * into smaller chunks without worry about boundaries
		 */
		packetsize *= 4;

		if (packetsize > KNET_MAX_PACKET_SIZE) {
			packetsize = KNET_MAX_PACKET_SIZE;
		}
	}

	knet_send(knet_h, ctrl_message, TEST_COMPLETE, channel);

	for (i = 0; i < PCKT_FRAG_MAX; i++) {
		free(tx_buf[i]);
	}
}

/* For sorting the node list into order */
static int node_compare(const void *aptr, const void *bptr)
{
	uint16_t a,b;

	a = *(uint16_t *)aptr;
	b = *(uint16_t *)bptr;

	return a > b;
}

static void display_stats(int level)
{
	struct knet_handle_stats handle_stats;
	struct knet_link_status link_status;
	struct knet_link_stats total_link_stats;
	knet_node_id_t host_list[KNET_MAX_HOST];
	uint8_t link_list[KNET_MAX_LINK];
	unsigned int i,j;
	size_t num_hosts, num_links;

	if (knet_handle_get_stats(knet_h, &handle_stats, sizeof(handle_stats)) < 0) {
		perror("[info]: failed to get knet handle stats");
		return;
	}

	if (compresscfg || cryptocfg) {
		printf("\n");
		printf("[stat]: handle stats\n");
		printf("[stat]: ------------\n");
		if (compresscfg) {
			printf("[stat]:  tx_uncompressed_packets: %" PRIu64 "\n", handle_stats.tx_uncompressed_packets);
			printf("[stat]:  tx_compressed_packets: %" PRIu64 "\n", handle_stats.tx_compressed_packets);
			printf("[stat]:  tx_compressed_original_bytes: %" PRIu64 "\n", handle_stats.tx_compressed_original_bytes);
			printf("[stat]:  tx_compressed_size_bytes: %" PRIu64 "\n", handle_stats.tx_compressed_size_bytes );
			printf("[stat]:  tx_compress_time_ave: %" PRIu64 "\n", handle_stats.tx_compress_time_ave);
			printf("[stat]:  tx_compress_time_min: %" PRIu64 "\n", handle_stats.tx_compress_time_min);
			printf("[stat]:  tx_compress_time_max: %" PRIu64 "\n", handle_stats.tx_compress_time_max);
			printf("[stat]:  rx_compressed_packets: %" PRIu64 "\n", handle_stats.rx_compressed_packets);
			printf("[stat]:  rx_compressed_original_bytes: %" PRIu64 "\n", handle_stats.rx_compressed_original_bytes);
			printf("[stat]:  rx_compressed_size_bytes: %" PRIu64 "\n", handle_stats.rx_compressed_size_bytes);
			printf("[stat]:  rx_compress_time_ave: %" PRIu64 "\n", handle_stats.rx_compress_time_ave);
			printf("[stat]:  rx_compress_time_min: %" PRIu64 "\n", handle_stats.rx_compress_time_min);
			printf("[stat]:  rx_compress_time_max: %" PRIu64 "\n", handle_stats.rx_compress_time_max);
			printf("\n");
		}
		if (cryptocfg) {
			printf("[stat]:  tx_crypt_packets: %" PRIu64 "\n", handle_stats.tx_crypt_packets);
			printf("[stat]:  tx_crypt_byte_overhead: %" PRIu64 "\n", handle_stats.tx_crypt_byte_overhead);
			printf("[stat]:  tx_crypt_time_ave: %" PRIu64 "\n", handle_stats.tx_crypt_time_ave);
			printf("[stat]:  tx_crypt_time_min: %" PRIu64 "\n", handle_stats.tx_crypt_time_min);
			printf("[stat]:  tx_crypt_time_max: %" PRIu64 "\n", handle_stats.tx_crypt_time_max);
			printf("[stat]:  rx_crypt_packets: %" PRIu64 "\n", handle_stats.rx_crypt_packets);
			printf("[stat]:  rx_crypt_time_ave: %" PRIu64 "\n", handle_stats.rx_crypt_time_ave);
			printf("[stat]:  rx_crypt_time_min: %" PRIu64 "\n", handle_stats.rx_crypt_time_min);
			printf("[stat]:  rx_crypt_time_max: %" PRIu64 "\n", handle_stats.rx_crypt_time_max);
			printf("\n");
		}
	}
	if (level < 2) {
		return;
	}

	memset(&total_link_stats, 0, sizeof(struct knet_link_stats));

	if (knet_host_get_host_list(knet_h, host_list, &num_hosts) < 0) {
		perror("[info]: cannot get host list for stats");
		return;
	}

	/* Print in host ID order */
	qsort(host_list, num_hosts, sizeof(uint16_t), node_compare);

	for (j=0; j<num_hosts; j++) {
		if (knet_link_get_link_list(knet_h, host_list[j], link_list, &num_links) < 0) {
			perror("[info]: cannot get link list for stats");
			return;
		}

		for (i=0; i < num_links; i++) {
			if (knet_link_get_status(knet_h, host_list[j], link_list[i], &link_status, sizeof(link_status)) < 0) {
				perror("[info]: cannot get link status");
				return;
			}

			total_link_stats.tx_data_packets += link_status.stats.tx_data_packets;
			total_link_stats.rx_data_packets += link_status.stats.rx_data_packets;
			total_link_stats.tx_data_bytes += link_status.stats.tx_data_bytes;
			total_link_stats.rx_data_bytes += link_status.stats.rx_data_bytes;
			total_link_stats.rx_ping_packets += link_status.stats.rx_ping_packets;
			total_link_stats.tx_ping_packets += link_status.stats.tx_ping_packets;
			total_link_stats.rx_ping_bytes += link_status.stats.rx_ping_bytes;
			total_link_stats.tx_ping_bytes += link_status.stats.tx_ping_bytes;
			total_link_stats.rx_pong_packets += link_status.stats.rx_pong_packets;
			total_link_stats.tx_pong_packets += link_status.stats.tx_pong_packets;
			total_link_stats.rx_pong_bytes += link_status.stats.rx_pong_bytes;
			total_link_stats.tx_pong_bytes += link_status.stats.tx_pong_bytes;
			total_link_stats.rx_pmtu_packets += link_status.stats.rx_pmtu_packets;
			total_link_stats.tx_pmtu_packets += link_status.stats.tx_pmtu_packets;
			total_link_stats.rx_pmtu_bytes += link_status.stats.rx_pmtu_bytes;
			total_link_stats.tx_pmtu_bytes += link_status.stats.tx_pmtu_bytes;

			total_link_stats.tx_total_packets += link_status.stats.tx_total_packets;
			total_link_stats.rx_total_packets += link_status.stats.rx_total_packets;
			total_link_stats.tx_total_bytes += link_status.stats.tx_total_bytes;
			total_link_stats.rx_total_bytes += link_status.stats.rx_total_bytes;
			total_link_stats.tx_total_errors += link_status.stats.tx_total_errors;
			total_link_stats.tx_total_retries += link_status.stats.tx_total_retries;

			total_link_stats.tx_pmtu_errors += link_status.stats.tx_pmtu_errors;
			total_link_stats.tx_pmtu_retries += link_status.stats.tx_pmtu_retries;
			total_link_stats.tx_ping_errors += link_status.stats.tx_ping_errors;
			total_link_stats.tx_ping_retries += link_status.stats.tx_ping_retries;
			total_link_stats.tx_pong_errors += link_status.stats.tx_pong_errors;
			total_link_stats.tx_pong_retries += link_status.stats.tx_pong_retries;
			total_link_stats.tx_data_errors += link_status.stats.tx_data_errors;
			total_link_stats.tx_data_retries += link_status.stats.tx_data_retries;

			total_link_stats.down_count += link_status.stats.down_count;
			total_link_stats.up_count += link_status.stats.up_count;

			if (level > 2) {
				printf("\n");
				printf("[stat]: Node %d Link %d\n", host_list[j], link_list[i]);

				printf("[stat]:   tx_data_packets:  %" PRIu64 "\n", link_status.stats.tx_data_packets);
				printf("[stat]:   rx_data_packets:  %" PRIu64 "\n", link_status.stats.rx_data_packets);
				printf("[stat]:   tx_data_bytes:    %" PRIu64 "\n", link_status.stats.tx_data_bytes);
				printf("[stat]:   rx_data_bytes:    %" PRIu64 "\n", link_status.stats.rx_data_bytes);
				printf("[stat]:   rx_ping_packets:  %" PRIu64 "\n", link_status.stats.rx_ping_packets);
				printf("[stat]:   tx_ping_packets:  %" PRIu64 "\n", link_status.stats.tx_ping_packets);
				printf("[stat]:   rx_ping_bytes:    %" PRIu64 "\n", link_status.stats.rx_ping_bytes);
				printf("[stat]:   tx_ping_bytes:    %" PRIu64 "\n", link_status.stats.tx_ping_bytes);
				printf("[stat]:   rx_pong_packets:  %" PRIu64 "\n", link_status.stats.rx_pong_packets);
				printf("[stat]:   tx_pong_packets:  %" PRIu64 "\n", link_status.stats.tx_pong_packets);
				printf("[stat]:   rx_pong_bytes:    %" PRIu64 "\n", link_status.stats.rx_pong_bytes);
				printf("[stat]:   tx_pong_bytes:    %" PRIu64 "\n", link_status.stats.tx_pong_bytes);
				printf("[stat]:   rx_pmtu_packets:  %" PRIu64 "\n", link_status.stats.rx_pmtu_packets);
				printf("[stat]:   tx_pmtu_packets:  %" PRIu64 "\n", link_status.stats.tx_pmtu_packets);
				printf("[stat]:   rx_pmtu_bytes:    %" PRIu64 "\n", link_status.stats.rx_pmtu_bytes);
				printf("[stat]:   tx_pmtu_bytes:    %" PRIu64 "\n", link_status.stats.tx_pmtu_bytes);

				printf("[stat]:   tx_total_packets: %" PRIu64 "\n", link_status.stats.tx_total_packets);
				printf("[stat]:   rx_total_packets: %" PRIu64 "\n", link_status.stats.rx_total_packets);
				printf("[stat]:   tx_total_bytes:   %" PRIu64 "\n", link_status.stats.tx_total_bytes);
				printf("[stat]:   rx_total_bytes:   %" PRIu64 "\n", link_status.stats.rx_total_bytes);
				printf("[stat]:   tx_total_errors:  %" PRIu64 "\n", link_status.stats.tx_total_errors);
				printf("[stat]:   tx_total_retries: %" PRIu64 "\n", link_status.stats.tx_total_retries);

				printf("[stat]:   tx_pmtu_errors:   %" PRIu32 "\n", link_status.stats.tx_pmtu_errors);
				printf("[stat]:   tx_pmtu_retries:  %" PRIu32 "\n", link_status.stats.tx_pmtu_retries);
				printf("[stat]:   tx_ping_errors:   %" PRIu32 "\n", link_status.stats.tx_ping_errors);
				printf("[stat]:   tx_ping_retries:  %" PRIu32 "\n", link_status.stats.tx_ping_retries);
				printf("[stat]:   tx_pong_errors:   %" PRIu32 "\n", link_status.stats.tx_pong_errors);
				printf("[stat]:   tx_pong_retries:  %" PRIu32 "\n", link_status.stats.tx_pong_retries);
				printf("[stat]:   tx_data_errors:   %" PRIu32 "\n", link_status.stats.tx_data_errors);
				printf("[stat]:   tx_data_retries:  %" PRIu32 "\n", link_status.stats.tx_data_retries);

				printf("[stat]:   latency_min:      %" PRIu32 "\n", link_status.stats.latency_min);
				printf("[stat]:   latency_max:      %" PRIu32 "\n", link_status.stats.latency_max);
				printf("[stat]:   latency_ave:      %" PRIu32 "\n", link_status.stats.latency_ave);
				printf("[stat]:   latency_samples:  %" PRIu32 "\n", link_status.stats.latency_samples);

				printf("[stat]:   down_count:       %" PRIu32 "\n", link_status.stats.down_count);
				printf("[stat]:   up_count:         %" PRIu32 "\n", link_status.stats.up_count);
			}
		}
	}
	printf("\n");
	printf("[stat]: Total link stats\n");
	printf("[stat]: ----------------\n");
	printf("[stat]: tx_data_packets:  %" PRIu64 "\n", total_link_stats.tx_data_packets);
	printf("[stat]: rx_data_packets:  %" PRIu64 "\n", total_link_stats.rx_data_packets);
	printf("[stat]: tx_data_bytes:    %" PRIu64 "\n", total_link_stats.tx_data_bytes);
	printf("[stat]: rx_data_bytes:    %" PRIu64 "\n", total_link_stats.rx_data_bytes);
	printf("[stat]: rx_ping_packets:  %" PRIu64 "\n", total_link_stats.rx_ping_packets);
	printf("[stat]: tx_ping_packets:  %" PRIu64 "\n", total_link_stats.tx_ping_packets);
	printf("[stat]: rx_ping_bytes:    %" PRIu64 "\n", total_link_stats.rx_ping_bytes);
	printf("[stat]: tx_ping_bytes:    %" PRIu64 "\n", total_link_stats.tx_ping_bytes);
	printf("[stat]: rx_pong_packets:  %" PRIu64 "\n", total_link_stats.rx_pong_packets);
	printf("[stat]: tx_pong_packets:  %" PRIu64 "\n", total_link_stats.tx_pong_packets);
	printf("[stat]: rx_pong_bytes:    %" PRIu64 "\n", total_link_stats.rx_pong_bytes);
	printf("[stat]: tx_pong_bytes:    %" PRIu64 "\n", total_link_stats.tx_pong_bytes);
	printf("[stat]: rx_pmtu_packets:  %" PRIu64 "\n", total_link_stats.rx_pmtu_packets);
	printf("[stat]: tx_pmtu_packets:  %" PRIu64 "\n", total_link_stats.tx_pmtu_packets);
	printf("[stat]: rx_pmtu_bytes:    %" PRIu64 "\n", total_link_stats.rx_pmtu_bytes);
	printf("[stat]: tx_pmtu_bytes:    %" PRIu64 "\n", total_link_stats.tx_pmtu_bytes);

	printf("[stat]: tx_total_packets: %" PRIu64 "\n", total_link_stats.tx_total_packets);
	printf("[stat]: rx_total_packets: %" PRIu64 "\n", total_link_stats.rx_total_packets);
	printf("[stat]: tx_total_bytes:   %" PRIu64 "\n", total_link_stats.tx_total_bytes);
	printf("[stat]: rx_total_bytes:   %" PRIu64 "\n", total_link_stats.rx_total_bytes);
	printf("[stat]: tx_total_errors:  %" PRIu64 "\n", total_link_stats.tx_total_errors);
	printf("[stat]: tx_total_retries: %" PRIu64 "\n", total_link_stats.tx_total_retries);

	printf("[stat]: tx_pmtu_errors:   %" PRIu32 "\n", total_link_stats.tx_pmtu_errors);
	printf("[stat]: tx_pmtu_retries:  %" PRIu32 "\n", total_link_stats.tx_pmtu_retries);
	printf("[stat]: tx_ping_errors:   %" PRIu32 "\n", total_link_stats.tx_ping_errors);
	printf("[stat]: tx_ping_retries:  %" PRIu32 "\n", total_link_stats.tx_ping_retries);
	printf("[stat]: tx_pong_errors:   %" PRIu32 "\n", total_link_stats.tx_pong_errors);
	printf("[stat]: tx_pong_retries:  %" PRIu32 "\n", total_link_stats.tx_pong_retries);
	printf("[stat]: tx_data_errors:   %" PRIu32 "\n", total_link_stats.tx_data_errors);
	printf("[stat]: tx_data_retries:  %" PRIu32 "\n", total_link_stats.tx_data_retries);

	printf("[stat]: down_count:       %" PRIu32 "\n", total_link_stats.down_count);
	printf("[stat]: up_count:         %" PRIu32 "\n", total_link_stats.up_count);

}

static void send_perf_data_by_time(void)
{
	char *tx_buf[PCKT_FRAG_MAX];
	struct knet_mmsghdr msg[PCKT_FRAG_MAX];
	struct iovec iov_out[PCKT_FRAG_MAX];
	char ctrl_message[16];
	int sent_msgs;
	int i;
	uint32_t packetsize = 64;
	struct timespec clock_start, clock_end;
	unsigned long long time_diff = 0;

	setup_send_buffers_common(msg, iov_out, tx_buf);

	memset(&clock_start, 0, sizeof(clock_start));
	memset(&clock_end, 0, sizeof(clock_start));

	while (packetsize <= KNET_MAX_PACKET_SIZE) {
		for (i = 0; i < PCKT_FRAG_MAX; i++) {
			iov_out[i].iov_len = packetsize;
		}
		printf("[info]: testing with %u bytes packet size for %" PRIu64 " seconds.\n", packetsize, perf_by_time_secs);

		memset(ctrl_message, 0, sizeof(ctrl_message));
		knet_send(knet_h, ctrl_message, TEST_START, channel);

		if (clock_gettime(CLOCK_MONOTONIC, &clock_start) != 0) {
			printf("[info]: unable to get start time!\n");
		}

		time_diff = 0;

		while (time_diff < (perf_by_time_secs * 1000000000llu)) {
			sent_msgs = send_messages(&msg[0], PCKT_FRAG_MAX);
			if (sent_msgs < 0) {
				printf("Something went wrong, aborting\n");
				exit(FAIL);
			}
			if (clock_gettime(CLOCK_MONOTONIC, &clock_end) != 0) {
				printf("[info]: unable to get end time!\n");
			}
			timespec_diff(clock_start, clock_end, &time_diff);
		}

		sleep(2);

		knet_send(knet_h, ctrl_message, TEST_STOP, channel);

		if (packetsize == KNET_MAX_PACKET_SIZE) {
			break;
		}

		/*
		 * Use a multiplier that can always divide properly a GB
		 * into smaller chunks without worry about boundaries
		 */
		packetsize *= 4;

		if (packetsize > KNET_MAX_PACKET_SIZE) {
			packetsize = KNET_MAX_PACKET_SIZE;
		}
	}

	knet_send(knet_h, ctrl_message, TEST_COMPLETE, channel);

	for (i = 0; i < PCKT_FRAG_MAX; i++) {
		free(tx_buf[i]);
	}
}

static void cleanup_all(void)
{
	if (pthread_mutex_lock(&shutdown_mutex)) {
		return;
	}

	if (bench_shutdown_in_progress) {
		pthread_mutex_unlock(&shutdown_mutex);
		return;
	}

	bench_shutdown_in_progress = 1;

	pthread_mutex_unlock(&shutdown_mutex);

	if (rx_thread) {
		stop_rx_thread();
	}
	knet_handle_stop(knet_h);
}

static void sigint_handler(int signum)
{
	printf("[info]: cleaning up... got signal: %d\n", signum);
	cleanup_all();
	exit(PASS);
}

int main(int argc, char *argv[])
{
	if (signal(SIGINT, sigint_handler) == SIG_ERR) {
		printf("Unable to configure SIGINT handler\n");
		exit(FAIL);
	}

	setup_knet(argc, argv);

	setup_data_txrx_common();

	sleep(5);

restart:
	switch(test_type) {
		default:
		case TEST_PING: /* basic ping, no data */
			sleep(5);
			break;
		case TEST_PING_AND_DATA:
			send_ping_data();
			break;
		case TEST_PERF_BY_SIZE:
			if (senderid == thisnodeid) {
				send_perf_data_by_size();
			} else {
				printf("[info]: waiting for perf rx thread to finish\n");
				while(!wait_for_perf_rx) {
					sleep(1);
				}
			}
			break;
		case TEST_PERF_BY_TIME:
			if (senderid == thisnodeid) {
				send_perf_data_by_time();
			} else {
				printf("[info]: waiting for perf rx thread to finish\n");
				while(!wait_for_perf_rx) {
					sleep(1);
				}
			}
			break;
	}
	if (continous) {
		goto restart;
	}
	if (show_stats) {
		display_stats(show_stats);
	}

	cleanup_all();

	return PASS;
}
