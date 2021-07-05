/*
 * Copyright (C) 2021 Red Hat, Inc.  All rights reserved.
 *
 * Authors: Christine Caulfield <ccaulfie@redhat.com>
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

#include "internals.h"
#include "netutils.h"
#include "test-common.h"

#define FAIL_ON_ERR(fn) \
	if ((res = fn) < 0) {				  \
	  knet_link_set_enable(knet_h[1], 2, 0, 0);	  \
	  knet_link_set_enable(knet_h[2], 1, 0, 0);	  \
	  knet_link_clear_config(knet_h[1], 2, 0);        \
	  knet_link_clear_config(knet_h[2], 1, 0);	  \
	  knet_host_remove(knet_h[1], 2);		  \
	  knet_handle_free(knet_h[1]);			  \
	  knet_host_remove(knet_h[2], 1);		  \
	  knet_handle_free(knet_h[2]);			  \
	  stop_logthread();				  \
	  flush_logs(logfds[0], stdout);		  \
	  close_logpipes(logfds);			  \
	  if (res == -2) {				  \
		  exit(SKIP);				  \
	  } else {					  \
		  printf("*** on line %d %s failed: %s\n", __LINE__ , #fn, strerror(errno)); \
		  exit(FAIL);				  \
	  }						  \
	} else {					  \
	  flush_logs(logfds[0], stdout);		  \
	}

static int knet_send_str(knet_handle_t knet_h, char *str)
{
	return knet_send_sync(knet_h, str, strlen(str)+1, 0);
}

/*
 * lo0 is filled in with the local address on return.
 * lo1 is expected to be provided - it's the actual remote address to connect to.
 */
int dyn_knet_link_set_config(knet_handle_t knet_h, knet_node_id_t host_id, uint8_t link_id,
			     uint8_t transport, uint64_t flags, int family, int dynamic,
			     struct sockaddr_storage *lo0, struct sockaddr_storage *lo1)
{
	int err = 0, savederrno = 0;
	uint32_t port;
	char portstr[32];

	for (port = 1025; port < 65536; port++) {
		sprintf(portstr, "%u", port);
		memset(lo0, 0, sizeof(struct sockaddr_storage));
		if (family == AF_INET6) {
			err = knet_strtoaddr("::1", portstr, lo0, sizeof(struct sockaddr_storage));
		} else {
			err = knet_strtoaddr("127.0.0.1", portstr, lo0, sizeof(struct sockaddr_storage));
		}
		if (err < 0) {
			printf("Unable to convert loopback to sockaddr: %s\n", strerror(errno));
			goto out;
		}
		errno = 0;
		if (dynamic) {
			err = knet_link_set_config(knet_h, host_id, link_id, transport, lo0, NULL, flags);
		} else {
			err = knet_link_set_config(knet_h, host_id, link_id, transport, lo0, lo1, flags);
		}
		savederrno = errno;
		if ((err < 0) && (savederrno != EADDRINUSE)) {
			if (savederrno == EPROTONOSUPPORT && transport == KNET_TRANSPORT_SCTP) {
				return -2;
			} else {
				printf("Unable to configure link: %s\n", strerror(savederrno));
				goto out;
			}
		}
		if (!err) {
			printf("Using port %u\n", port);
			goto out;
		}
	}

	if (err) {
		printf("No more ports available\n");
	}
out:
	errno = savederrno;
	return err;
}

static void *recv_messages(void *handle)
{
	knet_handle_t knet_h = (knet_handle_t)handle;
	char buf[4096];
	ssize_t len;
	static int err = 0;

	while ( (len = knet_recv(knet_h, buf, sizeof(buf), 0)) ) {
		if (len > 0) {
			printf("recv: (%ld) %s\n", (long)len, buf);
			if (strcmp("QUIT", buf) == 0) {
				break;
			}
			if (buf[0] == '0') { /* We should not have received this! */
				printf(" *** received packet that should have been blocked\n");
				err = 1;
				return &err;
			}
		}
		if (len < 0 && errno != EAGAIN) {
			break;
		} else {
			usleep(1000);
		}
	}
	printf("-- recv thread finished\n");
	return &err;
}

static void notify_fn(void *private_data,
		     int datafd,
		     int8_t channel,
		     uint8_t tx_rx,
		     int error,
		     int errorno)
{
	printf("NOTIFY fn called\n");
}


#define TESTNODES 2
static void test(int transport)
{
	knet_handle_t knet_h[3];
	int logfds[2];
	struct sockaddr_storage lo0, lo1;
	struct sockaddr_storage ss1, ss2;
	int res;
	pthread_t recv_thread;
	int *thread_err;
	int datafd;
	int8_t channel;

	// Initial setup gubbins
	setup_logpipes(logfds);
	start_logthread(logfds[1], stdout);
	knet_handle_start_nodes(knet_h, TESTNODES, logfds, KNET_LOG_DEBUG);
	flush_logs(logfds[0], stdout);

	FAIL_ON_ERR(knet_host_add(knet_h[2], 1));
	flush_logs(logfds[0], stdout);
	FAIL_ON_ERR(knet_host_add(knet_h[1], 2));
	flush_logs(logfds[0], stdout);

	// Create the dynamic (receiving) link
	FAIL_ON_ERR(dyn_knet_link_set_config(knet_h[1], 2, 0, transport, 0, AF_INET, 1, &lo0, NULL));

	// Connect to the dynamic link
	FAIL_ON_ERR(dyn_knet_link_set_config(knet_h[2], 1, 0, transport, 0, AF_INET, 0, &lo1, &lo0));

	// All the rest of the setup gubbins
	FAIL_ON_ERR(knet_handle_enable_sock_notify(knet_h[1], 0, &notify_fn));
	FAIL_ON_ERR(knet_handle_enable_sock_notify(knet_h[2], 0, &notify_fn));

	channel = datafd = 0;
	FAIL_ON_ERR(knet_handle_add_datafd(knet_h[1], &datafd, &channel));
	channel = datafd = 0;
	FAIL_ON_ERR(knet_handle_add_datafd(knet_h[2], &datafd, &channel));

	FAIL_ON_ERR(knet_link_set_enable(knet_h[1], 2, 0, 1));
	FAIL_ON_ERR(knet_link_set_enable(knet_h[2], 1, 0, 1));

	FAIL_ON_ERR(knet_handle_setfwd(knet_h[1], 1));
	FAIL_ON_ERR(knet_handle_setfwd(knet_h[2], 1));

	// Start receive thread
	FAIL_ON_ERR(pthread_create(&recv_thread, NULL, recv_messages, (void *)knet_h[1]));

	// Let everything settle down
	wait_for_nodes_state(knet_h[1], 2, 1, 60, logfds[0], stdout);
	flush_logs(logfds[0], stdout);

	/*
	 * TESTING STARTS HERE
	 * strings starting '1' should reach the receiving thread
	 * strings starting '0' should not
	 */

	// No ACL
	FAIL_ON_ERR(knet_send_str(knet_h[2], "1No ACL - this should get through"));

	// Block traffic from this address.
	memset(&ss1, 0, sizeof(ss1));
	memset(&ss2, 0, sizeof(ss1));
	knet_strtoaddr("127.0.0.1","0", &ss1, sizeof(ss1));
	FAIL_ON_ERR(knet_link_add_acl(knet_h[1], 2, 0, &ss1, NULL, CHECK_TYPE_ADDRESS, CHECK_REJECT));
	// Accept ACL for when we remove them
	FAIL_ON_ERR(knet_link_add_acl(knet_h[1], 2, 0, &ss1, NULL, CHECK_TYPE_ADDRESS, CHECK_ACCEPT));

	// This needs to go after the first ACLs are added
	FAIL_ON_ERR(knet_handle_enable_access_lists(knet_h[1], 1));
	FAIL_ON_ERR(knet_send_str(knet_h[2], "0Address blocked - this should NOT get through"));
	sleep(1); // Wait for receive to get it

	// Unblock and check again
	FAIL_ON_ERR(knet_link_rm_acl(knet_h[1], 2, 0, &ss1, NULL, CHECK_TYPE_ADDRESS, CHECK_REJECT));
	FAIL_ON_ERR(knet_send_str(knet_h[2], "1Address unblocked - this should get through"));

	// Block traffic using a netmask
	knet_strtoaddr("127.0.0.1","0", &ss1, sizeof(ss1));
	knet_strtoaddr("255.0.0.1","0", &ss2, sizeof(ss2));
	FAIL_ON_ERR(knet_link_insert_acl(knet_h[1], 2, 0, 0, &ss1, &ss2, CHECK_TYPE_MASK, CHECK_REJECT));
	FAIL_ON_ERR(knet_send_str(knet_h[2], "0Netmask blocked - this should NOT get through"));
	sleep(1); // Wait for receive to get it

	// Unblock and check again
	FAIL_ON_ERR(knet_link_rm_acl(knet_h[1], 2, 0, &ss1, &ss2, CHECK_TYPE_MASK, CHECK_REJECT));
	FAIL_ON_ERR(knet_send_str(knet_h[2], "1Netmask unblocked - this should get through"));

	// Block traffic from a range
	knet_strtoaddr("127.0.0.0","0", &ss1, sizeof(ss1));
	knet_strtoaddr("127.0.0.9","0", &ss2, sizeof(ss2));
	FAIL_ON_ERR(knet_link_insert_acl(knet_h[1], 2, 0, 0, &ss1, &ss2, CHECK_TYPE_RANGE, CHECK_REJECT));

	FAIL_ON_ERR(knet_send_str(knet_h[2], "0Range blocked - this should NOT get through"));
	sleep(1); // Wait for receive to get it

	// Unblock and check again
	FAIL_ON_ERR(knet_link_rm_acl(knet_h[1], 2, 0, &ss1, &ss2, CHECK_TYPE_RANGE, CHECK_REJECT));

	FAIL_ON_ERR(knet_send_str(knet_h[2], "1Range unblocked - this should get through"));

	// Finish up - disable ACLS to make sure the QUIT message gets through
	FAIL_ON_ERR(knet_handle_enable_access_lists(knet_h[1], 0));
	FAIL_ON_ERR(knet_send_str(knet_h[2], "QUIT"));

	// Check return from the receiving thread
	pthread_join(recv_thread, (void**)&thread_err);
	if (*thread_err) {
		exit(FAIL);
	}

	//  Tidy Up
	knet_link_set_enable(knet_h[1], 2, 0, 0);
	flush_logs(logfds[0], stdout);
	knet_link_set_enable(knet_h[2], 1, 0, 0);
	flush_logs(logfds[0], stdout);
	knet_link_clear_config(knet_h[1], 2, 0);
	flush_logs(logfds[0], stdout);
	knet_link_clear_config(knet_h[2], 1, 0);
	flush_logs(logfds[0], stdout);
	knet_host_remove(knet_h[1], 2);
	FAIL_ON_ERR(knet_handle_free(knet_h[1]));
	knet_host_remove(knet_h[2], 1);
	FAIL_ON_ERR(knet_handle_free(knet_h[2]));

	stop_logthread();
	flush_logs(logfds[0], stdout);
	close_logpipes(logfds);
}

int main(int argc, char *argv[])
{
	printf("Testing with UDP\n");
	test(KNET_TRANSPORT_UDP);

#ifdef HAVE_NETINET_SCTP_H
	printf("Testing with SCTP\n");
	test(KNET_TRANSPORT_SCTP);
#endif

	return PASS;
}
