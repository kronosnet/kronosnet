/*
 * Copyright (C) 2021-2025 Red Hat, Inc.  All rights reserved.
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
#include <pthread.h>
#include <poll.h>

#include "libknet.h"

#include "internals.h"
#include "netutils.h"
#include "test-common.h"


/*
 * Keep track of how many messages got through:
 * clean + 3xACLs + QUIT
 */
#define CORRECT_NUM_MSGS 5
static int msgs_recvd = 0;

#undef TESTNODES
#define TESTNODES 2

static pthread_mutex_t recv_mutex = PTHREAD_MUTEX_INITIALIZER;
static int quit_recv_thread = 0;

static int reply_pipe[2];

/* Our local version of FOE that also tidies up the threads */
#define FAIL_ON_ERR_THR(fn) \
	printf("FOE: %s\n", #fn);			  \
	if ((res = fn) != 0) {				  \
	  int savederrno = errno;			  \
	  pthread_mutex_lock(&recv_mutex);		  \
	  quit_recv_thread = 1;				  \
	  pthread_mutex_unlock(&recv_mutex);		  \
	  if (recv_thread) {				  \
		  pthread_join(recv_thread, (void**)&thread_err);	\
	  }						  \
	  knet_handle_stop_everything(knet_h, TESTNODES); \
	  stop_logthread();				  \
	  flush_logs(logfds[0], stdout);		  \
	  close_logpipes(logfds);			  \
	  close(reply_pipe[0]);				  \
	  close(reply_pipe[1]);				  \
	  if (res == -2) {				  \
		  exit(SKIP);				  \
	  } else {					  \
		  printf("*** FAIL on line %d %s failed: %s\n", __LINE__ , #fn, strerror(savederrno)); \
		  exit(FAIL);				  \
	  }						  \
	}


static int knet_send_str(knet_handle_t knet_h, char *str)
{
	// coverity[LOCK:SUPPRESS] - it's a test, get over it
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
			printf("Unable to configure link: %s\n", strerror(savederrno));
			goto out;
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
	int savederrno = 0, quit = 0;

	while ((len = knet_recv(knet_h, buf, sizeof(buf), 0)) && (!quit)) {
		savederrno = errno;
		pthread_mutex_lock(&recv_mutex);
		quit = quit_recv_thread;
		pthread_mutex_unlock(&recv_mutex);
		if (quit) {
			printf(" *** recv thread was requested to exit via FOE\n");
			err = 1;
			return &err;
		}
		if (len > 0) {
			int res;

			printf("recv: (%ld) %s\n", (long)len, buf);
			msgs_recvd++;
			if (strcmp("QUIT", buf) == 0) {
				break;
			}
			if (buf[0] == '0') { /* We should not have received this! */
				printf(" *** FAIL received packet that should have been blocked\n");
				err = 1;
				return &err;
			}
			/* Tell the main thread we have received something */
			res = write(reply_pipe[1], ".", 1);
			if (res != 1) {
				printf(" *** FAIL to send response back to main thread\n");
				err = 1;
				return &err;
			}
		}
		usleep(1000);
		if (len < 0 && savederrno != EAGAIN) {
			break;
		}
	}
	printf("-- recv thread finished: %zd %d %s\n", len, errno, strerror(savederrno));
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

/* A VERY basic filter because all data traffic is going to one place */
static int dhost_filter(void *pvt_data,
			const unsigned char *outdata,
			ssize_t outdata_len,
			uint8_t tx_rx,
			knet_node_id_t this_host_id,
			knet_node_id_t src_host_id,
			int8_t *dst_channel,
			knet_node_id_t *dst_host_ids,
			size_t *dst_host_ids_entries)
{
	dst_host_ids[0] = 1;
	*dst_host_ids_entries = 1;
	return 0;
}

/* This used to be a pthread condition variable, but
   there was a race where it could be triggered before
   the main thread was waiting for it.
   Go old-fashioned.
*/
static int wait_for_reply(int seconds)
{
	int res;
	struct pollfd pfds;
	char tmpbuf[32];

	pfds.fd = reply_pipe[0];
	pfds.events = POLLIN | POLLERR | POLLHUP;
	pfds.revents = 0;

	res = poll(&pfds, 1, seconds*1000);
	if (res == 1) {
		if (pfds.revents & POLLIN) {
			res = read(reply_pipe[0], tmpbuf, sizeof(tmpbuf));
			if (res > 0) {
				return 0;
			}
		} else {
			printf("Error on pipe poll revent = 0x%x\n", pfds.revents);
			errno = EIO;
		}
	}
	if (res == 0) {
		errno = ETIMEDOUT;
		return -1;
	}

	return -1;
}

static void test(int transport)
{
	knet_handle_t knet_h[TESTNODES+1];
	int logfds[2];
	struct sockaddr_storage lo0, lo1;
	struct sockaddr_storage ss1, ss2;
	int res;
	pthread_t recv_thread = 0;
	int *thread_err;
	int datafd;
	int8_t channel;
	int seconds = 90; // dynamic tests take longer than normal tests

	if (is_memcheck() || is_helgrind()) {
		printf("Test suite is running under valgrind, adjusting wait_for_host timeout\n");
		seconds = seconds * 16;
	}

	memset(knet_h, 0, sizeof(knet_h));
	memset(reply_pipe, 0, sizeof(reply_pipe));
	memset(logfds, 0, sizeof(logfds));

	FAIL_ON_ERR_THR(pipe(reply_pipe));

	// Initial setup gubbins
	msgs_recvd = 0;
	setup_logpipes(logfds);
	start_logthread(logfds[1], stdout);
	knet_handle_start_nodes(knet_h, TESTNODES, logfds, KNET_LOG_DEBUG);

	FAIL_ON_ERR_THR(knet_host_add(knet_h[2], 1));
	FAIL_ON_ERR_THR(knet_host_add(knet_h[1], 2));

	FAIL_ON_ERR_THR(knet_handle_enable_filter(knet_h[2], NULL, dhost_filter));

	// Create the dynamic (receiving) link
	FAIL_ON_ERR_THR(dyn_knet_link_set_config(knet_h[1], 2, 0, transport, 0, AF_INET, 1, &lo0, NULL));

	// Connect to the dynamic link
	FAIL_ON_ERR_THR(dyn_knet_link_set_config(knet_h[2], 1, 0, transport, 0, AF_INET, 0, &lo1, &lo0));

	// All the rest of the setup gubbins
	FAIL_ON_ERR_THR(knet_handle_enable_sock_notify(knet_h[1], 0, &notify_fn));
	FAIL_ON_ERR_THR(knet_handle_enable_sock_notify(knet_h[2], 0, &notify_fn));

	channel = datafd = 0;
	FAIL_ON_ERR_THR(knet_handle_add_datafd(knet_h[1], &datafd, &channel, 0));
	channel = datafd = 0;
	FAIL_ON_ERR_THR(knet_handle_add_datafd(knet_h[2], &datafd, &channel, 0));

	FAIL_ON_ERR_THR(knet_link_set_enable(knet_h[1], 2, 0, 1));
	FAIL_ON_ERR_THR(knet_link_set_enable(knet_h[2], 1, 0, 1));

	FAIL_ON_ERR_THR(knet_handle_setfwd(knet_h[1], 1));
	FAIL_ON_ERR_THR(knet_handle_setfwd(knet_h[2], 1));

	// Start receive thread
	FAIL_ON_ERR_THR(pthread_create(&recv_thread, NULL, recv_messages, (void *)knet_h[1]));

	// Let everything settle down
	FAIL_ON_ERR_THR(wait_for_nodes_state(knet_h[1], TESTNODES, 1, seconds, logfds[0], stdout));
	FAIL_ON_ERR_THR(wait_for_nodes_state(knet_h[2], TESTNODES, 1, seconds, logfds[0], stdout));

	/*
	 * TESTING STARTS HERE
	 * strings starting '1' should reach the receiving thread
	 * strings starting '0' should not
	 */

	// No ACL
	printf("Testing No ACL - this should get through\n");
	FAIL_ON_ERR_THR(knet_send_str(knet_h[2], "1No ACL - this should get through"));
	FAIL_ON_ERR_THR(wait_for_reply(seconds))

	// Block traffic from this address.
	memset(&ss1, 0, sizeof(ss1));
	memset(&ss2, 0, sizeof(ss1));
	knet_strtoaddr("127.0.0.1","0", &ss1, sizeof(ss1));
	FAIL_ON_ERR_THR(knet_link_add_acl(knet_h[1], 2, 0, &ss1, NULL, CHECK_TYPE_ADDRESS, CHECK_REJECT));
	// Accept ACL for when we remove them
	FAIL_ON_ERR_THR(knet_link_add_acl(knet_h[1], 2, 0, &ss1, NULL, CHECK_TYPE_ADDRESS, CHECK_ACCEPT));

	// This needs to go after the first ACLs are added
	FAIL_ON_ERR_THR(knet_handle_enable_access_lists(knet_h[1], 1));

	printf("Testing Address blocked - this should NOT get through\n");
	FAIL_ON_ERR_THR(knet_send_str(knet_h[2], "0Address blocked - this should NOT get through"));

	// Unblock and check again
	FAIL_ON_ERR_THR(wait_for_nodes_state(knet_h[1], TESTNODES, 0, seconds, logfds[0], stdout));
	FAIL_ON_ERR_THR(wait_for_nodes_state(knet_h[2], TESTNODES, 0, seconds, logfds[0], stdout));
	FAIL_ON_ERR_THR(knet_link_rm_acl(knet_h[1], 2, 0, &ss1, NULL, CHECK_TYPE_ADDRESS, CHECK_REJECT));
	FAIL_ON_ERR_THR(wait_for_nodes_state(knet_h[1], TESTNODES, 1, seconds, logfds[0], stdout));
	FAIL_ON_ERR_THR(wait_for_nodes_state(knet_h[2], TESTNODES, 1, seconds, logfds[0], stdout));

	printf("Testing Address unblocked - this should get through\n");
	FAIL_ON_ERR_THR(knet_send_str(knet_h[2], "1Address unblocked - this should get through"));
	FAIL_ON_ERR_THR(wait_for_reply(seconds));

	// Block traffic using a netmask
	knet_strtoaddr("127.0.0.1","0", &ss1, sizeof(ss1));
	knet_strtoaddr("255.0.0.1","0", &ss2, sizeof(ss2));
	FAIL_ON_ERR_THR(knet_link_insert_acl(knet_h[1], 2, 0, 0, &ss1, &ss2, CHECK_TYPE_MASK, CHECK_REJECT));

	printf("Testing Netmask blocked - this should NOT get through\n");
	FAIL_ON_ERR_THR(knet_send_str(knet_h[2], "0Netmask blocked - this should NOT get through"));

	// Unblock and check again
	FAIL_ON_ERR_THR(wait_for_nodes_state(knet_h[1], TESTNODES, 0, seconds, logfds[0], stdout));
	FAIL_ON_ERR_THR(wait_for_nodes_state(knet_h[2], TESTNODES, 0, seconds, logfds[0], stdout));
	FAIL_ON_ERR_THR(knet_link_rm_acl(knet_h[1], 2, 0, &ss1, &ss2, CHECK_TYPE_MASK, CHECK_REJECT));
	FAIL_ON_ERR_THR(wait_for_nodes_state(knet_h[1], TESTNODES, 1, seconds, logfds[0], stdout));
	FAIL_ON_ERR_THR(wait_for_nodes_state(knet_h[2], TESTNODES, 1, seconds, logfds[0], stdout));

	printf("Testing Netmask unblocked - this should get through\n");
	FAIL_ON_ERR_THR(knet_send_str(knet_h[2], "1Netmask unblocked - this should get through"));
	FAIL_ON_ERR_THR(wait_for_reply(seconds));

	// Block traffic from a range
	knet_strtoaddr("127.0.0.0", "0", &ss1, sizeof(ss1));
	knet_strtoaddr("127.0.0.9", "0", &ss2, sizeof(ss2));
	FAIL_ON_ERR_THR(knet_link_insert_acl(knet_h[1], 2, 0, 0, &ss1, &ss2, CHECK_TYPE_RANGE, CHECK_REJECT));

	printf("Testing Range blocked - this should NOT get through\n");
	FAIL_ON_ERR_THR(knet_send_str(knet_h[2], "0Range blocked - this should NOT get through"));

	// Unblock and check again
	FAIL_ON_ERR_THR(wait_for_nodes_state(knet_h[1], TESTNODES, 0, seconds, logfds[0], stdout));
	FAIL_ON_ERR_THR(wait_for_nodes_state(knet_h[2], TESTNODES, 0, seconds, logfds[0], stdout));
	FAIL_ON_ERR_THR(knet_link_rm_acl(knet_h[1], 2, 0, &ss1, &ss2, CHECK_TYPE_RANGE, CHECK_REJECT));
	FAIL_ON_ERR_THR(wait_for_nodes_state(knet_h[1], TESTNODES, 1, seconds, logfds[0], stdout));
	FAIL_ON_ERR_THR(wait_for_nodes_state(knet_h[2], TESTNODES, 1, seconds, logfds[0], stdout));

	printf("Testing Range unblocked - this should get through\n");
	FAIL_ON_ERR_THR(knet_send_str(knet_h[2], "1Range unblocked - this should get through"));
	FAIL_ON_ERR_THR(wait_for_reply(seconds));

	// Finish up - disable ACLS to make sure the QUIT message gets through
	FAIL_ON_ERR_THR(knet_handle_enable_access_lists(knet_h[1], 0));
	FAIL_ON_ERR_THR(wait_for_nodes_state(knet_h[1], TESTNODES, 1, seconds, logfds[0], stdout));
	FAIL_ON_ERR_THR(wait_for_nodes_state(knet_h[2], TESTNODES, 1, seconds, logfds[0], stdout));

	FAIL_ON_ERR_THR(knet_send_str(knet_h[2], "QUIT"));

	// Check return from the receiving thread
	pthread_join(recv_thread, (void**)&thread_err);
	if (*thread_err) {
		printf("Thread returned %d\n", *thread_err);
		clean_exit(knet_h, TESTNODES, logfds, FAIL);
	}

	if (msgs_recvd != CORRECT_NUM_MSGS) {
		printf("*** FAIL Recv thread got %d messages, expected %d\n", msgs_recvd, CORRECT_NUM_MSGS);
		clean_exit(knet_h, TESTNODES, logfds, FAIL);
	}
	clean_exit(knet_h, TESTNODES, logfds, PASS);
}

int main(int argc, char *argv[])
{
	printf("Testing with UDP\n");
	test(KNET_TRANSPORT_UDP);

	return PASS;
}
