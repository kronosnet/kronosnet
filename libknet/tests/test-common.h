/*
 * Copyright (C) 2016-2025 Red Hat, Inc.  All rights reserved.
 *
 * Authors: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *
 * This software licensed under GPL-2.0+
 */

#ifndef __KNET_TEST_COMMON_H__
#define __KNET_TEST_COMMON_H__

#include "internals.h"
#include <sched.h>

/*
 * error codes from automake test-driver
 */

#define PASS	0
#define SKIP	77
#define ERROR	99
#define FAIL	-1
/* Extra for us to continue while still using the cleanup code */
#define CONTINUE 101

/* For *BSD compatibility */
#ifndef s6_addr
#define s6_addr  __u6_addr.__u6_addr8
#endif

/*
 * common facilities
 */
#define TESTNODES 1

#define FAIL_ON_ERR(fn)					  \
	printf("FOE: %s\n", #fn);			  \
	if ((res = fn) != 0) {				  \
	  int savederrno = errno;			  \
	  knet_handle_stop_everything(knet_h, TESTNODES); \
	  stop_logthread();				  \
	  flush_logs(logfds[0], stdout);		  \
	  close_logpipes(logfds);			  \
	  if (res == -2) {				  \
		  exit(SKIP);				  \
	  } else {					  \
		  printf("*** FAIL on line %d. %s failed: %s\n", __LINE__ , #fn, strerror(savederrno)); \
		  exit(FAIL);				  \
	  }						  \
	} else {					  \
		flush_logs(logfds[0], stdout);		  \
	}

/* As above but allow a SKIP to continue */
#define FAIL_ON_ERR_ONLY(fn)				  \
	printf("FOEO: %s\n", #fn);			  \
	if ((res = fn) == -1) {				  \
	  int savederrno = errno;			  \
	  knet_handle_stop_everything(knet_h, TESTNODES); \
	  stop_logthread();				  \
	  flush_logs(logfds[0], stdout);		  \
	  close_logpipes(logfds);			  \
	  printf("*** FAIL on line %d. %s failed: %s\n", __LINE__ , #fn, strerror(savederrno)); \
	  exit(FAIL);							\
	} else {					  \
		flush_logs(logfds[0], stdout);		  \
	}

/* Voted "Best macro name of 2022" */
#define FAIL_ON_SUCCESS(fn, errcode)			  \
	printf("FOS: %s\n", #fn);			  \
	if (((res = fn) == 0) ||			  \
	    ((res == -1) && (errno != errcode))) {	  \
	  int savederrno = errno;			  \
	  knet_handle_stop_everything(knet_h, TESTNODES); \
	  stop_logthread();				  \
	  flush_logs(logfds[0], stdout);		  \
	  close_logpipes(logfds);			  \
	  if (res == -2) {				  \
		  exit(SKIP);				  \
	  } else {					  \
		  printf("*** FAIL on line %d. %s did not return correct error: %s\n", __LINE__ , #fn, strerror(savederrno)); \
		  exit(FAIL);				  \
	  }						  \
	} else {					  \
		flush_logs(logfds[0], stdout);		  \
	}

#define CLEAN_EXIT(r)					\
	clean_exit(knet_h, TESTNODES, logfds, r)

void clean_exit(knet_handle_t *knet_h, int testnodes, int *logfds, int exit_status);

int execute_shell(const char *command, char **error_string);

int is_memcheck(void);
int is_helgrind(void);

void set_scheduler(int policy);

knet_handle_t knet_handle_start(int logfds[2], uint8_t log_level, knet_handle_t knet_h_array[]);

/*
 * knet_link_set_config wrapper required to find a free port
 */

int _knet_link_set_config(knet_handle_t knet_h, knet_node_id_t host_id, uint8_t link_id,
			  uint8_t transport, uint64_t flags, int family, int dynamic,
			  struct sockaddr_storage *lo);

/*
 * functional test helpers
 */
void knet_handle_stop_everything(knet_handle_t knet_h[], uint8_t numnodes);
void knet_handle_start_nodes(knet_handle_t knet_h[], uint8_t numnodes, int logfds[2], uint8_t log_level);
void knet_handle_join_nodes(knet_handle_t knet_h[], uint8_t numnodes, uint8_t numlinks, int family, uint8_t transport);

/*
 * high level logging function.
 * automatically setup logpipes and start/stop logging thread.
 *
 * start_logging exit(FAIL) on error or fd to pass to knet_handle_new
 * and it will install an atexit handle to close logging properly
 *
 * WARNING: DO NOT use start_logging for api_ or int_ testing.
 * while start_logging would work just fine, the output
 * of the logs is more complex to read because of the way
 * the thread would interleave the output of printf from api_/int_ testing
 * with knet logs. Functionally speaking you get the exact same logs,
 * but a lot harder to read due to the thread latency in printing logs.
 */
int start_logging(FILE *std);

int setup_logpipes(int *logfds);
void close_logpipes(int *logfds);
void flush_logs(int logfd, FILE *std);
int start_logthread(int logfd, FILE *std);
int stop_logthread(void);
int make_local_sockaddr(struct sockaddr_storage *lo, int offset);
int make_local_sockaddr6(struct sockaddr_storage *lo, int offset);
int wait_for_host(knet_handle_t knet_h, uint16_t host_id, int seconds, int logfd, FILE *std);
int wait_for_packet(knet_handle_t knet_h, int seconds, int datafd, int logfd, FILE *std);
void test_sleep(knet_handle_t knet_h, int seconds);
int wait_for_nodes_state(knet_handle_t knet_h, size_t numnodes,
			 uint8_t state, uint32_t timeout,
			 int logfd, FILE *std);

#endif
