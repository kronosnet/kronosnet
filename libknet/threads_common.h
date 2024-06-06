/*
 * Copyright (C) 2012-2024 Red Hat, Inc.  All rights reserved.
 *
 * Authors: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *          Federico Simoncelli <fsimon@kronosnet.org>
 *
 * This software licensed under LGPL-2.0+
 */

#ifndef __KNET_THREADS_COMMON_H__
#define __KNET_THREADS_COMMON_H__

#include "internals.h"

#define KNET_THREADS_TIMERES 200000

#define KNET_THREAD_UNREGISTERED	0 /* thread does not exist */
#define KNET_THREAD_REGISTERED		1 /* thread has been registered before  pthread_create invocation.
					     make sure threads are registered before calling wait_all_thread_status */
#define KNET_THREAD_STARTED		2 /* thread has reported to be running */
#define KNET_THREAD_STOPPED		3 /* thread has returned */
#define KNET_THREAD_STATUS_MAX	KNET_THREAD_STOPPED + 1

#define KNET_THREAD_TX		0
#define KNET_THREAD_RX		1
#define KNET_THREAD_HB		2
#define KNET_THREAD_PMTUD	3
#define KNET_THREAD_DST_LINK	4
#ifdef HAVE_NETINET_SCTP_H
#define KNET_THREAD_SCTP_LISTEN	5
#define KNET_THREAD_SCTP_CONN	6
#endif
#define KNET_THREAD_MAX		32

#define KNET_THREAD_QUEUE_FLUSHED 0
#define KNET_THREAD_QUEUE_FLUSH   1

#define timespec_diff(start, end, diff) \
do { \
	if (end.tv_sec > start.tv_sec) \
		*(diff) = ((end.tv_sec - start.tv_sec) * 1000000000llu) \
					+ end.tv_nsec - start.tv_nsec; \
	else \
		*(diff) = end.tv_nsec - start.tv_nsec; \
} while (0);

int shutdown_in_progress(knet_handle_t knet_h);
int get_global_wrlock(knet_handle_t knet_h);
int get_thread_flush_queue(knet_handle_t knet_h, uint8_t thread_id);
int set_thread_flush_queue(knet_handle_t knet_h, uint8_t thread_id, uint8_t status);
int wait_all_threads_flush_queue(knet_handle_t knet_h);
int set_thread_status(knet_handle_t knet_h, uint8_t thread_id, uint8_t status);
int wait_all_threads_status(knet_handle_t knet_h, uint8_t status);
void force_pmtud_run(knet_handle_t knet_h, uint8_t subsystem, uint8_t reset_mtu, uint8_t force_restart);

#endif
