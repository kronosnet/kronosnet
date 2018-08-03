/*
 * Copyright (C) 2016-2018 Red Hat, Inc.  All rights reserved.
 *
 * Authors: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *          Federico Simoncelli <fsimon@kronosnet.org>
 *
 * This software licensed under GPL-2.0+, LGPL-2.0+
 */

#include "config.h"

#include <pthread.h>
#include <errno.h>
#include <string.h>

#include "internals.h"
#include "logging.h"
#include "threads_common.h"

int shutdown_in_progress(knet_handle_t knet_h)
{
	int savederrno = 0;
	int ret;

	savederrno = pthread_rwlock_rdlock(&knet_h->global_rwlock);
	if (savederrno) {
		log_err(knet_h, KNET_SUB_COMMON, "Unable to get read lock: %s",
			strerror(savederrno));
		errno = savederrno;
		return -1;
	}

	ret = knet_h->fini_in_progress;

	pthread_rwlock_unlock(&knet_h->global_rwlock);

	return ret;
}

static int pmtud_reschedule(knet_handle_t knet_h)
{
	if (pthread_mutex_lock(&knet_h->pmtud_mutex) != 0) {
		log_debug(knet_h, KNET_SUB_PMTUD, "Unable to get mutex lock");
		return -1;
	}

	if (knet_h->pmtud_running) {
		knet_h->pmtud_abort = 1;

		if (knet_h->pmtud_waiting) {
			pthread_cond_signal(&knet_h->pmtud_cond);
		}
	}

	pthread_mutex_unlock(&knet_h->pmtud_mutex);
	return 0;
}

int get_global_wrlock(knet_handle_t knet_h)
{
	if (pmtud_reschedule(knet_h) < 0) {
		log_info(knet_h, KNET_SUB_PMTUD, "Unable to notify PMTUd to reschedule. Expect delays in executing API calls");
	}
	return pthread_rwlock_wrlock(&knet_h->global_rwlock);
}

int set_thread_status(knet_handle_t knet_h, uint8_t thread_id, uint8_t status)
{
	if (pthread_mutex_lock(&knet_h->threads_status_mutex) != 0) {
		log_debug(knet_h, KNET_SUB_HANDLE, "Unable to get mutex lock");
		return -1;
	}

	knet_h->threads_status[thread_id] = status;

	log_debug(knet_h, KNET_SUB_HANDLE, "Updated status for thread %u to %u",
		  thread_id, status);

	pthread_mutex_unlock(&knet_h->threads_status_mutex);
	return 0;
}

int wait_all_threads_status(knet_handle_t knet_h, uint8_t status)
{
	uint8_t i = 0, found = 0;

	while (!found) {
		usleep(KNET_THREADS_TIMERES);

		if (pthread_mutex_lock(&knet_h->threads_status_mutex) != 0) {
			continue;
		}

		found = 1;

		for (i = 0; i < KNET_THREAD_MAX; i++) {
			log_debug(knet_h, KNET_SUB_HANDLE, "Checking thread: %u status: %u req: %u",
					i, knet_h->threads_status[i], status);
			if (knet_h->threads_status[i] != status) {
				found = 0;
			}
		}

		pthread_mutex_unlock(&knet_h->threads_status_mutex);
	}

	return 0;
}
