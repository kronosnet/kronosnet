/*
 * Copyright (C) 2016-2017 Red Hat, Inc.  All rights reserved.
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
