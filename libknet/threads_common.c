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
