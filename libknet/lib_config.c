/*
 * Copyright (C) 2021-2023 Red Hat, Inc.  All rights reserved.
 *
 * Authors: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *
 * This software licensed under LGPL-2.0+
 */

#include "config.h"

#include <pthread.h>
#include <string.h>
#include <errno.h>

#include "internals.h"
#include "logging.h"

pthread_mutex_t handle_config_mutex = PTHREAD_MUTEX_INITIALIZER;

struct handle_tracker handle_list;
uint8_t handle_list_init = 0;

int _is_valid_handle(knet_handle_t knet_h)
{
	int found = 0;
	int savederrno = 0;
	knet_handle_t temp = NULL;

	/*
	 * we are validating the handle, hence we cannot use
	 * the handle for logging purposes
	 */
	savederrno = pthread_mutex_lock(&handle_config_mutex);
	if (savederrno) {
		errno = savederrno;
		return 0;
	}

	errno = EINVAL;
	/*
	 * this is to protect against knet_handle_free being called
	 * before knet_handle_new that initialize the list struct
	 */
	if (handle_list_init) {
		qb_list_for_each_entry(temp, &handle_list.head, list) {
			if (temp == knet_h) {
				found = 1;
				errno = 0;
			}
		}
	}

	pthread_mutex_unlock(&handle_config_mutex);

	return found;
}

pthread_rwlock_t shlib_rwlock;
static uint8_t shlib_wrlock_init = 0;

int _init_shlib_tracker(knet_handle_t knet_h)
{
	int savederrno = 0;

	if (!shlib_wrlock_init) {
		savederrno = pthread_rwlock_init(&shlib_rwlock, NULL);
		if (savederrno) {
			log_err(knet_h, KNET_SUB_HANDLE, "Unable to initialize shared lib rwlock: %s",
				strerror(savederrno));
			errno = savederrno;
			return -1;
		}
		shlib_wrlock_init = 1;
	}

	return 0;
}

void _fini_shlib_tracker(void)
{
	if (qb_list_empty(&handle_list.head)) {
		pthread_rwlock_destroy(&shlib_rwlock);
		shlib_wrlock_init = 0;
	}
	return;
}
