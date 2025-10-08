/*
 * Copyright (C) 2016-2025 Red Hat, Inc.  All rights reserved.
 *
 * Authors: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *          Federico Simoncelli <fsimon@kronosnet.org>
 *
 * This software licensed under LGPL-2.0+
 */

#include "config.h"

#include <pthread.h>
#include <errno.h>
#include <string.h>
#include <zlib.h>

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

static int _pmtud_reschedule(knet_handle_t knet_h)
{
	// coverity[MISSING_LOCK:SUPPRESS] - lock is taken before fn call
	if (knet_h->pmtud_running) {
		knet_h->pmtud_abort = 1;

		// coverity[MISSING_LOCK:SUPPRESS] - lock is taken before fn call
		if (knet_h->pmtud_waiting) {
			pthread_cond_signal(&knet_h->pmtud_cond);
		}
	}
	return 0;
}

static int pmtud_reschedule(knet_handle_t knet_h)
{
	int res;

	if (pthread_mutex_lock(&knet_h->pmtud_mutex) != 0) {
		log_debug(knet_h, KNET_SUB_PMTUD, "Unable to get mutex lock");
		return -1;
	}
	res = _pmtud_reschedule(knet_h);
	pthread_mutex_unlock(&knet_h->pmtud_mutex);
	return res;
}

int get_global_wrlock(knet_handle_t knet_h)
{
	if (pmtud_reschedule(knet_h) < 0) {
		log_info(knet_h, KNET_SUB_PMTUD, "Unable to notify PMTUd to reschedule. Expect delays in executing API calls");
	}
	return pthread_rwlock_wrlock(&knet_h->global_rwlock);
}

static struct pretty_names thread_names[KNET_THREAD_MAX] =
{
	{ "TX", KNET_THREAD_TX },
	{ "RX", KNET_THREAD_RX },
	{ "HB", KNET_THREAD_HB },
	{ "PMTUD", KNET_THREAD_PMTUD },
	{ "DST_LINK", KNET_THREAD_DST_LINK }
};

static struct pretty_names thread_status[] =
{
	{ "unregistered", KNET_THREAD_UNREGISTERED },
	{ "registered", KNET_THREAD_REGISTERED },
	{ "started", KNET_THREAD_STARTED },
	{ "stopped", KNET_THREAD_STOPPED }
};

static const char *get_thread_status_name(uint8_t status)
{
	unsigned int i;

	for (i = 0; i < KNET_THREAD_STATUS_MAX; i++) {
		if (thread_status[i].val == status) {
			return thread_status[i].name;
		}
	}
	return "unknown";
}

static const char *get_thread_name(uint8_t thread_id)
{
	unsigned int i;

	for (i = 0; i < KNET_THREAD_MAX; i++) {
		if (thread_names[i].val == thread_id) {
			return thread_names[i].name;
		}
	}
	return "unknown";
}

int get_thread_flush_queue(knet_handle_t knet_h, uint8_t thread_id)
{
	uint8_t flush;

	if (pthread_mutex_lock(&knet_h->threads_status_mutex) != 0) {
		log_debug(knet_h, KNET_SUB_HANDLE, "Unable to get mutex lock");
		return -1;
	}

	flush = knet_h->threads_flush_queue[thread_id];

	pthread_mutex_unlock(&knet_h->threads_status_mutex);
	return flush;
}

int set_thread_flush_queue(knet_handle_t knet_h, uint8_t thread_id, uint8_t status)
{
	if (pthread_mutex_lock(&knet_h->threads_status_mutex) != 0) {
		log_debug(knet_h, KNET_SUB_HANDLE, "Unable to get mutex lock");
		return -1;
	}

	knet_h->threads_flush_queue[thread_id] = status;

	log_debug(knet_h, KNET_SUB_HANDLE, "Updated flush queue request for thread %s to %u",
		  get_thread_name(thread_id), status);

	pthread_mutex_unlock(&knet_h->threads_status_mutex);
	return 0;
}

int wait_all_threads_flush_queue(knet_handle_t knet_h)
{
	uint8_t i = 0, found = 0;

	while (!found) {
		usleep(knet_h->threads_timer_res);

		if (pthread_mutex_lock(&knet_h->threads_status_mutex) != 0) {
			continue;
		}

		found = 1;

		for (i = 0; i < KNET_THREAD_MAX; i++) {
			if (knet_h->threads_flush_queue[i] == KNET_THREAD_QUEUE_FLUSHED) {
				continue;
			}
			log_debug(knet_h, KNET_SUB_HANDLE, "Checking thread: %s queue: %u",
					get_thread_name(i),
					knet_h->threads_flush_queue[i]);
			if (knet_h->threads_flush_queue[i] != KNET_THREAD_QUEUE_FLUSHED) {
				found = 0;
			}
		}

		pthread_mutex_unlock(&knet_h->threads_status_mutex);
	}

	return 0;
}

int set_thread_status(knet_handle_t knet_h, uint8_t thread_id, uint8_t status)
{
	if (pthread_mutex_lock(&knet_h->threads_status_mutex) != 0) {
		log_debug(knet_h, KNET_SUB_HANDLE, "Unable to get mutex lock");
		return -1;
	}

	knet_h->threads_status[thread_id] = status;

	log_debug(knet_h, KNET_SUB_HANDLE, "Updated status for thread %s to %s",
		  get_thread_name(thread_id), get_thread_status_name(status));

	pthread_mutex_unlock(&knet_h->threads_status_mutex);
	return 0;
}

int wait_all_threads_status(knet_handle_t knet_h, uint8_t status)
{
	uint8_t i = 0, found = 0;

	while (!found) {
		usleep(knet_h->threads_timer_res);

		if (pthread_mutex_lock(&knet_h->threads_status_mutex) != 0) {
			continue;
		}

		found = 1;

		for (i = 0; i < KNET_THREAD_MAX; i++) {
			if (knet_h->threads_status[i] == KNET_THREAD_UNREGISTERED) {
				continue;
			}
			log_debug(knet_h, KNET_SUB_HANDLE, "Checking thread: %s status: %s req: %s",
					get_thread_name(i),
					get_thread_status_name(knet_h->threads_status[i]),
					get_thread_status_name(status));
			if (knet_h->threads_status[i] != status) {
				found = 0;
			}
		}

		pthread_mutex_unlock(&knet_h->threads_status_mutex);
	}

	return 0;
}

void force_pmtud_run(knet_handle_t knet_h, uint8_t subsystem, uint8_t reset_mtu, uint8_t force_restart)
{
	if (reset_mtu) {
		log_debug(knet_h, subsystem, "PMTUd has been reset to default");
		knet_h->data_mtu = calc_min_mtu(knet_h);
		if (knet_h->pmtud_notify_fn) {
			knet_h->pmtud_notify_fn(knet_h->pmtud_notify_fn_private_data,
						knet_h->data_mtu);
		}
	}

	/*
	 * we can only try to take a lock here. This part of the code
	 * can be invoked by any thread, including PMTUd that is already
	 * holding a lock at that stage.
	 * If PMTUd is holding the lock, most likely it is already running
	 * and we don't need to notify it back.
	 */
	if (!pthread_mutex_trylock(&knet_h->pmtud_mutex)) {
		if (!knet_h->pmtud_running) {
			if (!knet_h->pmtud_forcerun) {
				log_debug(knet_h, subsystem, "Notifying PMTUd to rerun");
				knet_h->pmtud_forcerun = 1;
			}
		} else {
			if (force_restart) {
				if (_pmtud_reschedule(knet_h) < 0) {
					log_info(knet_h, KNET_SUB_PMTUD, "Unable to notify PMTUd to reschedule. A joining node may struggle to connect properly");
				}
			}
		}
		pthread_mutex_unlock(&knet_h->pmtud_mutex);
	}
}

int knet_handle_set_threads_timer_res(knet_handle_t knet_h,
				      useconds_t timeres)
{
	int savederrno = 0, err = 0;
	struct knet_host *host;
	int link_idx;
	int found = 0;

	if (!_is_valid_handle(knet_h)) {
		return -1;
	}

	/*
	 * most threads use timeres / 1000 as timeout on epoll.
	 * anything below 1000 would generate a result of 0, making
	 * the threads spin at 100% cpu
	 */
	if ((timeres > 0) && (timeres < 1000)) {
		errno = EINVAL;
		return -1;
	}

	savederrno = get_global_wrlock(knet_h);
	if (savederrno) {
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to get write lock: %s",
			strerror(savederrno));
		errno = savederrno;
		return -1;
	}

	if (timeres) {
		if (timeres > knet_h->threads_timer_res) {
			for (host = knet_h->host_head; host != NULL; host = host->next) {
				for (link_idx = 0; link_idx < KNET_MAX_LINK; link_idx++) {
					if (!host->link[link_idx].configured) {
						continue;
					}
					if (host->link[link_idx].ping_interval < timeres) {
						log_warn(knet_h, KNET_SUB_HANDLE,
							 "Requested new threads timer resolution %u is higher than detected link ping interval on host: %u link: %u interval: %llu (ns).",
							 timeres, host->host_id, link_idx, host->link[link_idx].ping_interval);
					}
					if (host->link[link_idx].pong_timeout < timeres) {
						log_err(knet_h, KNET_SUB_HANDLE,
							"Requested new threads timer resolution %u is higher than detected link pong time on host: %u link: %u timeout: %llu (ns) and will cause network instability",
							timeres, host->host_id, link_idx, host->link[link_idx].pong_timeout);
						found = 1;
					}
				}
			}
			if (found) {
				err = -1;
				savederrno = EINVAL;
				goto exit_unlock;
			}
		}
		knet_h->threads_timer_res = timeres;
		log_debug(knet_h, KNET_SUB_HANDLE, "Setting new threads timer resolution to %u usecs", knet_h->threads_timer_res);
	} else {
		knet_h->threads_timer_res = KNET_THREADS_TIMER_RES;
		log_debug(knet_h, KNET_SUB_HANDLE, "Setting new threads timer resolution to default %u usecs", knet_h->threads_timer_res);
	}

exit_unlock:
	pthread_rwlock_unlock(&knet_h->global_rwlock);
	errno = err ? savederrno : 0;
	return err;
}

int knet_handle_get_threads_timer_res(knet_handle_t knet_h,
				      useconds_t *timeres)
{
	int savederrno = 0;

	if (!_is_valid_handle(knet_h)) {
		return -1;
	}

	if (!timeres) {
		errno = EINVAL;
		return -1;
	}

	savederrno = pthread_rwlock_rdlock(&knet_h->global_rwlock);
	if (savederrno) {
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to get read lock: %s",
			strerror(savederrno));
		errno = savederrno;
		return -1;
	}

	*timeres = knet_h->threads_timer_res;

	pthread_rwlock_unlock(&knet_h->global_rwlock);
	return 0;
}

uint32_t compute_chksum(const unsigned char *data, uint32_t data_len)
{
	uLong crc;

	crc = crc32(0, NULL, 0);
	crc = crc32(crc, (Bytef*)data, data_len);

	return crc;
}

uint32_t compute_chksumv(const struct iovec *iov_in, int iovcnt_in)
{
	uLong crc;
	int i;

	crc = crc32(0, NULL, 0);

	for (i = 0; i < iovcnt_in; i++) {
		crc = crc32(crc, (Bytef*)iov_in[i].iov_base, iov_in[i].iov_len);
	}

	return crc;
}
