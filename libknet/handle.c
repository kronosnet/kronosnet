/*
 * Copyright (C) 2010-2012 Red Hat, Inc.  All rights reserved.
 *
 * Authors: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *          Federico Simoncelli <fsimon@kronosnet.org>
 *
 * This software licensed under GPL-2.0+, LGPL-2.0+
 */

#include "config.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/epoll.h>

#include "internals.h"
#include "crypto.h"
#include "common.h"
#include "threads.h"
#include "logging.h"
#include "onwire.h"

static pthread_mutex_t handle_config_mutex = PTHREAD_MUTEX_INITIALIZER;

static int _init_locks(knet_handle_t knet_h)
{
	int savederrno = 0;

	savederrno = pthread_rwlock_init(&knet_h->list_rwlock, NULL);
	if (savederrno) {
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to initialize list rwlock: %s",
			strerror(savederrno));
		goto exit_fail;
	}

	knet_h->lock_init_done = 1;

	savederrno = pthread_rwlock_init(&knet_h->listener_rwlock, NULL);
	if (savederrno) {
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to initialize listener rwlock: %s",
			strerror(savederrno));
		goto exit_fail;
	}

	savederrno = pthread_rwlock_init(&knet_h->host_rwlock, NULL);
	if (savederrno) {
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to initialize host rwlock: %s",
			strerror(savederrno));
		goto exit_fail;
	}

	savederrno = pthread_mutex_init(&knet_h->host_mutex, NULL);
	if (savederrno) {
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to initialize host mutex: %s",
			strerror(savederrno));
		goto exit_fail;
	}

	savederrno = pthread_cond_init(&knet_h->host_cond, NULL);
	if (savederrno) {
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to initialize host conditional mutex: %s",
			strerror(savederrno));
		goto exit_fail;
	}

	savederrno = pthread_mutex_init(&knet_h->pmtud_mutex, NULL);
	if (savederrno) {
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to initialize pmtud mutex: %s",
			strerror(savederrno));
		goto exit_fail;
	}

	savederrno = pthread_cond_init(&knet_h->pmtud_cond, NULL);
	if (savederrno) {
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to initialize pmtud conditional mutex: %s",
			strerror(savederrno));
		goto exit_fail;
	}

	savederrno = pthread_mutex_init(&knet_h->pmtud_timer_mutex, NULL);
	if (savederrno) {
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to initialize pmtud timer mutex: %s",
			strerror(savederrno));
		goto exit_fail;
	}

	savederrno = pthread_cond_init(&knet_h->pmtud_timer_cond, NULL);
	if (savederrno) {
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to initialize pmtud timer conditional mutex: %s",
			strerror(savederrno));
		goto exit_fail;
	}

	return 0;

exit_fail:
	errno = savederrno;
	return -1;
}

static void _destroy_locks(knet_handle_t knet_h)
{
	knet_h->lock_init_done = 0;
	pthread_rwlock_destroy(&knet_h->list_rwlock);
	pthread_rwlock_destroy(&knet_h->listener_rwlock);
	pthread_rwlock_destroy(&knet_h->host_rwlock);
	pthread_mutex_destroy(&knet_h->host_mutex);
	pthread_cond_destroy(&knet_h->host_cond);
	pthread_mutex_destroy(&knet_h->pmtud_mutex);
	pthread_cond_destroy(&knet_h->pmtud_cond);
	pthread_mutex_destroy(&knet_h->pmtud_timer_mutex);
	pthread_cond_destroy(&knet_h->pmtud_timer_cond);
}

static int _init_pipes(knet_handle_t knet_h)
{
	int savederrno = 0;

	if (pipe(knet_h->dstpipefd)) {
		savederrno = errno;
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to initialize dstpipefd: %s",
			strerror(savederrno));
		goto exit_fail;
	}

	if (pipe(knet_h->hostpipefd)) {
		savederrno = errno;
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to initialize hostpipefd: %s",
			strerror(savederrno));
		goto exit_fail;
	}

	if (_fdset_cloexec(knet_h->dstpipefd[0])) {
		savederrno = errno;
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to set CLOEXEC on dstpipefd[0]: %s",
			strerror(savederrno));
		goto exit_fail;
	}

	if (_fdset_nonblock(knet_h->dstpipefd[0])) {
		savederrno = errno;
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to set NONBLOCK on dstpipefd[0]: %s", 
			strerror(savederrno));
		goto exit_fail;
	}

	if (_fdset_cloexec(knet_h->dstpipefd[1])) {
		savederrno = errno;
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to set CLOEXEC on dstpipefd[1]: %s",
			strerror(savederrno));
		goto exit_fail;
	}

	if (_fdset_nonblock(knet_h->dstpipefd[1])) {
		savederrno = errno;
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to set NONBLOCK on dstpipefd[1]: %s", 
			strerror(savederrno));
		goto exit_fail;
	}

	if (_fdset_cloexec(knet_h->hostpipefd[0])) {
		savederrno = errno;
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to set CLOEXEC on hostpipefd[0]: %s",
			strerror(savederrno));
		goto exit_fail;
	}

	if (_fdset_nonblock(knet_h->hostpipefd[0])) {
		savederrno = errno;
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to set NONBLOCK on hostpipefd[0]: %s", 
			strerror(savederrno));
		goto exit_fail;
	}

	if (_fdset_cloexec(knet_h->hostpipefd[1])) {
		savederrno = errno;
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to set CLOEXEC on hostpipefd[1]: %s",
			strerror(savederrno));
		goto exit_fail;
	}

	if (_fdset_nonblock(knet_h->hostpipefd[1])) {
		savederrno = errno;
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to set NONBLOCK on hostpipefd[1]: %s", 
			strerror(savederrno));
		goto exit_fail;
	}

	return 0;

exit_fail:
	errno = savederrno;
	return -1;
}

static void _close_pipes(knet_handle_t knet_h)
{
	close(knet_h->dstpipefd[0]);
	close(knet_h->dstpipefd[1]);
	close(knet_h->hostpipefd[0]);
	close(knet_h->hostpipefd[1]);
}

static int _init_buffers(knet_handle_t knet_h)
{
	int savederrno = 0;

	knet_h->tap_to_links_buf = malloc(KNET_DATABUFSIZE);
	if (!knet_h->tap_to_links_buf) {
		savederrno = errno;
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to allocate memory net_fd to link buffer: %s",
			strerror(savederrno));
		goto exit_fail;
	}
	memset(knet_h->tap_to_links_buf, 0, KNET_DATABUFSIZE);

	knet_h->recv_from_links_buf = malloc(KNET_DATABUFSIZE);
	if (!knet_h->recv_from_links_buf) {
		savederrno = errno;
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to allocate memory for link to net_fd buffer: %s",
			strerror(savederrno));
		goto exit_fail;
	}
	memset(knet_h->recv_from_links_buf, 0, KNET_DATABUFSIZE);

	knet_h->pingbuf = malloc(KNET_PING_SIZE);
	if (!knet_h->pingbuf) {
		savederrno = errno;
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to allocate memory for hearbeat buffer: %s",
			strerror(savederrno));
		goto exit_fail;
	}
	memset(knet_h->pingbuf, 0, KNET_PING_SIZE);

	knet_h->pmtudbuf = malloc(KNET_PMTUD_SIZE_V6);
	if (!knet_h->pmtudbuf) {
		savederrno = errno;
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to allocate memory for pmtud buffer: %s",
			strerror(savederrno));
		goto exit_fail;
	}
	memset(knet_h->pmtudbuf, 0, KNET_PMTUD_SIZE_V6);

	knet_h->tap_to_links_buf_crypt = malloc(KNET_DATABUFSIZE_CRYPT);
	if (!knet_h->tap_to_links_buf_crypt) {
		savederrno = errno;
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to allocate memory for crypto net_fd to link buffer: %s",
			strerror(savederrno));
		goto exit_fail;
	}
	memset(knet_h->tap_to_links_buf_crypt, 0, KNET_DATABUFSIZE_CRYPT);

	knet_h->recv_from_links_buf_crypt = malloc(KNET_DATABUFSIZE_CRYPT);
	if (!knet_h->recv_from_links_buf_crypt) {
		savederrno = errno;
		log_err(knet_h, KNET_SUB_CRYPTO, "Unable to allocate memory for crypto link to net_fd buffer: %s",
			strerror(savederrno));
		goto exit_fail;
	}
	memset(knet_h->recv_from_links_buf_crypt, 0, KNET_DATABUFSIZE_CRYPT);

	knet_h->pingbuf_crypt = malloc(KNET_DATABUFSIZE_CRYPT);
	if (!knet_h->pingbuf_crypt) {
		savederrno = errno; 
		log_err(knet_h, KNET_SUB_CRYPTO, "Unable to allocate memory for crypto hearbeat buffer: %s",
			strerror(savederrno));
		goto exit_fail;
	}
	memset(knet_h->pingbuf_crypt, 0, KNET_DATABUFSIZE_CRYPT);

	knet_h->pmtudbuf_crypt = malloc(KNET_DATABUFSIZE_CRYPT);
	if (!knet_h->pmtudbuf_crypt) {
		savederrno = errno;
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to allocate memory for crypto pmtud buffer: %s",
			strerror(savederrno));
		goto exit_fail;
	}
	memset(knet_h->pmtudbuf_crypt, 0, KNET_DATABUFSIZE_CRYPT);

	return 0;

exit_fail:
	errno = savederrno;
	return -1;
}

static void _destroy_buffers(knet_handle_t knet_h)
{
	free(knet_h->tap_to_links_buf);
	free(knet_h->tap_to_links_buf_crypt);
	free(knet_h->recv_from_links_buf);
	free(knet_h->recv_from_links_buf_crypt);
	free(knet_h->pingbuf);
	free(knet_h->pingbuf_crypt);
	free(knet_h->pmtudbuf);
	free(knet_h->pmtudbuf_crypt);
}

static int _init_epolls(knet_handle_t knet_h)
{
	struct epoll_event ev;
	int savederrno = 0;

	knet_h->tap_to_links_epollfd = epoll_create(KNET_EPOLL_MAX_EVENTS);
	if (knet_h->tap_to_links_epollfd < 0) {
		savederrno = errno;
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to create epoll net_fd to link fd: %s",
			strerror(savederrno));
		goto exit_fail;
	}

	knet_h->recv_from_links_epollfd = epoll_create(KNET_EPOLL_MAX_EVENTS);
	if (knet_h->recv_from_links_epollfd < 0) {
		savederrno = errno;
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to create epoll link to net_fd fd: %s",
			strerror(savederrno));
		goto exit_fail;
	}

	knet_h->dst_link_handler_epollfd = epoll_create(KNET_EPOLL_MAX_EVENTS);
	if (knet_h->dst_link_handler_epollfd < 0) {
		savederrno = errno;
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to create epoll dst cache fd: %s",
			strerror(savederrno));
		goto exit_fail;
	}

	if (_fdset_cloexec(knet_h->tap_to_links_epollfd)) {
		savederrno = errno;
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to set CLOEXEC on net_fd to link epoll fd: %s",
			strerror(savederrno)); 
		goto exit_fail;
	}

	if (_fdset_cloexec(knet_h->recv_from_links_epollfd)) {
		savederrno = errno;
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to set CLOEXEC on link to net_fd epoll fd: %s",
			strerror(savederrno)); 
		goto exit_fail;
	}
		
	if (_fdset_cloexec(knet_h->dst_link_handler_epollfd)) {
		savederrno = errno;
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to set CLOEXEC on dst cache epoll fd: %s",
			strerror(savederrno)); 
		goto exit_fail;
	}

	memset(&ev, 0, sizeof(struct epoll_event));
	ev.events = EPOLLIN;
	ev.data.fd = knet_h->sockfd;

	if (epoll_ctl(knet_h->tap_to_links_epollfd,
		      EPOLL_CTL_ADD, knet_h->sockfd, &ev)) {
		savederrno = errno;
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to add net_fd to link fd to epoll pool: %s",
			strerror(savederrno));
		goto exit_fail;
	}

	memset(&ev, 0, sizeof(struct epoll_event));
	ev.events = EPOLLIN;
	ev.data.fd = knet_h->hostpipefd[0];

	if (epoll_ctl(knet_h->tap_to_links_epollfd,
		      EPOLL_CTL_ADD, knet_h->hostpipefd[0], &ev)) {
		savederrno = errno;
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to add hostpipefd[0] to epoll pool: %s",
			strerror(savederrno));
		goto exit_fail;
	}

	memset(&ev, 0, sizeof(struct epoll_event));
	ev.events = EPOLLIN;
	ev.data.fd = knet_h->dstpipefd[0];

	if (epoll_ctl(knet_h->dst_link_handler_epollfd,
		      EPOLL_CTL_ADD, knet_h->dstpipefd[0], &ev)) {
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to add dstpipefd[0] to epoll pool: %s",
			strerror(savederrno));
		goto exit_fail;
	}

	return 0;

exit_fail:
	errno = savederrno;
	return -1;
}

static void _close_epolls(knet_handle_t knet_h)
{
	struct epoll_event ev;

	epoll_ctl(knet_h->tap_to_links_epollfd, EPOLL_CTL_DEL, knet_h->sockfd, &ev);
	epoll_ctl(knet_h->tap_to_links_epollfd, EPOLL_CTL_DEL, knet_h->hostpipefd[0], &ev);
	epoll_ctl(knet_h->dst_link_handler_epollfd, EPOLL_CTL_DEL, knet_h->dstpipefd[0], &ev);
	close(knet_h->tap_to_links_epollfd);
	close(knet_h->recv_from_links_epollfd);
	close(knet_h->dst_link_handler_epollfd);
}

static int _start_threads(knet_handle_t knet_h)
{
	int savederrno = 0;

	savederrno = pthread_create(&knet_h->pmtud_link_handler_thread, 0,
				    _handle_pmtud_link_thread, (void *) knet_h);
	if (savederrno) {
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to start pmtud link thread: %s",
			strerror(savederrno));
		goto exit_fail;
	}

	savederrno = pthread_create(&knet_h->dst_link_handler_thread, 0,
				    _handle_dst_link_handler_thread, (void *) knet_h);
	if (savederrno) {
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to start dst cache thread: %s",
			strerror(savederrno));
		goto exit_fail;
	}

	savederrno = pthread_create(&knet_h->tap_to_links_thread, 0,
				    _handle_tap_to_links_thread, (void *) knet_h);
	if (savederrno) {
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to start net_fd to link thread: %s",
			strerror(savederrno));
		goto exit_fail;
	}

	savederrno = pthread_create(&knet_h->recv_from_links_thread, 0,
				    _handle_recv_from_links_thread, (void *) knet_h);
	if (savederrno) {
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to start link to net_fd thread: %s",
			strerror(savederrno));
		goto exit_fail;
	}

	savederrno = pthread_create(&knet_h->heartbt_thread, 0,
				    _handle_heartbt_thread, (void *) knet_h);
	if (savederrno) {
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to start heartbeat thread: %s",
			strerror(savederrno));
		goto exit_fail;
	}
	return 0;

exit_fail:
	errno = savederrno;
	return -1;
}

static void _stop_threads(knet_handle_t knet_h)
{
	void *retval;

	pthread_mutex_lock(&knet_h->host_mutex);
	pthread_cond_signal(&knet_h->host_cond);
	pthread_mutex_unlock(&knet_h->host_mutex);

	pthread_cancel(knet_h->heartbt_thread);
	pthread_join(knet_h->heartbt_thread, &retval);

	pthread_cancel(knet_h->tap_to_links_thread);
	pthread_join(knet_h->tap_to_links_thread, &retval);

	pthread_cancel(knet_h->recv_from_links_thread);
	pthread_join(knet_h->recv_from_links_thread, &retval);

	pthread_cancel(knet_h->dst_link_handler_thread);
	pthread_join(knet_h->dst_link_handler_thread, &retval);

	pthread_mutex_lock(&knet_h->pmtud_mutex);
	pthread_cond_signal(&knet_h->pmtud_cond);
	pthread_mutex_unlock(&knet_h->pmtud_mutex);

	pthread_mutex_lock(&knet_h->pmtud_timer_mutex);
	pthread_cond_signal(&knet_h->pmtud_timer_cond);
	pthread_mutex_unlock(&knet_h->pmtud_timer_mutex);

	pthread_cancel(knet_h->pmtud_link_handler_thread);
	pthread_join(knet_h->pmtud_link_handler_thread, &retval);
}

knet_handle_t knet_handle_new(uint16_t host_id,
			      int      net_fd,
			      int      log_fd,
			      uint8_t  default_log_level)
{
	knet_handle_t knet_h;
	int savederrno = 0;

	/*
	 * validate incoming request
	 */

	if (net_fd <= 0) {
		errno = EINVAL;
		return NULL;
	}

	if ((log_fd > 0) && (default_log_level > KNET_LOG_DEBUG)) {
		errno = EINVAL;
		return NULL;
	}

	/*
	 * allocate handle
	 */

	knet_h = malloc(sizeof(struct knet_handle));
	if (!knet_h) {
		return NULL;
	}
	memset(knet_h, 0, sizeof(struct knet_handle));

	/*
	 * copy config in place
	 */

	knet_h->host_id = host_id;
	knet_h->sockfd = net_fd;
	knet_h->logfd = log_fd;
	if (knet_h->logfd > 0) {
		memset(&knet_h->log_levels, default_log_level, KNET_MAX_SUBSYSTEMS);
	}

	/*
	 * set pmtud default timers
	 */
	knet_h->pmtud_interval = KNET_PMTUD_DEFAULT_INTERVAL;

	/*
	 * init main locking structures
	 */

	if (_init_locks(knet_h)) {
		savederrno = errno;
		goto exit_fail;
	}

	/*
	 * init internal communication pipes
	 */

	if (_init_pipes(knet_h)) {
		savederrno = errno;
		goto exit_fail;
	}

	/*
	 * allocate packet buffers
	 */

	if (_init_buffers(knet_h)) {
		savederrno = errno;
		goto exit_fail;
	}

	/*
	 * create epoll fds
	 */

	if (_init_epolls(knet_h)) {
		savederrno = errno;
		goto exit_fail;
	}

	/*
	 * start internal threads
	 */

	if (_start_threads(knet_h)) {
		savederrno = errno;
		goto exit_fail;
	}

	return knet_h;

exit_fail:
	knet_handle_free(knet_h);
	errno = savederrno;
	return NULL;
}

int knet_handle_free(knet_handle_t knet_h)
{
	int savederrno = 0;

	savederrno = pthread_mutex_lock(&handle_config_mutex);
	if (savederrno) {
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to get handle mutex lock: %s",
			strerror(savederrno));
		errno = savederrno;
		return -1;
	}

	if (!knet_h) {
		pthread_mutex_unlock(&handle_config_mutex);
		errno = EINVAL;
		return -1;
	}

	if (knet_h->fini_in_progress) {
		pthread_mutex_unlock(&handle_config_mutex);
		errno = EBUSY;
		return -1;
	}

	/*
	 * we take a chance here to read a value that should be 0
	 * only if we could not init properly. Nothing else
	 * is started if lock_init_done is 0.
	 */

	if (!knet_h->lock_init_done) {
		goto exit_nolock;
	}

	savederrno = pthread_rwlock_wrlock(&knet_h->list_rwlock);
	if (savederrno) {
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to get write lock: %s",
			strerror(savederrno));
		errno = savederrno;
		return -1;
	}

	if ((knet_h->host_head != NULL) || (knet_h->listener_head != NULL)) {
		savederrno = EBUSY;
		log_err(knet_h, KNET_SUB_HANDLE,
			"Unable to free handle: host(s) or listener(s) are still active: %s",
			strerror(savederrno));
		pthread_rwlock_unlock(&knet_h->list_rwlock);
		errno = savederrno;
		return -1;
	}

	knet_h->fini_in_progress = 1;

	pthread_rwlock_unlock(&knet_h->list_rwlock);

	_stop_threads(knet_h);
	_close_epolls(knet_h);
	_destroy_buffers(knet_h);
	_close_pipes(knet_h);
	crypto_fini(knet_h);

	_destroy_locks(knet_h);

exit_nolock:
	free(knet_h);
	knet_h = NULL;
	pthread_mutex_unlock(&handle_config_mutex);
	return 0;
}

int knet_handle_enable_filter(knet_handle_t knet_h,
			      int (*dst_host_filter_fn) (
					const unsigned char *outdata,
					ssize_t outdata_len,
					uint16_t src_node_id,
					uint16_t *dst_host_ids,
					size_t *dst_host_ids_entries))
{
	int savederrno = 0;

	if (!knet_h) {
		errno = EINVAL;
		return -1;
	}

	savederrno = pthread_rwlock_wrlock(&knet_h->list_rwlock);
	if (savederrno) {
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to get write lock: %s",
			strerror(savederrno));
		errno = savederrno;
		return -1;
	}

	knet_h->dst_host_filter_fn = dst_host_filter_fn;
	if (knet_h->dst_host_filter_fn) {
		log_debug(knet_h, KNET_SUB_HANDLE, "dst_host_filter_fn enabled");
	} else {
		log_debug(knet_h, KNET_SUB_HANDLE, "dst_host_filter_fn disabled");
	}

	pthread_rwlock_unlock(&knet_h->list_rwlock);

	return 0;
}

int knet_handle_setfwd(knet_handle_t knet_h, unsigned int enabled)
{
	int savederrno = 0;

	if (!knet_h) {
		errno = EINVAL;
		return -1;
	}

	savederrno = pthread_rwlock_wrlock(&knet_h->list_rwlock);
	if (savederrno) {
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to get write lock: %s",
			strerror(savederrno));
		errno = savederrno;
		return -1;
	}

	if (enabled) {
		knet_h->enabled = 1;
		log_debug(knet_h, KNET_SUB_HANDLE, "Data forwarding is enabled");
	} else {
		knet_h->enabled = 0;
		log_debug(knet_h, KNET_SUB_HANDLE, "Data forwarding is disabled");
	}

	pthread_rwlock_unlock(&knet_h->list_rwlock);

	return 0;
}

int knet_handle_pmtud_setfreq(knet_handle_t knet_h, unsigned int interval)
{
	int savederrno = 0;

	if (!knet_h) {
		errno = EINVAL;
		return -1;
	}

	if ((!interval) || (interval > 86400)) {
		errno = EINVAL;
		return -1;
	}

	savederrno = pthread_rwlock_wrlock(&knet_h->list_rwlock);
	if (savederrno) {
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to get write lock: %s",
			strerror(savederrno));
		errno = savederrno;
		return -1;
	}

	knet_h->pmtud_interval = interval;
	log_debug(knet_h, KNET_SUB_HANDLE, "PMTUd interval set to: %u seconds", interval);

	/*
	 * errors here are not fatal and the value will be picked up in the next run
	 */
	if (!pthread_mutex_lock(&knet_h->pmtud_timer_mutex)) {
		pthread_cond_signal(&knet_h->pmtud_timer_cond);
		pthread_mutex_unlock(&knet_h->pmtud_timer_mutex);
	}

	pthread_rwlock_unlock(&knet_h->list_rwlock);

	return 0;
}

int knet_handle_enable_pmtud_notify(knet_handle_t knet_h,
				    void *pmtud_notify_fn_private_data,
				    void (*pmtud_notify_fn) (
						void *private_data,
						unsigned int link_mtu,
						unsigned int data_mtu))
{
	int savederrno = 0;

	if (!knet_h) {
		errno = EINVAL;
		return -1;
	}

	savederrno = pthread_rwlock_wrlock(&knet_h->list_rwlock);
	if (savederrno) {
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to get write lock: %s",
			strerror(savederrno));
		errno = savederrno;
		return -1;
	}

	knet_h->pmtud_notify_fn_private_data = pmtud_notify_fn_private_data;
	knet_h->pmtud_notify_fn = pmtud_notify_fn;
	if (knet_h->pmtud_notify_fn) {
		log_debug(knet_h, KNET_SUB_HANDLE, "pmtud_notify_fn enabled");
	} else {
		log_debug(knet_h, KNET_SUB_HANDLE, "pmtud_notify_fn disabled");
	}

	pthread_rwlock_unlock(&knet_h->list_rwlock);

	return 0;
}

int knet_handle_pmtud_get(knet_handle_t knet_h,
			  unsigned int *link_mtu,
			  unsigned int *data_mtu)
{
	int savederrno = 0;

	if (!knet_h) {
		errno = EINVAL;
		return -1;
	}

	savederrno = pthread_rwlock_rdlock(&knet_h->list_rwlock);
	if (savederrno) {
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to get write lock: %s",
			strerror(savederrno));
		errno = savederrno;
		return -1;
	}

	*link_mtu = knet_h->link_mtu;
	*data_mtu = knet_h->data_mtu;

	pthread_rwlock_unlock(&knet_h->list_rwlock);

	return 0;
}

int knet_handle_crypto(knet_handle_t knet_h, struct knet_handle_crypto_cfg *knet_handle_crypto_cfg)
{
	int savederrno = 0;
	int err;

	if ((!knet_h) || (!knet_handle_crypto_cfg)) {
		errno = EINVAL;
		return -1;
	}

	savederrno = pthread_rwlock_wrlock(&knet_h->list_rwlock);
	if (savederrno) {
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to get write lock: %s",
			strerror(savederrno));
		errno = savederrno;
		return -1;
	}

	crypto_fini(knet_h);

	if ((!strncmp("none", knet_handle_crypto_cfg->crypto_model, 4)) || 
	    ((!strncmp("none", knet_handle_crypto_cfg->crypto_cipher_type, 4)) &&
	     (!strncmp("none", knet_handle_crypto_cfg->crypto_hash_type, 4)))) {
		log_debug(knet_h, KNET_SUB_CRYPTO, "crypto is not enabled");
		err = 0;
		goto exit_unlock;
	}

	err = crypto_init(knet_h, knet_handle_crypto_cfg);

	if (err) {
		err = -2;
	}

exit_unlock:
	pthread_rwlock_unlock(&knet_h->list_rwlock);
	return err;
}
