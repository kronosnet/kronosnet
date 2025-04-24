/*
 * Copyright (C) 2010-2025 Red Hat, Inc.  All rights reserved.
 *
 * Authors: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *          Federico Simoncelli <fsimon@kronosnet.org>
 *
 * This software licensed under LGPL-2.0+
 */

#include "config.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <math.h>
#include <sys/time.h>
#include <sys/resource.h>

#include "internals.h"
#include "crypto.h"
#include "links.h"
#include "compress.h"
#include "compat.h"
#include "common.h"
#include "threads_common.h"
#include "threads_heartbeat.h"
#include "threads_pmtud.h"
#include "threads_dsthandler.h"
#include "threads_rx.h"
#include "threads_tx.h"
#include "transports.h"
#include "transport_common.h"
#include "logging.h"

static int _init_locks(knet_handle_t knet_h)
{
	int savederrno = 0;

	savederrno = pthread_rwlock_init(&knet_h->global_rwlock, NULL);
	if (savederrno) {
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to initialize list rwlock: %s",
			strerror(savederrno));
		goto exit_fail;
	}

	savederrno = pthread_mutex_init(&knet_h->handle_stats_mutex, NULL);
	if (savederrno) {
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to initialize handle stats mutex: %s",
			strerror(savederrno));
		goto exit_fail;
	}

	savederrno = pthread_mutex_init(&knet_h->threads_status_mutex, NULL);
	if (savederrno) {
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to initialize threads status mutex: %s",
			strerror(savederrno));
		goto exit_fail;
	}

	savederrno = pthread_mutex_init(&knet_h->pmtud_mutex, NULL);
	if (savederrno) {
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to initialize pmtud mutex: %s",
			strerror(savederrno));
		goto exit_fail;
	}

	savederrno = pthread_mutex_init(&knet_h->kmtu_mutex, NULL);
	if (savederrno) {
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to initialize kernel_mtu mutex: %s",
			strerror(savederrno));
		goto exit_fail;
	}

	savederrno = pthread_cond_init(&knet_h->pmtud_cond, NULL);
	if (savederrno) {
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to initialize pmtud conditional mutex: %s",
			strerror(savederrno));
		goto exit_fail;
	}

	savederrno = pthread_mutex_init(&knet_h->hb_mutex, NULL);
	if (savederrno) {
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to initialize hb_thread mutex: %s",
			strerror(savederrno));
		goto exit_fail;
	}

	savederrno = pthread_mutex_init(&knet_h->tx_mutex, NULL);
	if (savederrno) {
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to initialize tx_thread mutex: %s",
			strerror(savederrno));
		goto exit_fail;
	}

	savederrno = pthread_mutex_init(&knet_h->backoff_mutex, NULL);
	if (savederrno) {
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to initialize pong timeout backoff mutex: %s",
			strerror(savederrno));
		goto exit_fail;
	}

	savederrno = pthread_mutex_init(&knet_h->tx_seq_num_mutex, NULL);
	if (savederrno) {
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to initialize tx_seq_num_mutex mutex: %s",
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
	pthread_rwlock_destroy(&knet_h->global_rwlock);
	pthread_mutex_destroy(&knet_h->pmtud_mutex);
	pthread_mutex_destroy(&knet_h->kmtu_mutex);
	pthread_cond_destroy(&knet_h->pmtud_cond);
	pthread_mutex_destroy(&knet_h->hb_mutex);
	pthread_mutex_destroy(&knet_h->tx_mutex);
	pthread_mutex_destroy(&knet_h->backoff_mutex);
	pthread_mutex_destroy(&knet_h->tx_seq_num_mutex);
	pthread_mutex_destroy(&knet_h->threads_status_mutex);
	pthread_mutex_destroy(&knet_h->handle_stats_mutex);
}

static int _init_socks(knet_handle_t knet_h)
{
	int savederrno = 0;

	if (_init_socketpair(knet_h, knet_h->dstsockfd)) {
		savederrno = errno;
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to initialize internal dstsockpair: %s",
			strerror(savederrno));
		goto exit_fail;
	}

	return 0;

exit_fail:
	errno = savederrno;
	return -1;
}

static void _close_socks(knet_handle_t knet_h)
{
	_close_socketpair(knet_h, knet_h->dstsockfd);
}

static int _init_buffers(knet_handle_t knet_h)
{
	int savederrno = 0;
	int i;
	size_t bufsize;

	for (i = 0; i < PCKT_FRAG_MAX; i++) {
		bufsize = ceil((float)KNET_MAX_PACKET_SIZE / (i + 1)) + KNET_HEADER_ALL_SIZE;
		knet_h->send_to_links_buf[i] = malloc(bufsize);
		if (!knet_h->send_to_links_buf[i]) {
			savederrno = errno;
			log_err(knet_h, KNET_SUB_HANDLE, "Unable to allocate memory datafd to link buffer: %s",
				strerror(savederrno));
			goto exit_fail;
		}
		memset(knet_h->send_to_links_buf[i], 0, bufsize);
	}

	for (i = 0; i < PCKT_RX_BUFS; i++) {
		knet_h->recv_from_links_buf[i] = malloc(KNET_DATABUFSIZE);
		if (!knet_h->recv_from_links_buf[i]) {
			savederrno = errno;
			log_err(knet_h, KNET_SUB_HANDLE, "Unable to allocate memory for link to datafd buffer: %s",
				strerror(savederrno));
			goto exit_fail;
		}
		memset(knet_h->recv_from_links_buf[i], 0, KNET_DATABUFSIZE);
	}

	knet_h->recv_from_sock_buf = malloc(KNET_DATABUFSIZE);
	if (!knet_h->recv_from_sock_buf) {
		savederrno = errno;
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to allocate memory for app to datafd buffer: %s",
				strerror(savederrno));
		goto exit_fail;
	}
	memset(knet_h->recv_from_sock_buf, 0, KNET_DATABUFSIZE);

	knet_h->pingbuf = malloc(KNET_HEADER_PING_SIZE);
	if (!knet_h->pingbuf) {
		savederrno = errno;
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to allocate memory for hearbeat buffer: %s",
			strerror(savederrno));
		goto exit_fail;
	}
	memset(knet_h->pingbuf, 0, KNET_HEADER_PING_SIZE);

	knet_h->pmtudbuf = malloc(KNET_PMTUD_SIZE_V6 + KNET_HEADER_ALL_SIZE);
	if (!knet_h->pmtudbuf) {
		savederrno = errno;
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to allocate memory for pmtud buffer: %s",
			strerror(savederrno));
		goto exit_fail;
	}
	memset(knet_h->pmtudbuf, 0, KNET_PMTUD_SIZE_V6 + KNET_HEADER_ALL_SIZE);

	for (i = 0; i < PCKT_FRAG_MAX; i++) {
		bufsize = ceil((float)KNET_MAX_PACKET_SIZE / (i + 1)) + KNET_HEADER_ALL_SIZE + KNET_DATABUFSIZE_CRYPT_PAD;
		knet_h->send_to_links_buf_crypt[i] = malloc(bufsize);
		if (!knet_h->send_to_links_buf_crypt[i]) {
			savederrno = errno;
			log_err(knet_h, KNET_SUB_HANDLE, "Unable to allocate memory for crypto datafd to link buffer: %s",
				strerror(savederrno));
			goto exit_fail;
		}
		memset(knet_h->send_to_links_buf_crypt[i], 0, bufsize);
	}

	knet_h->recv_from_links_buf_decrypt = malloc(KNET_DATABUFSIZE_CRYPT);
	if (!knet_h->recv_from_links_buf_decrypt) {
		savederrno = errno;
		log_err(knet_h, KNET_SUB_CRYPTO, "Unable to allocate memory for crypto link to datafd buffer: %s",
			strerror(savederrno));
		goto exit_fail;
	}
	memset(knet_h->recv_from_links_buf_decrypt, 0, KNET_DATABUFSIZE_CRYPT);

	knet_h->recv_from_links_buf_crypt = malloc(KNET_DATABUFSIZE_CRYPT);
	if (!knet_h->recv_from_links_buf_crypt) {
		savederrno = errno;
		log_err(knet_h, KNET_SUB_CRYPTO, "Unable to allocate memory for crypto link to datafd buffer: %s",
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

	knet_h->recv_from_links_buf_decompress = malloc(KNET_DATABUFSIZE_COMPRESS);
	if (!knet_h->recv_from_links_buf_decompress) {
		savederrno = errno;
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to allocate memory for decompress buffer: %s",
			strerror(savederrno));
		goto exit_fail;
	}
	memset(knet_h->recv_from_links_buf_decompress, 0, KNET_DATABUFSIZE_COMPRESS);

	knet_h->send_to_links_buf_compress = malloc(KNET_DATABUFSIZE_COMPRESS);
	if (!knet_h->send_to_links_buf_compress) {
		savederrno = errno;
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to allocate memory for compress buffer: %s",
			strerror(savederrno));
		goto exit_fail;
	}
	memset(knet_h->send_to_links_buf_compress, 0, KNET_DATABUFSIZE_COMPRESS);

	memset(knet_h->knet_transport_fd_tracker, 0, sizeof(knet_h->knet_transport_fd_tracker));
	for (i = 0; i < KNET_MAX_FDS; i++) {
		knet_h->knet_transport_fd_tracker[i].transport = KNET_MAX_TRANSPORTS;
	}

	return 0;

exit_fail:
	errno = savederrno;
	return -1;
}

static void _destroy_buffers(knet_handle_t knet_h)
{
	int i;

	for (i = 0; i < PCKT_FRAG_MAX; i++) {
		free(knet_h->send_to_links_buf[i]);
		free(knet_h->send_to_links_buf_crypt[i]);
	}

	for (i = 0; i < PCKT_RX_BUFS; i++) {
		free(knet_h->recv_from_links_buf[i]);
	}

	free(knet_h->recv_from_links_buf_decompress);
	free(knet_h->send_to_links_buf_compress);
	free(knet_h->recv_from_sock_buf);
	free(knet_h->recv_from_links_buf_decrypt);
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

	/*
	 * even if the kernel does dynamic allocation with epoll_ctl
	 * we need to reserve one extra for host to host communication
	 */
	knet_h->send_to_links_epollfd = epoll_create(KNET_EPOLL_MAX_EVENTS + 1);
	if (knet_h->send_to_links_epollfd < 0) {
		savederrno = errno;
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to create epoll datafd to link fd: %s",
			strerror(savederrno));
		goto exit_fail;
	}

	knet_h->recv_from_links_epollfd = epoll_create(KNET_EPOLL_MAX_EVENTS);
	if (knet_h->recv_from_links_epollfd < 0) {
		savederrno = errno;
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to create epoll link to datafd fd: %s",
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

	if (_fdset_cloexec(knet_h->send_to_links_epollfd)) {
		savederrno = errno;
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to set CLOEXEC on datafd to link epoll fd: %s",
			strerror(savederrno)); 
		goto exit_fail;
	}

	if (_fdset_cloexec(knet_h->recv_from_links_epollfd)) {
		savederrno = errno;
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to set CLOEXEC on link to datafd epoll fd: %s",
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
	ev.data.fd = knet_h->dstsockfd[0];

	if (epoll_ctl(knet_h->dst_link_handler_epollfd,
		      EPOLL_CTL_ADD, knet_h->dstsockfd[0], &ev)) {
		savederrno = errno;
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to add dstsockfd[0] to epoll pool: %s",
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
	int i;

	memset(&ev, 0, sizeof(struct epoll_event));

	for (i = 0; i < KNET_DATAFD_MAX; i++) {
		if (knet_h->sockfd[i].in_use) {
			epoll_ctl(knet_h->send_to_links_epollfd, EPOLL_CTL_DEL, knet_h->sockfd[i].sockfd[knet_h->sockfd[i].is_created], &ev);
			if  (knet_h->sockfd[i].sockfd[knet_h->sockfd[i].is_created]) {
				 _close_socketpair(knet_h, knet_h->sockfd[i].sockfd);
			}
		}
	}

	epoll_ctl(knet_h->dst_link_handler_epollfd, EPOLL_CTL_DEL, knet_h->dstsockfd[0], &ev);
	close(knet_h->send_to_links_epollfd);
	close(knet_h->recv_from_links_epollfd);
	close(knet_h->dst_link_handler_epollfd);
}

static int _start_threads(knet_handle_t knet_h)
{
	int savederrno = 0;
	pthread_attr_t attr;

	set_thread_status(knet_h, KNET_THREAD_PMTUD, KNET_THREAD_REGISTERED);

	savederrno = pthread_attr_init(&attr);
	if (savederrno) {
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to init pthread attributes: %s",
			strerror(savederrno));
		goto exit_fail;
	}
	savederrno = pthread_attr_setstacksize(&attr, KNET_THREAD_STACK_SIZE);
	if (savederrno) {
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to set stack size attribute: %s",
			strerror(savederrno));
		goto exit_fail;
	}

	savederrno = pthread_create(&knet_h->pmtud_link_handler_thread, &attr,
				    _handle_pmtud_link_thread, (void *) knet_h);
	if (savederrno) {
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to start pmtud link thread: %s",
			strerror(savederrno));
		goto exit_fail;
	}

	set_thread_status(knet_h, KNET_THREAD_DST_LINK, KNET_THREAD_REGISTERED);
	savederrno = pthread_create(&knet_h->dst_link_handler_thread, &attr,
				    _handle_dst_link_handler_thread, (void *) knet_h);
	if (savederrno) {
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to start dst cache thread: %s",
			strerror(savederrno));
		goto exit_fail;
	}

	set_thread_status(knet_h, KNET_THREAD_TX, KNET_THREAD_REGISTERED);
	savederrno = pthread_create(&knet_h->send_to_links_thread, &attr,
				    _handle_send_to_links_thread, (void *) knet_h);
	if (savederrno) {
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to start datafd to link thread: %s",
			strerror(savederrno));
		goto exit_fail;
	}

	set_thread_status(knet_h, KNET_THREAD_RX, KNET_THREAD_REGISTERED);
	savederrno = pthread_create(&knet_h->recv_from_links_thread, &attr,
				    _handle_recv_from_links_thread, (void *) knet_h);
	if (savederrno) {
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to start link to datafd thread: %s",
			strerror(savederrno));
		goto exit_fail;
	}

	set_thread_status(knet_h, KNET_THREAD_HB, KNET_THREAD_REGISTERED);
	savederrno = pthread_create(&knet_h->heartbt_thread, &attr,
				    _handle_heartbt_thread, (void *) knet_h);
	if (savederrno) {
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to start heartbeat thread: %s",
			strerror(savederrno));
		goto exit_fail;
	}

	savederrno = pthread_attr_destroy(&attr);
	if (savederrno) {
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to destroy pthread attributes: %s",
			strerror(savederrno));
		/*
		 * Do not return error code. Error is not critical.
		 */
	}

	return 0;

exit_fail:
	errno = savederrno;
	return -1;
}

static void _stop_threads(knet_handle_t knet_h)
{
	void *retval;

	wait_all_threads_status(knet_h, KNET_THREAD_STOPPED);

	if (knet_h->heartbt_thread) {
		pthread_cancel(knet_h->heartbt_thread);
		pthread_join(knet_h->heartbt_thread, &retval);
	}

	if (knet_h->send_to_links_thread) {
		pthread_cancel(knet_h->send_to_links_thread);
		pthread_join(knet_h->send_to_links_thread, &retval);
	}

	if (knet_h->recv_from_links_thread) {
		pthread_cancel(knet_h->recv_from_links_thread);
		pthread_join(knet_h->recv_from_links_thread, &retval);
	}

	if (knet_h->dst_link_handler_thread) {
		pthread_cancel(knet_h->dst_link_handler_thread);
		pthread_join(knet_h->dst_link_handler_thread, &retval);
	}

	if (knet_h->pmtud_link_handler_thread) {
		pthread_cancel(knet_h->pmtud_link_handler_thread);
		pthread_join(knet_h->pmtud_link_handler_thread, &retval);
	}
}

knet_handle_t knet_handle_new_ex(knet_node_id_t host_id,
				 int            log_fd,
				 uint8_t        default_log_level,
				 uint64_t       flags)
{
	knet_handle_t knet_h;
	int savederrno = 0;
	struct rlimit cur;

	if (getrlimit(RLIMIT_NOFILE, &cur) < 0) {
		return NULL;
	}

	if ((log_fd < 0) || ((unsigned int)log_fd >= cur.rlim_max)) {
		errno = EINVAL;
		return NULL;
	}

	/*
	 * validate incoming request
	 */

	if ((log_fd) && (default_log_level > KNET_LOG_DEBUG)) {
		errno = EINVAL;
		return NULL;
	}

	if (flags > KNET_HANDLE_FLAG_PRIVILEGED * 2 - 1) {
		errno = EINVAL;
		return NULL;
	}

	/*
	 * allocate handle
	 */

	knet_h = malloc(sizeof(struct knet_handle));
	if (!knet_h) {
		errno = ENOMEM;
		return NULL;
	}
	memset(knet_h, 0, sizeof(struct knet_handle));

	/*
	 * setting up some handle data so that we can use logging
	 * also when initializing the library global locks
	 * and trackers
	 */

	knet_h->flags = flags;

	/*
	 * copy config in place
	 */

	knet_h->host_id = host_id;
	knet_h->logfd = log_fd;
	if (knet_h->logfd > 0) {
		memset(&knet_h->log_levels, default_log_level, KNET_MAX_SUBSYSTEMS);
	}

	/*
	 * set pmtud default timers
	 */
	knet_h->pmtud_interval = KNET_PMTUD_DEFAULT_INTERVAL;

	/*
	 * set transports reconnect default timers
	 */
	knet_h->reconnect_int = KNET_TRANSPORT_DEFAULT_RECONNECT_INTERVAL;

	/*
	 * Set the default path for plugins
	 */
	knet_h->plugin_path = PLUGINPATH;

	/*
	 * Set 'min' stats to the maximum value so the
	 * first value we get is always less
	 */
	knet_h->stats.tx_compress_time_min = UINT64_MAX;
	knet_h->stats.rx_compress_time_min = UINT64_MAX;
	knet_h->stats.tx_crypt_time_min = UINT64_MAX;
	knet_h->stats.rx_crypt_time_min = UINT64_MAX;

	/*
	 * init global shared bits
	 */
	savederrno = pthread_mutex_lock(&handle_config_mutex);
	if (savederrno) {
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to get handle mutex lock: %s",
			strerror(savederrno));
		free(knet_h);
		knet_h = NULL;
		errno = savederrno;
		return NULL;
	}

	if (!handle_list_init) {
		qb_list_init(&handle_list.head);
		handle_list_init = 1;
	}

	qb_list_add(&knet_h->list, &handle_list.head);

	/*
	 * init global shlib tracker
	 */
	if (_init_shlib_tracker(knet_h) < 0) {
		savederrno = errno;
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to init handle tracker: %s",
			strerror(savederrno));
		errno = savederrno;
		pthread_mutex_unlock(&handle_config_mutex);
		goto exit_fail;
	}

	pthread_mutex_unlock(&handle_config_mutex);

	/*
	 * init main locking structures
	 */

	if (_init_locks(knet_h)) {
		savederrno = errno;
		goto exit_fail;
	}

	/*
	 * init sockets
	 */

	if (_init_socks(knet_h)) {
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

	if (compress_init(knet_h)) {
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
	 * start transports
	 */

	if (start_all_transports(knet_h)) {
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

	wait_all_threads_status(knet_h, KNET_THREAD_STARTED);

	errno = 0;
	return knet_h;

exit_fail:
	knet_handle_free(knet_h);
	errno = savederrno;
	return NULL;
}

knet_handle_t knet_handle_new(knet_node_id_t host_id,
			      int            log_fd,
			      uint8_t        default_log_level)
{
	return knet_handle_new_ex(host_id, log_fd, default_log_level, KNET_HANDLE_FLAG_PRIVILEGED);
}

int knet_handle_free(knet_handle_t knet_h)
{
	int savederrno = 0;

	if (!_is_valid_handle(knet_h)) {
		return -1;
	}

	savederrno = get_global_wrlock(knet_h);
	if (savederrno) {
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to get write lock: %s",
			strerror(savederrno));
		errno = savederrno;
		return -1;
	}

	if (knet_h->host_head != NULL) {
		savederrno = EBUSY;
		log_err(knet_h, KNET_SUB_HANDLE,
			"Unable to free handle: host(s) or listener(s) are still active: %s",
			strerror(savederrno));
		pthread_rwlock_unlock(&knet_h->global_rwlock);
		errno = savederrno;
		return -1;
	}

	knet_h->fini_in_progress = 1;

	pthread_rwlock_unlock(&knet_h->global_rwlock);

	_stop_threads(knet_h);
	stop_all_transports(knet_h);
	_close_epolls(knet_h);
	_destroy_buffers(knet_h);
	_close_socks(knet_h);
	crypto_fini(knet_h, KNET_MAX_CRYPTO_INSTANCES + 1); /* values above MAX_CRYPTO will release all crypto resources */
	compress_fini(knet_h, 1);
	_destroy_locks(knet_h);

	(void)pthread_mutex_lock(&handle_config_mutex);
	qb_list_del(&knet_h->list);
	_fini_shlib_tracker();
	pthread_mutex_unlock(&handle_config_mutex);

	free(knet_h);
	knet_h = NULL;

	errno = 0;
	return 0;
}
