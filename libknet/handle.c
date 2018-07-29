/*
 * Copyright (C) 2010-2018 Red Hat, Inc.  All rights reserved.
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
#include <sys/uio.h>
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

static pthread_mutex_t handle_config_mutex = PTHREAD_MUTEX_INITIALIZER;

pthread_rwlock_t shlib_rwlock;
static uint8_t shlib_wrlock_init = 0;

static uint32_t knet_ref = 0;

static int _init_shlib_tracker(knet_handle_t knet_h)
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

static void _fini_shlib_tracker(void)
{
	if (knet_ref == 0) {
		pthread_rwlock_destroy(&shlib_rwlock);
		shlib_wrlock_init = 0;
	}
	return;
}

static int _init_locks(knet_handle_t knet_h)
{
	int savederrno = 0;

	savederrno = pthread_rwlock_init(&knet_h->global_rwlock, NULL);
	if (savederrno) {
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to initialize list rwlock: %s",
			strerror(savederrno));
		goto exit_fail;
	}

	knet_h->lock_init_done = 1;

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
	knet_h->lock_init_done = 0;
	pthread_rwlock_destroy(&knet_h->global_rwlock);
	pthread_mutex_destroy(&knet_h->pmtud_mutex);
	pthread_mutex_destroy(&knet_h->kmtu_mutex);
	pthread_cond_destroy(&knet_h->pmtud_cond);
	pthread_mutex_destroy(&knet_h->hb_mutex);
	pthread_mutex_destroy(&knet_h->tx_mutex);
	pthread_mutex_destroy(&knet_h->backoff_mutex);
	pthread_mutex_destroy(&knet_h->tx_seq_num_mutex);
}

static int _init_socks(knet_handle_t knet_h)
{
	int savederrno = 0;

	if (_init_socketpair(knet_h, knet_h->hostsockfd)) {
		savederrno = errno;
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to initialize internal hostsockpair: %s",
			strerror(savederrno));
		goto exit_fail;
	}

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
	_close_socketpair(knet_h, knet_h->hostsockfd);
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

	knet_h->pmtudbuf = malloc(KNET_PMTUD_SIZE_V6);
	if (!knet_h->pmtudbuf) {
		savederrno = errno;
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to allocate memory for pmtud buffer: %s",
			strerror(savederrno));
		goto exit_fail;
	}
	memset(knet_h->pmtudbuf, 0, KNET_PMTUD_SIZE_V6);

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

	memset(knet_h->knet_transport_fd_tracker, KNET_MAX_TRANSPORTS, sizeof(knet_h->knet_transport_fd_tracker));

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
	ev.data.fd = knet_h->hostsockfd[0];

	if (epoll_ctl(knet_h->send_to_links_epollfd,
		      EPOLL_CTL_ADD, knet_h->hostsockfd[0], &ev)) {
		savederrno = errno;
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to add hostsockfd[0] to epoll pool: %s",
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

	epoll_ctl(knet_h->send_to_links_epollfd, EPOLL_CTL_DEL, knet_h->hostsockfd[0], &ev);
	epoll_ctl(knet_h->dst_link_handler_epollfd, EPOLL_CTL_DEL, knet_h->dstsockfd[0], &ev);
	close(knet_h->send_to_links_epollfd);
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

	savederrno = pthread_create(&knet_h->send_to_links_thread, 0,
				    _handle_send_to_links_thread, (void *) knet_h);
	if (savederrno) {
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to start datafd to link thread: %s",
			strerror(savederrno));
		goto exit_fail;
	}

	savederrno = pthread_create(&knet_h->recv_from_links_thread, 0,
				    _handle_recv_from_links_thread, (void *) knet_h);
	if (savederrno) {
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to start link to datafd thread: %s",
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

	/*
	 * allow threads to catch on shutdown request
	 * and release locks before we stop them.
	 * this isn't the most efficent way to handle it
	 * but it works good enough for now
	 */

	sleep(1);

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

	knet_h->flags = flags;

	savederrno = pthread_mutex_lock(&handle_config_mutex);
	if (savederrno) {
		errno = savederrno;
		goto exit_fail;
	}

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
	 * Set 'min' stats to the maximum value so the
	 * first value we get is always less
	 */
	knet_h->stats.tx_compress_time_min = UINT64_MAX;
	knet_h->stats.rx_compress_time_min = UINT64_MAX;
	knet_h->stats.tx_crypt_time_min = UINT64_MAX;
	knet_h->stats.rx_crypt_time_min = UINT64_MAX;

	/*
	 * init global shlib tracker
	 */
	if (_init_shlib_tracker(knet_h) < 0) {
		savederrno = errno;
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to init handles traceker: %s",
			strerror(savederrno));
		errno = savederrno;
		goto exit_fail;
	}

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

	knet_ref++;

	pthread_mutex_unlock(&handle_config_mutex);
	return knet_h;

exit_fail:
	pthread_mutex_unlock(&handle_config_mutex);
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

	if (!knet_h->lock_init_done) {
		goto exit_nolock;
	}

	savederrno = get_global_wrlock(knet_h);
	if (savederrno) {
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to get write lock: %s",
			strerror(savederrno));
		pthread_mutex_unlock(&handle_config_mutex);
		errno = savederrno;
		return -1;
	}

	if (knet_h->host_head != NULL) {
		savederrno = EBUSY;
		log_err(knet_h, KNET_SUB_HANDLE,
			"Unable to free handle: host(s) or listener(s) are still active: %s",
			strerror(savederrno));
		pthread_rwlock_unlock(&knet_h->global_rwlock);
		pthread_mutex_unlock(&handle_config_mutex);
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
	crypto_fini(knet_h);
	compress_fini(knet_h, 1);
	_destroy_locks(knet_h);

exit_nolock:
	free(knet_h);
	knet_h = NULL;
	knet_ref--;
	_fini_shlib_tracker();
	pthread_mutex_unlock(&handle_config_mutex);
	return 0;
}

int knet_handle_enable_sock_notify(knet_handle_t knet_h,
				   void *sock_notify_fn_private_data,
				   void (*sock_notify_fn) (
						void *private_data,
						int datafd,
						int8_t channel,
						uint8_t tx_rx,
						int error,
						int errorno))
{
	int savederrno = 0, err = 0;

	if (!knet_h) {
		errno = EINVAL;
		return -1;
	}

	if (!sock_notify_fn) {
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

	knet_h->sock_notify_fn_private_data = sock_notify_fn_private_data;
	knet_h->sock_notify_fn = sock_notify_fn;
	log_debug(knet_h, KNET_SUB_HANDLE, "sock_notify_fn enabled");

	pthread_rwlock_unlock(&knet_h->global_rwlock);

	return err;
}

int knet_handle_add_datafd(knet_handle_t knet_h, int *datafd, int8_t *channel)
{
	int err = 0, savederrno = 0;
	int i;
	struct epoll_event ev;

	if (!knet_h) {
		errno = EINVAL;
		return -1;
	}

	if (datafd == NULL) {
		errno = EINVAL;
		return -1;
	}

	if (channel == NULL) {
		errno = EINVAL;
		return -1;
	}

	if (*channel >= KNET_DATAFD_MAX) {
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

	if (!knet_h->sock_notify_fn) {
		log_err(knet_h, KNET_SUB_HANDLE, "Adding datafd requires sock notify callback enabled!");
		savederrno = EINVAL;
		err = -1;
		goto out_unlock;
	}

	if (*datafd > 0) {
		for (i = 0; i < KNET_DATAFD_MAX; i++) {
			if  ((knet_h->sockfd[i].in_use) && (knet_h->sockfd[i].sockfd[0] == *datafd)) {
				log_err(knet_h, KNET_SUB_HANDLE, "requested datafd: %d already exist in index: %d", *datafd, i);
				savederrno = EEXIST;
				err = -1;
				goto out_unlock;
			}
		}
	}

	/*
	 * auto allocate a channel
	 */
	if (*channel < 0) {
		for (i = 0; i < KNET_DATAFD_MAX; i++) {
			if (!knet_h->sockfd[i].in_use) {
				*channel = i;
				break;
			}
		}
		if (*channel < 0) {
			savederrno = EBUSY;
			err = -1;
			goto out_unlock;
		}
	} else {
		if (knet_h->sockfd[*channel].in_use) {
			savederrno = EBUSY;
			err = -1;
			goto out_unlock;
		}
	}

	knet_h->sockfd[*channel].is_created = 0;
	knet_h->sockfd[*channel].is_socket = 0;
	knet_h->sockfd[*channel].has_error = 0;

	if (*datafd > 0) {
		int sockopt;
		socklen_t sockoptlen = sizeof(sockopt);

		if (_fdset_cloexec(*datafd)) {
			savederrno = errno;
			err = -1;
			log_err(knet_h, KNET_SUB_HANDLE, "Unable to set CLOEXEC on datafd: %s",
				strerror(savederrno));
			goto out_unlock;
		}

		if (_fdset_nonblock(*datafd)) {
			savederrno = errno;
			err = -1;
			log_err(knet_h, KNET_SUB_HANDLE, "Unable to set NONBLOCK on datafd: %s",
				strerror(savederrno));
			goto out_unlock;
		}

		knet_h->sockfd[*channel].sockfd[0] = *datafd;
		knet_h->sockfd[*channel].sockfd[1] = 0;

		if (!getsockopt(knet_h->sockfd[*channel].sockfd[0], SOL_SOCKET, SO_TYPE, &sockopt, &sockoptlen)) {
			knet_h->sockfd[*channel].is_socket = 1;
		}
	} else {
		if (_init_socketpair(knet_h, knet_h->sockfd[*channel].sockfd)) {
			savederrno = errno;
			err = -1;
			goto out_unlock;
		}

		knet_h->sockfd[*channel].is_created = 1;
		knet_h->sockfd[*channel].is_socket = 1;
		*datafd = knet_h->sockfd[*channel].sockfd[0];
	}

	memset(&ev, 0, sizeof(struct epoll_event));
	ev.events = EPOLLIN;
	ev.data.fd = knet_h->sockfd[*channel].sockfd[knet_h->sockfd[*channel].is_created];

	if (epoll_ctl(knet_h->send_to_links_epollfd,
		      EPOLL_CTL_ADD, knet_h->sockfd[*channel].sockfd[knet_h->sockfd[*channel].is_created], &ev)) {
		savederrno = errno;
		err = -1;
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to add datafd %d to linkfd epoll pool: %s",
			knet_h->sockfd[*channel].sockfd[knet_h->sockfd[*channel].is_created], strerror(savederrno));
		if (knet_h->sockfd[*channel].is_created) {
			_close_socketpair(knet_h, knet_h->sockfd[*channel].sockfd);
		}
		goto out_unlock;
	}

	knet_h->sockfd[*channel].in_use = 1;

out_unlock:
	pthread_rwlock_unlock(&knet_h->global_rwlock);
	errno = savederrno;
	return err;
}

int knet_handle_remove_datafd(knet_handle_t knet_h, int datafd)
{
	int err = 0, savederrno = 0;
	int8_t channel = -1;
	int i;
	struct epoll_event ev;

	if (!knet_h) {
		errno = EINVAL;
		return -1;
	}

	if (datafd <= 0) {
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

	for (i = 0; i < KNET_DATAFD_MAX; i++) {
		if  ((knet_h->sockfd[i].in_use) &&
		     (knet_h->sockfd[i].sockfd[0] == datafd)) {
			channel = i;
			break;
		}
	}

	if (channel < 0) {
		savederrno = EINVAL;
		err = -1;
		goto out_unlock;
	}

	if (!knet_h->sockfd[channel].has_error) {
		memset(&ev, 0, sizeof(struct epoll_event));

		if (epoll_ctl(knet_h->send_to_links_epollfd,
			      EPOLL_CTL_DEL, knet_h->sockfd[channel].sockfd[knet_h->sockfd[channel].is_created], &ev)) {
			savederrno = errno;
			err = -1;
			log_err(knet_h, KNET_SUB_HANDLE, "Unable to del datafd %d from linkfd epoll pool: %s",
				knet_h->sockfd[channel].sockfd[0], strerror(savederrno));
			goto out_unlock;
		}
	}

	if (knet_h->sockfd[channel].is_created) {
		_close_socketpair(knet_h, knet_h->sockfd[channel].sockfd);
	}

	memset(&knet_h->sockfd[channel], 0, sizeof(struct knet_sock));

out_unlock:
	pthread_rwlock_unlock(&knet_h->global_rwlock);
	errno = savederrno;
	return err;
}

int knet_handle_get_datafd(knet_handle_t knet_h, const int8_t channel, int *datafd)
{
	int err = 0, savederrno = 0;

	if (!knet_h) {
		errno = EINVAL;
		return -1;
	}

	if ((channel < 0) || (channel >= KNET_DATAFD_MAX)) {
		errno = EINVAL;
		return -1;
	}

	if (datafd == NULL) {
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

	if (!knet_h->sockfd[channel].in_use) {
		savederrno = EINVAL;
		err = -1;
		goto out_unlock;
	}

	*datafd = knet_h->sockfd[channel].sockfd[0];

out_unlock:
	pthread_rwlock_unlock(&knet_h->global_rwlock);
	errno = savederrno;
	return err;
}

int knet_handle_get_channel(knet_handle_t knet_h, const int datafd, int8_t *channel)
{
	int err = 0, savederrno = 0;
	int i;

	if (!knet_h) {
		errno = EINVAL;
		return -1;
	}

	if (datafd <= 0) {
		errno = EINVAL;
		return -1;
	}

	if (channel == NULL) {
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

	*channel = -1;

	for (i = 0; i < KNET_DATAFD_MAX; i++) {
		if  ((knet_h->sockfd[i].in_use) &&
		     (knet_h->sockfd[i].sockfd[0] == datafd)) {
			*channel = i;
			break;
		}
	}

	if (*channel < 0) {
		savederrno = EINVAL;
		err = -1;
		goto out_unlock;
	}

out_unlock:
	pthread_rwlock_unlock(&knet_h->global_rwlock);
	errno = savederrno;
	return err;
}

int knet_handle_enable_filter(knet_handle_t knet_h,
			      void *dst_host_filter_fn_private_data,
			      int (*dst_host_filter_fn) (
					void *private_data,
					const unsigned char *outdata,
					ssize_t outdata_len,
					uint8_t tx_rx,
					knet_node_id_t this_host_id,
					knet_node_id_t src_node_id,
					int8_t *channel,
					knet_node_id_t *dst_host_ids,
					size_t *dst_host_ids_entries))
{
	int savederrno = 0;

	if (!knet_h) {
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

	knet_h->dst_host_filter_fn_private_data = dst_host_filter_fn_private_data;
	knet_h->dst_host_filter_fn = dst_host_filter_fn;
	if (knet_h->dst_host_filter_fn) {
		log_debug(knet_h, KNET_SUB_HANDLE, "dst_host_filter_fn enabled");
	} else {
		log_debug(knet_h, KNET_SUB_HANDLE, "dst_host_filter_fn disabled");
	}

	pthread_rwlock_unlock(&knet_h->global_rwlock);

	return 0;
}

int knet_handle_setfwd(knet_handle_t knet_h, unsigned int enabled)
{
	int savederrno = 0;

	if (!knet_h) {
		errno = EINVAL;
		return -1;
	}

	if (enabled > 1) {
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

	knet_h->enabled = enabled;

	if (enabled) {
		log_debug(knet_h, KNET_SUB_HANDLE, "Data forwarding is enabled");
	} else {
		log_debug(knet_h, KNET_SUB_HANDLE, "Data forwarding is disabled");
	}

	pthread_rwlock_unlock(&knet_h->global_rwlock);

	return 0;
}

int knet_handle_pmtud_getfreq(knet_handle_t knet_h, unsigned int *interval)
{
	int savederrno = 0;

	if (!knet_h) {
		errno = EINVAL;
		return -1;
	}

	if (!interval) {
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

	*interval = knet_h->pmtud_interval;

	pthread_rwlock_unlock(&knet_h->global_rwlock);

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

	savederrno = get_global_wrlock(knet_h);
	if (savederrno) {
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to get write lock: %s",
			strerror(savederrno));
		errno = savederrno;
		return -1;
	}

	knet_h->pmtud_interval = interval;
	log_debug(knet_h, KNET_SUB_HANDLE, "PMTUd interval set to: %u seconds", interval);

	pthread_rwlock_unlock(&knet_h->global_rwlock);

	return 0;
}

int knet_handle_enable_pmtud_notify(knet_handle_t knet_h,
				    void *pmtud_notify_fn_private_data,
				    void (*pmtud_notify_fn) (
						void *private_data,
						unsigned int data_mtu))
{
	int savederrno = 0;

	if (!knet_h) {
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

	knet_h->pmtud_notify_fn_private_data = pmtud_notify_fn_private_data;
	knet_h->pmtud_notify_fn = pmtud_notify_fn;
	if (knet_h->pmtud_notify_fn) {
		log_debug(knet_h, KNET_SUB_HANDLE, "pmtud_notify_fn enabled");
	} else {
		log_debug(knet_h, KNET_SUB_HANDLE, "pmtud_notify_fn disabled");
	}

	pthread_rwlock_unlock(&knet_h->global_rwlock);

	return 0;
}

int knet_handle_pmtud_get(knet_handle_t knet_h,
			  unsigned int *data_mtu)
{
	int savederrno = 0;

	if (!knet_h) {
		errno = EINVAL;
		return -1;
	}

	if (!data_mtu) {
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

	*data_mtu = knet_h->data_mtu;

	pthread_rwlock_unlock(&knet_h->global_rwlock);

	return 0;
}

int knet_handle_crypto(knet_handle_t knet_h, struct knet_handle_crypto_cfg *knet_handle_crypto_cfg)
{
	int savederrno = 0;
	int err = 0;

	if (!knet_h) {
		errno = EINVAL;
		return -1;
	}

	if (!knet_handle_crypto_cfg) {
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

	crypto_fini(knet_h);

	if ((!strncmp("none", knet_handle_crypto_cfg->crypto_model, 4)) || 
	    ((!strncmp("none", knet_handle_crypto_cfg->crypto_cipher_type, 4)) &&
	     (!strncmp("none", knet_handle_crypto_cfg->crypto_hash_type, 4)))) {
		log_debug(knet_h, KNET_SUB_CRYPTO, "crypto is not enabled");
		err = 0;
		goto exit_unlock;
	}

	if (knet_handle_crypto_cfg->private_key_len < KNET_MIN_KEY_LEN) {
		log_debug(knet_h, KNET_SUB_CRYPTO, "private key len too short (min %d): %u",
			  KNET_MIN_KEY_LEN, knet_handle_crypto_cfg->private_key_len);
		savederrno = EINVAL;
		err = -1;
		goto exit_unlock;
	}

	if (knet_handle_crypto_cfg->private_key_len > KNET_MAX_KEY_LEN) {
		log_debug(knet_h, KNET_SUB_CRYPTO, "private key len too long (max %d): %u",
			  KNET_MAX_KEY_LEN, knet_handle_crypto_cfg->private_key_len);
		savederrno = EINVAL;
		err = -1;
		goto exit_unlock;
	}

	err = crypto_init(knet_h, knet_handle_crypto_cfg);

	if (err) {
		err = -2;
		savederrno = errno;
	}

exit_unlock:
	pthread_rwlock_unlock(&knet_h->global_rwlock);
	errno = savederrno;
	return err;
}

int knet_handle_compress(knet_handle_t knet_h, struct knet_handle_compress_cfg *knet_handle_compress_cfg)
{
	int savederrno = 0;
	int err = 0;

	if (!knet_h) {
		errno = EINVAL;
		return -1;
	}

	if (!knet_handle_compress_cfg) {
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

	compress_fini(knet_h, 0);
	err = compress_cfg(knet_h, knet_handle_compress_cfg);
	savederrno = errno;

	pthread_rwlock_unlock(&knet_h->global_rwlock);
	errno = savederrno;
	return err;
}

ssize_t knet_recv(knet_handle_t knet_h, char *buff, const size_t buff_len, const int8_t channel)
{
	int savederrno = 0;
	ssize_t err = 0;
	struct iovec iov_in;

	if (!knet_h) {
		errno = EINVAL;
		return -1;
	}

	if (buff == NULL) {
		errno = EINVAL;
		return -1;
	}

	if (buff_len <= 0) {
		errno = EINVAL;
		return -1;
	}

	if (buff_len > KNET_MAX_PACKET_SIZE) {
		errno = EINVAL;
		return -1;
	}

	if (channel < 0) {
		errno = EINVAL;
		return -1;
	}

	if (channel >= KNET_DATAFD_MAX) {
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

	if (!knet_h->sockfd[channel].in_use) {
		savederrno = EINVAL;
		err = -1;
		goto out_unlock;
	}

	memset(&iov_in, 0, sizeof(iov_in));
	iov_in.iov_base = (void *)buff;
	iov_in.iov_len = buff_len;

	err = readv(knet_h->sockfd[channel].sockfd[0], &iov_in, 1);
	savederrno = errno;

out_unlock:
	pthread_rwlock_unlock(&knet_h->global_rwlock);
	errno = savederrno;
	return err;
}

ssize_t knet_send(knet_handle_t knet_h, const char *buff, const size_t buff_len, const int8_t channel)
{
	int savederrno = 0;
	ssize_t err = 0;
	struct iovec iov_out[1];

	if (!knet_h) {
		errno = EINVAL;
		return -1;
	}

	if (buff == NULL) {
		errno = EINVAL;
		return -1;
	}

	if (buff_len <= 0) {
		errno = EINVAL;
		return -1;
	}

	if (buff_len > KNET_MAX_PACKET_SIZE) {
		errno = EINVAL;
		return -1;
	}

	if (channel < 0) {
		errno = EINVAL;
		return -1;
	}

	if (channel >= KNET_DATAFD_MAX) {
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

	if (!knet_h->sockfd[channel].in_use) {
		savederrno = EINVAL;
		err = -1;
		goto out_unlock;
	}

	memset(iov_out, 0, sizeof(iov_out));

	iov_out[0].iov_base = (void *)buff;
	iov_out[0].iov_len = buff_len;

	err = writev(knet_h->sockfd[channel].sockfd[0], iov_out, 1);
	savederrno = errno;

out_unlock:
	pthread_rwlock_unlock(&knet_h->global_rwlock);
	errno = savederrno;
	return err;
}

int knet_handle_get_stats(knet_handle_t knet_h, struct knet_handle_stats *stats, size_t struct_size)
{
	int savederrno = 0;
	int err = 0;

	if (!knet_h) {
		errno = EINVAL;
		return -1;
	}

	if (!stats) {
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

	if (struct_size > sizeof(struct knet_handle_stats)) {
		struct_size = sizeof(struct knet_handle_stats);
	}

	memmove(stats, &knet_h->stats, struct_size);

	/*
	 * TX crypt stats only count the data packets sent, so add in the ping/pong/pmtud figures
	 * RX is OK as it counts them before they are sorted.
	 */

	stats->tx_crypt_packets += knet_h->stats_extra.tx_crypt_ping_packets +
		knet_h->stats_extra.tx_crypt_pong_packets +
		knet_h->stats_extra.tx_crypt_pmtu_packets +
		knet_h->stats_extra.tx_crypt_pmtu_reply_packets;

	/* Tell the caller our full size in case they have an old version */
	stats->size = sizeof(struct knet_handle_stats);

	pthread_rwlock_unlock(&knet_h->global_rwlock);
	errno = savederrno;
	return err;
}

int knet_handle_clear_stats(knet_handle_t knet_h, int clear_option)
{
	int savederrno = 0;
	int err = 0;

	if (!knet_h) {
		errno = EINVAL;
		return -1;
	}

	if (clear_option != KNET_CLEARSTATS_HANDLE_ONLY &&
	    clear_option != KNET_CLEARSTATS_HANDLE_AND_LINK) {
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

	memset(&knet_h->stats, 0, sizeof(struct knet_handle_stats));
	memset(&knet_h->stats_extra, 0, sizeof(struct knet_handle_stats_extra));
	if (clear_option == KNET_CLEARSTATS_HANDLE_AND_LINK) {
		_link_clear_stats(knet_h);
	}

	pthread_rwlock_unlock(&knet_h->global_rwlock);
	errno = savederrno;
	return err;
}

