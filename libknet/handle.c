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
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>

#include "internals.h"
#include "onwire.h"
#include "crypto.h"
#include "common.h"
#include "host.h"
#include "logging.h"
#include "listener.h"
#include "link.h"
#include "threads.h"

knet_handle_t knet_handle_new(uint16_t host_id,
			      int      net_fd,
			      int      log_fd,
			      uint8_t  default_log_level)
{
	knet_handle_t knet_h;
	struct epoll_event ev;

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

	if ((knet_h = malloc(sizeof(struct knet_handle))) == NULL) {
		return NULL;
	}

	memset(knet_h, 0, sizeof(struct knet_handle));

	knet_h->host_id = host_id;
	knet_h->sockfd = net_fd;
	knet_h->logfd = log_fd;

	if (knet_h->logfd > 0) {
		memset(&knet_h->log_levels, default_log_level, KNET_MAX_SUBSYSTEMS);
	}

	if (pipe(knet_h->dstpipefd) ||
	    pipe(knet_h->hostpipefd)) {
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to initialize internal comm pipe");
		goto exit_fail1;
	}

	if ((_fdset_cloexec(knet_h->dstpipefd[0])) ||
	    (_fdset_cloexec(knet_h->dstpipefd[1])) ||
	    (_fdset_nonblock(knet_h->dstpipefd[0])) ||
	    (_fdset_nonblock(knet_h->dstpipefd[1])) ||
	    (_fdset_cloexec(knet_h->hostpipefd[0])) ||
	    (_fdset_cloexec(knet_h->hostpipefd[1])) ||
	    (_fdset_nonblock(knet_h->hostpipefd[0])) ||
	    (_fdset_nonblock(knet_h->hostpipefd[1]))) {
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to set internal comm pipe sockopts");
		goto exit_fail2;
	}

	if ((knet_h->tap_to_links_buf = malloc(KNET_DATABUFSIZE))== NULL) {
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to allocate memory for tap to link buffer");
		goto exit_fail2;
	}

	memset(knet_h->tap_to_links_buf, 0, KNET_DATABUFSIZE);

	if ((knet_h->recv_from_links_buf = malloc(KNET_DATABUFSIZE))== NULL) {
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to allocate memory for link to tap buffer");
		goto exit_fail3;
	}

	memset(knet_h->recv_from_links_buf, 0, KNET_DATABUFSIZE);

	if ((knet_h->pingbuf = malloc(KNET_PING_SIZE))== NULL) {
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to allocate memory for hearbeat buffer");
		goto exit_fail4;
	}

	memset(knet_h->pingbuf, 0, KNET_PING_SIZE);

	if ((pthread_rwlock_init(&knet_h->list_rwlock, NULL) != 0) ||
	    (pthread_rwlock_init(&knet_h->host_rwlock, NULL) != 0) ||
	    (pthread_mutex_init(&knet_h->host_mutex, NULL) != 0) ||
	    (pthread_cond_init(&knet_h->host_cond, NULL) != 0)) {
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to initialize locks");
		goto exit_fail5;
	}

	knet_h->tap_to_links_epollfd = epoll_create(KNET_MAX_EVENTS);
	knet_h->recv_from_links_epollfd = epoll_create(KNET_MAX_EVENTS);
	knet_h->dst_link_handler_epollfd = epoll_create(KNET_MAX_EVENTS);

	if ((knet_h->tap_to_links_epollfd < 0) ||
	    (knet_h->recv_from_links_epollfd < 0) ||
	    (knet_h->dst_link_handler_epollfd < 0)) {
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to create epoll(s) fd(s)");
		goto exit_fail6;
	}

	if ((_fdset_cloexec(knet_h->tap_to_links_epollfd) != 0) ||
	    (_fdset_cloexec(knet_h->recv_from_links_epollfd) != 0) ||
	    (_fdset_cloexec(knet_h->dst_link_handler_epollfd) != 0)) {
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to set epoll(s) fd(s) opt(s)");
		goto exit_fail6;
	}

	memset(&ev, 0, sizeof(struct epoll_event));

	ev.events = EPOLLIN;
	ev.data.fd = knet_h->sockfd;

	if (epoll_ctl(knet_h->tap_to_links_epollfd,
				EPOLL_CTL_ADD, knet_h->sockfd, &ev) != 0) {
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to add tapfd to epoll pool");
		goto exit_fail6;
	}

	memset(&ev, 0, sizeof(struct epoll_event));

	ev.events = EPOLLIN;
	ev.data.fd = knet_h->hostpipefd[0];

	if (epoll_ctl(knet_h->tap_to_links_epollfd,
				EPOLL_CTL_ADD, knet_h->hostpipefd[0], &ev) != 0) {
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to add hostpipefd to epoll pool");
		goto exit_fail6;
	}

	memset(&ev, 0, sizeof(struct epoll_event));

	ev.events = EPOLLIN;
	ev.data.fd = knet_h->dstpipefd[0];

	if (epoll_ctl(knet_h->dst_link_handler_epollfd,
				EPOLL_CTL_ADD, knet_h->dstpipefd[0], &ev) != 0) {
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to add dstpipefd to epoll pool");
		goto exit_fail6;
	}

	if (pthread_create(&knet_h->dst_link_handler_thread, 0,
				_handle_dst_link_handler_thread, (void *) knet_h) != 0) {
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to start switching manager thread");
		goto exit_fail6;
	}

	if (pthread_create(&knet_h->tap_to_links_thread, 0,
				_handle_tap_to_links_thread, (void *) knet_h) != 0) {
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to start sending thread");
		goto exit_fail7;
	}

	if (pthread_create(&knet_h->recv_from_links_thread, 0,
				_handle_recv_from_links_thread, (void *) knet_h) != 0) {
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to start receiving thread");
		goto exit_fail8;
	}

	if (pthread_create(&knet_h->heartbt_thread, 0,
				_handle_heartbt_thread, (void *) knet_h) != 0) {
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to start heartbeat thread");
		goto exit_fail9;
	}

	return knet_h;

exit_fail9:
	pthread_cancel(knet_h->recv_from_links_thread);

exit_fail8:
	pthread_cancel(knet_h->tap_to_links_thread);

exit_fail7:
	pthread_cancel(knet_h->dst_link_handler_thread);

exit_fail6:
	if (knet_h->tap_to_links_epollfd >= 0)
		close(knet_h->tap_to_links_epollfd);
	if (knet_h->recv_from_links_epollfd >= 0)
		close(knet_h->recv_from_links_epollfd);
	if (knet_h->dst_link_handler_epollfd >= 0)
		close(knet_h->dst_link_handler_epollfd);

	pthread_rwlock_destroy(&knet_h->list_rwlock);
	pthread_rwlock_destroy(&knet_h->host_rwlock);
	pthread_mutex_destroy(&knet_h->host_mutex);
	pthread_cond_destroy(&knet_h->host_cond);

exit_fail5:
	free(knet_h->pingbuf);

exit_fail4:
	free(knet_h->recv_from_links_buf);

exit_fail3:
	free(knet_h->tap_to_links_buf);

exit_fail2:
	close(knet_h->dstpipefd[0]);
	close(knet_h->dstpipefd[1]);
	close(knet_h->hostpipefd[0]);
	close(knet_h->hostpipefd[1]);

exit_fail1:
	free(knet_h);
	return NULL;
}

int knet_handle_free(knet_handle_t knet_h)
{
	void *retval;
	struct epoll_event ev;

	if ((knet_h->host_head != NULL) || (knet_h->listener_head != NULL)) {
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to free handle: host(s) or listener(s) are still active");
		goto exit_busy;
	}

	if (epoll_ctl(knet_h->tap_to_links_epollfd, EPOLL_CTL_DEL, knet_h->sockfd, &ev)) {
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to remove epoll sockfd");
		goto exit_busy;
	}

	if (epoll_ctl(knet_h->tap_to_links_epollfd, EPOLL_CTL_DEL, knet_h->hostpipefd[0], &ev)) {
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to remove epoll hostpipefd");
		goto exit_busy;
	}

	if (epoll_ctl(knet_h->dst_link_handler_epollfd, EPOLL_CTL_DEL, knet_h->dstpipefd[0], &ev)) {
		log_err(knet_h, KNET_SUB_HANDLE, "knet_handle_free real: unable to remove epoll dstpipefd");
		goto exit_busy;
	}

	pthread_cancel(knet_h->heartbt_thread);
	pthread_join(knet_h->heartbt_thread, &retval);

	if (retval != PTHREAD_CANCELED) {
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to stop heartbeat thread");
		goto exit_busy;
	}

	pthread_cancel(knet_h->tap_to_links_thread);
	pthread_join(knet_h->tap_to_links_thread, &retval);
	if (retval != PTHREAD_CANCELED) {
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to stop sending thread");
		goto exit_busy;
	}

	pthread_cancel(knet_h->recv_from_links_thread);
	pthread_join(knet_h->recv_from_links_thread, &retval);

	if (retval != PTHREAD_CANCELED) {
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to stop receiving thread");
		goto exit_busy;
	}

	pthread_cancel(knet_h->dst_link_handler_thread);
	pthread_join(knet_h->dst_link_handler_thread, &retval);

	if (retval != PTHREAD_CANCELED) {
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to stop switching manager thread");
		goto exit_busy;
	}

	close(knet_h->tap_to_links_epollfd);
	close(knet_h->recv_from_links_epollfd);
	close(knet_h->dst_link_handler_epollfd);
	close(knet_h->dstpipefd[0]);
	close(knet_h->dstpipefd[1]);
	close(knet_h->hostpipefd[0]);
	close(knet_h->hostpipefd[1]);

	pthread_rwlock_destroy(&knet_h->list_rwlock);
	pthread_rwlock_destroy(&knet_h->host_rwlock);
	pthread_mutex_destroy(&knet_h->host_mutex);
	pthread_cond_destroy(&knet_h->host_cond);

	free(knet_h->tap_to_links_buf);
	free(knet_h->tap_to_links_buf_crypt);
	free(knet_h->recv_from_links_buf);
	free(knet_h->recv_from_links_buf_crypt);
	free(knet_h->pingbuf);
	free(knet_h->pingbuf_crypt);

	crypto_fini(knet_h);

	free(knet_h);

	return 0;

 exit_busy:
	errno = EBUSY;
	return -EBUSY;
}

int knet_handle_enable_filter(knet_handle_t knet_h,
			      int (*dst_host_filter_fn) (
					const unsigned char *outdata,
					ssize_t outdata_len,
					uint16_t src_node_id,
					uint16_t *dst_host_ids,
					size_t *dst_host_ids_entries))
{
	knet_h->dst_host_filter_fn = dst_host_filter_fn;
	if (knet_h->dst_host_filter_fn) {
		log_debug(knet_h, KNET_SUB_HANDLE, "dst_host_filter_fn enabled");
	} else {
		log_debug(knet_h, KNET_SUB_HANDLE, "dst_host_filter_fn disabled");
	}
	return 0;
}

int knet_handle_setfwd(knet_handle_t knet_h, int enabled)
{
	knet_h->enabled = (enabled == 1) ? 1 : 0;

	return 0;
}

int knet_handle_crypto(knet_handle_t knet_h, struct knet_handle_crypto_cfg *knet_handle_crypto_cfg)
{
	if (knet_h->enabled) {
		log_err(knet_h, KNET_SUB_CRYPTO, "Cannot enable crypto while forwarding is enabled");
		return -1;
	}

	crypto_fini(knet_h);

	if ((!strncmp("none", knet_handle_crypto_cfg->crypto_model, 4)) || 
	    ((!strncmp("none", knet_handle_crypto_cfg->crypto_cipher_type, 4)) &&
	     (!strncmp("none", knet_handle_crypto_cfg->crypto_hash_type, 4)))) {
		log_debug(knet_h, KNET_SUB_CRYPTO, "crypto is not enabled");
		return 0;
	}

	if (!knet_h->tap_to_links_buf_crypt) {
		knet_h->tap_to_links_buf_crypt = malloc(KNET_DATABUFSIZE_CRYPT);
		if (!knet_h->tap_to_links_buf_crypt) {
			log_err(knet_h, KNET_SUB_CRYPTO, "unable to allocate memory for crypto send buffer");
			return -1;
		}
	}

	if (!knet_h->pingbuf_crypt) {
		knet_h->pingbuf_crypt = malloc(KNET_DATABUFSIZE_CRYPT);
		if (!knet_h->pingbuf_crypt) {
			log_err(knet_h, KNET_SUB_CRYPTO, "unable to allocate memory for crypto hb buffer");
			goto exit_fail1;
		}
	}

	if (!knet_h->recv_from_links_buf_crypt) {
		knet_h->recv_from_links_buf_crypt = malloc(KNET_DATABUFSIZE_CRYPT);
		if (!knet_h->recv_from_links_buf_crypt) {
			log_err(knet_h, KNET_SUB_CRYPTO, "unable to allocate memory for crypto recv buffer");
			goto exit_fail2;
		}
	}

	return crypto_init(knet_h, knet_handle_crypto_cfg);

exit_fail2:
	free(knet_h->pingbuf_crypt);
	knet_h->pingbuf_crypt = NULL;

exit_fail1:
	free(knet_h->tap_to_links_buf_crypt);
	knet_h->tap_to_links_buf_crypt = NULL;
	return -1;
}
