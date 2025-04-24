/*
 * Copyright (C) 2020-2025 Red Hat, Inc.  All rights reserved.
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
#include <sys/uio.h>

#include "internals.h"
#include "crypto.h"
#include "links.h"
#include "common.h"
#include "transport_common.h"
#include "logging.h"

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
	int savederrno = 0;

	if (!_is_valid_handle(knet_h)) {
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

	return 0;
}

int knet_handle_add_datafd(knet_handle_t knet_h, int *datafd, int8_t *channel)
{
	int err = 0, savederrno = 0;
	int i;
	struct epoll_event ev;

	if (!_is_valid_handle(knet_h)) {
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
	errno = err ? savederrno : 0;
	return err;
}

int knet_handle_remove_datafd(knet_handle_t knet_h, int datafd)
{
	int err = 0, savederrno = 0;
	int8_t channel = -1;
	int i;
	struct epoll_event ev;

	if (!_is_valid_handle(knet_h)) {
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
	errno = err ? savederrno : 0;
	return err;
}

int knet_handle_get_datafd(knet_handle_t knet_h, const int8_t channel, int *datafd)
{
	int err = 0, savederrno = 0;

	if (!_is_valid_handle(knet_h)) {
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
	errno = err ? savederrno : 0;
	return err;
}

int knet_handle_get_channel(knet_handle_t knet_h, const int datafd, int8_t *channel)
{
	int err = 0, savederrno = 0;
	int i;

	if (!_is_valid_handle(knet_h)) {
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
	errno = err ? savederrno : 0;
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

	knet_h->dst_host_filter_fn_private_data = dst_host_filter_fn_private_data;
	knet_h->dst_host_filter_fn = dst_host_filter_fn;
	if (knet_h->dst_host_filter_fn) {
		log_debug(knet_h, KNET_SUB_HANDLE, "dst_host_filter_fn enabled");
	} else {
		log_debug(knet_h, KNET_SUB_HANDLE, "dst_host_filter_fn disabled");
	}

	pthread_rwlock_unlock(&knet_h->global_rwlock);

	errno = 0;
	return 0;
}

int knet_handle_setfwd(knet_handle_t knet_h, unsigned int enabled)
{
	int savederrno = 0;

	if (!_is_valid_handle(knet_h)) {
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

	if (enabled) {
		knet_h->enabled = enabled;
		log_debug(knet_h, KNET_SUB_HANDLE, "Data forwarding is enabled");
	} else {
		/*
		 * notify TX and RX threads to flush the queues
		 */
		if (set_thread_flush_queue(knet_h, KNET_THREAD_TX, KNET_THREAD_QUEUE_FLUSH) < 0) {
			log_debug(knet_h, KNET_SUB_HANDLE, "Unable to request queue flushing for TX thread");
		}
		if (set_thread_flush_queue(knet_h, KNET_THREAD_RX, KNET_THREAD_QUEUE_FLUSH) < 0) {
			log_debug(knet_h, KNET_SUB_HANDLE, "Unable to request queue flushing for RX thread");
		}
	}

	pthread_rwlock_unlock(&knet_h->global_rwlock);

	/*
	 * when disabling data forward, we need to give time to TX and RX
	 * to flush the queues.
	 *
	 * the TX thread is the main leader here. When there is no more
	 * data in the TX queue, we will also close traffic for RX.
	 */
	if (!enabled) {
		/*
		 * this usleep might be unnecessary, but wait_all_threads_flush_queue
		 * adds extra locking delay.
		 *
		 * allow all threads to run free without extra locking interference
		 * and then we switch to a more active wait in case the scheduler
		 * has decided to delay one thread or another
		 */
		usleep(KNET_THREADS_TIMERES * 2);
		wait_all_threads_flush_queue(knet_h);

		/*
		 * all threads have done flushing the queue, we can stop data forwarding
		 */
		savederrno = get_global_wrlock(knet_h);
		if (savederrno) {
			log_err(knet_h, KNET_SUB_HANDLE, "Unable to get write lock: %s",
				strerror(savederrno));
			errno = savederrno;
			return -1;
		}
		knet_h->enabled = enabled;
		log_debug(knet_h, KNET_SUB_HANDLE, "Data forwarding is disabled");
		pthread_rwlock_unlock(&knet_h->global_rwlock);
	}

	errno = 0;
	return 0;
}

int knet_handle_get_stats(knet_handle_t knet_h, struct knet_handle_stats *stats, size_t struct_size)
{
	int err = 0, savederrno = 0;

	if (!_is_valid_handle(knet_h)) {
		return -1;
	}

	if (!stats) {
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

	savederrno = pthread_mutex_lock(&knet_h->handle_stats_mutex);
	if (savederrno) {
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to get mutex lock: %s",
			strerror(savederrno));
		err = -1;
		goto out_unlock;
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

out_unlock:
	pthread_mutex_unlock(&knet_h->handle_stats_mutex);
	pthread_rwlock_unlock(&knet_h->global_rwlock);
	return err;
}

int knet_handle_clear_stats(knet_handle_t knet_h, int clear_option)
{
	int savederrno = 0;

	if (!_is_valid_handle(knet_h)) {
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
	return 0;
}

int knet_handle_enable_access_lists(knet_handle_t knet_h, unsigned int enabled)
{
	int savederrno = 0;

	if (!_is_valid_handle(knet_h)) {
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

	knet_h->use_access_lists = enabled;

	if (enabled) {
		log_debug(knet_h, KNET_SUB_HANDLE, "Links access lists are enabled");
	} else {
		log_debug(knet_h, KNET_SUB_HANDLE, "Links access lists are disabled");
	}

	pthread_rwlock_unlock(&knet_h->global_rwlock);

	errno = 0;
	return 0;
}
