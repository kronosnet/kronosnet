/*
 * Copyright (C) 2010-2015 Red Hat, Inc.  All rights reserved.
 *
 * Authors: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *          Federico Simoncelli <fsimon@kronosnet.org>
 *
 * This software licensed under GPL-2.0+, LGPL-2.0+
 */

#include "config.h"

#include <unistd.h>
#include <pthread.h>
#include <sys/epoll.h>

#include "host.h"
#include "logging.h"
#include "threads_common.h"
#include "threads_dsthandler.h"

static void _handle_dst_link_updates(knet_handle_t knet_h)
{
	uint16_t host_id;
	struct knet_host *host;

	if (recv(knet_h->dstsockfd[0], &host_id, sizeof(host_id), MSG_DONTWAIT | MSG_NOSIGNAL) != sizeof(host_id)) {
		log_debug(knet_h, KNET_SUB_DSTCACHE, "Short read on dstsockfd");
		return;
	}

	if (pthread_rwlock_wrlock(&knet_h->global_rwlock) != 0) {
		log_debug(knet_h, KNET_SUB_DSTCACHE, "Unable to get read lock");
		return;
	}

	host = knet_h->host_index[host_id];
	if (!host) {
		log_debug(knet_h, KNET_SUB_DSTCACHE, "Unable to find host: %u", host_id);
		goto out_unlock;
	}

	_host_dstcache_update_sync(knet_h, host);

out_unlock:
	pthread_rwlock_unlock(&knet_h->global_rwlock);

	return;
}

void *_handle_dst_link_handler_thread(void *data)
{
	knet_handle_t knet_h = (knet_handle_t) data;
	struct epoll_event events[KNET_EPOLL_MAX_EVENTS];

	while (!shutdown_in_progress(knet_h)) {
		if (epoll_wait(knet_h->dst_link_handler_epollfd, events, KNET_EPOLL_MAX_EVENTS, -1) >= 1)
			_handle_dst_link_updates(knet_h);
	}

	return NULL;
}
