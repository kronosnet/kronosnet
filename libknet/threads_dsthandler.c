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
#include <time.h>
#include <sys/uio.h>
#include <math.h>

#include "internals.h"
#include "onwire.h"
#include "crypto.h"
#include "common.h"
#include "host.h"
#include "logging.h"
#include "listener.h"
#include "link.h"
#include "threads_common.h"
#include "threads_dsthandler.h"

static void _handle_dst_link_updates(knet_handle_t knet_h)
{
	uint16_t host_id;
	struct knet_host *host;

	if (read(knet_h->dstpipefd[0], &host_id, sizeof(host_id)) != sizeof(host_id)) {
		log_debug(knet_h, KNET_SUB_SWITCH_T, "Short read on pipe");
		return;
	}

	if (pthread_rwlock_rdlock(&knet_h->list_rwlock) != 0) {
		log_debug(knet_h, KNET_SUB_SWITCH_T, "Unable to get read lock");
		return;
	}

	host = knet_h->host_index[host_id];
	if (!host) {
		log_debug(knet_h, KNET_SUB_SWITCH_T, "Unable to find host: %u", host_id);
		goto out_unlock;
	}

	_host_dstcache_update_sync(knet_h, host);

out_unlock:
	pthread_rwlock_unlock(&knet_h->list_rwlock);

	return;
}

void *_handle_dst_link_handler_thread(void *data)
{
	knet_handle_t knet_h = (knet_handle_t) data;
	struct epoll_event events[KNET_EPOLL_MAX_EVENTS];

	while (!knet_h->fini_in_progress) {
		if (epoll_wait(knet_h->dst_link_handler_epollfd, events, KNET_EPOLL_MAX_EVENTS, -1) >= 1)
			_handle_dst_link_updates(knet_h);
	}

	return NULL;
}
