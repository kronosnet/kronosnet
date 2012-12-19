/*
 * Copyright (C) 2010-2012 Red Hat, Inc.  All rights reserved.
 *
 * Authors: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *          Federico Simoncelli <fsimon@kronosnet.org>
 *
 * This software licensed under GPL-2.0+, LGPL-2.0+
 */

#include "config.h"

#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/epoll.h>
#include <string.h>
#include <stdlib.h>

#include "internals.h"
#include "common.h"
#include "logging.h"

#define KNET_RING_RCVBUFF 8388608

int _listener_add(knet_handle_t knet_h, struct knet_link *lnk)
{
	int value;
	struct epoll_event ev;
	int save_errno = 0;
	struct knet_listener *listener;

	if (pthread_rwlock_wrlock(&knet_h->list_rwlock) != 0) {
		save_errno = errno;
		log_err(knet_h, KNET_SUB_LISTENER, "listener_add: Unable to get write lock");
		errno = save_errno;
		return -1;
	}

	listener = knet_h->listener_head;

	while (listener) {
		if (!memcmp(&lnk->src_addr, &listener->address, sizeof(struct sockaddr_storage))) {
			log_debug(knet_h, KNET_SUB_LISTENER, "found active listener");
			break;
		}
		listener = listener->next;
	}

	if (!listener) {
		listener = malloc(sizeof(struct knet_listener));
		if (!listener) {
			save_errno = errno;
			log_debug(knet_h, KNET_SUB_LISTENER, "out of memory to allocate listener");
			goto exit_fail1;
		}

		memset(listener, 0, sizeof(struct knet_listener));
		memcpy(&listener->address, &lnk->src_addr, sizeof(struct sockaddr_storage));

		listener->sock = socket(listener->address.ss_family, SOCK_DGRAM, 0);
		if (listener->sock < 0) {
			save_errno = errno;
			log_err(knet_h, KNET_SUB_LISTENER, "Unable to create listener socket");
			goto exit_fail2;
		}

		value = KNET_RING_RCVBUFF;
		setsockopt(listener->sock, SOL_SOCKET, SO_RCVBUFFORCE, &value, sizeof(value));

		if (listener->address.ss_family == AF_INET6) {
			value = 1;
			setsockopt(listener->sock, IPPROTO_IPV6, IPV6_V6ONLY,
				   &value, sizeof(value));
		}

		if (_fdset_cloexec(listener->sock) != 0) {
			save_errno = errno;
			log_err(knet_h, KNET_SUB_LISTENER, "Unable to set listener socket opts");
			goto exit_fail3;
		}

		if (bind(listener->sock, (struct sockaddr *) &listener->address,
						sizeof(struct sockaddr_storage)) != 0) {
			save_errno = errno;
			log_err(knet_h, KNET_SUB_LISTENER, "Unable to bind listener socket");
			goto exit_fail3;
		}

		memset(&ev, 0, sizeof(struct epoll_event));

		ev.events = EPOLLIN;
		ev.data.fd = listener->sock;

		if (epoll_ctl(knet_h->recv_from_links_epollfd, EPOLL_CTL_ADD, listener->sock, &ev) != 0) {
			save_errno = errno;
			log_err(knet_h, KNET_SUB_LISTENER, "Unable to add listener to epoll pool");
			goto exit_fail3;
		}

		/* pushing new host to the front */
		listener->next		= knet_h->listener_head;
		knet_h->listener_head	= listener;
	}
	lnk->listener_sock = listener->sock;

	pthread_rwlock_unlock(&knet_h->list_rwlock);

	return 0;

 exit_fail3:
	close(listener->sock);

 exit_fail2:
	if (listener)
		free(listener);

 exit_fail1:
	pthread_rwlock_unlock(&knet_h->list_rwlock);
	errno = save_errno;
	return -1;
}

int _listener_remove(knet_handle_t knet_h, struct knet_link *lnk)
{
	int link_idx, ret;
	struct epoll_event ev; /* kernel < 2.6.9 bug (see epoll_ctl man) */
	struct knet_host *host;
	struct knet_listener *tmp_listener;
	struct knet_listener *listener;
	int listener_cnt = 0;

	if (pthread_rwlock_wrlock(&knet_h->list_rwlock) != 0) {
		log_err(knet_h, KNET_SUB_LISTENER, "listener_remove: Unable to get write lock");
		return -EINVAL;
	}

	ret = 0;

	/* checking if listener is in use */
	for (host = knet_h->host_head; host != NULL; host = host->next) {
		for (link_idx = 0; link_idx < KNET_MAX_LINK; link_idx++) {
			if (host->link[link_idx].status.configured != 1)
				continue;

			if (host->link[link_idx].listener_sock == lnk->listener_sock) {
				listener_cnt++;
			}
		}
	}

	if (listener_cnt > 1) {
		log_debug(knet_h, KNET_SUB_LISTENER, "listener_remove: listener still in use");
		ret = EBUSY;
		goto exit_unlock;
	}

	listener = knet_h->listener_head;
	while (listener) {
		if (listener->sock == lnk->listener_sock)
			break;
		listener = listener->next;
	}

	/* TODO: use a doubly-linked list? */
	if (listener == knet_h->listener_head) {
		knet_h->listener_head = knet_h->listener_head->next;
	} else {
		for (tmp_listener = knet_h->listener_head; tmp_listener != NULL; tmp_listener = tmp_listener->next) {
			if (listener == tmp_listener->next) {
				tmp_listener->next = tmp_listener->next->next;
				break;
			}
		}
	}

	epoll_ctl(knet_h->recv_from_links_epollfd, EPOLL_CTL_DEL, listener->sock, &ev);
	close(listener->sock);
	free(listener);

 exit_unlock:
	pthread_rwlock_unlock(&knet_h->list_rwlock);

	if (ret < 0)
		errno = -ret;
	return ret;
}
