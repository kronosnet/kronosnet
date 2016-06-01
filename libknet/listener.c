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
#include <errno.h>
#include <pthread.h>
#include <sys/epoll.h>
#include <string.h>
#include <stdlib.h>

#include "internals.h"
#include "common.h"
#include "logging.h"
#include "listener.h"

int _listener_add(knet_handle_t knet_h, uint16_t host_id, uint8_t link_id)
{
	int value, count = 0;
	struct epoll_event ev;
	int savederrno = 0, err = 0;
	struct knet_link *lnk = &knet_h->host_index[host_id]->link[link_id];
	struct knet_listener *listener = NULL;

	savederrno = pthread_rwlock_wrlock(&knet_h->listener_rwlock);
	if (savederrno) {
		log_err(knet_h, KNET_SUB_LISTENER, "Unable to get write lock: %s",
			strerror(savederrno));
		errno = savederrno;
		return -1;
	}

	listener = knet_h->listener_head;

	while (listener) {
		count++;
		log_debug(knet_h, KNET_SUB_LISTENER, "checking listener: %d", count);
		if (!memcmp(&lnk->src_addr, &listener->address, sizeof(struct sockaddr_storage))) {
			log_debug(knet_h, KNET_SUB_LISTENER, "found active listener");
			break;
		}
		listener = listener->next;
	}

	if (!listener) {
		listener = malloc(sizeof(struct knet_listener));
		if (!listener) {
			savederrno = errno;
			err = -1;
			log_err(knet_h, KNET_SUB_LISTENER, "out of memory to allocate listener: %s",
				  strerror(savederrno));
			goto exit_unlock;
		}

		memset(listener, 0, sizeof(struct knet_listener));
		memmove(&listener->address, &lnk->src_addr, sizeof(struct sockaddr_storage));

		listener->sock = socket(listener->address.ss_family, SOCK_DGRAM, 0);
		if (listener->sock < 0) {
			savederrno = errno;
			err = -1;
			log_err(knet_h, KNET_SUB_LISTENER, "Unable to create listener socket: %s",
				strerror(savederrno));
			goto exit_unlock;
		}

		value = KNET_RING_RCVBUFF;
		if (setsockopt(listener->sock, SOL_SOCKET, SO_RCVBUFFORCE, &value, sizeof(value)) < 0) {
			savederrno = errno;
			err = -1;
			log_err(knet_h, KNET_SUB_LISTENER, "Unable to set listener receive buffer: %s",
				strerror(savederrno));
			goto exit_unlock;
		}

		value = 1;
		if (setsockopt(listener->sock, SOL_IP, IP_FREEBIND, &value, sizeof(value)) <0) {
			savederrno = errno;
			err = -1;
			log_err(knet_h, KNET_SUB_LISTENER, "Unable to set FREEBIND on listener socket: %s",
				strerror(savederrno));
			goto exit_unlock;
		}

		if (listener->address.ss_family == AF_INET6) {
			value = 1;
			if (setsockopt(listener->sock, IPPROTO_IPV6, IPV6_V6ONLY,
				       &value, sizeof(value)) < 0) {
				savederrno = errno;
				err = -1;
				log_err(knet_h, KNET_SUB_LISTENER, "Unable to set listener IPv6 only: %s",
					strerror(savederrno));
				goto exit_unlock;

			}
			value = IPV6_PMTUDISC_PROBE;
			if (setsockopt(listener->sock, SOL_IPV6, IPV6_MTU_DISCOVER, &value, sizeof(value)) <0) {
				savederrno = errno;
				err = -1;
				log_err(knet_h, KNET_SUB_LISTENER, "Unable to set PMTUDISC on listener socket: %s",
					strerror(savederrno));
				goto exit_unlock;
			}
		} else {
			value = IP_PMTUDISC_PROBE;
			if (setsockopt(listener->sock, SOL_IP, IP_MTU_DISCOVER, &value, sizeof(value)) <0) {
				savederrno = errno;
				err = -1;
				log_err(knet_h, KNET_SUB_LISTENER, "Unable to set PMTUDISC on listener socket: %s",
					strerror(savederrno));
				goto exit_unlock;
			}
		}

		if (_fdset_cloexec(listener->sock)) {
			savederrno = errno;
			err = -1;
			log_err(knet_h, KNET_SUB_LISTENER, "Unable to set listener CLOEXEC socket opts: %s",
				strerror(savederrno));
			goto exit_unlock;
		}

		if (_fdset_nonblock(listener->sock)) {
			savederrno = errno;
			err = -1;
			log_err(knet_h, KNET_SUB_LISTENER, "Unable to set listener NONBLOCK socket opts: %s",
				strerror(savederrno));
			goto exit_unlock;
		}

		if (bind(listener->sock, (struct sockaddr *)&listener->address, sizeof(struct sockaddr_storage)) < 0) {
			savederrno = errno;
			err = -1;
			log_err(knet_h, KNET_SUB_LISTENER, "Unable to bind listener socket: %s",
				strerror(savederrno));
			goto exit_unlock;
		}

		memset(&ev, 0, sizeof(struct epoll_event));

		ev.events = EPOLLIN;
		ev.data.fd = listener->sock;

		if (epoll_ctl(knet_h->recv_from_links_epollfd, EPOLL_CTL_ADD, listener->sock, &ev)) {
			savederrno = errno;
			err = -1;
			log_err(knet_h, KNET_SUB_LISTENER, "Unable to add listener to epoll pool: %s",
				strerror(savederrno));
			goto exit_unlock;
		}

		/* pushing new host to the front */
		listener->next		= knet_h->listener_head;
		knet_h->listener_head	= listener;
	}
	lnk->listener_sock = listener->sock;

exit_unlock:
	if ((err) && (listener)) {
		if (listener->sock >= 0) {
			close(listener->sock);
		}
		free(listener);
		listener = NULL;
	}

	pthread_rwlock_unlock(&knet_h->listener_rwlock);
	errno = savederrno;
	return err;
}

int _listener_remove(knet_handle_t knet_h, uint16_t host_id, uint8_t link_id)
{
	int err = 0, savederrno = 0;
	int link_idx;
	struct epoll_event ev; /* kernel < 2.6.9 bug (see epoll_ctl man) */
	struct knet_host *host;
	struct knet_link *lnk = &knet_h->host_index[host_id]->link[link_id];
	struct knet_listener *tmp_listener;
	struct knet_listener *listener;
	int listener_cnt = 0;

	savederrno = pthread_rwlock_wrlock(&knet_h->listener_rwlock);
	if (savederrno) {
		log_err(knet_h, KNET_SUB_LISTENER, "Unable to get write lock: %s",
			strerror(savederrno));
		errno = savederrno;
		return -1;
	}

	/* checking if listener is in use */
	for (host = knet_h->host_head; host != NULL; host = host->next) {
		for (link_idx = 0; link_idx < KNET_MAX_LINK; link_idx++) {
			if (host->link[link_idx].status.enabled != 1)
				continue;

			if (host->link[link_idx].listener_sock == lnk->listener_sock) {
				listener_cnt++;
			}
		}
	}

	if (listener_cnt) {
		lnk->listener_sock = 0;
		log_debug(knet_h, KNET_SUB_LISTENER, "listener_remove: listener still in use");
		savederrno = EBUSY;
		err = -1;
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
	pthread_rwlock_unlock(&knet_h->listener_rwlock);

	errno = savederrno;
	return err;
}

#if 0
void socket_debug(knet_handle_t knet_h, int sockfd)
{
	struct sockaddr_storage sock;
	char host[KNET_MAX_HOST_LEN];
	char port[KNET_MAX_PORT_LEN];
	socklen_t socklen = sizeof(struct sockaddr_storage);
	int err;

	memset(&host, 0, KNET_MAX_HOST_LEN);
	memset(&port, 0, KNET_MAX_PORT_LEN);

	if (getsockname(sockfd, (struct sockaddr *)&sock, &socklen) < 0) {
		log_debug(knet_h, KNET_SUB_LINK_T, "Unable to getsockname: %s", strerror(errno));
	} else {
		err = getnameinfo((const struct sockaddr *)&sock, sizeof(struct sockaddr_storage),
				(char *)&host, KNET_MAX_HOST_LEN, (char *)&port, KNET_MAX_PORT_LEN, NI_NUMERICHOST | NI_NUMERICSERV);
		if (err) {
			log_debug(knet_h, KNET_SUB_LINK_T, "Unable to getnameinfo: %d", err);
		} else {
			log_debug(knet_h, KNET_SUB_LINK_T, "Sock host: %s port: %s", host, port);
		}
	}

	return;
}
#endif
