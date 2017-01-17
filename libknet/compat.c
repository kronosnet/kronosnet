/*
 * Copyright (C) 2016 Red Hat, Inc.  All rights reserved.
 *
 * Author: Jan Friesse <jfriesse@redhat.com>
 *
 * This software licensed under GPL-2.0+, LGPL-2.0+
 */

#include "config.h"

#include <unistd.h>
#include <sys/syscall.h>

#include "compat.h"

#ifndef HAVE_SENDMMSG
int sendmmsg(int sockfd, struct mmsghdr *msgvec, unsigned int vlen,
    unsigned int flags)
{
#ifdef SYS_sendmmsg
	/*
	 * For systems where kernel supports sendmmsg but glibc doesn't (RHEL 6)
	 */
	return (syscall(SYS_sendmmsg, sockfd, msgvec, vlen, flags));
#else
	/*
	 * Generic implementation of sendmmsg using sendmsg
	 */
	unsigned int i;
	ssize_t ret;

	if (vlen == 0) {
		return (0);
	}

	for (i = 0; i < vlen; i++) {
		ret = sendmsg(sockfd, &msgvec[i].msg_hdr, flags);
		if (ret >= 0) {
			msgvec[i].msg_len = ret;
		} else {
			break ;
		}
	}

	return ((ret >= 0) ? vlen : ret);
#endif
}
#endif

#ifndef HAVE_RECVMMSG
extern int recvmmsg(int sockfd, struct mmsghdr *msgvec, unsigned int vlen,
    unsigned int flags, struct timespec *timeout)
{
#ifdef SYS_recvmmsg
	/*
	 * For systems where kernel supports recvmmsg but glibc doesn't (RHEL 6)
	 */
	return (syscall(SYS_recvmmsg, sockfd, msgvec, vlen, flags, timeout));
#else
	/*
	 * Generic implementation of recvmmsg using recvmsg
	 */
	unsigned int i;
	ssize_t ret;

	if (vlan == 0) {
		return (0);
	}

	if (timeout != NULL || (flags && MSG_WAITFORONE)) {
		/*
		 * Not implemented
		 */
		errno = EINVAL;
		return (-1);
	}

	for (i = 0; i < vlen; i++) {
		ret = recvmsg(sockfd, &msgvec[i].msg_hdr, flags);
		if (ret >= 0) {
			msgvec[i].msg_len = ret;
		} else {
			break ;
		}
	}

	return ((ret >= 0) ? vlen : ret);
#endif
}
#endif

#ifndef HAVE_SYS_EPOLL_H
#ifdef HAVE_KEVENT

/* for FreeBSD which has kevent instead of epoll */

#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>
#include <sys/errno.h>

static int32_t
_poll_to_filter_(int32_t event)
{
	int32_t out = 0;
	if (event & POLLIN)
		out |= EVFILT_READ;
	if (event & POLLOUT)
		out |= EVFILT_WRITE;
	return out;
}

int epoll_create(int size)
{
	return kqueue();
}


int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)
{
	int ret = 0;
	struct kevent ke;
	short filters = _poll_to_filter_(event->events);

	switch (op) {
		/* The kevent man page says that EV_ADD also does MOD */
		case EPOLL_CTL_ADD:
		case EPOLL_CTL_MOD:
			EV_SET(&ke, fd, filters, EV_ADD | EV_ENABLE, 0, 0, event->data.ptr);
			break;
		case EPOLL_CTL_DEL:
			EV_SET(&ke, fd, filters, EV_DELETE, 0, 0, event->data.ptr);
			break;
		default:
			errno = EINVAL;
			return -1;
	}
	ret = kevent(epfd, &ke, 1, NULL, 0, NULL);
	return ret;
}

int epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout_ms)
{
	struct kevent kevents[maxevents];
        struct timespec timeout = { 0, 0 };
        struct timespec *timeout_ptr = &timeout;
	uint32_t revents;
	int event_count;
	int i;
	int returned_events;

	if (timeout_ms != -1) {
	        timeout.tv_sec = timeout_ms/1000;
		timeout.tv_nsec += (timeout_ms % 1000) * 1000000ULL;
	}
	else {
		timeout_ptr = NULL;
	}

	event_count = kevent(epfd, NULL, 0, kevents, maxevents, timeout_ptr);
	if (event_count == -1) {
		return -1;
	}

	returned_events = 0;
	for (i = 0; i < event_count; i++) {
		revents = 0;

		if (kevents[i].flags & EV_ERROR) {
			revents |= POLLERR;
		}
		if (kevents[i].flags & EV_EOF) {
			revents |= POLLHUP;
		}
		if (kevents[i].filter == EVFILT_READ) {
			revents |= POLLIN;
		}
		if (kevents[i].filter == EVFILT_WRITE) {
			revents |= POLLOUT;
		}
		events[returned_events].events = revents;
		events[returned_events].data.ptr = kevents[i].udata;
		returned_events++;
	}

	return returned_events;
}
#endif /* HAVE_KEVENT */
#endif /* HAVE_SYS_EPOLL_H */
