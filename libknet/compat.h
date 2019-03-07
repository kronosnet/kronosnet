/*
 * Copyright (C) 2016-2018 Red Hat, Inc.  All rights reserved.
 *
 * Authors: Jan Friesse <jfriesse@redhat.com>
 *
 * This software licensed under GPL-2.0+, LGPL-2.0+
 */

#ifndef __KNET_COMPAT_H__
#define __KNET_COMPAT_H__

#include "config.h"
#include <sys/socket.h>
#include <stdint.h>

#ifndef ETIME
#define ETIME ETIMEDOUT
#endif

#ifdef HAVE_SYS_EPOLL_H
#include <sys/epoll.h>
#else
#ifdef HAVE_KEVENT
#include <poll.h>
#define EPOLL_CTL_ADD 1
#define EPOLL_CTL_MOD 2
#define EPOLL_CTL_DEL 3

#define EPOLLIN POLLIN
#define EPOLLOUT POLLOUT

typedef union epoll_data {
	void        *ptr;
	int          fd;
	uint32_t     u32;
	uint64_t     u64;
} epoll_data_t;

struct epoll_event {
	uint32_t     events;      /* Epoll events */
	epoll_data_t data;        /* User data variable */
};

int epoll_create1(int flags);
int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event);
int epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout_ms);

#endif /* HAVE_KEVENT */
#endif /* HAVE_SYS_EPOLL_H */
#endif /* __KNET_COMPAT_H__ */
