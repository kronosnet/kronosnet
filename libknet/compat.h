/*
 * Copyright (C) 2016 Red Hat, Inc.  All rights reserved.
 *
 * Authors: Jan Friesse <jfriesse@redhat.com>
 *
 * This software licensed under GPL-2.0+, LGPL-2.0+
 */

#ifndef __COMPAT_H__
#define __COMPAT_H__

#include "config.h"
#include <sys/socket.h>
#include <stdint.h>

#ifndef HAVE_MMSGHDR
struct mmsghdr {
	struct msghdr msg_hdr;  /* Message header */
	unsigned int  msg_len;  /* Number of bytes transmitted */
};
#endif

#ifndef MSG_WAITFORONE
#define MSG_WAITFORONE  0x10000
#endif

#ifndef HAVE_SENDMMSG
extern int sendmmsg(int sockfd, struct mmsghdr *msgvec, unsigned int vlen,
    unsigned int flags);
#endif

#ifndef HAVE_RECVMMSG
extern int recvmmsg(int sockfd, struct mmsghdr *msgvec, unsigned int vlen,
    unsigned int flags, struct timespec *timeout);
#endif

#ifndef ETIME
#define ETIME ETIMEDOUT
#endif

#ifndef HAVE_EPOLL

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

int epoll_create(int size);
int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event);
int epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout_ms);

#endif

#endif
