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

#endif
