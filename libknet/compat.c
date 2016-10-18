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
