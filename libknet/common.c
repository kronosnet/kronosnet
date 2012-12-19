/*
 * Copyright (C) 2010-2012 Red Hat, Inc.  All rights reserved.
 *
 * Author: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *
 * This software licensed under GPL-2.0+, LGPL-2.0+
 */

#include "config.h"

#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <pthread.h>
#include <strings.h>

#include "internals.h"
#include "common.h"
#include "logging.h"

int _fdset_cloexec(int fd)
{
	int fdflags;

	fdflags = fcntl(fd, F_GETFD, 0);
	if (fdflags < 0)
		return -1;

	fdflags |= FD_CLOEXEC;

	if (fcntl(fd, F_SETFD, fdflags) < 0)
		return -1;

	return 0;
}

int _fdset_nonblock(int fd)
{
	int fdflags;

	fdflags = fcntl(fd, F_GETFL, 0);
	if (fdflags < 0)
		return -1;

	fdflags |= O_NONBLOCK;

	if (fcntl(fd, F_SETFL, fdflags) < 0)
		return -1;

	return 0;
}

int _dst_cache_update(knet_handle_t knet_h, uint16_t node_id)
{
	int write_retry = 0;

try_again:
	if (write(knet_h->dstpipefd[1], &node_id, sizeof(node_id)) != sizeof(node_id)) {
		if ((write_retry < 10) && ((errno = EAGAIN) || (errno = EWOULDBLOCK))) {
			write_retry++;
			goto try_again;
		} else {
			log_debug(knet_h, KNET_SUB_COMMON, "Unable to write to comm pipe");
			return -1;
		}
	}

	return 0;
}
