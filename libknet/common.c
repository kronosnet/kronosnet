/*
 * Copyright (C) 2010-2015 Red Hat, Inc.  All rights reserved.
 *
 * Author: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *
 * This software licensed under GPL-2.0+, LGPL-2.0+
 */

#include "config.h"

#include <unistd.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <errno.h>
#include <string.h>
#include <sys/param.h>

#include "logging.h"
#include "common.h"

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

void *open_lib(knet_handle_t knet_h, const char *libname, int extra_flags)
{
	char *error = NULL;
	char path[MAXPATHLEN];
	void *ret = NULL;

	/*
	 * clear any pending error
	 */
	dlerror();

	ret = dlopen(libname, RTLD_LAZY | RTLD_GLOBAL | extra_flags);
	error = dlerror();
	if (error != NULL) {
		log_err(knet_h, KNET_SUB_COMMON, "unable to dlopen %s: %s",
			libname, error);
		errno = EAGAIN;
		return NULL;
	}

	memset(path, 0, sizeof(path));
	if (dlinfo(ret, RTLD_DI_ORIGIN, &path) < 0) {
		log_warn(knet_h, KNET_SUB_COMMON, "unable to dlinfo %s: %s",
			 libname, error);
	} else {
		log_info(knet_h, KNET_SUB_COMMON, "%s has been loaded from %s/%s",
			 libname, path, libname);
	}

	return ret;
}
