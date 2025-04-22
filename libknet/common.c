/*
 * Copyright (C) 2010-2025 Red Hat, Inc.  All rights reserved.
 *
 * Author: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *
 * This software licensed under LGPL-2.0+
 */

#include "config.h"

#include <unistd.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <errno.h>
#include <libgen.h>
#include <link.h>
#include <string.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>

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

static int get_lib_dir(void *lib_handle, char dir[MAXPATHLEN])
{
	int res;
#ifndef HAVE_RTLD_DI_ORIGIN
	struct link_map *lm;
	char l_name[MAXPATHLEN];
#endif

#ifdef HAVE_RTLD_DI_ORIGIN
	res = dlinfo(lib_handle, RTLD_DI_ORIGIN, dir);
#else
	/*
	 * musl libc doesn't support RTLD_DI_ORIGIN
	 */
	res = dlinfo(lib_handle, RTLD_DI_LINKMAP, &lm);
	if (res == 0) {
		snprintf(l_name, sizeof(l_name), "%s", lm->l_name);
		snprintf(dir, MAXPATHLEN, "%s", dirname(l_name));
	}
#endif

	return res;
}

static void *open_lib(knet_handle_t knet_h, const char *libname, int extra_flags)
{
	void *ret = NULL;
	char *error = NULL;
	char dir[MAXPATHLEN], path[MAXPATHLEN * 2], link[MAXPATHLEN];
	struct stat sb;

	/*
	 * clear any pending error
	 */
	dlerror();
	strncpy(path, knet_h->plugin_path, sizeof(path)-1);
	strncat(path, "/", sizeof(path)-1);
	strncat(path, libname, sizeof(path)-strlen(knet_h->plugin_path)-2);

	ret = dlopen(path, RTLD_NOW | RTLD_GLOBAL | extra_flags);
	if (!ret) {
		error = dlerror();
		if (error) {
			log_err(knet_h, KNET_SUB_COMMON, "unable to dlopen %s: %s", libname, error);
		} else {
			log_err(knet_h, KNET_SUB_COMMON, "unable to dlopen %s: unknown error", libname);
		}
		errno = EAGAIN;
		return NULL;
	}

	memset(dir, 0, sizeof(dir));
	memset(link, 0, sizeof(link));
	memset(path, 0, sizeof(path));
	if (get_lib_dir(ret, dir) < 0) {
		/*
		 * should we dlclose and return error?
		 */
		error = dlerror();
		log_warn(knet_h, KNET_SUB_COMMON, "unable to dlinfo %s: %s",
			 libname, error);
	} else {
		snprintf(path, sizeof(path), "%s/%s", dir, libname);

		log_info(knet_h, KNET_SUB_COMMON, "%s has been loaded from %s", libname, path);

		/*
		 * try to resolve the library and check if it is a symlink and to where.
		 * we can't prevent symlink attacks but at least we can log where the library
		 * has been loaded from
		 */
		if (lstat(path, &sb) < 0) {
			log_debug(knet_h, KNET_SUB_COMMON, "Unable to stat %s: %s", path, strerror(errno));
			goto out;
		}

		if (S_ISLNK(sb.st_mode)) {
			if (readlink(path, link, sizeof(link)-1) < 0) {
				log_debug(knet_h, KNET_SUB_COMMON, "Unable to readlink %s: %s", path, strerror(errno));
				goto out;
			}
			link[sizeof(link) - 1] = 0;
			/*
			 * symlink is relative to the directory
			 */
			if (link[0] != '/') {
				snprintf(path, sizeof(path), "%s/%s", dir, link);
				log_info(knet_h, KNET_SUB_COMMON, "%s/%s is a symlink to %s", dir, libname, path);
			} else {
				log_info(knet_h, KNET_SUB_COMMON, "%s/%s is a symlink to %s", dir, libname, link);
			}
		}
	}
out:
	return ret;
}

void *load_module(knet_handle_t knet_h, const char *type, const char *name)
{
	void *module, *ops;
	log_msg_t **log_msg_sym;
	char soname[MAXPATHLEN], opsname[MAXPATHLEN];

	snprintf (soname, sizeof soname, "%s_%s.so", type, name);

	module = open_lib(knet_h, soname, 0);
	if (!module) {
		return NULL;
	}

        log_msg_sym = dlsym (module, "log_msg");
        if (!log_msg_sym) {
		log_err (knet_h, KNET_SUB_COMMON, "unable to map symbol 'log_msg' in module %s: %s",
			 soname, dlerror ());
		errno = EINVAL;
		return NULL;
	}
	*log_msg_sym = log_msg;

	snprintf (opsname, sizeof opsname, "%s_model", type);

	ops = dlsym (module, opsname);
	if (!ops) {
		log_err (knet_h, KNET_SUB_COMMON, "unable to map symbol 'model' in module %s: %s",
			 soname, dlerror ());
		errno = EINVAL;
		return NULL;
	}

	return ops;
}
