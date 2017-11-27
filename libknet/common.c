/*
 * Copyright (C) 2010-2017 Red Hat, Inc.  All rights reserved.
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

void *open_lib(knet_handle_t knet_h, const char *libname, int extra_flags)
{
	void *ret = NULL;
	char *error = NULL;
	char dir[MAXPATHLEN], path[MAXPATHLEN], link[MAXPATHLEN];
	struct stat sb;

	/*
	 * clear any pending error
	 */
	dlerror();

	ret = dlopen(libname, RTLD_NOW | RTLD_GLOBAL | extra_flags);
	error = dlerror();
	if (error != NULL) {
		log_err(knet_h, KNET_SUB_COMMON, "unable to dlopen %s: %s",
			libname, error);
		errno = EAGAIN;
		return NULL;
	}

	memset(dir, 0, sizeof(dir));
	memset(link, 0, sizeof(link));
	memset(path, 0, sizeof(path));
	if (dlinfo(ret, RTLD_DI_ORIGIN, &dir) < 0) {
		/*
		 * should we dlclose and return error?
		 */
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
			if (readlink(path, link, sizeof(link)) < 0) {
				log_debug(knet_h, KNET_SUB_COMMON, "Unable to readlink %s: %s", path, strerror(errno));
				goto out;
			}
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

void *remap_symbol(knet_handle_t knet_h, uint8_t subsystem,
		   void *lib_handle, const char *symbol_name)
{
	void *symbol = dlsym (lib_handle, symbol_name);
	if (!symbol) {
		log_err (knet_h, subsystem, "unable to map %s: %s", symbol_name, dlerror ());
	}
	return symbol;
}

int load_compress_lib(knet_handle_t knet_h, compress_model_t *model)
{
	void *module;
	compress_model_t *module_cmds;
	char soname[MAXPATHLEN];
	const char model_sym[] = "compress_model";

	if (model->loaded) {
		return 0;
	}
	snprintf (soname, sizeof soname, "compress_%s.so", model->model_name);
	module = open_lib(knet_h, soname, 0);
	if (!module) {
		return -1;
	}
	module_cmds = dlsym (module, model_sym);
	if (!module_cmds) {
		log_err (knet_h, KNET_SUB_COMPRESS, "unable to map symbol %s in module %s: %s",
			 model_sym, soname, dlerror ());
		errno = EINVAL;
		return -1;
	}
	model->is_init = module_cmds->is_init;
	model->init = module_cmds->init;
	model->fini = module_cmds->fini;
	model->val_level = module_cmds->val_level;
	model->compress = module_cmds->compress;
	model->decompress = module_cmds->decompress;
	return 0;
}
