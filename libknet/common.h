/*
 * Copyright (C) 2012-2017 Red Hat, Inc.  All rights reserved.
 *
 * Authors: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *          Federico Simoncelli <fsimon@kronosnet.org>
 *
 * This software licensed under GPL-2.0+, LGPL-2.0+
 */

#include "internals.h"
#include "compress_model.h"

#ifndef __KNET_COMMON_H__
#define __KNET_COMMON_H__

int _fdset_cloexec(int fd);
int _fdset_nonblock(int fd);
void *open_lib(knet_handle_t knet_h, const char *libname, int extra_flags);
void *remap_symbol(knet_handle_t knet_h, uint8_t subsystem,
		   void *lib_handle, const char *symbol_name);
int load_compress_lib(knet_handle_t knet_h, compress_model_t *model);

#endif
