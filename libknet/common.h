/*
 * Copyright (C) 2012-2019 Red Hat, Inc.  All rights reserved.
 *
 * Authors: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *          Federico Simoncelli <fsimon@kronosnet.org>
 *
 * This software licensed under LGPL-2.0+
 */

#include "internals.h"

#ifndef __KNET_COMMON_H__
#define __KNET_COMMON_H__

int _fdset_cloexec(int fd);
int _fdset_nonblock(int fd);
void *load_module(knet_handle_t knet_h, const char *type, const char *name);

#endif
