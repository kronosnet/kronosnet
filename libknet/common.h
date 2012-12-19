/*
 * Copyright (C) 2010-2012 Red Hat, Inc.  All rights reserved.
 *
 * Authors: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *          Federico Simoncelli <fsimon@kronosnet.org>
 *
 * This software licensed under GPL-2.0+, LGPL-2.0+
 */

#ifndef __COMMON_H__
#define __COMMON_H__

int _fdset_cloexec(int fd);
int _fdset_nonblock(int fd);
int _dst_cache_update(knet_handle_t knet_h, uint16_t node_id);

#endif
