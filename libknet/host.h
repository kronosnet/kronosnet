/*
 * Copyright (C) 2012-2024 Red Hat, Inc.  All rights reserved.
 *
 * Authors: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *          Federico Simoncelli <fsimon@kronosnet.org>
 *
 * This software licensed under LGPL-2.0+
 */

#ifndef __KNET_HOST_H__
#define __KNET_HOST_H__

#include "internals.h"

int _seq_num_lookup(struct knet_host *host, seq_num_t seq_num, int defrag_buf, int clear_buf);
void _seq_num_set(struct knet_host *host, seq_num_t seq_num, int defrag_buf);

int _host_dstcache_update_async(knet_handle_t knet_h, struct knet_host *host);
int _host_dstcache_update_sync(knet_handle_t knet_h, struct knet_host *host);

#endif
