/*
 * Copyright (C) 2012-2020 Red Hat, Inc.  All rights reserved.
 *
 * Authors: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *          Federico Simoncelli <fsimon@kronosnet.org>
 *
 * This software licensed under LGPL-2.0+
 */

#ifndef __KNET_THREADS_HEARTBEAT_H__
#define __KNET_THREADS_HEARTBEAT_H__

void _send_pings(knet_handle_t knet_h, int timed);
void *_handle_heartbt_thread(void *data);

#endif
