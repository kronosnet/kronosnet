/*
 * Copyright (C) 2012-2023 Red Hat, Inc.  All rights reserved.
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

void process_ping(knet_handle_t knet_h, struct knet_host *src_host, struct knet_link *src_link, struct knet_header *inbuf, ssize_t len);
void process_pong(knet_handle_t knet_h, struct knet_host *src_host, struct knet_link *src_link, struct knet_header *inbuf, ssize_t len);

#endif
