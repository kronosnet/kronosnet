/*
 * Copyright (C) 2012-2025 Red Hat, Inc.  All rights reserved.
 *
 * Authors: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *          Federico Simoncelli <fsimon@kronosnet.org>
 *
 * This software licensed under LGPL-2.0+
 */

#ifndef __KNET_THREADS_PMTUD_H__
#define __KNET_THREADS_PMTUD_H__

void *_handle_pmtud_link_thread(void *data);

void process_pmtud(knet_handle_t knet_h, struct knet_link *src_link, struct knet_header *inbuf);
void process_pmtud_reply(knet_handle_t knet_h, struct knet_link *src_link, struct knet_header *inbuf);

#endif
