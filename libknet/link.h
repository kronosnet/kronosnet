/*
 * Copyright (C) 2010-2012 Red Hat, Inc.  All rights reserved.
 *
 * Authors: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *          Federico Simoncelli <fsimon@kronosnet.org>
 *
 * This software licensed under GPL-2.0+, LGPL-2.0+
 */

#ifndef __LINK_H__
#define __LINK_H__

int _link_updown(knet_handle_t knet_h, uint16_t node_id,
		 struct knet_link *lnk, int configured, int connected);

#endif
