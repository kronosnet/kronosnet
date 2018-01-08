/*
 * Copyright (C) 2010-2018 Red Hat, Inc.  All rights reserved.
 *
 * Author: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *
 * This software licensed under GPL-2.0+, LGPL-2.0+
 */

#ifndef __KNETD_VTY_AUTH_H__
#define __KNETD_VTY_AUTH_H__

#include "vty.h"

#define AUTH_MAX_RETRY 3

int knet_vty_auth_user(struct knet_vty *vty, const char *user);

#endif
