/*
 * Copyright (C) 2010-2015 Red Hat, Inc.  All rights reserved.
 *
 * Authors: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *          Federico Simoncelli <fsimon@kronosnet.org>
 *
 * This software licensed under GPL-2.0+, LGPL-2.0+
 */

#ifndef __NETUTILS_H__
#define __NETUTILS_H__

#include <sys/socket.h>

int cmpaddr(const struct sockaddr_storage *ss1, socklen_t sslen1, const struct sockaddr_storage *ss2, socklen_t sslen2);
int cpyaddrport(struct sockaddr_storage *dst, const struct sockaddr_storage *src);

socklen_t knet_sockaddr_len(const struct sockaddr_storage *ss);
#endif
