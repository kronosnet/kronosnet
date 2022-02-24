/*
 * Copyright (C) 2010-2022 Red Hat, Inc.  All rights reserved.
 *
 * Authors: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *          Federico Simoncelli <fsimon@kronosnet.org>
 *
 * This software licensed under LGPL-2.0+
 */

#ifndef __KNET_NETUTILS_H__
#define __KNET_NETUTILS_H__

#include <sys/socket.h>
#include <netinet/in.h>

/*
 * s6_addr32 is not defined in BSD userland, only kernel.
 * definition is the same as linux and it works fine for
 * what we need.
 */

#ifndef s6_addr32
#define s6_addr32 __u6_addr.__u6_addr32
#endif

int cmpaddr(const struct sockaddr_storage *ss1, const struct sockaddr_storage *ss2);

void copy_sockaddr(struct sockaddr_storage *sout, const struct sockaddr_storage *sin);

socklen_t sockaddr_len(const struct sockaddr_storage *ss);
#endif
