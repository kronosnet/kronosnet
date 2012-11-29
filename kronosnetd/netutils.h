/*
 * Copyright (C) 2010-2012 Red Hat, Inc.  All rights reserved.
 *
 * Authors: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *          Federico Simoncelli <fsimon@kronosnet.org>
 *
 * This software licensed under GPL-2.0+, LGPL-2.0+
 */

#ifndef __NETUTILS_H__
#define __NETUTILS_H__

#include <sys/socket.h>

int cmpaddr(struct sockaddr_storage *ss1, socklen_t sslen1, struct sockaddr_storage *ss2, socklen_t sslen2);
int strtoaddr(const char *host, const char *port, struct sockaddr *sa, socklen_t salen);
int addrtostr(const struct sockaddr *sa, socklen_t salen, char *str[2]);
void addrtostr_free(char *str[2]);

#endif
