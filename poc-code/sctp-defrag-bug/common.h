/*
 * Copyright (C) 2017 Red Hat, Inc.  All rights reserved.
 *
 * Authors: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *
 * This software licensed under GPL-2.0+, LGPL-2.0+
 */

#ifndef __COMMON_H__
#define __COMMON_H__

int strtoaddr(const char *host, const char *port, struct sockaddr_storage *ss, socklen_t sslen);
int _fdset_cloexec(int fd);
int _fdset_nonblock(int fd);
int setup_sctp_common_sock_opts(int sock, struct sockaddr_storage *ss);
int setup_sctp_server_sock_opts(int sock, struct sockaddr_storage *ss);
void get_incoming_data(int sock, struct mmsghdr *msg, int check_crc);
int setup_rx_buffers(struct mmsghdr *msg);

#endif
