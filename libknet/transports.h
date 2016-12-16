/*
 * Copyright (C) 2016 Red Hat, Inc.  All rights reserved.
 *
 * Authors: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *
 * This software licensed under GPL-2.0+, LGPL-2.0+
 */

#ifndef __TRANSPORTS_H__
#define __TRANSPORTS_H__

knet_transport_ops_t *get_udp_transport(void);

#ifdef HAVE_NETINET_SCTP_H
knet_transport_ops_t *get_sctp_transport(void);
#endif

int _configure_transport_socket(knet_handle_t knet_h, int sock, struct sockaddr_storage *address, const char *type);
void _close_socket(knet_handle_t knet_h, int sockfd);
void _handle_socket_notification(knet_handle_t knet_h, int sockfd, struct iovec *iov, size_t iovlen);

int _transport_addrtostr(const struct sockaddr *sa, socklen_t salen, char *str[2]);
void _transport_addrtostr_free(char *str[2]);

#endif
