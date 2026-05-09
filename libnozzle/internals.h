/*
 * Copyright (C) 2017-2026 Red Hat, Inc.  All rights reserved.
 *
 * Author: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *
 * This software licensed under LGPL-2.0+
 */

#ifndef __NOZZLE_INTERNALS_H__
#define __NOZZLE_INTERNALS_H__

#include "config.h"

#include <limits.h>

#ifdef KNET_LINUX
#include <netlink/netlink.h>
#endif
#ifdef KNET_SOLARIS
#include <sys/sockio.h>
#endif
#include <net/if.h>
#include "libnozzle.h"

struct nozzle_lib_config {
	struct nozzle_iface *head;
	int ioctlfd;
#ifdef KNET_LINUX
	struct nl_sock *nlsock;
#endif
#if defined(KNET_BSD) || defined(KNET_SOLARIS)
	int ip_fd;
	int ip6_fd;
#endif
};

#define MACADDR_CHAR_MAX   18

/*
 * 11 = post-down.d
 * 1  = /
 */
#define UPDOWN_PATH_MAX    PATH_MAX - 11 - 1 - IFNAMSIZ

struct nozzle_iface {
	char name[IFNAMSIZ];		/* interface name */
	int fd;				/* interface fd */
	int up;				/* interface status 0 is down, 1 is up */
	/*
	 * extra data
	 */
	struct nozzle_ip *ip;		/* configured ip addresses */

	/*
	 * default MAC address assigned by the kernel at creation time
	 */
	char default_mac[MACADDR_CHAR_MAX + 1];

	int default_mtu;		/* MTU assigned by the kernel at creation time */
	int current_mtu;		/* MTU configured by libnozzle user */

	int hasupdown;			/* interface has up/down path to scripts configured */
	char updownpath[UPDOWN_PATH_MAX]; /* path to up/down scripts if configured */

	struct nozzle_iface *next;

#ifdef KNET_SOLARIS
	int ip_fd;	/* STREAMS plumbing socket for IPv4 */
	int ip6_fd;	/* STREAMS plumbing socket for IPv6 */
#endif
};

/*
 * Platform-specific type and macro abstractions
 */
#ifdef KNET_SOLARIS
typedef struct lifreq nozzle_ifreq;
#define ifname ifr.lifr_name
#define ifmtu ifr.lifr_mtu
#define ifflags ifr.lifr_flags
#define NOZZLE_IOCTL_FD lib_cfg.ip_fd
#define NOZZLE_SET_MTU SIOCSLIFMTU
#define NOZZLE_SOCKET_DOMAIN AF_INET
#define NOZZLE_IPV6_IS_SECONDARY(domain) ((domain) == AF_INET6)
#else
typedef struct ifreq nozzle_ifreq;
#define ifname ifr.ifr_name
#define ifmtu ifr.ifr_mtu
#define ifflags ifr.ifr_flags
#define NOZZLE_SET_MTU SIOCSIFMTU
#define NOZZLE_SOCKET_DOMAIN AF_INET
#define NOZZLE_IPV6_IS_SECONDARY(domain) 0
#ifdef KNET_BSD
#undef NOZZLE_SOCKET_DOMAIN
#define NOZZLE_SOCKET_DOMAIN AF_LOCAL
#define NOZZLE_IOCTL_FD lib_cfg.ioctlfd
#else
#define NOZZLE_IOCTL_FD lib_cfg.ioctlfd
#endif
#endif

/*
 * Global library configuration (defined in libnozzle.c)
 */
extern struct nozzle_lib_config lib_cfg;

int execute_bin_sh_command(const char *command, char **error_string);

int find_ip(nozzle_t nozzle,
	    const char *ipaddr, const char *prefix,
	    struct nozzle_ip **ip, struct nozzle_ip **ip_prev);

char *generate_v4_broadcast(const char *ipaddr, const char *prefix);

/*
 * Platform-specific functions
 */
int _platform_init(struct nozzle_lib_config *lib_cfg);
void _platform_fini(struct nozzle_lib_config *lib_cfg);

int _platform_create_tap(nozzle_t nozzle, char *devname, size_t devname_size);
void _platform_close_tap(nozzle_t nozzle);
void _platform_destroy_tap(nozzle_t nozzle);

int _platform_get_mac(const nozzle_t nozzle, char **ether_addr);
int _platform_set_mac(nozzle_t nozzle, const char *ether_addr);
int _platform_get_mtu(const nozzle_t nozzle);

int _platform_add_ip(nozzle_t nozzle, const char *ipaddr, const char *prefix, int secondary);
int _platform_del_ip(nozzle_t nozzle, const char *ipaddr, const char *prefix, int secondary);

#endif
