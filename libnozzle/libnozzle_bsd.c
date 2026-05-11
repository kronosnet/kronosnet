/*
 * Copyright (C) 2010-2026 Red Hat, Inc.  All rights reserved.
 *
 * Author: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *
 * This software licensed under LGPL-2.0+
 */

#include "config.h"

#ifdef KNET_BSD

#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/sockio.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet6/in6_var.h>
#include <netinet6/nd6.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "libnozzle.h"
#include "internals.h"

int _platform_init(struct nozzle_lib_config *lib_cfg)
{
	int savederrno;

	lib_cfg->ip_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (lib_cfg->ip_fd < 0) {
		return -1;
	}

	lib_cfg->ip6_fd = socket(AF_INET6, SOCK_DGRAM, 0);
	if (lib_cfg->ip6_fd < 0) {
		savederrno = errno;
		close(lib_cfg->ip_fd);
		lib_cfg->ip_fd = -1;
		errno = savederrno;
		return -1;
	}

	return 0;
}

void _platform_fini(struct nozzle_lib_config *lib_cfg)
{
	if (lib_cfg->ip_fd >= 0) {
		close(lib_cfg->ip_fd);
		lib_cfg->ip_fd = -1;
	}

	if (lib_cfg->ip6_fd >= 0) {
		close(lib_cfg->ip6_fd);
		lib_cfg->ip6_fd = -1;
	}
}

enum bsd_addr_operation {
	BSD_ADDR_ADD,
	BSD_ADDR_DELETE
};

static int _bsd_modify_ipv4(nozzle_t nozzle, const char *ipaddr, int prefix_len,
			     const char *broadcast, enum bsd_addr_operation operation)
{
	int err;

	if (operation == BSD_ADDR_ADD) {
		struct in_aliasreq ifra;
		uint32_t mask;

		memset(&ifra, 0, sizeof(ifra));
		strncpy(ifra.ifra_name, nozzle->name, IFNAMSIZ);

		/* Set address */
		ifra.ifra_addr.sin_family = AF_INET;
		ifra.ifra_addr.sin_len = sizeof(struct sockaddr_in);
		if (inet_pton(AF_INET, ipaddr, &ifra.ifra_addr.sin_addr) <= 0) {
			errno = EINVAL;
			return -1;
		}

		/* Set netmask */
		ifra.ifra_mask.sin_family = AF_INET;
		ifra.ifra_mask.sin_len = sizeof(struct sockaddr_in);
		mask = _ipv4_prefix_to_netmask(prefix_len);
		ifra.ifra_mask.sin_addr.s_addr = mask;

		/* Set broadcast address */
		if (broadcast) {
			ifra.ifra_broadaddr.sin_family = AF_INET;
			ifra.ifra_broadaddr.sin_len = sizeof(struct sockaddr_in);
			if (inet_pton(AF_INET, broadcast, &ifra.ifra_broadaddr.sin_addr) <= 0) {
				errno = EINVAL;
				return -1;
			}
		}

		err = ioctl(lib_cfg.ip_fd, SIOCAIFADDR, &ifra);
	} else {
		struct ifreq ifr;
		struct sockaddr_in *sin;

		memset(&ifr, 0, sizeof(ifr));
		strncpy(ifr.ifr_name, nozzle->name, IFNAMSIZ);

		sin = (struct sockaddr_in *)&ifr.ifr_addr;
		sin->sin_family = AF_INET;
		sin->sin_len = sizeof(struct sockaddr_in);
		if (inet_pton(AF_INET, ipaddr, &sin->sin_addr) <= 0) {
			errno = EINVAL;
			return -1;
		}

		err = ioctl(lib_cfg.ip_fd, SIOCDIFADDR, &ifr);
	}

	return (err < 0) ? -1 : 0;
}

static int _bsd_modify_ipv6(nozzle_t nozzle, const char *ipaddr, int prefix_len,
			     enum bsd_addr_operation operation)
{
	int err;

	if (operation == BSD_ADDR_ADD) {
		struct in6_aliasreq ifra6;
		struct sockaddr_in6 *sin6_addr, *sin6_mask;

		memset(&ifra6, 0, sizeof(ifra6));
		strncpy(ifra6.ifra_name, nozzle->name, IFNAMSIZ);

		/* Set address */
		sin6_addr = &ifra6.ifra_addr;
		sin6_addr->sin6_family = AF_INET6;
		sin6_addr->sin6_len = sizeof(struct sockaddr_in6);
		if (inet_pton(AF_INET6, ipaddr, &sin6_addr->sin6_addr) <= 0) {
			errno = EINVAL;
			return -1;
		}

		/* Set prefix mask */
		sin6_mask = &ifra6.ifra_prefixmask;
		sin6_mask->sin6_family = AF_INET6;
		sin6_mask->sin6_len = sizeof(struct sockaddr_in6);

		_ipv6_prefix_to_mask(prefix_len, &sin6_mask->sin6_addr);

		/* Set address lifetime to infinity */
		ifra6.ifra_lifetime.ia6t_vltime = ND6_INFINITE_LIFETIME;
		ifra6.ifra_lifetime.ia6t_pltime = ND6_INFINITE_LIFETIME;

		err = ioctl(lib_cfg.ip6_fd, SIOCAIFADDR_IN6, &ifra6);
	} else {
		struct in6_ifreq ifr6;

		memset(&ifr6, 0, sizeof(ifr6));
		strncpy(ifr6.ifr_name, nozzle->name, IFNAMSIZ);

		ifr6.ifr_addr.sin6_family = AF_INET6;
		ifr6.ifr_addr.sin6_len = sizeof(struct sockaddr_in6);
		if (inet_pton(AF_INET6, ipaddr, &ifr6.ifr_addr.sin6_addr) <= 0) {
			errno = EINVAL;
			return -1;
		}

		err = ioctl(lib_cfg.ip6_fd, SIOCDIFADDR_IN6, &ifr6);
	}

	return (err < 0) ? -1 : 0;
}

int _platform_add_ip(nozzle_t nozzle, const char *ipaddr, const char *prefix, int secondary)
{
	int fam;
	int err;
	char *broadcast = NULL;
	int prefix_len;

	fam = _determine_family(ipaddr);

	prefix_len = _validate_prefix(fam, prefix);
	if (prefix_len < 0) {
		return -1;
	}

	if (fam == AF_INET) {
		broadcast = generate_v4_broadcast(ipaddr, prefix);
		if (!broadcast) {
			errno = EINVAL;
			return -1;
		}

		err = _bsd_modify_ipv4(nozzle, ipaddr, prefix_len, broadcast, BSD_ADDR_ADD);
		free(broadcast);
	} else {
		err = _bsd_modify_ipv6(nozzle, ipaddr, prefix_len, BSD_ADDR_ADD);
	}

	return err;
}

int _platform_del_ip(nozzle_t nozzle, const char *ipaddr, const char *prefix, int secondary)
{
	int fam;
	int err;
	char *broadcast = NULL;
	int prefix_len;

	fam = _determine_family(ipaddr);

	prefix_len = _validate_prefix(fam, prefix);
	if (prefix_len < 0) {
		return -1;
	}

	if (fam == AF_INET) {
		broadcast = generate_v4_broadcast(ipaddr, prefix);
		if (!broadcast) {
			errno = EINVAL;
			return -1;
		}

		err = _bsd_modify_ipv4(nozzle, ipaddr, prefix_len, broadcast, BSD_ADDR_DELETE);
		free(broadcast);
	} else {
		err = _bsd_modify_ipv6(nozzle, ipaddr, prefix_len, BSD_ADDR_DELETE);
	}

	return err;
}

int _platform_create_tap(nozzle_t nozzle, char *devname, size_t devname_size)
{
	uint16_t i;
	long int nozzlenum = 0;
	char curnozzle[IFNAMSIZ];
	struct ifreq ifr;
	int savederrno = 0;

	/*
	 * BSD does not support named devices like Linux
	 * but it is possible to force a tapX device number
	 * where X is 0 to 255.
	 */
	if (strlen(devname)) {
		if (strncmp(devname, "tap", 3)) {
			errno = EINVAL;
			return -1;
		}
		errno = 0;
		nozzlenum = strtol(devname+3, NULL, 10);
		if (errno) {
			errno = EINVAL;
			return -1;
		}
		if ((nozzlenum < 0) || (nozzlenum > 255)) {
			errno = EINVAL;
			return -1;
		}
	}

	if (!strlen(devname)) {
		for (i = 0; i < 256; i++) {
			memset(&ifr, 0, sizeof(ifr));

			snprintf(curnozzle, sizeof(curnozzle) - 1, "tap%u", i);
			memmove(ifr.ifr_name, curnozzle, IFNAMSIZ);
			if (ioctl(lib_cfg.ioctlfd, SIOCIFCREATE2, &ifr) < 0) {
				continue;
			}
			snprintf(curnozzle, sizeof(curnozzle) - 1, "/dev/tap%u", i);
			nozzle->fd = open(curnozzle, O_RDWR);
			savederrno = errno;
			if (nozzle->fd > 0) {
				break;
			}
			/* For some reason we can't open that device, keep trying
			   but don't leave debris */
			(void)ioctl(lib_cfg.ioctlfd, SIOCIFDESTROY, &ifr);
			(void)ioctl(lib_cfg.ioctlfd, SIOCGIFFLAGS, &ifr);
		}
		snprintf(curnozzle, sizeof(curnozzle) -1 , "tap%u", i);
	} else {
		memmove(ifr.ifr_name, devname, IFNAMSIZ);
		if (ioctl(lib_cfg.ioctlfd, SIOCIFCREATE2, &ifr) < 0) {
			return -1;
		}
		snprintf(curnozzle, sizeof(curnozzle) - 1, "/dev/%s", devname);
		nozzle->fd = open(curnozzle, O_RDWR);
		savederrno = errno;
		snprintf(curnozzle, sizeof(curnozzle) - 1, "%s", devname);
	}

	if (nozzle->fd < 0) {
		errno = savederrno ? savederrno : EBUSY;
		return -1;
	}

	memmove(devname, curnozzle, IFNAMSIZ);
	memmove(nozzle->name, curnozzle, IFNAMSIZ);

	return nozzle->fd;
}

void _platform_close_tap(nozzle_t nozzle)
{
	/* No platform-specific cleanup needed for BSD */
}

void _platform_destroy_tap(nozzle_t nozzle)
{
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(struct ifreq));
	memmove(ifr.ifr_name, nozzle->name, IFNAMSIZ);

	ioctl(lib_cfg.ioctlfd, SIOCIFDESTROY, &ifr);
	ioctl(lib_cfg.ioctlfd, SIOCGIFFLAGS, &ifr);
}

int _platform_get_mac(const nozzle_t nozzle, char **ether_addr)
{
	struct ifaddrs *ifap = NULL;
	struct ifaddrs *ifa;
	struct sockaddr_dl *sdl;
	char mac[MACADDR_CHAR_MAX];
	int found = 0;

	memset(&mac, 0, MACADDR_CHAR_MAX);

	/*
	 * there is no ioctl to get the ether address of an interface on FreeBSD
	 * (not to be confused with hwaddr). Use workaround described here:
	 * https://lists.freebsd.org/pipermail/freebsd-hackers/2004-June/007394.html
	 */
	if (getifaddrs(&ifap) < 0) {
		return -1;
	}

	ifa = ifap;
	while (ifa) {
		if ((strncmp(nozzle->name, ifa->ifa_name, IFNAMSIZ) == 0) &&
		    (ifa->ifa_addr->sa_family == AF_LINK)) {
			sdl = (struct sockaddr_dl *)ifa->ifa_addr;
			if (sdl->sdl_alen == ETHER_ADDR_LEN) {
				ether_ntoa_r((struct ether_addr *)LLADDR(sdl), mac);
				found = 1;
				break;
			}
		}
		ifa = ifa->ifa_next;
	}

	freeifaddrs(ifap);

	if (!found) {
		errno = EINVAL;
		return -1;
	}

	*ether_addr = strdup(mac);
	if (*ether_addr == NULL) {
		errno = ENOMEM;
		return -1;
	}

	return 0;
}

int _platform_set_mac(nozzle_t nozzle, const char *ether_addr)
{
	struct ifreq ifr;
	int err;

	memset(&ifr, 0, sizeof(struct ifreq));
	memmove(ifr.ifr_name, nozzle->name, IFNAMSIZ);

	err = ioctl(lib_cfg.ioctlfd, SIOCGIFADDR, &ifr);
	if (err) {
		return -1;
	}

	memmove(ifr.ifr_addr.sa_data, ether_aton(ether_addr), ETHER_ADDR_LEN);
	ifr.ifr_addr.sa_len = ETHER_ADDR_LEN;

	err = ioctl(lib_cfg.ioctlfd, SIOCSIFLLADDR, &ifr);
	if (err) {
		return -1;
	}

	return 0;
}

int _platform_get_mtu(const nozzle_t nozzle)
{
	struct ifreq ifr;
	int err;

	memset(&ifr, 0, sizeof(ifr));
	memmove(ifr.ifr_name, nozzle->name, IFNAMSIZ);

	err = ioctl(lib_cfg.ioctlfd, SIOCGIFMTU, &ifr);
	if (err) {
		return -1;
	}

	return ifr.ifr_mtu;
}

#endif /* KNET_BSD */
