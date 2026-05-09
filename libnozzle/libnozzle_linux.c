/*
 * Copyright (C) 2010-2026 Red Hat, Inc.  All rights reserved.
 *
 * Author: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *
 * This software licensed under LGPL-2.0+
 */

#include "config.h"

#ifdef KNET_LINUX

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <netinet/ether.h>
#include <netlink/netlink.h>
#include <netlink/route/addr.h>
#include <netlink/route/link.h>
#include <netlink/errno.h>

#include "libnozzle.h"
#include "internals.h"

/*
 * Convert libnl error codes to errno values for better error reporting.
 * libnl functions return negative NLE_* error codes, which need translation
 * to standard errno values that applications expect.
 */
static int nlerr_to_errno(int nlerr)
{
	if (nlerr >= 0)
		return 0;

	/*
	 * NLE_* error codes are small negative integers.
	 * Kernel errors passed through netlink are already errno values.
	 * Use NLE_MAX as threshold to distinguish between the two.
	 */
	if (-nlerr > NLE_MAX) {
		/* Already an errno value from kernel */
		return -nlerr;
	}

	/* Common NLE_* to errno mappings */
	switch (-nlerr) {
		case NLE_NOMEM:
			return ENOMEM;
		case NLE_EXIST:
			return EEXIST;
		case NLE_NOADDR:
			return EADDRNOTAVAIL;
		case NLE_OBJ_NOTFOUND:
			return ENOENT;
		case NLE_INVAL:
			return EINVAL;
		case NLE_BUSY:
			return EBUSY;
		case NLE_AGAIN:
			return EAGAIN;
		case NLE_NODEV:
			return ENODEV;
		case NLE_OPNOTSUPP:
			return EOPNOTSUPP;
		case NLE_PERM:
			return EPERM;
		default:
			return EINVAL;
	}
}

int _platform_init(struct nozzle_lib_config *lib_cfg)
{
	lib_cfg->nlsock = nl_socket_alloc();
	if (!lib_cfg->nlsock) {
		errno = ENOMEM;
		return -1;
	}

	if (nl_connect(lib_cfg->nlsock, NETLINK_ROUTE) < 0) {
		nl_socket_free(lib_cfg->nlsock);
		lib_cfg->nlsock = NULL;
		errno = EBUSY;
		return -1;
	}

	return 0;
}

void _platform_fini(struct nozzle_lib_config *lib_cfg)
{
	if (lib_cfg->nlsock) {
		nl_socket_free(lib_cfg->nlsock);
		lib_cfg->nlsock = NULL;
	}
}

int _platform_add_ip(nozzle_t nozzle, const char *ipaddr, const char *prefix, int secondary)
{
	struct rtnl_addr *addr = NULL;
	struct nl_addr *local_addr = NULL;
	struct nl_addr *bcast_addr = NULL;
	struct nl_cache *cache = NULL;
	char *broadcast = NULL;
	int fam;
	int ifindex;
	int nlerr;
	int err = 0;
	if (!strchr(ipaddr, ':')) {
		fam = AF_INET;
		broadcast = generate_v4_broadcast(ipaddr, prefix);
		if (!broadcast) {
			errno = EINVAL;
			return -1;
		}
	} else {
		fam = AF_INET6;
	}

	addr = rtnl_addr_alloc();
	if (!addr) {
		errno = ENOMEM;
		err = -1;
		goto out;
	}

	nlerr = rtnl_link_alloc_cache(lib_cfg.nlsock, AF_UNSPEC, &cache);
	if (nlerr < 0) {
		errno = nlerr_to_errno(nlerr);
		err = -1;
		goto out;
	}

	ifindex = rtnl_link_name2i(cache, nozzle->name);
	if (ifindex == 0) {
		errno = ENOENT;
		err = -1;
		goto out;
	}

	rtnl_addr_set_ifindex(addr, ifindex);

	nlerr = nl_addr_parse(ipaddr, fam, &local_addr);
	if (nlerr < 0) {
		errno = nlerr_to_errno(nlerr);
		err = -1;
		goto out;
	}

	nlerr = rtnl_addr_set_local(addr, local_addr);
	if (nlerr < 0) {
		errno = nlerr_to_errno(nlerr);
		err = -1;
		goto out;
	}

	if (broadcast) {
		nlerr = nl_addr_parse(broadcast, fam, &bcast_addr);
		if (nlerr < 0) {
			errno = nlerr_to_errno(nlerr);
			err = -1;
			goto out;
		}

		nlerr = rtnl_addr_set_broadcast(addr, bcast_addr);
		if (nlerr < 0) {
			errno = nlerr_to_errno(nlerr);
			err = -1;
			goto out;
		}
	}

	rtnl_addr_set_prefixlen(addr, atoi(prefix));

	nlerr = rtnl_addr_add(lib_cfg.nlsock, addr, 0);
	if (nlerr < 0) {
		errno = nlerr_to_errno(nlerr);
		err = -1;
		goto out;
	}

out:
	if (addr) {
		rtnl_addr_put(addr);
	}
	if (local_addr) {
		nl_addr_put(local_addr);
	}
	if (bcast_addr) {
		nl_addr_put(bcast_addr);
	}
	if (cache) {
		nl_cache_put(cache);
	}
	if (broadcast) {
		free(broadcast);
	}
	return err;
}

int _platform_del_ip(nozzle_t nozzle, const char *ipaddr, const char *prefix, int secondary)
{
	struct rtnl_addr *addr = NULL;
	struct nl_addr *local_addr = NULL;
	struct nl_cache *cache = NULL;
	char *broadcast = NULL;
	int fam;
	int ifindex;
	int nlerr;
	int err = 0;
	if (!strchr(ipaddr, ':')) {
		fam = AF_INET;
		broadcast = generate_v4_broadcast(ipaddr, prefix);
		if (!broadcast) {
			errno = EINVAL;
			return -1;
		}
	} else {
		fam = AF_INET6;
	}

	addr = rtnl_addr_alloc();
	if (!addr) {
		errno = ENOMEM;
		err = -1;
		goto out;
	}

	nlerr = rtnl_link_alloc_cache(lib_cfg.nlsock, AF_UNSPEC, &cache);
	if (nlerr < 0) {
		errno = nlerr_to_errno(nlerr);
		err = -1;
		goto out;
	}

	ifindex = rtnl_link_name2i(cache, nozzle->name);
	if (ifindex == 0) {
		errno = ENOENT;
		err = -1;
		goto out;
	}

	rtnl_addr_set_ifindex(addr, ifindex);

	nlerr = nl_addr_parse(ipaddr, fam, &local_addr);
	if (nlerr < 0) {
		errno = nlerr_to_errno(nlerr);
		err = -1;
		goto out;
	}

	nlerr = rtnl_addr_set_local(addr, local_addr);
	if (nlerr < 0) {
		errno = nlerr_to_errno(nlerr);
		err = -1;
		goto out;
	}

	rtnl_addr_set_prefixlen(addr, atoi(prefix));

	nlerr = rtnl_addr_delete(lib_cfg.nlsock, addr, 0);
	if (nlerr < 0) {
		errno = nlerr_to_errno(nlerr);
		err = -1;
		goto out;
	}

out:
	if (addr) {
		rtnl_addr_put(addr);
	}
	if (local_addr) {
		nl_addr_put(local_addr);
	}
	if (cache) {
		nl_cache_put(cache);
	}
	if (broadcast) {
		free(broadcast);
	}
	return err;
}

int _platform_create_tap(nozzle_t nozzle, char *devname, size_t devname_size)
{
	struct ifreq ifr;
	int savederrno;

	nozzle->fd = open("/dev/net/tun", O_RDWR);
	if (nozzle->fd < 0) {
		return -1;
	}

	memset(&ifr, 0, sizeof(struct ifreq));
	memmove(ifr.ifr_name, devname, IFNAMSIZ);
	ifr.ifr_flags = IFF_TAP | IFF_NO_PI;

	/*
	 * Use IFF_TUN_EXCL to prevent race conditions when creating named devices.
	 * Without this flag, another process could create the same device name
	 * between our check and creation, leading to unexpected behavior.
	 * Available since Linux 3.4. Fallback to non-exclusive if not supported.
	 */
	if (strlen(devname) > 0) {
#ifdef IFF_TUN_EXCL
		ifr.ifr_flags |= IFF_TUN_EXCL;
#endif
	}

	if (ioctl(nozzle->fd, TUNSETIFF, &ifr) < 0) {
		savederrno = errno;
		close(nozzle->fd);
		nozzle->fd = -1;
		errno = savederrno;
		return -1;
	}

	if ((strlen(devname) > 0) && (strcmp(devname, ifr.ifr_name) != 0)) {
		close(nozzle->fd);
		nozzle->fd = -1;
		errno = EBUSY;
		return -1;
	}

	memmove(devname, ifr.ifr_name, IFNAMSIZ);
	memmove(nozzle->name, ifr.ifr_name, IFNAMSIZ);

	return nozzle->fd;
}

void _platform_close_tap(nozzle_t nozzle)
{
	/* No platform-specific cleanup needed for Linux */
}

void _platform_destroy_tap(nozzle_t nozzle)
{
	/* No platform-specific cleanup needed for Linux */
}

int _platform_get_mac(const nozzle_t nozzle, char **ether_addr)
{
	struct ifreq ifr;
	char mac[MACADDR_CHAR_MAX];
	int err;

	memset(&mac, 0, MACADDR_CHAR_MAX);
	memset(&ifr, 0, sizeof(struct ifreq));
	memmove(ifr.ifr_name, nozzle->name, IFNAMSIZ);

	err = ioctl(lib_cfg.ioctlfd, SIOCGIFHWADDR, &ifr);
	if (err) {
		return -1;
	}

	ether_ntoa_r((struct ether_addr *)ifr.ifr_hwaddr.sa_data, mac);

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

	err = ioctl(lib_cfg.ioctlfd, SIOCGIFHWADDR, &ifr);
	if (err) {
		return -1;
	}

	memmove(ifr.ifr_hwaddr.sa_data, ether_aton(ether_addr), ETH_ALEN);

	err = ioctl(lib_cfg.ioctlfd, SIOCSIFHWADDR, &ifr);
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

#endif /* KNET_LINUX */
