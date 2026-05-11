/*
 * Copyright (C) 2010-2026 Red Hat, Inc.  All rights reserved.
 *
 * Author: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *
 * This software licensed under LGPL-2.0+
 */

#include "config.h"

#ifdef KNET_SOLARIS

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/sockio.h>
#include <sys/ethernet.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stropts.h>
#include <net/if_tun.h>
#include <libdlpi.h>

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

enum solaris_addr_operation {
	SOLARIS_ADDR_ADD,
	SOLARIS_ADDR_DELETE
};

static int _solaris_modify_ipv4(nozzle_t nozzle, const char *ipaddr, int prefix_len,
				 const char *broadcast, int secondary,
				 enum solaris_addr_operation operation)
{
	struct lifreq lifr;
	struct sockaddr_in *sin_addr, *sin_mask, *sin_bcast;
	uint32_t mask;
	int err;

	memset(&lifr, 0, sizeof(lifr));
	strncpy(lifr.lifr_name, nozzle->name, LIFNAMSIZ);

	if (operation == SOLARIS_ADDR_ADD) {
		/* For secondary addresses, create logical interface first */
		if (secondary) {
			memset(&lifr.lifr_addr, 0, sizeof(lifr.lifr_addr));
			if (ioctl(lib_cfg.ip_fd, SIOCLIFADDIF, &lifr) < 0) {
				return -1;
			}
		}

		/* Set netmask */
		sin_mask = (struct sockaddr_in *)&lifr.lifr_addr;
		sin_mask->sin_family = AF_INET;
		mask = _ipv4_prefix_to_netmask(prefix_len);
		sin_mask->sin_addr.s_addr = mask;

		if (ioctl(lib_cfg.ip_fd, SIOCSLIFNETMASK, &lifr) < 0) {
			if (secondary) {
				(void)ioctl(lib_cfg.ip_fd, SIOCLIFREMOVEIF, &lifr);
			}
			return -1;
		}

		/* Set address */
		sin_addr = (struct sockaddr_in *)&lifr.lifr_addr;
		sin_addr->sin_family = AF_INET;
		if (inet_pton(AF_INET, ipaddr, &sin_addr->sin_addr) <= 0) {
			if (secondary) {
				(void)ioctl(lib_cfg.ip_fd, SIOCLIFREMOVEIF, &lifr);
			}
			errno = EINVAL;
			return -1;
		}

		err = ioctl(lib_cfg.ip_fd, SIOCSLIFADDR, &lifr);
		if (err < 0) {
			if (secondary) {
				(void)ioctl(lib_cfg.ip_fd, SIOCLIFREMOVEIF, &lifr);
			}
			return -1;
		}

		/* Set broadcast address if provided */
		if (broadcast) {
			sin_bcast = (struct sockaddr_in *)&lifr.lifr_broadaddr;
			sin_bcast->sin_family = AF_INET;
			if (inet_pton(AF_INET, broadcast, &sin_bcast->sin_addr) <= 0) {
				errno = EINVAL;
				return -1;
			}

			err = ioctl(lib_cfg.ip_fd, SIOCSLIFBRDADDR, &lifr);
			/* Non-fatal if broadcast fails */
		}
	} else {
		/* Delete address */
		if (secondary) {
			/* Set the address to delete so Solaris can find the right logical interface */
			sin_addr = (struct sockaddr_in *)&lifr.lifr_addr;
			sin_addr->sin_family = AF_INET;
			if (inet_pton(AF_INET, ipaddr, &sin_addr->sin_addr) <= 0) {
				errno = EINVAL;
				return -1;
			}
			err = ioctl(lib_cfg.ip_fd, SIOCLIFREMOVEIF, &lifr);
		} else {
			/* Primary IPv4: set to 0.0.0.0 */
			sin_addr = (struct sockaddr_in *)&lifr.lifr_addr;
			sin_addr->sin_family = AF_INET;
			sin_addr->sin_addr.s_addr = 0;
			err = ioctl(lib_cfg.ip_fd, SIOCSLIFADDR, &lifr);
		}
	}

	return (err < 0) ? -1 : 0;
}

static int _solaris_modify_ipv6(nozzle_t nozzle, const char *ipaddr, int prefix_len,
				 int secondary, enum solaris_addr_operation operation)
{
	struct lifreq lifr;
	struct sockaddr_in6 *sin6_addr, *sin6_mask;
	int err;

	memset(&lifr, 0, sizeof(lifr));
	strncpy(lifr.lifr_name, nozzle->name, LIFNAMSIZ);

	if (operation == SOLARIS_ADDR_ADD) {
		/* For secondary addresses, create logical interface first */
		if (secondary) {
			memset(&lifr.lifr_addr, 0, sizeof(lifr.lifr_addr));
			if (ioctl(lib_cfg.ip6_fd, SIOCLIFADDIF, &lifr) < 0) {
				return -1;
			}
		}

		/* Set prefix mask */
		sin6_mask = (struct sockaddr_in6 *)&lifr.lifr_addr;
		sin6_mask->sin6_family = AF_INET6;

		_ipv6_prefix_to_mask(prefix_len, &sin6_mask->sin6_addr);

		if (ioctl(lib_cfg.ip6_fd, SIOCSLIFNETMASK, &lifr) < 0) {
			if (secondary) {
				(void)ioctl(lib_cfg.ip6_fd, SIOCLIFREMOVEIF, &lifr);
			}
			return -1;
		}

		/* Set address */
		sin6_addr = (struct sockaddr_in6 *)&lifr.lifr_addr;
		sin6_addr->sin6_family = AF_INET6;
		if (inet_pton(AF_INET6, ipaddr, &sin6_addr->sin6_addr) <= 0) {
			if (secondary) {
				(void)ioctl(lib_cfg.ip6_fd, SIOCLIFREMOVEIF, &lifr);
			}
			errno = EINVAL;
			return -1;
		}

		err = ioctl(lib_cfg.ip6_fd, SIOCSLIFADDR, &lifr);
		if (err < 0) {
			if (secondary) {
				(void)ioctl(lib_cfg.ip6_fd, SIOCLIFREMOVEIF, &lifr);
			}
			return -1;
		}
	} else {
		/* Delete address */
		if (secondary) {
			/* Set the address to delete so Solaris can find the right logical interface */
			sin6_addr = (struct sockaddr_in6 *)&lifr.lifr_addr;
			sin6_addr->sin6_family = AF_INET6;
			if (inet_pton(AF_INET6, ipaddr, &sin6_addr->sin6_addr) <= 0) {
				errno = EINVAL;
				return -1;
			}
			err = ioctl(lib_cfg.ip6_fd, SIOCLIFREMOVEIF, &lifr);
		} else {
			/* Primary IPv6: set to :: */
			sin6_addr = (struct sockaddr_in6 *)&lifr.lifr_addr;
			sin6_addr->sin6_family = AF_INET6;
			memset(&sin6_addr->sin6_addr, 0, sizeof(sin6_addr->sin6_addr));
			err = ioctl(lib_cfg.ip6_fd, SIOCSLIFADDR, &lifr);
		}
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

		err = _solaris_modify_ipv4(nozzle, ipaddr, prefix_len, broadcast, secondary, SOLARIS_ADDR_ADD);
		free(broadcast);
	} else {
		err = _solaris_modify_ipv6(nozzle, ipaddr, prefix_len, secondary, SOLARIS_ADDR_ADD);
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

		err = _solaris_modify_ipv4(nozzle, ipaddr, prefix_len, broadcast, secondary, SOLARIS_ADDR_DELETE);
		free(broadcast);
	} else {
		err = _solaris_modify_ipv6(nozzle, ipaddr, prefix_len, secondary, SOLARIS_ADDR_DELETE);
	}

	return err;
}

// Most of this taken from openconnect
static int link_proto(nozzle_t nozzle, int unit_nr,
		      const char *devname, uint64_t flags)
{
	int ip_fd, mux_id, tap2_fd;
	int savederrno;
	struct lifreq ifr;

	tap2_fd = open("/dev/tap", O_RDWR);
	if (tap2_fd < 0) {
		return -EIO;
	}
	if (ioctl(tap2_fd, I_PUSH, "ip") < 0) {
		close(tap2_fd);
		return -EIO;
	}

	sprintf(ifr.lifr_name, "tap%d", unit_nr);
	ifr.lifr_ppa = unit_nr;
	ifr.lifr_flags = flags;

	// We need to do this, but it is allowed to fail.
	// No I don't understand it.
	(void)ioctl(tap2_fd, SIOCSLIFNAME, &ifr);

	ip_fd = open(devname, O_RDWR);
	if (ip_fd < 0) {
		savederrno = errno;
		close(tap2_fd);
		errno = savederrno;
		return -1;
	}

	mux_id = ioctl(ip_fd, I_LINK, tap2_fd);
	if (mux_id < 0) {
		savederrno = errno;
		close(tap2_fd);
		close(ip_fd);
		errno = savederrno;
		return -1;
	}

	close(tap2_fd);

	return ip_fd;
}

int solaris_setup_tap(nozzle_t nozzle, char *devname, int namelen)
{
	int tap_fd = -1;
	static char tap_name[80];
	int unit_nr;

	tap_fd = open("/dev/tap", O_RDWR);
	if (tap_fd < 0) {
		return -EIO;
	}

	unit_nr = ioctl(tap_fd, TUNNEWPPA, -1);
	if (unit_nr < 0) {
		close(tap_fd);
		return -EIO;
	}

	if (ioctl(tap_fd, I_SRDOPT, RMSGD) < 0) {
		close(tap_fd);
		return -EIO;
	}

	if (strlen(devname) == 0) {
		sprintf(tap_name, "tap%d", unit_nr);
		strncpy(devname, tap_name, namelen);
	} else {
		if (sscanf(devname, "tap%d", &unit_nr) == 1) {
			struct strioctl strioc_ppa;
			int ppa = unit_nr;
			int newppa;
			memset(&strioc_ppa, 0, sizeof(strioc_ppa));

			strioc_ppa.ic_cmd = TUNNEWPPA;
			strioc_ppa.ic_timout = 0;
			strioc_ppa.ic_len = sizeof(ppa);
			strioc_ppa.ic_dp = (char *)&ppa;
			if ((newppa = ioctl(tap_fd, I_STR, &strioc_ppa)) < 0) {
				return -errno;
			}
		} else {
			return -EIO;
		}
	}

	nozzle->ip_fd = link_proto(nozzle, unit_nr, "/dev/udp", IFF_IPV4);
	if (nozzle->ip_fd < 0) {
		close(tap_fd);
		return -EIO;
	}

	nozzle->ip6_fd = link_proto(nozzle, unit_nr, "/dev/udp6", IFF_IPV6);
	if (nozzle->ip6_fd < 0) {
		close(tap_fd);
		close(nozzle->ip_fd);
		nozzle->ip_fd = -1;
		return -EIO;
	}

	return tap_fd;
}

int _platform_create_tap(nozzle_t nozzle, char *devname, size_t devname_size)
{
	nozzle->fd = solaris_setup_tap(nozzle, devname, devname_size);
	if (nozzle->fd < 0) {
		return -1;
	}

	memmove(nozzle->name, devname, IFNAMSIZ);
	return nozzle->fd;
}

void _platform_close_tap(nozzle_t nozzle)
{
	if (nozzle->ip_fd >= 0) {
		close(nozzle->ip_fd);
		nozzle->ip_fd = -1;
	}

	if (nozzle->ip6_fd >= 0) {
		close(nozzle->ip6_fd);
		nozzle->ip6_fd = -1;
	}
}

void _platform_destroy_tap(nozzle_t nozzle)
{
	/* No platform-specific cleanup needed for Solaris */
}

int _platform_get_mac(const nozzle_t nozzle, char **ether_addr)
{
	dlpi_handle_t dlpi_handle;
	dlpi_info_t dlpi_if_info;
	char mac[MACADDR_CHAR_MAX];
	int err;

	memset(&mac, 0, MACADDR_CHAR_MAX);

	err = dlpi_open(nozzle->name, &dlpi_handle, 0);
	if (err != DLPI_SUCCESS) {
		return -1;
	}

	err = dlpi_info(dlpi_handle, &dlpi_if_info, 0);
	if (err != DLPI_SUCCESS) {
		dlpi_close(dlpi_handle);
		return -1;
	}

	dlpi_close(dlpi_handle);
	ether_ntoa_r((struct ether_addr *)dlpi_if_info.di_physaddr, mac);

	*ether_addr = strdup(mac);
	if (*ether_addr == NULL) {
		errno = ENOMEM;
		return -1;
	}

	return 0;
}

int _platform_set_mac(nozzle_t nozzle, const char *ether_addr)
{
	dlpi_handle_t dlpi_handle;
	int err;

	err = dlpi_open(nozzle->name, &dlpi_handle, 0);
	if (err != DLPI_SUCCESS) {
		return -1;
	}

	err = dlpi_set_physaddr(dlpi_handle, DL_CURR_PHYS_ADDR,
				ether_aton(ether_addr), ETHERADDRL);
	if (err != DLPI_SUCCESS) {
		dlpi_close(dlpi_handle);
		return -1;
	}

	dlpi_close(dlpi_handle);
	return 0;
}

int _platform_get_mtu(const nozzle_t nozzle)
{
	struct lifreq ifr;
	int err;

	memset(&ifr, 0, sizeof(ifr));
	memmove(ifr.lifr_name, nozzle->name, IFNAMSIZ);

	err = ioctl(lib_cfg.ioctlfd, SIOCGLIFMTU, &ifr);
	if (err) {
		return -1;
	}

	return ifr.lifr_mtu;
}

#endif /* KNET_SOLARIS */
