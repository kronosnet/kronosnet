/*
 * Copyright (C) 2010-2019 Red Hat, Inc.  All rights reserved.
 *
 * Author: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *
 * This software licensed under LGPL-2.0+
 */

#include "config.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/ethernet.h>
#include <pthread.h>
#include <limits.h>
#include <stdio.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <stdint.h>

#ifdef KNET_LINUX
#include <linux/if_tun.h>
/*
 * libnl3 < 3.3 includes kernel headers directly
 * causing conflicts with net/if.h included above
 */
#ifdef LIBNL3_WORKAROUND
#define _LINUX_IF_H 1
#endif
#include <netinet/ether.h>
#include <netlink/netlink.h>
#include <netlink/route/addr.h>
#include <netlink/route/link.h>
#endif
#ifdef KNET_BSD
#include <net/if_dl.h>
#endif

#include "libnozzle.h"
#include "internals.h"

/*
 * internal functions are all _unlocked_
 * locking should be handled at external API functions
 */
static int lib_init = 0;
static struct nozzle_lib_config lib_cfg;
static pthread_mutex_t config_mutex = PTHREAD_MUTEX_INITIALIZER;

/*
 * internal helpers
 */

static void lib_fini(void)
{
	if (lib_cfg.head == NULL) {
#ifdef KNET_LINUX
		nl_close(lib_cfg.nlsock);
		nl_socket_free(lib_cfg.nlsock);
#endif
		close(lib_cfg.ioctlfd);
		lib_init = 0;
	}
}

static int is_valid_nozzle(const nozzle_t nozzle)
{
	nozzle_t temp;

	if (!nozzle) {
		return 0;
	}

	if (!lib_init) {
		return 0;
	}

	temp = lib_cfg.head;

	while (temp != NULL) {
		if (nozzle == temp)
			return 1;

		temp = temp->next;
	}

	return 0;
}

static void destroy_iface(nozzle_t nozzle)
{
#ifdef KNET_BSD
	struct ifreq ifr;
#endif

	if (!nozzle)
		return;

	if (nozzle->fd >= 0)
		close(nozzle->fd);

#ifdef KNET_BSD
	memset(&ifr, 0, sizeof(struct ifreq));
	strncpy(ifname, nozzle->name, IFNAMSIZ);

	ioctl(lib_cfg.ioctlfd, SIOCIFDESTROY, &ifr);
#endif

	free(nozzle);

	lib_fini();

	return;
}

static int get_iface_mtu(const nozzle_t nozzle)
{
	int err = 0, savederrno = 0;
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(struct ifreq));
	strncpy(ifname, nozzle->name, IFNAMSIZ);

	err = ioctl(lib_cfg.ioctlfd, SIOCGIFMTU, &ifr);
	if (err) {
		savederrno = errno;
		goto out_clean;
	}

	err = ifr.ifr_mtu;

out_clean:
	errno = savederrno;
	return err;
}

static int get_iface_mac(const nozzle_t nozzle, char **ether_addr)
{
	int err = 0, savederrno = 0;
	struct ifreq ifr;
	char mac[MACADDR_CHAR_MAX];
#ifdef KNET_BSD
	struct ifaddrs *ifap = NULL;
	struct ifaddrs *ifa;
	int found = 0;
#endif

	memset(&mac, 0, MACADDR_CHAR_MAX);
	memset(&ifr, 0, sizeof(struct ifreq));
	strncpy(ifname, nozzle->name, IFNAMSIZ);

#ifdef KNET_LINUX
	err = ioctl(lib_cfg.ioctlfd, SIOCGIFHWADDR, &ifr);
	if (err) {
		savederrno = errno;
		goto out_clean;
	}

	ether_ntoa_r((struct ether_addr *)ifr.ifr_hwaddr.sa_data, mac);
#endif
#ifdef KNET_BSD
	/*
	 * there is no ioctl to get the ether address of an interface on FreeBSD
	 * (not to be confused with hwaddr). Use workaround described here:
	 * https://lists.freebsd.org/pipermail/freebsd-hackers/2004-June/007394.html
	 */
	err = getifaddrs(&ifap);
	if (err < 0) {
		savederrno = errno;
		goto out_clean;
	}

	ifa = ifap;

	while (ifa) {
		if (!strncmp(nozzle->name, ifa->ifa_name, IFNAMSIZ)) {
			found = 1;
			break;
		}
		ifa=ifa->ifa_next;
	}

	if (found) {
		ether_ntoa_r((struct ether_addr *)LLADDR((struct sockaddr_dl *)ifa->ifa_addr), mac);
	} else {
		errno = EINVAL;
		err = -1;
	}

	freeifaddrs(ifap);

	if (err) {
		goto out_clean;
	}

#endif
	*ether_addr = strdup(mac);
	if (!*ether_addr) {
		savederrno = errno;
		err = -1;
	}

out_clean:
	errno = savederrno;
	return err;
}

#define IP_ADD 1
#define IP_DEL 2

static int _set_ip(nozzle_t nozzle,
		   int command,
		   const char *ipaddr, const char *prefix,
		   int secondary)
{
	int fam;
	char *broadcast = NULL;
	int err = 0;
#ifdef KNET_LINUX
	struct rtnl_addr *addr = NULL;
	struct nl_addr *local_addr = NULL;
	struct nl_addr *bcast_addr = NULL;
	struct nl_cache *cache = NULL;
	int ifindex;
#endif
#ifdef KNET_BSD
	char cmdline[4096];
	char proto[6];
	char *error_string = NULL;
#endif

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

#ifdef KNET_LINUX
	addr = rtnl_addr_alloc();
	if (!addr) {
		errno = ENOMEM;
		err = -1;
		goto out;
	}

	if (rtnl_link_alloc_cache(lib_cfg.nlsock, AF_UNSPEC, &cache) < 0) {
		errno = ENOMEM;
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

	if (nl_addr_parse(ipaddr, fam, &local_addr) < 0) {
		errno = EINVAL;
		err = -1;
		goto out;
	}

	if (rtnl_addr_set_local(addr, local_addr) < 0) {
		errno = EINVAL;
		err = -1;
		goto out;
	}

	if (broadcast) {
		if (nl_addr_parse(broadcast, fam, &bcast_addr) < 0) {
			errno = EINVAL;
			err = -1;
			goto out;
		}

		if (rtnl_addr_set_broadcast(addr, bcast_addr) < 0) {
			errno = EINVAL;
			err = -1;
			goto out;
		}
	}

	rtnl_addr_set_prefixlen(addr, atoi(prefix));

	if (command == IP_ADD) {
		if (rtnl_addr_add(lib_cfg.nlsock, addr, 0) < 0) {
			errno = EINVAL;
			err = -1;
			goto out;
		}
	} else {
		if (rtnl_addr_delete(lib_cfg.nlsock, addr, 0) < 0) {
			errno = EINVAL;
			err = -1;
			goto out;
		}
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
#endif
#ifdef KNET_BSD
	/*
	 * TODO: port to use ioctl and such, drop shell forking here
	 */
	memset(cmdline, 0, sizeof(cmdline));

	if (fam == AF_INET) {
		snprintf(proto, sizeof(proto), "inet");
	} else {
		snprintf(proto, sizeof(proto), "inet6");
	}

	if (command == IP_ADD) {
		snprintf(cmdline, sizeof(cmdline)-1,
			 "ifconfig %s %s %s/%s",
			 nozzle->name, proto, ipaddr, prefix);
		if (broadcast) {
			snprintf(cmdline + strlen(cmdline),
				 sizeof(cmdline) - strlen(cmdline) -1,
				 " broadcast %s", broadcast);
		}
		if ((secondary) && (fam == AF_INET)) {
			snprintf(cmdline + strlen(cmdline),
				 sizeof(cmdline) - strlen(cmdline) -1,
				 " alias");
		}
	} else {
		snprintf(cmdline, sizeof(cmdline)-1,
				 "ifconfig %s %s %s/%s delete",
				 nozzle->name, proto, ipaddr, prefix);
	}
	if (broadcast) {
		free(broadcast);
	}

	/*
	 * temporary workaround as we port libnozzle to BSD ioctl
	 * for IP address management
	 */
	err = execute_bin_sh_command(cmdline, &error_string);
	if (error_string) {
		free(error_string);
		error_string = NULL;
	}
	return err;
#endif
}

/*
 * Exported public API
 */

nozzle_t nozzle_open(char *devname, size_t devname_size, const char *updownpath)
{
	int savederrno = 0;
	nozzle_t nozzle = NULL;
	char *temp_mac = NULL;
#ifdef KNET_LINUX
	struct ifreq ifr;
#endif
#ifdef KNET_BSD
	uint16_t i;
	long int nozzlenum = 0;
	char curnozzle[IFNAMSIZ];
#endif

	if (devname == NULL) {
		errno = EINVAL;
		return NULL;
	}

	if (devname_size < IFNAMSIZ) {
		errno = EINVAL;
		return NULL;
	}

	/* Need to allow space for trailing NUL */
	if (strlen(devname) >= IFNAMSIZ) {
		errno = E2BIG;
		return NULL;
	}

#ifdef KNET_BSD
	/*
	 * BSD does not support named devices like Linux
	 * but it is possible to force a nozzleX device number
	 * where X is 0 to 255.
	 */
	if (strlen(devname)) {
		if (strncmp(devname, "tap", 3)) {
			errno = EINVAL;
			return NULL;
		}
		errno = 0;
		nozzlenum = strtol(devname+3, NULL, 10);
		if (errno) {
			errno = EINVAL;
			return NULL;
		}
		if ((nozzlenum < 0) || (nozzlenum > 255)) {
			errno = EINVAL;
			return NULL;
		}
	}
#endif

	if (updownpath) {
		/* only absolute paths */
		if (updownpath[0] != '/') {
			errno = EINVAL;
			return NULL;
		}
		if (strlen(updownpath) >= UPDOWN_PATH_MAX) {
			errno = E2BIG;
			return NULL;
		}
	}

	savederrno = pthread_mutex_lock(&config_mutex);
	if (savederrno) {
		errno = savederrno;
		return NULL;
	}

	if (!lib_init) {
		lib_cfg.head = NULL;
#ifdef KNET_LINUX
		lib_cfg.nlsock = nl_socket_alloc();
		if (!lib_cfg.nlsock) {
			savederrno = errno;
			goto out_error;
		}
		if (nl_connect(lib_cfg.nlsock, NETLINK_ROUTE) < 0) {
			savederrno = EBUSY;
			goto out_error;
		}
		lib_cfg.ioctlfd = socket(AF_INET, SOCK_STREAM, 0);
#endif
#ifdef KNET_BSD
		lib_cfg.ioctlfd = socket(AF_LOCAL, SOCK_DGRAM, 0);
#endif
		if (lib_cfg.ioctlfd < 0) {
			savederrno = errno;
			goto out_error;
		}
		lib_init = 1;
	}

	nozzle = malloc(sizeof(struct nozzle_iface));
	if (!nozzle) {
		savederrno = ENOMEM;
		goto out_error;
	}

	memset(nozzle, 0, sizeof(struct nozzle_iface));

#ifdef KNET_BSD
	if (!strlen(devname)) {
		for (i = 0; i < 256; i++) {
			snprintf(curnozzle, sizeof(curnozzle) - 1, "/dev/tap%u", i);
			nozzle->fd = open(curnozzle, O_RDWR);
			savederrno = errno;
			if (nozzle->fd > 0) {
				break;
			}
		}
		snprintf(curnozzle, sizeof(curnozzle) -1 , "tap%u", i);
	} else {
		snprintf(curnozzle, sizeof(curnozzle) - 1, "/dev/%s", devname);
		nozzle->fd = open(curnozzle, O_RDWR);
		savederrno = errno;
		snprintf(curnozzle, sizeof(curnozzle) - 1, "%s", devname);
	}
	if (nozzle->fd < 0) {
		savederrno = EBUSY;
		goto out_error;
	}
	strncpy(devname, curnozzle, IFNAMSIZ);
	strncpy(nozzle->name, curnozzle, IFNAMSIZ);
#endif

#ifdef KNET_LINUX
	if ((nozzle->fd = open("/dev/net/tun", O_RDWR)) < 0) {
		savederrno = errno;
		goto out_error;
	}

	memset(&ifr, 0, sizeof(struct ifreq));
	memmove(ifname, devname, IFNAMSIZ);
	ifr.ifr_flags = IFF_TAP | IFF_NO_PI;

	if (ioctl(nozzle->fd, TUNSETIFF, &ifr) < 0) {
		savederrno = errno;
		goto out_error;
	}

	if ((strlen(devname) > 0) && (strcmp(devname, ifname) != 0)) {
		savederrno = EBUSY;
		goto out_error;
	}

	strncpy(devname, ifname, IFNAMSIZ);
	strncpy(nozzle->name, ifname, IFNAMSIZ);
#endif

	nozzle->default_mtu = get_iface_mtu(nozzle);
	if (nozzle->default_mtu < 0) {
		savederrno = errno;
		goto out_error;
	}

	if (get_iface_mac(nozzle, &temp_mac) < 0) {
		savederrno = errno;
		goto out_error;
	}

	strncpy(nozzle->default_mac, temp_mac, 18);
	free(temp_mac);

	if (updownpath) {
		int len = strlen(updownpath);

		strcpy(nozzle->updownpath, updownpath);
		if (nozzle->updownpath[len-1] != '/') {
			nozzle->updownpath[len] = '/';
		}
		nozzle->hasupdown = 1;
	}

	nozzle->next = lib_cfg.head;
	lib_cfg.head = nozzle;

	pthread_mutex_unlock(&config_mutex);
	errno = savederrno;
	return nozzle;

out_error:
	destroy_iface(nozzle);
	pthread_mutex_unlock(&config_mutex);
	errno = savederrno;
	return NULL;
}

int nozzle_close(nozzle_t nozzle)
{
	int err = 0, savederrno = 0;
	nozzle_t temp = lib_cfg.head;
	nozzle_t prev = lib_cfg.head;
	struct nozzle_ip *ip, *ip_next;

	savederrno = pthread_mutex_lock(&config_mutex);
	if (savederrno) {
		errno = savederrno;
		return -1;
	}

	if (!is_valid_nozzle(nozzle)) {
		savederrno = EINVAL;
		err = -1;
		goto out_clean;
	}

	while ((temp) && (temp != nozzle)) {
		prev = temp;
		temp = temp->next;
	}

	if (nozzle == prev) {
		lib_cfg.head = nozzle->next;
	} else {
		prev->next = nozzle->next;
	}

	ip = nozzle->ip;
	while (ip) {
		ip_next = ip->next;
		free(ip);
		ip = ip_next;
	}

	destroy_iface(nozzle);

out_clean:
	pthread_mutex_unlock(&config_mutex);
	errno = savederrno;
	return err;
}

int nozzle_run_updown(const nozzle_t nozzle, uint8_t action, char **exec_string)
{
	int err = 0, savederrno = 0;
	char command[PATH_MAX];
	const char *action_str = NULL;
	struct stat sb;

	if (action > NOZZLE_POSTDOWN) {
		errno = EINVAL;
		return -1;
	}

	if (!exec_string) {
		errno = EINVAL;
		return -1;
	}

	savederrno = pthread_mutex_lock(&config_mutex);
	if (savederrno) {
		errno = savederrno;
		return -1;
	}

	if (!is_valid_nozzle(nozzle)) {
		savederrno = EINVAL;
		err = -1;
		goto out_clean;
	}

	if (!nozzle->hasupdown) {
		savederrno = EINVAL;
		err = -1;
		goto out_clean;
	}

	switch(action) {
		case NOZZLE_PREUP:
			action_str = "pre-up.d";
			break;
		case NOZZLE_UP:
			action_str = "up.d";
			break;
		case NOZZLE_DOWN:
			action_str = "down.d";
			break;
		case NOZZLE_POSTDOWN:
			action_str = "post-down.d";
			break;
	}

	memset(command, 0, PATH_MAX);

	snprintf(command, PATH_MAX, "%s/%s/%s", nozzle->updownpath, action_str, nozzle->name);

	err = stat(command, &sb);
	if (err) {
		savederrno = errno;
		goto out_clean;
	}

	/*
	 * clear errno from previous calls as there is no errno
	 * returned from execute_bin_sh_command
	 */
	savederrno = 0;
	err = execute_bin_sh_command(command, exec_string);
	if (err) {
		err = -2;
	}

out_clean:
	pthread_mutex_unlock(&config_mutex);
	errno =  savederrno;
	return err;
}

int nozzle_set_up(nozzle_t nozzle)
{
	int err = 0, savederrno = 0;
	struct ifreq ifr;

	savederrno = pthread_mutex_lock(&config_mutex);
	if (savederrno) {
		errno = savederrno;
		return -1;
	}

	if (!is_valid_nozzle(nozzle)) {
		savederrno = EINVAL;
		err = -1;
		goto out_clean;
	}

	if (nozzle->up) {
		goto out_clean;
	}

	memset(&ifr, 0, sizeof(struct ifreq));
	strncpy(ifname, nozzle->name, IFNAMSIZ);

	err = ioctl(lib_cfg.ioctlfd, SIOCGIFFLAGS, &ifr);
	if (err) {
		savederrno = errno;
		goto out_clean;
	}

	ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
	err = ioctl(lib_cfg.ioctlfd, SIOCSIFFLAGS, &ifr);
	if (err) {
		savederrno = errno;
		goto out_clean;
	}

	nozzle->up = 1;

out_clean:
	pthread_mutex_unlock(&config_mutex);
	errno = savederrno;
	return err;
}

int nozzle_set_down(nozzle_t nozzle)
{
	int err = 0, savederrno = 0;
	struct ifreq ifr;

	savederrno = pthread_mutex_lock(&config_mutex);
	if (savederrno) {
		errno = savederrno;
		return -1;
	}

	if (!is_valid_nozzle(nozzle)) {
		savederrno = EINVAL;
		err = -1;
		goto out_clean;
	}

	if (!nozzle->up) {
		goto out_clean;
	}

	memset(&ifr, 0, sizeof(struct ifreq));
	strncpy(ifname, nozzle->name, IFNAMSIZ);

	err = ioctl(lib_cfg.ioctlfd, SIOCGIFFLAGS, &ifr);
	if (err) {
		savederrno = errno;
		goto out_clean;
	}

	ifr.ifr_flags &= ~IFF_UP;

	err = ioctl(lib_cfg.ioctlfd, SIOCSIFFLAGS, &ifr);
	if (err) {
		savederrno = errno;
		goto out_clean;
	}

	nozzle->up = 0;

out_clean:
	pthread_mutex_unlock(&config_mutex);
	errno = savederrno;
	return err;
}

int nozzle_get_mtu(const nozzle_t nozzle)
{
	int err = 0, savederrno = 0;

	savederrno = pthread_mutex_lock(&config_mutex);
	if (savederrno) {
		errno = savederrno;
		return -1;
	}

	if (!is_valid_nozzle(nozzle)) {
		savederrno = EINVAL;
		err = -1;
		goto out_clean;
	}

	err = get_iface_mtu(nozzle);
	savederrno = errno;

out_clean:
	pthread_mutex_unlock(&config_mutex);
	errno = savederrno;
	return err;
}

int nozzle_get_mac(const nozzle_t nozzle, char **ether_addr)
{
	int err = 0, savederrno = 0;

	if (!ether_addr) {
		errno = EINVAL;
		return -1;
	}

	savederrno = pthread_mutex_lock(&config_mutex);
	if (savederrno) {
		errno = savederrno;
		return -1;
	}

	if (!is_valid_nozzle(nozzle)) {
		savederrno = EINVAL;
		err = -1;
		goto out_clean;
	}

	err = get_iface_mac(nozzle, ether_addr);

out_clean:
	pthread_mutex_unlock(&config_mutex);
	errno = savederrno;
	return err;
}

int nozzle_set_mac(nozzle_t nozzle, const char *ether_addr)
{
	int err = 0, savederrno = 0;
	struct ifreq ifr;

	if (!ether_addr) {
		errno = EINVAL;
		return -1;
	}

	savederrno = pthread_mutex_lock(&config_mutex);
	if (savederrno) {
		errno = savederrno;
		return -1;
	}

	if (!is_valid_nozzle(nozzle)) {
		savederrno = EINVAL;
		err = -1;
		goto out_clean;
	}

	memset(&ifr, 0, sizeof(struct ifreq));
	strncpy(ifname, nozzle->name, IFNAMSIZ);
#ifdef KNET_LINUX
	err = ioctl(lib_cfg.ioctlfd, SIOCGIFHWADDR, &ifr);
	if (err) {
		savederrno = errno;
		goto out_clean;
	}

	memmove(ifr.ifr_hwaddr.sa_data, ether_aton(ether_addr), ETH_ALEN);

	err = ioctl(lib_cfg.ioctlfd, SIOCSIFHWADDR, &ifr);
	savederrno = errno;
#endif
#ifdef KNET_BSD
	err = ioctl(lib_cfg.ioctlfd, SIOCGIFADDR, &ifr);
	if (err) {
		savederrno = errno;
		goto out_clean;
	}

	memmove(ifr.ifr_addr.sa_data, ether_aton(ether_addr), ETHER_ADDR_LEN);
	ifr.ifr_addr.sa_len = ETHER_ADDR_LEN;

	err = ioctl(lib_cfg.ioctlfd, SIOCSIFLLADDR, &ifr);
	savederrno = errno;
#endif
out_clean:
	pthread_mutex_unlock(&config_mutex);
	errno = savederrno;
	return err;
}

int nozzle_reset_mac(nozzle_t nozzle)
{
	return nozzle_set_mac(nozzle, nozzle->default_mac);
}

nozzle_t nozzle_get_handle_by_name(const char *devname)
{
	int savederrno = 0;
	nozzle_t nozzle;

	if ((devname == NULL) || (strlen(devname) > IFNAMSIZ)) {
		errno = EINVAL;
		return NULL;
	}

	savederrno = pthread_mutex_lock(&config_mutex);
	if (savederrno) {
		errno = savederrno;
		return NULL;
	}

	nozzle = lib_cfg.head;
	while (nozzle != NULL) {
		if (!strcmp(devname, nozzle->name))
			break;
		nozzle = nozzle->next;
	}

	if (!nozzle) {
		savederrno = ENOENT;
	}

	pthread_mutex_unlock(&config_mutex);
	errno = savederrno;
	return nozzle;
}

const char *nozzle_get_name_by_handle(const nozzle_t nozzle)
{
	int savederrno = 0;
	char *name = NULL;

	savederrno = pthread_mutex_lock(&config_mutex);
	if (savederrno) {
		errno = savederrno;
		return NULL;
	}

	if (!is_valid_nozzle(nozzle)) {
		savederrno = ENOENT;
		goto out_clean;
	}

	name = nozzle->name;

out_clean:
	pthread_mutex_unlock(&config_mutex);
	errno = savederrno;
	return name;
}

int nozzle_get_fd(const nozzle_t nozzle)
{
	int fd = -1, savederrno = 0;

	savederrno = pthread_mutex_lock(&config_mutex);
	if (savederrno) {
		errno = savederrno;
		return -1;
	}

	if (!is_valid_nozzle(nozzle)) {
		savederrno = ENOENT;
		fd = -1;
		goto out_clean;
	}

	fd = nozzle->fd;

out_clean:
	pthread_mutex_unlock(&config_mutex);
	errno = savederrno;
	return fd;
}

int nozzle_set_mtu(nozzle_t nozzle, const int mtu)
{
	int err = 0, savederrno = 0;
	struct nozzle_ip *tmp_ip;
	struct ifreq ifr;

	if (!mtu) {
		errno = EINVAL;
		return -1;
	}

	savederrno = pthread_mutex_lock(&config_mutex);
	if (savederrno) {
		errno = savederrno;
		return -1;
	}

	if (!is_valid_nozzle(nozzle)) {
		savederrno = EINVAL;
		err = -1;
		goto out_clean;
	}

	err = nozzle->current_mtu = get_iface_mtu(nozzle);
	if (err < 0) {
		savederrno = errno;
		goto out_clean;
	}

	memset(&ifr, 0, sizeof(struct ifreq));
	strncpy(ifname, nozzle->name, IFNAMSIZ);
	ifr.ifr_mtu = mtu;

	err = ioctl(lib_cfg.ioctlfd, SIOCSIFMTU, &ifr);
	if (err) {
		savederrno = errno;
		goto out_clean;
	}

	if ((nozzle->current_mtu < 1280) && (mtu >= 1280)) {
		tmp_ip = nozzle->ip;
		while(tmp_ip) {
			if (tmp_ip->domain == AF_INET6) {
				err = _set_ip(nozzle, IP_ADD, tmp_ip->ipaddr, tmp_ip->prefix, 0);
				if (err) {
					savederrno = errno;
					err = -1;
					goto out_clean;
				}
			}
			tmp_ip = tmp_ip->next;
		}
	}

out_clean:
	pthread_mutex_unlock(&config_mutex);
	errno = savederrno;
	return err;
}

int nozzle_reset_mtu(nozzle_t nozzle)
{
	return nozzle_set_mtu(nozzle, nozzle->default_mtu);
}

int nozzle_add_ip(nozzle_t nozzle, const char *ipaddr, const char *prefix)
{
	int err = 0, savederrno = 0;
	int found = 0;
	struct nozzle_ip *ip = NULL, *ip_prev = NULL, *ip_last = NULL;
	int secondary = 0;

	if ((!ipaddr) || (!prefix)) {
		errno = EINVAL;
		return -1;
	}

	savederrno = pthread_mutex_lock(&config_mutex);
	if (savederrno) {
		errno = savederrno;
		return -1;
	}

	if (!is_valid_nozzle(nozzle)) {
		savederrno = EINVAL;
		err = -1;
		goto out_clean;
	}

	found = find_ip(nozzle, ipaddr, prefix, &ip, &ip_prev);
	if (found) {
		goto out_clean;
	}

	ip = malloc(sizeof(struct nozzle_ip));
	if (!ip) {
		savederrno = errno;
		err = -1 ;
		goto out_clean;
	}

	memset(ip, 0, sizeof(struct nozzle_ip));
	strncpy(ip->ipaddr, ipaddr, IPADDR_CHAR_MAX);
	strncpy(ip->prefix, prefix, PREFIX_CHAR_MAX);
	if (!strchr(ip->ipaddr, ':')) {
		ip->domain = AF_INET;
	} else {
		ip->domain = AF_INET6;
	}

	/*
	 * if user asks for an IPv6 address, but MTU < 1280
	 * store the IP and bring it up later if and when MTU > 1280
	 */
	if ((ip->domain == AF_INET6) && (get_iface_mtu(nozzle) < 1280)) {
		err = 0;
	} else {
		if (nozzle->ip) {
			secondary = 1;
		}
		err = _set_ip(nozzle, IP_ADD, ipaddr, prefix, secondary);
		savederrno = errno;
	}

	if (err) {
		free(ip);
		goto out_clean;
	}

	if (nozzle->ip) {
		ip_last = nozzle->ip;
		while (ip_last->next != NULL) {
			ip_last = ip_last->next;
		}
		ip_last->next = ip;
	} else {
		nozzle->ip = ip;
	}

out_clean:
	pthread_mutex_unlock(&config_mutex);
	errno = savederrno;
	return err;
}

int nozzle_del_ip(nozzle_t nozzle, const char *ipaddr, const char *prefix)
{
	int err = 0, savederrno = 0;
        int found = 0;
	struct nozzle_ip *ip = NULL, *ip_prev = NULL;

	if ((!ipaddr) || (!prefix)) {
		errno = EINVAL;
		return -1;
	}

	savederrno = pthread_mutex_lock(&config_mutex);
	if (savederrno) {
		errno = savederrno;
		return -1;
	}

	if (!is_valid_nozzle(nozzle)) {
		savederrno = EINVAL;
		err = -1;
		goto out_clean;
	}

	found = find_ip(nozzle, ipaddr, prefix, &ip, &ip_prev);
	if (!found) {
		goto out_clean;
	}

	/*
	 * if user asks for an IPv6 address, but MTU < 1280
	 * the IP might not be configured on the interface and we only need to
	 * remove it from our internal database
	 */
	if ((ip->domain == AF_INET6) && (get_iface_mtu(nozzle) < 1280)) {
		err = 0;
	} else {
		err = _set_ip(nozzle, IP_DEL, ipaddr, prefix, 0);
		savederrno = errno;
	}

	if (!err) {
		if (ip == ip_prev) {
			nozzle->ip = ip->next;
		} else {
			ip_prev->next = ip->next;
		}
		free(ip);
	}

out_clean:
	pthread_mutex_unlock(&config_mutex);
	errno = savederrno;
	return err;
}

int nozzle_get_ips(const nozzle_t nozzle, struct nozzle_ip **nozzle_ip)
{
	int err = 0, savederrno = 0;

	if (!nozzle_ip) {
		errno = EINVAL;
		return -1;
	}

	savederrno = pthread_mutex_lock(&config_mutex);
	if (savederrno) {
		errno = savederrno;
		return -1;
	}

	if (!is_valid_nozzle(nozzle)) {
		err = -1;
		savederrno = EINVAL;
		goto out_clean;
	}

	*nozzle_ip = nozzle->ip;

out_clean:
	pthread_mutex_unlock(&config_mutex);
	errno = savederrno;
	return err;
}
