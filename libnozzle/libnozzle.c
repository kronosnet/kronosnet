/*
 * Copyright (C) 2010-2018 Red Hat, Inc.  All rights reserved.
 *
 * Author: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *
 * This software licensed under GPL-2.0+, LGPL-2.0+
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
#include <arpa/inet.h>
#include <pthread.h>
#include <limits.h>
#include <stdio.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <stdint.h>

#ifdef KNET_LINUX
#include <linux/if_tun.h>
#include <netinet/ether.h>
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

/* forward declarations */
static void _close(nozzle_t nozzle);
static void _close_cfg(void);
static int _get_mtu(const nozzle_t nozzle);
static int _get_mac(const nozzle_t nozzle, char **ether_addr);
static int _set_down(nozzle_t nozzle, char **error_down, char **error_postdown);
static char *_get_v4_broadcast(const char *ipaddr, const char *prefix);
static int _set_ip(nozzle_t nozzle, const char *command,
		      const char *ipaddr, const char *prefix,
		      char **error_string, int secondary);
static int _find_ip(nozzle_t nozzle,
			const char *ipaddr, const char *prefix,
			struct nozzle_ip **ip, struct nozzle_ip **ip_prev);

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

static void _close(nozzle_t nozzle)
{
#ifdef KNET_BSD
	struct ifreq ifr;
#endif

	if (!nozzle)
		return;

	if (nozzle->fd)
		close(nozzle->fd);

#ifdef KNET_BSD
	memset(&ifr, 0, sizeof(struct ifreq));
	strncpy(ifname, nozzle->name, IFNAMSIZ);

	ioctl(lib_cfg.ioctlfd, SIOCIFDESTROY, &ifr);
#endif

	free(nozzle);

	return;
}

static void _close_cfg(void)
{
	if (lib_cfg.head == NULL) {
		close(lib_cfg.ioctlfd);
		lib_init = 0;
	}
}

static int _get_mtu(const nozzle_t nozzle)
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

static int _get_mac(const nozzle_t nozzle, char **ether_addr)
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

nozzle_t nozzle_get_handle_by_name(char *devname)
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

	if (strlen(devname) > IFNAMSIZ) {
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
		errno = EBUSY;
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
	strncpy(ifname, devname, IFNAMSIZ);
	ifr.ifr_flags = IFF_TAP | IFF_NO_PI;

	if (ioctl(nozzle->fd, TUNSETIFF, &ifr) < 0) {
		savederrno = errno;
		goto out_error;
	}

	if ((strlen(devname) > 0) && (strcmp(devname, ifname) != 0)) {
		errno = EBUSY;
		goto out_error;
	}

	strncpy(devname, ifname, IFNAMSIZ);
	strncpy(nozzle->name, ifname, IFNAMSIZ);
#endif

	nozzle->default_mtu = _get_mtu(nozzle);
	if (nozzle->default_mtu < 0) {
		savederrno = errno;
		goto out_error;
	}

	if (_get_mac(nozzle, &temp_mac) < 0) {
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
	_close(nozzle);
	_close_cfg();
	pthread_mutex_unlock(&config_mutex);
	errno = savederrno;
	return NULL;
}

int nozzle_close(nozzle_t nozzle,  char **error_down, char **error_postdown)
{
	int err = 0, savederrno = 0;
	nozzle_t temp = lib_cfg.head;
	nozzle_t prev = lib_cfg.head;
	struct nozzle_ip *ip, *ip_next;
	char *error_string = NULL;

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

	_set_down(nozzle, error_down, error_postdown);

	ip = nozzle->ip;
	while (ip) {
		ip_next = ip->next;
		_set_ip(nozzle, "del", ip->ipaddr, ip->prefix, &error_string, 0);
		if (error_string) {
			free(error_string);
			error_string = NULL;
		}
		free(ip);
		ip = ip_next;
	}

	_close(nozzle);
	_close_cfg();

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

	err = _get_mtu(nozzle);
	savederrno = errno;

out_clean:
	pthread_mutex_unlock(&config_mutex);
	savederrno = errno;
	return err;
}

int nozzle_set_mtu(nozzle_t nozzle, const int mtu, char **error_string)
{
	int err = 0, savederrno = 0;
	struct nozzle_ip *tmp_ip;
	struct ifreq ifr;

	if ((!mtu) || (!error_string)) {
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

	err = nozzle->current_mtu = _get_mtu(nozzle);
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
				err = _set_ip(nozzle, "add", tmp_ip->ipaddr, tmp_ip->prefix, error_string, 0);
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

int nozzle_reset_mtu(nozzle_t nozzle, char **error_string)
{
	return nozzle_set_mtu(nozzle, nozzle->default_mtu, error_string);
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

	err = _get_mac(nozzle, ether_addr);

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

int nozzle_set_up(nozzle_t nozzle, char **error_preup, char **error_up)
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

	if ((nozzle->hasupdown) && ((!error_preup) || (!error_up))) {
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

	run_updown(nozzle, "pre-up.d", error_preup);

	ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
	err = ioctl(lib_cfg.ioctlfd, SIOCSIFFLAGS, &ifr);
	if (err) {
		savederrno = errno;
		goto out_clean;
	}

	run_updown(nozzle, "up.d", error_up);

	nozzle->up = 1;

out_clean:
	pthread_mutex_unlock(&config_mutex);
	errno = savederrno;
	return err;
}

static int _set_down(nozzle_t nozzle, char **error_down, char **error_postdown)
{
	int err = 0, savederrno = 0;
	struct ifreq ifr;

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

	run_updown(nozzle, "down.d", error_down);

	ifr.ifr_flags &= ~IFF_UP;

	err = ioctl(lib_cfg.ioctlfd, SIOCSIFFLAGS, &ifr);
	if (err) {
		savederrno = errno;
		goto out_clean;
	}

	run_updown(nozzle, "post-down.d", error_postdown);

	nozzle->up = 0;

out_clean:
	errno = savederrno;
	return err;
}

int nozzle_set_down(nozzle_t nozzle, char **error_down, char **error_postdown)
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

	if ((nozzle->hasupdown) && ((!error_down) || (!error_postdown))) {
		savederrno = EINVAL;
		err = -1;
		goto out_clean;
	}

	err = _set_down(nozzle, error_down, error_postdown);
	savederrno = errno;

out_clean:
	pthread_mutex_unlock(&config_mutex);
	errno = savederrno;
	return err;
}

static char *_get_v4_broadcast(const char *ipaddr, const char *prefix)
{
	int prefix_len;
	struct in_addr mask;
	struct in_addr broadcast;
	struct in_addr address;

	prefix_len = atoi(prefix);

	if ((prefix_len > 32) || (prefix_len < 0))
		return NULL;

	if (inet_pton(AF_INET, ipaddr, &address) <= 0)
		return NULL;

	mask.s_addr = htonl(~((1 << (32 - prefix_len)) - 1));

	memset(&broadcast, 0, sizeof(broadcast));
	broadcast.s_addr = (address.s_addr & mask.s_addr) | ~mask.s_addr;

	return strdup(inet_ntoa(broadcast));
}

static int _set_ip(nozzle_t nozzle, const char *command,
		      const char *ipaddr, const char *prefix,
		      char **error_string, int secondary)
{
	char *broadcast = NULL;
	char cmdline[4096];
#ifdef KNET_BSD
	char proto[6];
	int v4 = 1;

	snprintf(proto, sizeof(proto), "inet");
#endif

	if (!strchr(ipaddr, ':')) {
		broadcast = _get_v4_broadcast(ipaddr, prefix);
		if (!broadcast) {
			errno = EINVAL;
			return -1;
		}
	}
#ifdef KNET_BSD
	  else {
		v4 = 0;
		snprintf(proto, sizeof(proto), "inet6");
	}
#endif

	memset(cmdline, 0, sizeof(cmdline));

#ifdef KNET_LINUX
	if (broadcast) {
		snprintf(cmdline, sizeof(cmdline)-1,
			 "ip addr %s %s/%s dev %s broadcast %s",
			 command, ipaddr, prefix,
			 nozzle->name, broadcast);
	} else {
		snprintf(cmdline, sizeof(cmdline)-1,
			 "ip addr %s %s/%s dev %s",
			command, ipaddr, prefix,
			nozzle->name);
	}
#endif
#ifdef KNET_BSD
	if (!strcmp(command, "add")) {
		snprintf(cmdline, sizeof(cmdline)-1,
			 "ifconfig %s %s %s/%s",
			 nozzle->name, proto, ipaddr, prefix);
		if (broadcast) {
			snprintf(cmdline + strlen(cmdline),
				 sizeof(cmdline) - strlen(cmdline) -1,
				 " broadcast %s", broadcast);
		}
		if ((secondary) && (v4)) {
			snprintf(cmdline + strlen(cmdline),
				 sizeof(cmdline) - strlen(cmdline) -1,
				 " alias");
		}
	} else {
		snprintf(cmdline, sizeof(cmdline)-1,
				 "ifconfig %s %s %s/%s delete",
				 nozzle->name, proto, ipaddr, prefix);
	}
#endif
	if (broadcast) {
		free(broadcast);
	}
	return execute_bin_sh_command(cmdline, error_string);
}

static int _find_ip(nozzle_t nozzle,
			const char *ipaddr, const char *prefix,
			struct nozzle_ip **ip, struct nozzle_ip **ip_prev)
{
	struct nozzle_ip *local_ip, *local_ip_prev;
	int found = 0;

	local_ip = local_ip_prev = nozzle->ip;

	while(local_ip) {
		if ((!strcmp(local_ip->ipaddr, ipaddr)) && (!strcmp(local_ip->prefix, prefix))) {
			found = 1;
			break;
		}
		local_ip_prev = local_ip;
		local_ip = local_ip->next;
	}

	if (found) {
		*ip = local_ip;
		*ip_prev = local_ip_prev;
	}

	return found;
}

int nozzle_add_ip(nozzle_t nozzle, const char *ipaddr, const char *prefix, char **error_string)
{
	int err = 0, savederrno = 0;
	int found = 0;
	struct nozzle_ip *ip = NULL, *ip_prev = NULL, *ip_last = NULL;
	int secondary = 0;

	if ((!ipaddr) || (!prefix) || (!error_string)) {
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

	found = _find_ip(nozzle, ipaddr, prefix, &ip, &ip_prev);
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
	if ((ip->domain == AF_INET6) && (_get_mtu(nozzle) < 1280)) {
		err = 0;
	} else {
		if (nozzle->ip) {
			secondary = 1;
		}
		err = _set_ip(nozzle, "add", ipaddr, prefix, error_string, secondary);
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

int nozzle_del_ip(nozzle_t nozzle, const char *ipaddr, const char *prefix, char **error_string)
{
	int err = 0, savederrno = 0;
        int found = 0;
	struct nozzle_ip *ip = NULL, *ip_prev = NULL;

	if ((!ipaddr) || (!prefix) || (!error_string)) {
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

	found = _find_ip(nozzle, ipaddr, prefix, &ip, &ip_prev);
	if (!found) {
		goto out_clean;
	}

	err = _set_ip(nozzle, "del", ipaddr, prefix, error_string, 0);
	savederrno = errno;
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

int nozzle_get_ips(const nozzle_t nozzle, char **ipaddr_list, int *entries)
{
	int err = 0, savederrno = 0;
	int found = 0;
	char *ip_list = NULL;
	int size = 0, offset = 0, len;
	struct nozzle_ip *ip = NULL;

	if ((!ipaddr_list) || (!entries)) {
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
		goto out_clean;
	}

	ip = nozzle->ip;

	while (ip) {
		found++;
		ip = ip->next;
	}

	if (!found) {
		*ipaddr_list = NULL;
		*entries = 0;
		goto out_clean;
	}

	size = found * (IPADDR_CHAR_MAX + PREFIX_CHAR_MAX + 2);

	ip_list = malloc(size);
	if (!ip_list) {
		savederrno = errno;
		err = -1;
		goto out_clean;
	}

	memset(ip_list, 0, size);

	ip = nozzle->ip;

	while (ip) {
		len = strlen(ip->ipaddr);
		memmove(ip_list + offset, ip->ipaddr, len);
		offset = offset + len + 1;
		len = strlen(ip->prefix);
		memmove(ip_list + offset, ip->prefix, len);
		offset = offset + len + 1;
		ip = ip->next;
	}

	*ipaddr_list = ip_list;
	*entries = found;

out_clean:
	pthread_mutex_unlock(&config_mutex);
	errno = savederrno;
	return err;
}
