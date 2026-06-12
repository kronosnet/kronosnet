/*
 * Copyright (C) 2010-2026 Red Hat, Inc.  All rights reserved.
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
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <pthread.h>
#include <limits.h>
#include <stdio.h>
#include <net/if.h>
#include <stdint.h>

#include "libnozzle.h"
#include "internals.h"

/*
 * internal functions are all _unlocked_
 * locking should be handled at external API functions
 */
static int lib_init = 0;
struct nozzle_lib_config lib_cfg;
static pthread_mutex_t config_mutex = PTHREAD_MUTEX_INITIALIZER;

/*
 * internal helpers
 */

static void lib_fini(void)
{
	if (lib_cfg.head == NULL) {
		_platform_fini(&lib_cfg);
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
	if (!nozzle)
		return;

	if (nozzle->fd >= 0)
		close(nozzle->fd);

	_platform_destroy_tap(nozzle);

	free(nozzle);

	lib_fini();

	return;
}

static int get_iface_mtu(const nozzle_t nozzle)
{
	return _platform_get_mtu(nozzle);
}

static int get_iface_mac(const nozzle_t nozzle, char **ether_addr)
{
	return _platform_get_mac(nozzle, ether_addr);
}

#define IP_ADD 1
#define IP_DEL 2

static int _set_ip(nozzle_t nozzle,
		   int command,
		   const char *ipaddr, const char *prefix,
		   int secondary)
{
	char *endptr;
	long prefix_val;
	int fam;

	if (!strchr(ipaddr, ':')) {
		fam = AF_INET;
	} else {
		fam = AF_INET6;
	}

	/*
	 * Validate prefix length before use. strtol() provides proper error
	 * detection for invalid input, overflow, and trailing garbage.
	 */
	errno = 0;
	prefix_val = strtol(prefix, &endptr, 10);

	if (errno != 0 || endptr == prefix || *endptr != '\0') {
		/* Error, no digits found, or trailing garbage */
		errno = EINVAL;
		return -1;
	}

	if (prefix_val <= 0 || prefix_val > 128) {
		errno = EINVAL;
		return -1;
	}

	if ((fam == AF_INET && prefix_val > 32) ||
	    (fam == AF_INET6 && prefix_val > 128)) {
		errno = EINVAL;
		return -1;
	}

	if (command == IP_ADD) {
		return _platform_add_ip(nozzle, ipaddr, prefix, secondary);
	} else {
		return _platform_del_ip(nozzle, ipaddr, prefix, secondary);
	}
}

/*
 * Exported public API
 */

nozzle_t nozzle_open(char *devname, size_t devname_size, const char *updownpath)
{
	int savederrno = 0;
	nozzle_t nozzle = NULL;
	char *temp_mac = NULL;

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

		if (_platform_init(&lib_cfg) < 0) {
			savederrno = errno;
			goto out_error;
		}

		lib_cfg.ioctlfd = socket(NOZZLE_SOCKET_DOMAIN, SOCK_DGRAM, 0);
		if (lib_cfg.ioctlfd < 0) {
			savederrno = errno;
			_platform_fini(&lib_cfg);
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

	if (_platform_create_tap(nozzle, devname, devname_size) < 0) {
		savederrno = errno;
		goto out_error;
	}
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
	nozzle_t temp;
	nozzle_t prev;
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

	temp = lib_cfg.head;
	prev = lib_cfg.head;
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

	_platform_close_tap(nozzle);

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
	nozzle_ifreq ifr;

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

	memset(&ifr, 0, sizeof(nozzle_ifreq));
	memmove(ifname, nozzle->name, IFNAMSIZ);

	err = ioctl(NOZZLE_IOCTL_FD, SIOCGIFFLAGS, &ifr);
	if (err) {
		savederrno = errno;
		goto out_clean;
	}

	ifflags |= IFF_UP | IFF_RUNNING;
	err = ioctl(NOZZLE_IOCTL_FD, SIOCSIFFLAGS, &ifr);
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
	nozzle_ifreq ifr;

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

	memset(&ifr, 0, sizeof(nozzle_ifreq));
	memmove(ifname, nozzle->name, IFNAMSIZ);

	err = ioctl(NOZZLE_IOCTL_FD, SIOCGIFFLAGS, &ifr);
	if (err) {
		savederrno = errno;
		goto out_clean;
	}

	ifflags &= ~IFF_UP;

	err = ioctl(NOZZLE_IOCTL_FD, SIOCSIFFLAGS, &ifr);
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

	err = _platform_set_mac(nozzle, ether_addr);
	savederrno = errno;

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
	nozzle_ifreq ifr;

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

	memset(&ifr, 0, sizeof(ifr));
	memmove(ifname, nozzle->name, IFNAMSIZ);
	ifmtu = mtu;

	err = ioctl(NOZZLE_IOCTL_FD, NOZZLE_SET_MTU, &ifr);
	if (err) {
		savederrno = errno;
		goto out_clean;
	}

	if ((nozzle->current_mtu < 1280) && (mtu >= 1280)) {
		tmp_ip = nozzle->ip;
		while(tmp_ip) {
			if (tmp_ip->domain == AF_INET6) {
				int secondary = NOZZLE_IPV6_IS_SECONDARY(tmp_ip->domain);
				err = _set_ip(nozzle, IP_ADD, tmp_ip->ipaddr, tmp_ip->prefix, secondary);
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
		/* We make all Solaris IP6 addresses secondary's (using addif)
		 * otherwise we can't remove the last one
		 */
		if (nozzle->ip || NOZZLE_IPV6_IS_SECONDARY(ip->domain)) {
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
		/* On Solaris, all IPv6 addresses are secondary logical interfaces */
		int secondary = NOZZLE_IPV6_IS_SECONDARY(ip->domain);
		err = _set_ip(nozzle, IP_DEL, ipaddr, prefix, secondary);
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
