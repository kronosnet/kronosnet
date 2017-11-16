/*
 * Copyright (C) 2010-2017 Red Hat, Inc.  All rights reserved.
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

#include "libtap.h"

#define MAX_IP_CHAR	128
#define MAX_PREFIX_CHAR	4
#define MAX_MAC_CHAR	18

struct _ip {
	char ip_addr[MAX_IP_CHAR];
	char prefix[MAX_PREFIX_CHAR];
	int  domain;
	struct _ip *next;
};

struct _iface {
	struct ifreq ifr;
	int fd;
	char tapname[IFNAMSIZ];
	char default_mac[MAX_MAC_CHAR];
	int default_mtu;
	int current_mtu;
	char updownpath[PATH_MAX - 11 - 1 - IFNAMSIZ]; /* 11 = post-down.d 1 = / */
	int hasupdown;
	int up;
	struct _ip *ip;
	struct _iface *next;
};
#define ifname ifr.ifr_name

struct _config {
	struct _iface *head;
	int sockfd;
};

static int lib_init = 0;
static struct _config lib_cfg;
static pthread_mutex_t lib_mutex = PTHREAD_MUTEX_INITIALIZER;

/* forward declarations */
static int _execute_shell(const char *command, char **error_string);
static int _exec_updown(const tap_t tap, const char *action, char **error_string);
static int _read_pipe(int fd, char **file, size_t *length);
static int _check(const tap_t tap);
static void _close(tap_t tap);
static void _close_cfg(void);
static int _get_mtu(const tap_t tap);
static int _get_mac(const tap_t tap, char **ether_addr);
static int _set_down(tap_t tap, char **error_down, char **error_postdown);
static char *_get_v4_broadcast(const char *ip_addr, const char *prefix);
static int _set_ip(tap_t tap, const char *command,
		      const char *ip_addr, const char *prefix,
		      char **error_string, int secondary);
static int _find_ip(tap_t tap,
			const char *ip_addr, const char *prefix,
			struct _ip **ip, struct _ip **ip_prev);

static int _read_pipe(int fd, char **file, size_t *length)
{
	char buf[4096];
	int n;
	int done = 0;

	*file = NULL;
	*length = 0;

	memset(buf, 0, sizeof(buf));

	while (!done) {

		n = read(fd, buf, sizeof(buf));

		if (n < 0) {
			if (errno == EINTR)
				continue;

			if (*file)
				free(*file);

			return n;
		}

		if (n == 0 && (!*length))
			return 0;

		if (n == 0)
			done = 1;

		if (*file)
			*file = realloc(*file, (*length) + n + done);
		else
			*file = malloc(n + done);

		if (!*file)
			return -1;

		memmove((*file) + (*length), buf, n);
		*length += (done + n);
	}

	/* Null terminator */
	(*file)[(*length) - 1] = 0;

	return 0;
}

static int _execute_shell(const char *command, char **error_string)
{
	pid_t pid;
	int status, err = 0;
	int fd[2];
	size_t size = 0;

	if ((command == NULL) || (!error_string)) {
		errno = EINVAL;
		return -1;
	}

	*error_string = NULL;

	err = pipe(fd);
	if (err)
		goto out_clean;

	pid = fork();
	if (pid < 0) {
		err = pid;
		goto out_clean;
	}

	if (pid) { /* parent */

		close(fd[1]);
		err = _read_pipe(fd[0], error_string, &size);
		if (err)
			goto out_clean0;

		waitpid(pid, &status, 0);
		if (!WIFEXITED(status)) {
			err = -1;
			goto out_clean0;
		}
		if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
			err = WEXITSTATUS(status);
			goto out_clean0;
		}
		goto out_clean0;
	} else { /* child */
		close(0);
		close(1);
		close(2);

		close(fd[0]);
		dup2(fd[1], 1);
		dup2(fd[1], 2);
		close(fd[1]);

		execlp("/bin/sh", "/bin/sh", "-c", command, NULL);
		exit(EXIT_FAILURE);
	}

out_clean:
	close(fd[1]);
out_clean0:
	close(fd[0]);

	return err;
}

static int _exec_updown(const tap_t tap, const char *action, char **error_string)
{
	char command[PATH_MAX];
	struct stat sb;
	int err = 0;

	if (!tap->hasupdown)
		return 0;

	memset(command, 0, PATH_MAX);

	snprintf(command, PATH_MAX, "%s%s/%s", tap->updownpath, action, tap->tapname);

	err = stat(command, &sb);
	if ((err < 0) && (errno == ENOENT))
		return 0;

	err = _execute_shell(command, error_string);
	if ((!err) && (*error_string)) {
		free(*error_string);
		*error_string = NULL;
	}

	return err;
}

static int _check(const tap_t tap)
{
	tap_t temp = lib_cfg.head;

	if (!tap) {
		return 0;
	}

	while (temp != NULL) {
		if (tap == temp)
			return 1;

		temp = temp->next;
	}

	return 0;
}

static void _close(tap_t tap)
{
	if (!tap)
		return;

	if (tap->fd)
		close(tap->fd);

#ifdef KNET_BSD
	memset(&tap->ifr, 0, sizeof(struct ifreq));
	strncpy(tap->ifname, tap->tapname, IFNAMSIZ);

	ioctl(lib_cfg.sockfd, SIOCIFDESTROY, &tap->ifr);
#endif

	free(tap);

	return;
}

static void _close_cfg(void)
{
	if (lib_cfg.head == NULL) {
		close(lib_cfg.sockfd);
		lib_init = 0;
	}
}

static int _get_mtu(const tap_t tap)
{
	int err;

	memset(&tap->ifr, 0, sizeof(struct ifreq));
	strncpy(tap->ifname, tap->tapname, IFNAMSIZ);

	err = ioctl(lib_cfg.sockfd, SIOCGIFMTU, &tap->ifr);
	if (err)
		goto out_clean;

	err = tap->ifr.ifr_mtu;

out_clean:
	return err;
}

static int _get_mac(const tap_t tap, char **ether_addr)
{
	int err = 0;
	char mac[MAX_MAC_CHAR];
#ifdef KNET_BSD
	struct ifaddrs *ifap = NULL;
	struct ifaddrs *ifa;
	int found = 0;
#endif

	memset(&mac, 0, MAX_MAC_CHAR);
	memset(&tap->ifr, 0, sizeof(struct ifreq));
	strncpy(tap->ifname, tap->tapname, IFNAMSIZ);

#ifdef KNET_LINUX
	err = ioctl(lib_cfg.sockfd, SIOCGIFHWADDR, &tap->ifr);
	if (err)
		goto out_clean;

	ether_ntoa_r((struct ether_addr *)tap->ifr.ifr_hwaddr.sa_data, mac);
#endif
#ifdef KNET_BSD
	/*
	 * there is no ioctl to get the ether address of an interface on FreeBSD
	 * (not to be confused with hwaddr). Use workaround described here:
	 * https://lists.freebsd.org/pipermail/freebsd-hackers/2004-June/007394.html
	 */
	err = getifaddrs(&ifap);
	if (err < 0)
		goto out_clean;

	ifa = ifap;

	while (ifa) {
		if (!strncmp(tap->tapname, ifa->ifa_name, IFNAMSIZ)) {
			found = 1;
			break;
		}
		ifa=ifa->ifa_next;
	}

	if (found) {
		ether_ntoa_r((struct ether_addr *)LLADDR((struct sockaddr_dl *)ifa->ifa_addr), mac);
	} else {
		err = -1;
	}
	freeifaddrs(ifap);

	if (err)
		goto out_clean;

#endif
	*ether_addr = strdup(mac);
	if (!*ether_addr)
		err = -1;

out_clean:

	return err;
}

tap_t tap_find(char *dev, size_t dev_size)
{
	tap_t tap;

	if (dev == NULL) {
		errno = EINVAL;
		return NULL;
	}

	if (dev_size < IFNAMSIZ) {
		errno = EINVAL;
		return NULL;
	}

	if (strlen(dev) > IFNAMSIZ) {
		errno = E2BIG;
		return NULL;
	}

	pthread_mutex_lock(&lib_mutex);

	tap = lib_cfg.head;
	while (tap != NULL) {
		if (!strcmp(dev, tap->tapname))
			break;
		tap = tap->next;
	}

	pthread_mutex_unlock(&lib_mutex);
	return tap;
}

tap_t tap_open(char *dev, size_t dev_size, const char *updownpath)
{
	tap_t tap;
	char *temp_mac = NULL;
#ifdef KNET_BSD
	uint16_t i;
	long int tapnum = 0;
	char curtap[IFNAMSIZ];
#endif

	if (dev == NULL) {
		errno = EINVAL;
		return NULL;
	}

	if (dev_size < IFNAMSIZ) {
		errno = EINVAL;
		return NULL;
	}

	if (strlen(dev) > IFNAMSIZ) {
		errno = E2BIG;
		return NULL;
	}

#ifdef KNET_BSD
	/*
	 * BSD does not support named devices like Linux
	 * but it is possible to force a tapX device number
	 * where X is 0 to 255.
	 */
	if (strlen(dev)) {
		if (strncmp(dev, "tap", 3)) {
			errno = EINVAL;
			return NULL;
		}
		errno = 0;
		tapnum = strtol(dev+3, NULL, 10);
		if (errno) {
			errno = EINVAL;
			return NULL;
		}
		if ((tapnum < 0) || (tapnum > 255)) {
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
		/* 14: 2 for /, 1 for \0 + 11 (post-down.d) */
		if (strlen(updownpath) >= (PATH_MAX - (strlen(dev) + 14))) {
			errno = E2BIG;
			return NULL;
		}
	}

	tap = malloc(sizeof(struct _iface));
	if (!tap) {
		return NULL;
	}

	memset(tap, 0, sizeof(struct _iface));

	pthread_mutex_lock(&lib_mutex);

	if (!lib_init) {
		lib_cfg.head = NULL;
#ifdef KNET_LINUX
		lib_cfg.sockfd = socket(AF_INET, SOCK_STREAM, 0);
#endif
#ifdef KNET_BSD
		lib_cfg.sockfd = socket(AF_LOCAL, SOCK_DGRAM, 0);
#endif
		if (lib_cfg.sockfd < 0)
			goto out_error;
		lib_init = 1;
	}


#ifdef KNET_BSD
	if (!strlen(dev)) {
		for (i = 0; i < 256; i++) {
			snprintf(curtap, sizeof(curtap) - 1, "/dev/tap%u", i);
			tap->fd = open(curtap, O_RDWR);
			if (tap->fd > 0) {
				break;
			}
		}
		snprintf(curtap, sizeof(curtap) -1 , "tap%u", i);
	} else {
		snprintf(curtap, sizeof(curtap) - 1, "/dev/%s", dev);
		tap->fd = open(curtap, O_RDWR);
		snprintf(curtap, sizeof(curtap) - 1, "%s", dev);
	}
	if (tap->fd < 0) {
		errno = EBUSY;
		goto out_error;
	}
	strncpy(dev, curtap, IFNAMSIZ);
	strncpy(tap->tapname, curtap, IFNAMSIZ);
#endif

#ifdef KNET_LINUX
	if ((tap->fd = open("/dev/net/tun", O_RDWR)) < 0)
		goto out_error;

	memset(&tap->ifr, 0, sizeof(struct ifreq));
	strncpy(tap->ifname, dev, IFNAMSIZ);
	tap->ifr.ifr_flags = IFF_TAP | IFF_NO_PI;

	if (ioctl(tap->fd, TUNSETIFF, &tap->ifr) < 0)
		goto out_error;

	if ((strlen(dev) > 0) && (strcmp(dev, tap->ifname) != 0)) {
		errno = EBUSY;
		goto out_error;
	}

	strncpy(dev, tap->ifname, IFNAMSIZ);
	strncpy(tap->tapname, tap->ifname, IFNAMSIZ);
#endif

	tap->default_mtu = _get_mtu(tap);
	if (tap->default_mtu < 0)
		goto out_error;

	if (_get_mac(tap, &temp_mac) < 0)
		goto out_error;

	strncpy(tap->default_mac, temp_mac, 18);
	free(temp_mac);

	if (updownpath) {
		int len = strlen(updownpath);

		strcpy(tap->updownpath, updownpath);
		if (tap->updownpath[len-1] != '/') {
			tap->updownpath[len] = '/';
		}
		tap->hasupdown = 1;
	}

	tap->next = lib_cfg.head;
	lib_cfg.head = tap;

	pthread_mutex_unlock(&lib_mutex);
	return tap;

out_error:
	_close(tap);
	_close_cfg();
	pthread_mutex_unlock(&lib_mutex);
	return NULL;
}

// TODO: consider better error report from here
int tap_close(tap_t tap)
{
	int err = 0;
	tap_t temp = lib_cfg.head;
	tap_t prev = lib_cfg.head;
	struct _ip *ip, *ip_next;
	char *error_string = NULL;
	char *error_down = NULL, *error_postdown = NULL;

	pthread_mutex_lock(&lib_mutex);

	if (!_check(tap)) {
		errno = EINVAL;
		err = -1;
		goto out_clean;
	}

	while ((temp) && (temp != tap)) {
		prev = temp;
		temp = temp->next;
	}

	if (tap == prev) {
		lib_cfg.head = tap->next;
	} else {
		prev->next = tap->next;
	}

	_set_down(tap, &error_down, &error_postdown);
	if (error_down)
		free(error_down);
	if (error_postdown)
		free(error_postdown);

	ip = tap->ip;
	while (ip) {
		ip_next = ip->next;
		_set_ip(tap, "del", ip->ip_addr, ip->prefix, &error_string, 0);
		if (error_string) {
			free(error_string);
			error_string = NULL;
		}
		free(ip);
		ip = ip_next;
	}

	_close(tap);
	_close_cfg();

out_clean:
	pthread_mutex_unlock(&lib_mutex);

	return err;
}

int tap_get_mtu(const tap_t tap)
{
	int err;

	pthread_mutex_lock(&lib_mutex);

	if (!_check(tap)) {
		errno = EINVAL;
		err = -1;
		goto out_clean;
	}

	err = _get_mtu(tap);

out_clean:
	pthread_mutex_unlock(&lib_mutex);

	return err;
}

int tap_set_mtu(tap_t tap, const int mtu)
{
	struct _ip *tmp_ip;
	char *error_string = NULL;
	int err;

	pthread_mutex_lock(&lib_mutex);

	if (!_check(tap)) {
		errno = EINVAL;
		err = -1;
		goto out_clean;
	}

	err = tap->current_mtu = _get_mtu(tap);
	if (err < 0)
		goto out_clean;

	tap->ifr.ifr_mtu = mtu;

	err = ioctl(lib_cfg.sockfd, SIOCSIFMTU, &tap->ifr);

	if ((!err) && (tap->current_mtu < 1280) && (mtu >= 1280)) {
		tmp_ip = tap->ip;
		while(tmp_ip) {
			if (tmp_ip->domain == AF_INET6) {
				err = _set_ip(tap, "add", tmp_ip->ip_addr, tmp_ip->prefix, &error_string, 0);
				if (error_string) {
					free(error_string);
					error_string = NULL;
				}
			}
			tmp_ip = tmp_ip->next;
		}
	}

out_clean:
	pthread_mutex_unlock(&lib_mutex);

	return err;
}

int tap_reset_mtu(tap_t tap)
{
	return tap_set_mtu(tap, tap->default_mtu);
}

int tap_get_mac(const tap_t tap, char **ether_addr)
{
	int err;

	pthread_mutex_lock(&lib_mutex);

	if ((!_check(tap)) || (!ether_addr)) {
		errno = EINVAL;
		err = -1;
		goto out_clean;
	}

	err = _get_mac(tap, ether_addr);

out_clean:
	pthread_mutex_unlock(&lib_mutex);

	return err;
}

int tap_set_mac(tap_t tap, const char *ether_addr)
{
	int err;

	pthread_mutex_lock(&lib_mutex);

	if ((!_check(tap)) || (!ether_addr)) {
		errno = EINVAL;
		err = -1;
		goto out_clean;
	}

	memset(&tap->ifr, 0, sizeof(struct ifreq));
	strncpy(tap->ifname, tap->tapname, IFNAMSIZ);
#ifdef KNET_LINUX
	err = ioctl(lib_cfg.sockfd, SIOCGIFHWADDR, &tap->ifr);
	if (err)
		goto out_clean;

	memmove(tap->ifr.ifr_hwaddr.sa_data, ether_aton(ether_addr), ETH_ALEN);

	err = ioctl(lib_cfg.sockfd, SIOCSIFHWADDR, &tap->ifr);
#endif
#ifdef KNET_BSD
	err = ioctl(lib_cfg.sockfd, SIOCGIFADDR, &tap->ifr);
	if (err)
		goto out_clean;

	memmove(tap->ifr.ifr_addr.sa_data, ether_aton(ether_addr), ETHER_ADDR_LEN);
	tap->ifr.ifr_addr.sa_len = ETHER_ADDR_LEN;

	err = ioctl(lib_cfg.sockfd, SIOCSIFLLADDR, &tap->ifr);
#endif
out_clean:
	pthread_mutex_unlock(&lib_mutex);

	return err;
}

int tap_reset_mac(tap_t tap)
{
	return tap_set_mac(tap, tap->default_mac);
}

int tap_set_up(tap_t tap, char **error_preup, char **error_up)
{
	int err = 0;

	pthread_mutex_lock(&lib_mutex);

	if (!_check(tap)) {
		errno = EINVAL;
		err = -1;
		goto out_clean;
	}

	if ((tap->hasupdown) && ((!error_preup) || (!error_up))) {
		errno = EINVAL;
		err = -1;
		goto out_clean;
	}

	if (tap->up)
		goto out_clean;

	memset(&tap->ifr, 0, sizeof(struct ifreq));
	strncpy(tap->ifname, tap->tapname, IFNAMSIZ);

	err=ioctl(lib_cfg.sockfd, SIOCGIFFLAGS, &tap->ifr);
	if (err)
		goto out_clean;

	_exec_updown(tap, "pre-up.d", error_preup);

	tap->ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
	err=ioctl(lib_cfg.sockfd, SIOCSIFFLAGS, &tap->ifr);

	if (err)
		goto out_clean;

	_exec_updown(tap, "up.d", error_up);

	tap->up = 1;
out_clean:
	pthread_mutex_unlock(&lib_mutex);

	return err;
}

static int _set_down(tap_t tap, char **error_down, char **error_postdown)
{
	int err = 0;

	if (!tap->up)
		goto out_clean;

	memset(&tap->ifr, 0, sizeof(struct ifreq));
	strncpy(tap->ifname, tap->tapname, IFNAMSIZ);

	err=ioctl(lib_cfg.sockfd, SIOCGIFFLAGS, &tap->ifr);
	if (err)
		goto out_clean;

	_exec_updown(tap, "down.d", error_down);

	tap->ifr.ifr_flags &= ~IFF_UP;
	err=ioctl(lib_cfg.sockfd, SIOCSIFFLAGS, &tap->ifr);

	if (err)
		goto out_clean;

	_exec_updown(tap, "post-down.d", error_postdown);

	tap->up = 0;

out_clean:
	return err;
}

int tap_set_down(tap_t tap, char **error_down, char **error_postdown)
{
	int err = 0;

	pthread_mutex_lock(&lib_mutex);

	if (!_check(tap)) {
		errno = EINVAL;
		err = -1;
		goto out_clean;
	}

	if ((tap->hasupdown) && ((!error_down) || (!error_postdown))) {
		errno = EINVAL;
		err = -1;
		goto out_clean;
	}

	err = _set_down(tap, error_down, error_postdown);

out_clean:
	pthread_mutex_unlock(&lib_mutex);

	return err;
}

static char *_get_v4_broadcast(const char *ip_addr, const char *prefix)
{
	int prefix_len;
	struct in_addr mask;
	struct in_addr broadcast;
	struct in_addr address;

	prefix_len = atoi(prefix);

	if ((prefix_len > 32) || (prefix_len < 0))
		return NULL;

	if (inet_pton(AF_INET, ip_addr, &address) <= 0)
		return NULL;

	mask.s_addr = htonl(~((1 << (32 - prefix_len)) - 1));

	memset(&broadcast, 0, sizeof(broadcast));
	broadcast.s_addr = (address.s_addr & mask.s_addr) | ~mask.s_addr;

	return strdup(inet_ntoa(broadcast));
}

static int _set_ip(tap_t tap, const char *command,
		      const char *ip_addr, const char *prefix,
		      char **error_string, int secondary)
{
	char *broadcast = NULL;
	char cmdline[4096];
#ifdef KNET_BSD
	char proto[6];
	int v4 = 1;

	snprintf(proto, sizeof(proto), "inet");
#endif

	if (!strchr(ip_addr, ':')) {
		broadcast = _get_v4_broadcast(ip_addr, prefix);
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
			 command, ip_addr, prefix,
			 tap->tapname, broadcast);
	} else {
		snprintf(cmdline, sizeof(cmdline)-1,
			 "ip addr %s %s/%s dev %s",
			command, ip_addr, prefix,
			tap->tapname);
	}
#endif
#ifdef KNET_BSD
	if (!strcmp(command, "add")) {
		snprintf(cmdline, sizeof(cmdline)-1,
			 "ifconfig %s %s %s/%s",
			 tap->tapname, proto, ip_addr, prefix);
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
				 tap->tapname, proto, ip_addr, prefix);
	}
#endif
	if (broadcast) {
		free(broadcast);
	}
	return _execute_shell(cmdline, error_string);
}

static int _find_ip(tap_t tap,
			const char *ip_addr, const char *prefix,
			struct _ip **ip, struct _ip **ip_prev)
{
	struct _ip *local_ip, *local_ip_prev;
	int found = 0;

	local_ip = local_ip_prev = tap->ip;

	while(local_ip) {
		if ((!strcmp(local_ip->ip_addr, ip_addr)) && (!strcmp(local_ip->prefix, prefix))) {
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

int tap_add_ip(tap_t tap, const char *ip_addr, const char *prefix, char **error_string)
{
	int err = 0, found;
	struct _ip *ip = NULL, *ip_prev = NULL, *ip_last = NULL;
	int secondary = 0;

	pthread_mutex_lock(&lib_mutex);

	if ((!_check(tap)) || (!ip_addr) || (!prefix) || (!error_string)) {
		errno = EINVAL;
		err = -1;
		goto out_clean;
	}

	found = _find_ip(tap, ip_addr, prefix, &ip, &ip_prev);
	if (found)
		goto out_clean;

	ip = malloc(sizeof(struct _ip));
	if (!ip) {
		err = -1 ;
		goto out_clean;
	}
	memset(ip, 0, sizeof(struct _ip));
	strncpy(ip->ip_addr, ip_addr, MAX_IP_CHAR);
	strncpy(ip->prefix, prefix, MAX_PREFIX_CHAR);
	if (!strchr(ip->ip_addr, ':')) {
		ip->domain = AF_INET;
	} else {
		ip->domain = AF_INET6;
	}

	/*
	 * if user asks for an IPv6 address, but MTU < 1280
	 * store the IP and bring it up later if and when MTU > 1280
	 */
	if ((ip->domain == AF_INET6) && (_get_mtu(tap) < 1280)) {
		err = 0;
	} else {
		if (tap->ip) {
			secondary = 1;
		}
		err = _set_ip(tap, "add", ip_addr, prefix, error_string, secondary);
	}

	if (err) {
		free(ip);
		goto out_clean;
	}

	if (tap->ip) {
		ip_last = tap->ip;
		while (ip_last->next != NULL) {
			ip_last = ip_last->next;
		}
		ip_last->next = ip;
	} else {
		tap->ip = ip;
	}

out_clean:
	pthread_mutex_unlock(&lib_mutex);

	return err;
}

int tap_del_ip(tap_t tap, const char *ip_addr, const char *prefix, char **error_string)
{
	int err = 0, found;
	struct _ip *ip = NULL, *ip_prev = NULL;

	pthread_mutex_lock(&lib_mutex);

	if ((!_check(tap)) || (!ip_addr) || (!prefix) || (!error_string)) {
		errno = EINVAL;
		err = -1;
		goto out_clean;
	}

	found = _find_ip(tap, ip_addr, prefix, &ip, &ip_prev);
	if (!found)
		goto out_clean;

	err = _set_ip(tap, "del", ip_addr, prefix, error_string, 0);

	if (!err) {
		if (ip == ip_prev) {
			tap->ip = ip->next;
		} else {
			ip_prev->next = ip->next;
		}
		free(ip);
	}

out_clean:
	pthread_mutex_unlock(&lib_mutex);

	return err;
}

int tap_get_fd(const tap_t tap)
{
	int fd;

	pthread_mutex_lock(&lib_mutex);

	if (!_check(tap)) {
		errno = EINVAL;
		fd = -1;
		goto out_clean;
	}

	fd = tap->fd;

out_clean:
	pthread_mutex_unlock(&lib_mutex);

	return fd;
}

const char *tap_get_name(const tap_t tap)
{
	char *name = NULL;

	pthread_mutex_lock(&lib_mutex);

	if (!_check(tap)) {
		errno = EINVAL;
		goto out_clean;
	}

	name = tap->tapname;

out_clean:
	pthread_mutex_unlock(&lib_mutex);

	return name;
}

int tap_get_ips(const tap_t tap, char **ip_addr_list, int *entries)
{
	int err = 0;
	int found = 0;
	char *ip_list = NULL;
	int size = 0, offset = 0, len;
	struct _ip *ip = tap->ip;

	pthread_mutex_lock(&lib_mutex);

	while (ip) {
		found++;
		ip = ip->next;
	}

	size = found * (MAX_IP_CHAR + MAX_PREFIX_CHAR + 2);
	ip_list = malloc(size);
	if (!ip_list) {
		err = -1;
		goto out_clean;
	}

	memset(ip_list, 0, size);

	ip = tap->ip;

	while (ip) {
		len = strlen(ip->ip_addr);
		memmove(ip_list + offset, ip->ip_addr, len);
		offset = offset + len + 1;
		len = strlen(ip->prefix);
		memmove(ip_list + offset, ip->prefix, len);
		offset = offset + len + 1;
		ip = ip->next;
	}

	*ip_addr_list = ip_list;
	*entries = found;

out_clean:
	pthread_mutex_unlock(&lib_mutex);

	return err;
}

#ifdef TEST

char testipv4_1[1024];
char testipv4_2[1024];
char testipv6_1[1024];
char testipv6_2[1024];
/*
 * use this one to randomize knet interface name
 * for named creation test
 */
uint8_t randombyte = 0;

static int is_if_in_system(char *name)
{
	struct ifaddrs *ifap = NULL;
	struct ifaddrs *ifa;
	int found = 0;

	if (getifaddrs(&ifap) < 0) {
		printf("Unable to get interface list.\n");
		return -1;
	}

	ifa = ifap;

	while (ifa) {
		if (!strncmp(name, ifa->ifa_name, IFNAMSIZ)) {
			found = 1;
			break;
		}
		ifa=ifa->ifa_next;
	}

	freeifaddrs(ifap);
	return found;
}

static int test_iface(char *name, size_t size, const char *updownpath)
{
	tap_t tap;

	tap=tap_open(name, size, updownpath);
	if (!tap) {
		if (lib_cfg.sockfd < 0)
			printf("Unable to open knet_socket\n");
		printf("Unable to open knet.\n");
		return -1;
	}
	printf("Created interface: %s\n", name);

	if (is_if_in_system(name) > 0) {
		printf("Found interface %s on the system\n", name);
	} else {
		printf("Unable to find interface %s on the system\n", name);
	}

	if (!tap_find(name, size)) {
		printf("Unable to find interface %s in tap db\n", name);
	} else {
		printf("Found interface %s in tap db\n", name);
	}

	tap_close(tap);

	if (is_if_in_system(name) == 0)
		printf("Successfully removed interface %s from the system\n", name);

	return 0;
}

static int check_tap_open_close(void)
{
	char device_name[2*IFNAMSIZ];
	char fakepath[PATH_MAX];
	size_t size = IFNAMSIZ;

	memset(device_name, 0, sizeof(device_name));

	printf("Creating random tap interface:\n");
	if (test_iface(device_name, size,  NULL) < 0) {
		printf("Unable to create random interface\n");
		return -1;
	}

#ifdef KNET_LINUX
	printf("Creating kronostest%u tap interface:\n", randombyte);
	snprintf(device_name, IFNAMSIZ, "kronostest%u", randombyte);
	if (test_iface(device_name, size, NULL) < 0) {
		printf("Unable to create kronostest%u interface\n", randombyte);
		return -1;
	}
#endif
#ifdef KNET_BSD
	printf("Creating tap%u tap interface:\n", randombyte);
	snprintf(device_name, IFNAMSIZ, "tap%u", randombyte);
	if (test_iface(device_name, size, NULL) < 0) {
		printf("Unable to create tap%u interface\n", randombyte);
		return -1;
	}

	printf("Creating kronostest%u tap interface:\n", randombyte);
	snprintf(device_name, IFNAMSIZ, "kronostest%u", randombyte);
	if (test_iface(device_name, size, NULL) == 0) {
		printf("BSD should not accept kronostest%u interface\n", randombyte);
		return -1;
	}
#endif

	printf("Testing ERROR conditions\n");

	printf("Testing dev == NULL\n");
	errno=0;
	if ((test_iface(NULL, size, NULL) >= 0) || (errno != EINVAL)) {
		printf("Something is wrong in tap_open sanity checks\n");
		return -1;
	}

	printf("Testing size < IFNAMSIZ\n");
	errno=0;
	if ((test_iface(device_name, 1, NULL) >= 0) || (errno != EINVAL)) {
		printf("Something is wrong in tap_open sanity checks\n");
		return -1;
	}

	printf("Testing device_name size > IFNAMSIZ\n");
	errno=0;
	strcpy(device_name, "abcdefghilmnopqrstuvwz");
	if ((test_iface(device_name, IFNAMSIZ, NULL) >= 0) || (errno != E2BIG)) {
		printf("Something is wrong in tap_open sanity checks\n");
		return -1;
	}

	printf("Testing updown path != abs\n");
	errno=0;

	memset(device_name, 0, IFNAMSIZ);
	if ((test_iface(device_name, IFNAMSIZ, "foo")  >= 0) || (errno != EINVAL)) {
		printf("Something is wrong in tap_open sanity checks\n");
		return -1;
	}

	memset(fakepath, 0, PATH_MAX);
	memset(fakepath, '/', PATH_MAX - 2);

	printf("Testing updown path > PATH_MAX\n");
	errno=0;

	memset(device_name, 0, IFNAMSIZ);
	if ((test_iface(device_name, IFNAMSIZ, fakepath)  >= 0) || (errno != E2BIG)) {
		printf("Something is wrong in tap_open sanity checks\n");
		return -1;
	}

	return 0;
}

static int check_knet_multi_eth(void)
{
	char device_name1[IFNAMSIZ];
	char device_name2[IFNAMSIZ];
	size_t size = IFNAMSIZ;
	int err=0;
	tap_t tap1 = NULL;
	tap_t tap2 = NULL;

	printf("Testing multiple knet interface instances\n");

	memset(device_name1, 0, size);
	memset(device_name2, 0, size);

	tap1 = tap_open(device_name1, size, NULL);
	if (!tap1) {
		printf("Unable to init %s\n", device_name1);
		err = -1;
		goto out_clean;
	}

	if (is_if_in_system(device_name1) > 0) {
		printf("Found interface %s on the system\n", device_name1);
	} else {
		printf("Unable to find interface %s on the system\n", device_name1);
	}

	tap2 = tap_open(device_name2, size, NULL);
	if (!tap2) {
		printf("Unable to init %s\n", device_name2);
		err = -1;
		goto out_clean;
	}

	if (is_if_in_system(device_name2) > 0) {
		printf("Found interface %s on the system\n", device_name2);
	} else {
		printf("Unable to find interface %s on the system\n", device_name2);
	}

	if (tap1)
		tap_close(tap1);
	if (tap2)
		tap_close(tap2);

	printf("Testing error conditions\n");

	printf("Open same device twice\n");

	memset(device_name1, 0, size);

	tap1 = tap_open(device_name1, size, NULL);
	if (!tap1) {
		printf("Unable to init %s\n", device_name1);
		err = -1;
		goto out_clean;
	}

	if (is_if_in_system(device_name1) > 0) {
		printf("Found interface %s on the system\n", device_name1);
	} else {
		printf("Unable to find interface %s on the system\n", device_name1);
	}

	tap2 = tap_open(device_name1, size, NULL);
	if (tap2) {
		printf("We were able to init 2 interfaces with the same name!\n");
		err = -1;
		goto out_clean;
	}

out_clean:
	if (tap1)
		tap_close(tap1);
	if (tap2)
		tap_close(tap2);
	return err;
}

static int check_knet_mtu(void)
{
	char device_name[IFNAMSIZ];
	size_t size = IFNAMSIZ;
	int err=0;
	tap_t tap;

	int current_mtu = 0;
	int expected_mtu = 1500;

	printf("Testing get/set MTU\n");

	memset(device_name, 0, size);
	tap = tap_open(device_name, size, NULL);
	if (!tap) {
		printf("Unable to init %s\n", device_name);
		return -1;
	}

	printf("Comparing default MTU\n");
	current_mtu = tap_get_mtu(tap);
	if (current_mtu < 0) {
		printf("Unable to get MTU\n");
		err = -1;
		goto out_clean;
	}
	if (current_mtu != expected_mtu) {
		printf("current mtu [%d] does not match expected default [%d]\n", current_mtu, expected_mtu);
		err = -1;
		goto out_clean;
	}

	printf("Setting MTU to 9000\n");
	expected_mtu = 9000;
	if (tap_set_mtu(tap, expected_mtu) < 0) {
		printf("Unable to set MTU to %d\n", expected_mtu);
		err = -1;
		goto out_clean;
	}

	current_mtu = tap_get_mtu(tap);
	if (current_mtu < 0) {
		printf("Unable to get MTU\n");
		err = -1;
		goto out_clean;
	}
	if (current_mtu != expected_mtu) {
		printf("current mtu [%d] does not match expected value [%d]\n", current_mtu, expected_mtu);
		err = -1;
		goto out_clean;
	}

	printf("Testing ERROR conditions\n");

	printf("Passing empty struct to get_mtu\n");
	if (tap_get_mtu(NULL) > 0) {
		printf("Something is wrong in tap_get_mtu sanity checks\n");
		err = -1;
		goto out_clean;
	}

	printf("Passing empty struct to set_mtu\n");
	if (tap_set_mtu(NULL, 1500) == 0) {
		printf("Something is wrong in tap_set_mtu sanity checks\n"); 
		err = -1;
		goto out_clean;
	}

out_clean:
	tap_close(tap);

	return err;
}

static int check_knet_mtu_ipv6(void)
{
	char device_name[IFNAMSIZ];
	size_t size = IFNAMSIZ;
	char verifycmd[1024];
	int err=0;
	tap_t tap;
	char *error_string = NULL;

	printf("Testing get/set MTU with IPv6 address\n");

	memset(device_name, 0, size);

	tap = tap_open(device_name, size, NULL);
	if (!tap) {
		printf("Unable to init %s\n", device_name);
		return -1;
	}

	printf("Adding ip: %s/64\n", testipv6_1);

	err = tap_add_ip(tap, testipv6_1, "64", &error_string);
	if (error_string) {
		printf("add ipv6 output: %s\n", error_string);
		free(error_string);
		error_string = NULL;
	}
	if (err) {
		printf("Unable to assign IP address\n");
		err=-1;
		sleep(30);
		goto out_clean;
	}

	memset(verifycmd, 0, sizeof(verifycmd));
	snprintf(verifycmd, sizeof(verifycmd)-1,
#ifdef KNET_LINUX
		 "ip addr show dev %s | grep -q %s/64", tap->tapname, testipv6_1);
#endif
#ifdef KNET_BSD
		 "ifconfig %s | grep -q %s", tap->tapname, testipv6_1);
#endif
	err = _execute_shell(verifycmd, &error_string);
	if (error_string) {
		printf("Error string: %s\n", error_string);
		free(error_string);
		error_string = NULL;
	}
	if (err) {
		printf("Unable to verify IP address\n");
		err=-1;
		goto out_clean;
	}

	printf("Setting MTU to 1200\n");
	if (tap_set_mtu(tap, 1200) < 0) {
		printf("Unable to set MTU to 1200\n");
		err = -1;
		goto out_clean;
	}

	err = _execute_shell(verifycmd, &error_string);
	if (error_string) {
		printf("Error string: %s\n", error_string);
		free(error_string);
		error_string = NULL;
	}
#ifdef KNET_LINUX
	if (!err) {
#endif
#ifdef KNET_BSD
	if (err) {
#endif
		printf("Unable to verify IP address\n");
		err=-1;
		goto out_clean;
	}

	printf("Adding ip: %s/64\n", testipv6_2);
	err = tap_add_ip(tap, testipv6_2, "64", &error_string);
	if (error_string) {
		printf("add ipv6 output: %s\n", error_string);
		free(error_string);
		error_string = NULL;
	}
	if (err < 0) {
		printf("Unable to assign IP address\n");
		err=-1;
		goto out_clean;
	}

	memset(verifycmd, 0, sizeof(verifycmd));
	snprintf(verifycmd, sizeof(verifycmd)-1,
#ifdef KNET_LINUX
		 "ip addr show dev %s | grep -q %s/64", tap->tapname, testipv6_2);
#endif
#ifdef KNET_BSD
		 "ifconfig %s | grep -q %s", tap->tapname, testipv6_2);
#endif
	err = _execute_shell(verifycmd, &error_string);
	if (error_string) {
		printf("Error string: %s\n", error_string);
		free(error_string);
		error_string = NULL;
	}
	if (!err) {
		printf("Unable to verify IP address\n");
		err=-1;
		goto out_clean;
	}

	printf("Restoring MTU to default\n");
	if (tap_reset_mtu(tap) < 0) {
		printf("Unable to reset mtu\n");
		err = -1;
		goto out_clean;
	}

	memset(verifycmd, 0, sizeof(verifycmd));
	snprintf(verifycmd, sizeof(verifycmd)-1,
#ifdef KNET_LINUX
		 "ip addr show dev %s | grep -q %s/64", tap->tapname, testipv6_1);
#endif
#ifdef KNET_BSD
		 "ifconfig %s | grep -q %s", tap->tapname, testipv6_1);
#endif
	err = _execute_shell(verifycmd, &error_string);
	if (error_string) {
		printf("Error string: %s\n", error_string);
		free(error_string);
		error_string = NULL;
	}
	if (err) {
		printf("Unable to verify IP address\n");
		err=-1;
		goto out_clean;
	}

	memset(verifycmd, 0, sizeof(verifycmd));
	snprintf(verifycmd, sizeof(verifycmd)-1,
#ifdef KNET_LINUX
		 "ip addr show dev %s | grep -q %s/64", tap->tapname, testipv6_2);
#endif
#ifdef KNET_BSD
		 "ifconfig %s | grep -q %s", tap->tapname, testipv6_2);
#endif
	err = _execute_shell(verifycmd, &error_string);
	if (error_string) {
		printf("Error string: %s\n", error_string);
		free(error_string);
		error_string = NULL;
	}
	if (err) {
		printf("Unable to verify IP address\n");
		err=-1;
		goto out_clean;
	}

out_clean:
	tap_close(tap);

	return err;
}

static int check_knet_mac(void)
{
	char device_name[IFNAMSIZ];
	size_t size = IFNAMSIZ;
	int err=0;
	tap_t tap;
	char *current_mac = NULL, *temp_mac = NULL, *err_mac = NULL;
	struct ether_addr *cur_mac, *tmp_mac;

	printf("Testing get/set MAC\n");

	memset(device_name, 0, size);
	tap = tap_open(device_name, size, NULL);
	if (!tap) {
		printf("Unable to init %s\n", device_name);
		return -1;
	}

	printf("Get current MAC\n");

	if (tap_get_mac(tap, &current_mac) < 0) {
		printf("Unable to get current MAC address.\n");
		err = -1;
		goto out_clean;
	}

	printf("Current MAC: %s\n", current_mac);

	printf("Setting MAC: 00:01:01:01:01:01\n");

	if (tap_set_mac(tap, "00:01:01:01:01:01") < 0) {
		printf("Unable to set current MAC address.\n");
		err = -1;
		goto out_clean;
	}

	if (tap_get_mac(tap, &temp_mac) < 0) {
		printf("Unable to get current MAC address.\n");
		err = -1;
		goto out_clean;
	}

	printf("Current MAC: %s\n", temp_mac);

	cur_mac = ether_aton(current_mac);
	tmp_mac = ether_aton(temp_mac);

	printf("Comparing MAC addresses\n");
	if (memcmp(cur_mac, tmp_mac, sizeof(struct ether_addr))) {
		printf("Mac addresses are not the same?!\n");
		err = -1;
		sleep(20);
		goto out_clean;
	}

	printf("Testing ERROR conditions\n");

	printf("Pass NULL to get_mac (pass1)\n");
	errno = 0;
	if ((tap_get_mac(NULL, &err_mac) >= 0) || (errno != EINVAL)) {
		printf("Something is wrong in tap_get_mac sanity checks\n");
		err = -1;
		goto out_clean;
	}

	printf("Pass NULL to get_mac (pass2)\n");
	errno = 0;
	if ((tap_get_mac(tap, NULL) >= 0) || (errno != EINVAL)) {
		printf("Something is wrong in tap_get_mac sanity checks\n");
		err = -1;
		goto out_clean;
	}

	printf("Pass NULL to set_mac (pass1)\n");
	errno = 0;
	if ((tap_set_mac(tap, NULL) >= 0) || (errno != EINVAL)) {
		printf("Something is wrong in tap_set_mac sanity checks\n");
		err = -1;
		goto out_clean;
	}

	printf("Pass NULL to set_mac (pass2)\n");
	errno = 0;
	if ((tap_set_mac(NULL, err_mac) >= 0) || (errno != EINVAL)) {
		printf("Something is wrong in tap_set_mac sanity checks\n");
		err = -1;
		goto out_clean;
	}

out_clean:
	if (err_mac) {
		printf("Something managed to set err_mac!\n");
		err = -1;
		free(err_mac);
	}

	if (current_mac)
		free(current_mac);
	if (temp_mac)
		free(temp_mac);

	tap_close(tap);

	return err;
}

static int check_tap_execute_shell(void)
{
	int err = 0;
	char command[4096];
	char *error_string = NULL;

	memset(command, 0, sizeof(command));

	printf("Testing _execute_shell\n");

	printf("command true\n");

	err = _execute_shell("true", &error_string);
	if (error_string) {
		printf("Error string: %s\n", error_string);
		free(error_string);
		error_string = NULL;
	}
	if (err) {
		printf("Unable to execute true ?!?!\n");
		goto out_clean;
	}

	printf("Testing ERROR conditions\n");

	printf("command false\n");

	err = _execute_shell("false", &error_string);
	if (error_string) {
		printf("Error string: %s\n", error_string);
		free(error_string);
		error_string = NULL;
	}
	if (!err) {
		printf("Can we really execute false successfully?!?!\n");
		err = -1;
		goto out_clean;
	}

	printf("command that outputs to stdout (enforcing redirect)\n");

	err = _execute_shell("grep -h 2>&1", &error_string);
	if (error_string) {
		printf("Error string: %s\n", error_string);
		free(error_string);
		error_string = NULL;
	}
	if (!err) {
		printf("Can we really execute grep -h successfully?!?\n");
		err = -1;
		goto out_clean;
	} 

	printf("command that outputs to stderr\n");
	err = _execute_shell("grep -h", &error_string);
	if (error_string) {
		printf("Error string: %s\n", error_string);
		free(error_string);
		error_string = NULL;
	}
	if (!err) {
		printf("Can we really execute grep -h successfully?!?\n");
		err = -1;
		goto out_clean;
	} 

	printf("empty command\n");
	err = _execute_shell(NULL, &error_string);
	if (error_string) {
		printf("Error string: %s\n", error_string);
		free(error_string);
		error_string = NULL;
	}
	if (!err) {
		printf("Can we really execute (nil) successfully?!?!\n");
		err = -1;
		goto out_clean;
	}

	printf("empty error\n");
	err = _execute_shell("true", NULL);
	if (!err) {
		printf("Check EINVAL filter for no error_string!\n");
		err = -1;
		goto out_clean;
	}

	err = 0;

out_clean:

	return err;
}

static int check_knet_up_down(void)
{
	char verifycmd[1024];
	char device_name[IFNAMSIZ];
	size_t size = IFNAMSIZ;
	int err=0;
	tap_t tap;
	char *error_string = NULL;
	char *error_preup = NULL, *error_up = NULL;
	char *error_down = NULL, *error_postdown = NULL;

	printf("Testing interface up/down\n");

	memset(device_name, 0, size);
	tap = tap_open(device_name, size, NULL);
	if (!tap) {
		printf("Unable to init %s\n", device_name);
		return -1;
	}

	printf("Put the interface up\n");

	err = tap_set_up(tap, &error_preup, &error_up);
	if (error_preup) {
		printf("preup output: %s\n", error_preup);
		free(error_preup);
		error_preup = NULL;
	}
	if (error_up) {
		printf("up output: %s\n", error_up);
		free(error_up);
		error_up = NULL;
	}
	if (err < 0) {
		printf("Unable to set interface up\n");
		err = -1;
		goto out_clean;
	}

	memset(verifycmd, 0, sizeof(verifycmd));
	snprintf(verifycmd, sizeof(verifycmd)-1,
#ifdef KNET_LINUX
		 "ip addr show dev %s | grep -q UP", tap->tapname);
#endif
#ifdef KNET_BSD
		 "ifconfig %s | grep -q UP", tap->tapname);
#endif
	err = _execute_shell(verifycmd, &error_string);
	if (error_string) {
		printf("Error string: %s\n", error_string);
		free(error_string);
		error_string = NULL;
	}
	if (err < 0) {
		printf("Unable to verify inteface UP\n");
		err = -1;
		goto out_clean;
	}

	printf("Put the interface down\n");

	err = tap_set_down(tap, &error_down, &error_postdown);
	if (error_down) {
		printf("down output: %s\n", error_down);
		free(error_down);
		error_down = NULL;
	}
	if (error_postdown) {
		printf("postdown output: %s\n", error_down);
		free(error_down);
		error_down = NULL;
	}
	if (err < 0) {
		printf("Unable to put the interface down\n");
		err = -1;
		goto out_clean;
	}

	memset(verifycmd, 0, sizeof(verifycmd));
	snprintf(verifycmd, sizeof(verifycmd)-1,
#ifdef KNET_LINUX
		 "ip addr show dev %s | grep -q UP", tap->tapname);
#endif
#ifdef KNET_BSD
		 "ifconfig %s | grep -q UP", tap->tapname);
#endif
	err = _execute_shell(verifycmd, &error_string);
	if (error_string) {
		printf("Error string: %s\n", error_string);
		free(error_string);
		error_string = NULL;
	}
	if (!err) {
		printf("Unable to verify inteface DOWN\n");
		err = -1;
		goto out_clean;
	}

	tap_close(tap);

	printf("Testing interface pre-up/up/down/post-down (exec errors)\n");

	memset(device_name, 0, size);
	tap = tap_open(device_name, size, ABSBUILDDIR "/tap_updown_bad");
	if (!tap) {
		printf("Unable to init %s\n", device_name);
		return -1;
	}

	printf("Put the interface up\n");

	err = tap_set_up(tap, &error_preup, &error_up);
	if (error_preup) {
		printf("preup output: %s\n", error_preup);
		free(error_preup);
		error_preup = NULL;
	}
	if (error_up) {
		printf("up output: %s\n", error_up);
		free(error_up);
		error_up = NULL;
	}
	if (err < 0) {
		printf("Unable to set interface up\n");
		err = -1;
		goto out_clean;
	}

	printf("Put the interface down\n");

	err = tap_set_down(tap, &error_down, &error_postdown);
	if (error_down) {
		printf("down output: %s\n", error_down);
		free(error_down);
		error_down = NULL;
	}
	if (error_postdown) {
		printf("postdown output: %s\n", error_down);
		free(error_down);
		error_down = NULL;
	}
	if (err < 0) {
		printf("Unable to put the interface down\n");
		err = -1;
		goto out_clean;
	}

	tap_close(tap);

	printf("Testing interface pre-up/up/down/post-down\n");

	memset(device_name, 0, size);

	tap = tap_open(device_name, size, ABSBUILDDIR "/tap_updown_good");
	if (!tap) {
		printf("Unable to init %s\n", device_name);
		return -1;
	}

	printf("Put the interface up\n");

	err = tap_set_up(tap, &error_preup, &error_up);
	if (error_preup) {
		printf("preup output: %s\n", error_preup);
		free(error_preup);
		error_preup = NULL;
	}
	if (error_up) {
		printf("up output: %s\n", error_up);
		free(error_up);
		error_up = NULL;
	}
	if (err < 0) {
		printf("Unable to set interface up\n");
		err = -1;
		goto out_clean;
	}

	printf("Put the interface down\n");

	err = tap_set_down(tap, &error_down, &error_postdown);
	if (error_down) {
		printf("down output: %s\n", error_down);
		free(error_down);
		error_down = NULL;
	}
	if (error_postdown) {
		printf("postdown output: %s\n", error_down);
		free(error_down);
		error_down = NULL;
	}
	if (err < 0) {
		printf("Unable to put the interface down\n");
		err = -1;
		goto out_clean;
	}

	tap_close(tap);

	printf("Test ERROR conditions\n");

	printf("Pass NULL to tap set_up\n");
	errno = 0;
	if ((tap_set_up(NULL, &error_preup, &error_up) >= 0) || (errno != EINVAL)) {
		printf("Something is wrong in tap_set_up sanity checks\n");
		err = -1;
		goto out_clean;
	}

	printf("Pass NULL to error_preup set_up\n");
	errno = 0;
	if ((tap_set_up(tap, NULL, &error_up) >= 0) || (errno != EINVAL)) {
		printf("Something is wrong in tap_set_up sanity checks\n");
		err = -1;
		goto out_clean;
	}

	printf("Pass NULL to error_up set_up\n");
	errno = 0;
	if ((tap_set_up(tap, &error_preup, NULL) >= 0) || (errno != EINVAL)) {
		printf("Something is wrong in tap_set_up sanity checks\n");
		err = -1;
		goto out_clean;
	}

	printf("Pass NULL to tap set_down\n");
	errno = 0;
	if ((tap_set_down(NULL, &error_down, &error_postdown) >= 0) || (errno != EINVAL)) {
		printf("Something is wrong in tap_set_down sanity checks\n");
		err = -1;
		goto out_clean;
	}

	printf("Pass NULL to error_down set_down\n");
	errno = 0;
	if ((tap_set_down(tap, NULL, &error_postdown) >= 0) || (errno != EINVAL)) {
		printf("Something is wrong in tap_set_down sanity checks\n");
		err = -1;
		goto out_clean;
	}

	printf("Pass NULL to error_postdown set_down\n");
	errno = 0;
	if ((tap_set_down(tap, &error_down, NULL) >= 0) || (errno != EINVAL)) {
		printf("Something is wrong in tap_set_down sanity checks\n");
		err = -1;
		goto out_clean;
	}

out_clean:

	tap_close(tap);

	return err;
}

static int check_knet_close_leak(void)
{
	char device_name[IFNAMSIZ];
	size_t size = IFNAMSIZ;
	int err=0;
	tap_t tap;
	char *error_string = NULL;

	printf("Testing close leak (needs valgrind)\n");

	memset(device_name, 0, size);

	tap = tap_open(device_name, size, NULL);
	if (!tap) {
		printf("Unable to init %s\n", device_name);
		return -1;
	}

	printf("Adding ip: %s/24\n", testipv4_1);

	err = tap_add_ip(tap, testipv4_1, "24", &error_string);
	if (error_string) {
		printf("add ip output: %s\n", error_string);
		free(error_string);
		error_string = NULL;
	}
	if (err < 0) {
		printf("Unable to assign IP address\n");
		err=-1;
		goto out_clean;
	}

	printf("Adding ip: %s/24\n", testipv4_2);

	err = tap_add_ip(tap, testipv4_2, "24", &error_string);
	if (error_string) {
		printf("add ip output: %s\n", error_string);
		free(error_string);
		error_string = NULL;
	}
	if (err < 0) {
		printf("Unable to assign IP address\n");
		err=-1;
		goto out_clean;
	}

out_clean:

	tap_close(tap);

	return err;
}

static int check_knet_set_del_ip(void)
{
	char device_name[IFNAMSIZ];
	size_t size = IFNAMSIZ;
	char verifycmd[1024];
	int err=0;
	tap_t tap;
	char *ip_list = NULL;
	int ip_list_entries = 0, i, offset = 0;
	char *error_string = NULL;

	printf("Testing interface add/remove ip\n");

	memset(device_name, 0, size);

	tap = tap_open(device_name, size, NULL);
	if (!tap) {
		printf("Unable to init %s\n", device_name);
		return -1;
	}

	printf("Adding ip: %s/24\n", testipv4_1);

	err = tap_add_ip(tap, testipv4_1, "24", &error_string);
	if (error_string) {
		printf("add ip output: %s\n", error_string);
		free(error_string);
		error_string = NULL;
	}
	if (err < 0) {
		printf("Unable to assign IP address\n");
		err=-1;
		goto out_clean;
	}

	printf("Adding ip: %s/24\n", testipv4_2);

	err = tap_add_ip(tap, testipv4_2, "24", &error_string);
	if (error_string) {
		printf("add ip output: %s\n", error_string);
		free(error_string);
		error_string = NULL;
	}
	if (err < 0) {
		printf("Unable to assign IP address\n");
		err=-1;
		goto out_clean;
	}

	printf("Adding duplicate ip: %s/24\n", testipv4_1);

	err = tap_add_ip(tap, testipv4_1, "24", &error_string);
	if (error_string) {
		printf("add ip output: %s\n", error_string);
		free(error_string);
		error_string = NULL;
	}
	if (err < 0) {
		printf("Unable to find IP address in libtap db\n");
		err=-1;
		goto out_clean;
	}

	printf("Checking ip: %s/24\n", testipv4_1);

	memset(verifycmd, 0, sizeof(verifycmd));
	snprintf(verifycmd, sizeof(verifycmd)-1,
#ifdef KNET_LINUX
		 "ip addr show dev %s | grep -q %s/24", tap->tapname, testipv4_1);
#endif
#ifdef KNET_BSD
		 "ifconfig %s | grep -q %s", tap->tapname, testipv4_1);
#endif
	err = _execute_shell(verifycmd, &error_string);
	if (error_string) {
		printf("Error string: %s\n", error_string);
		free(error_string);
		error_string = NULL;
	}
	if (err) {
		printf("Unable to verify IP address\n");
		err=-1;
		goto out_clean;
	}

	printf("Get ip list from libtap:\n");

	if (tap_get_ips(tap, &ip_list, &ip_list_entries) < 0) {
		printf("Not enough mem?\n");
		err=-1;
		goto out_clean;
	}

	if (ip_list_entries != 2) {
		printf("Didn't get enough ip back from libtap?\n");
		err=-1;
		goto out_clean;
	}

	for (i = 1; i <= ip_list_entries; i++) {
		printf("Found IP %s %s in libtap db\n", ip_list + offset, ip_list + offset + strlen(ip_list + offset) + 1);
		offset = offset + strlen(ip_list) + 1;
		offset = offset + strlen(ip_list + offset) + 1;
	}

	free(ip_list);

	printf("Deleting ip: %s/24\n", testipv4_1);

	err = tap_del_ip(tap, testipv4_1, "24", &error_string);
	if (error_string) {
		printf("del ip output: %s\n", error_string);
		free(error_string);
		error_string = NULL;
	}
	if (err < 0) {
		printf("Unable to delete IP address\n");
		err=-1;
		goto out_clean;
	}

	printf("Deleting ip: %s/24\n", testipv4_2);

	err = tap_del_ip(tap, testipv4_2, "24", &error_string);
	if (error_string) {
		printf("del ip output: %s\n", error_string);
		free(error_string);
		error_string = NULL;
	}
	if (err < 0) {
		printf("Unable to delete IP address\n");
		err=-1;
		goto out_clean;
	}

	printf("Deleting again ip: %s/24\n", testipv4_1);

	err = tap_del_ip(tap, testipv4_1, "24", &error_string);
	if (error_string) {
		printf("del ip output: %s\n", error_string);
		free(error_string);
		error_string = NULL;
	}
	if (err < 0) {
		printf("Unable to delete IP address\n");
		err=-1;
		goto out_clean;
	}

	memset(verifycmd, 0, sizeof(verifycmd));
	snprintf(verifycmd, sizeof(verifycmd)-1,
#ifdef KNET_LINUX
		 "ip addr show dev %s | grep -q %s/24", tap->tapname, testipv4_1);
#endif
#ifdef KNET_BSD
		 "ifconfig %s | grep -q %s", tap->tapname, testipv4_1);
#endif
	err = _execute_shell(verifycmd, &error_string);
	if (error_string) {
		printf("Error string: %s\n", error_string);
		free(error_string);
		error_string = NULL;
	}
	if (!err) {
		printf("Unable to verify IP address\n");
		err=-1;
		goto out_clean;
	}

	printf("Adding ip: %s/64\n", testipv6_1);

	err = tap_add_ip(tap, testipv6_1, "64", &error_string);
	if (error_string) {
		printf("add ipv6 output: %s\n", error_string);
		free(error_string);
		error_string = NULL;
	}
	if (err < 0) {
		printf("Unable to assign IP address\n");
		err=-1;
		goto out_clean;
	}

	memset(verifycmd, 0, sizeof(verifycmd));
	snprintf(verifycmd, sizeof(verifycmd)-1,
#ifdef KNET_LINUX
		 "ip addr show dev %s | grep -q %s/64", tap->tapname, testipv6_1);
#endif
#ifdef KNET_BSD
		 "ifconfig %s | grep -q %s", tap->tapname, testipv6_1);
#endif
	err = _execute_shell(verifycmd, &error_string);
	if (error_string) {
		printf("Error string: %s\n", error_string);
		free(error_string);
		error_string = NULL;
	}
	if (err) {
		printf("Unable to verify IP address\n");
		err=-1;
		goto out_clean;
	}

	printf("Deleting ip: %s/64\n", testipv6_1);

	err = tap_del_ip(tap, testipv6_1, "64", &error_string);
	if (error_string) {
		printf("Error string: %s\n", error_string);
		free(error_string);
		error_string = NULL;
	}
	if (err) {
		printf("Unable to delete IP address\n");
		err=-1;
		goto out_clean;
	}

	memset(verifycmd, 0, sizeof(verifycmd));
	snprintf(verifycmd, sizeof(verifycmd)-1,
#ifdef KNET_LINUX
		 "ip addr show dev %s | grep -q %s/64", tap->tapname, testipv6_1);
#endif
#ifdef KNET_BSD
		 "ifconfig %s | grep -q %s", tap->tapname, testipv6_1);
#endif
	err = _execute_shell(verifycmd, &error_string);
	if (error_string) {
		printf("Error string: %s\n", error_string);
		free(error_string);
		error_string = NULL;
	}
	if (!err) {
		printf("Unable to verify IP address\n");
		err=-1;
		goto out_clean;
	}

out_clean:

	tap_close(tap);

	return err;
}

static void make_local_ips(void)
{
	pid_t mypid;
	uint8_t *pid;
	uint8_t i;

	if (sizeof(pid_t) < 4) {
		printf("pid_t is smaller than 4 bytes?\n");
		exit(77);
	}

	memset(testipv4_1, 0, sizeof(testipv4_1));
	memset(testipv4_2, 0, sizeof(testipv4_2));
	memset(testipv6_1, 0, sizeof(testipv6_1));
	memset(testipv6_2, 0, sizeof(testipv6_2));

	mypid = getpid();
	pid = (uint8_t *)&mypid;

	for (i = 0; i < sizeof(pid_t); i++) {
		if (pid[i] == 0) {
			pid[i] = 128;
		}
	}

	randombyte = pid[1];

	snprintf(testipv4_1,
		 sizeof(testipv4_1) - 1,
		 "127.%u.%u.%u",
		 pid[1],
		 pid[2],
		 pid[0]);

	snprintf(testipv4_2,
		 sizeof(testipv4_2) - 1,
		 "127.%u.%d.%u",
		 pid[1],
		 pid[2]+1,
		 pid[0]);

	snprintf(testipv6_1,
		 sizeof(testipv6_1) - 1,
		 "fd%x:%x%x::1",
		 pid[1],
		 pid[2],
		 pid[0]);

	snprintf(testipv6_2,
		 sizeof(testipv6_2) - 1,
		 "fd%x:%x%x:1::1",
		 pid[1],
		 pid[2],
		 pid[0]);
}

int main(void)
{
	if (geteuid() != 0) {
		printf("This test requires root privileges\n");
		exit(77);
	}

	make_local_ips();

	if (check_tap_open_close() < 0)
		return -1;

	if (check_knet_multi_eth() < 0)
		return -1;

	if (check_knet_mtu() < 0)
		return -1;

	if (check_knet_mtu_ipv6() < 0)
		return -1;

	if (check_knet_mac() < 0)
		return -1;

	if (check_tap_execute_shell() < 0)
		return -1;

	if (check_knet_up_down() < 0)
		return -1;

	if (check_knet_set_del_ip() < 0)
		return -1;

	if (check_knet_close_leak() < 0)
		return -1;

	return 0;
}
#endif
