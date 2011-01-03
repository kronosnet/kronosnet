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
#include <linux/if_tun.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <limits.h>
#include <stdio.h>

#include "libtap.h"
#include "libtap-private.h"

STATIC int lib_init = 0;
STATIC struct _config lib_cfg;
STATIC pthread_mutex_t lib_mutex = PTHREAD_MUTEX_INITIALIZER;

/* forward declarations */
STATIC int _execute_shell(const char *command, char **error_string);
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
		      char **error_string);
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

		memcpy((*file) + (*length), buf, n);
		*length += (done + n);
	}

	/* Null terminator */
	(*file)[(*length) - 1] = 0;

	return 0;
}

STATIC int _execute_shell(const char *command, char **error_string)
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
			goto out_clean;

		waitpid(pid, &status, 0);
		if (!WIFEXITED(status)) {
			err = -1;
			goto out_clean;
		}
		if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
			err = WEXITSTATUS(status);
			goto out_clean;
		}
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
	close(fd[0]);
	close(fd[1]);

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

	snprintf(command, PATH_MAX, "%s%s/%s", tap->updownpath, action, tap->ifname);

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

	if (!tap)
		return 0;

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

	err = ioctl(lib_cfg.sockfd, SIOCGIFMTU, &tap->ifr);
	if (err)
		goto out_clean;

	err = tap->ifr.ifr_mtu;

out_clean:
	return err;
}

static int _get_mac(const tap_t tap, char **ether_addr)
{
	int err;
	char mac[MAX_MAC_CHAR];

	err = ioctl(lib_cfg.sockfd, SIOCGIFHWADDR, &tap->ifr);
	if (err)
		goto out_clean;

	ether_ntoa_r((struct ether_addr *)tap->ifr.ifr_hwaddr.sa_data, mac);

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
		if (!strcmp(dev, tap->ifname))
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

	pthread_mutex_lock(&lib_mutex);

	tap = malloc(sizeof(struct _iface));
	if (!tap)
		return NULL;

	memset(tap, 0, sizeof(struct _iface));

	if ((tap->fd = open("/dev/net/tun", O_RDWR)) < 0)
		goto out_error;

	strncpy(tap->ifname, dev, IFNAMSIZ);
	tap->ifr.ifr_flags = IFF_TAP | IFF_NO_PI;

	if (ioctl(tap->fd, TUNSETIFF, &tap->ifr) < 0)
		goto out_error;

	if ((strlen(dev) > 0) && (strcmp(dev, tap->ifname) != 0)) {
		errno = EBUSY;
		goto out_error;
	}

	strcpy(dev, tap->ifname);

	if (!lib_init) {
		lib_cfg.head = NULL;
		lib_cfg.sockfd = socket(AF_INET, SOCK_STREAM, 0);
			if (lib_cfg.sockfd < 0)
				goto out_error;
		lib_init = 1;
	}

	if (ioctl(lib_cfg.sockfd, SIOGIFINDEX, &tap->ifr) < 0)
		goto out_error;

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
		_set_ip(tap, "del", ip->ip_addr, ip->prefix, &error_string);
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
	int err, oldmtu;

	pthread_mutex_lock(&lib_mutex);

	if (!_check(tap)) {
		errno = EINVAL;
		err = -1;
		goto out_clean;
	}

	oldmtu = tap->ifr.ifr_mtu;
	tap->ifr.ifr_mtu = mtu;

	err = ioctl(lib_cfg.sockfd, SIOCSIFMTU, &tap->ifr);
	if (err)
		tap->ifr.ifr_mtu = oldmtu;

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
	struct ether_addr oldmac;
	int err;

	pthread_mutex_lock(&lib_mutex);

	if ((!_check(tap)) || (!ether_addr)) {
		errno = EINVAL;
		err = -1;
		goto out_clean;
	}

	memcpy(&oldmac, tap->ifr.ifr_hwaddr.sa_data, ETH_ALEN);
	memcpy(tap->ifr.ifr_hwaddr.sa_data, ether_aton(ether_addr), ETH_ALEN);

	err = ioctl(lib_cfg.sockfd, SIOCSIFHWADDR, &tap->ifr);
	if (err)
		memcpy(tap->ifr.ifr_hwaddr.sa_data, &oldmac, ETH_ALEN);

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
	short int oldflags;

	pthread_mutex_lock(&lib_mutex);

	if (!_check(tap) || (!error_preup) || (!error_up)) {
		errno = EINVAL;
		err = -1;
		goto out_clean;
	}

	if (tap->up)
		goto out_clean;

	_exec_updown(tap, "pre-up.d", error_preup);

	oldflags = tap->ifr.ifr_flags;
	tap->ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
	err=ioctl(lib_cfg.sockfd, SIOCSIFFLAGS, &tap->ifr);

	if (err)
		tap->ifr.ifr_flags = oldflags;

	_exec_updown(tap, "up.d", error_up);

	tap->up = 1;
out_clean:
	pthread_mutex_unlock(&lib_mutex);

	return err;
}

static int _set_down(tap_t tap, char **error_down, char **error_postdown)
{
	int err = 0;
	short int oldflags;

	if (!tap->up)
		goto out_clean;

	_exec_updown(tap, "down.d", error_down);

	oldflags = tap->ifr.ifr_flags;
	tap->ifr.ifr_flags &= ~IFF_UP;
	err=ioctl(lib_cfg.sockfd, SIOCSIFFLAGS, &tap->ifr);

	if (err) {
		tap->ifr.ifr_flags = oldflags;
		goto out_clean;
	}

	_exec_updown(tap, "post-down.d", error_postdown);

	tap->up = 0;

out_clean:
	return err;
}

int tap_set_down(tap_t tap, char **error_down, char **error_postdown)
{
	int err = 0;

	pthread_mutex_lock(&lib_mutex);

	if (!_check(tap) || (!error_down) || (!error_postdown)) {
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
		      char **error_string)
{
	char *broadcast = NULL;
	char cmdline[4096];

	if (!strchr(ip_addr, ':')) {
		broadcast = _get_v4_broadcast(ip_addr, prefix);
		if (!broadcast) {
			errno = EINVAL;
			return -1;
		}
	}

	memset(cmdline, 0, sizeof(cmdline));

	if (broadcast) {
		snprintf(cmdline, sizeof(cmdline)-1,
			"ip addr %s %s/%s dev %s broadcast %s",
			 command, ip_addr, prefix,
			 tap->ifname, broadcast);
		free(broadcast);
	} else {
		snprintf(cmdline, sizeof(cmdline)-1,
			"ip addr %s %s/%s dev %s",
			command, ip_addr, prefix,
			tap->ifname);
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
	struct _ip *ip = NULL, *ip_prev = NULL;

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

	err = _set_ip(tap, "add", ip_addr, prefix, error_string);

	if (err) {
		free(ip);
		goto out_clean;
	}

	ip->next = tap->ip;
	tap->ip = ip;

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

	err = _set_ip(tap, "del", ip_addr, prefix, error_string);

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

	name = tap->ifname;

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
		memcpy(ip_list + offset, ip->ip_addr, len);
		offset = offset + len + 1;
		len = strlen(ip->prefix);
		memcpy(ip_list + offset, ip->prefix, len);
		offset = offset + len + 1;
		ip = ip->next;
	}

	*ip_addr_list = ip_list;
	*entries = found;

out_clean:
	pthread_mutex_unlock(&lib_mutex);

	return err;
}
