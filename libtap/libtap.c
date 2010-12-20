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

#include "utils.h"
#include "libtap.h"
#include "libtap_private.h"

STATIC int tap_init = 0;
STATIC struct tap_config tap_cfg;
STATIC pthread_mutex_t tap_mutex = PTHREAD_MUTEX_INITIALIZER;

/* forward declarations */
STATIC int tap_execute_shell(const char *command);
static int tap_exec_updown(const knet_tap_t knet_tap, const char *action);
static int tap_set_down(knet_tap_t knet_tap);
static int tap_read_pipe(int fd, char **file, size_t *length);
static int tap_check(const knet_tap_t knet_tap);
static void tap_close(knet_tap_t knet_tap);
static void tap_close_cfg(void);
static int tap_get_mtu(const knet_tap_t knet_tap);
static int tap_get_mac(const knet_tap_t knet_tap, char **ether_addr);
static int tap_set_down(knet_tap_t knet_tap);
static char *tap_get_v4_broadcast(const char *ip_addr, const char *prefix);
static int tap_set_ip(knet_tap_t knet_tap, const char *command,
		      const char *ip_addr, const char *prefix);
static int tap_find_ip(knet_tap_t knet_tap,
			const char *ip_addr, const char *prefix,
			struct tap_ip **tap_ip, struct tap_ip **tap_ip_prev);

static int tap_read_pipe(int fd, char **file, size_t *length)
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

STATIC int tap_execute_shell(const char *command)
{
	pid_t pid;
	int status, err = 0;
	int fd[2];
	char *data = NULL;
	size_t size = 0;

	if (command == NULL) {
		errno = EINVAL;
		return -1;
	}

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
		err = tap_read_pipe(fd[0], &data, &size);
		if (err)
			goto out_clean;

		waitpid(pid, &status, 0);
		if (!WIFEXITED(status)) {
			log_error("shell: child did not terminate normally");
			err = -1;
			goto out_clean;
		}
		if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
			log_error("shell: child returned %d", WEXITSTATUS(status));
			err = -1;
			goto out_clean;
		}
	} else { /* child */
		close(0);
		close(1);
		close(2);

		close(fd[0]);
		if(dup2(fd[1], 1) < 0)
			log_error("Unable to redirect stdout");
		if(dup2(fd[1], 2) < 0)
			log_error("Unable to redirect stderr");
		close(fd[1]);

		execlp("/bin/sh", "/bin/sh", "-c", command, NULL);
		exit(EXIT_FAILURE);
	}

out_clean:
	close(fd[0]);
	close(fd[1]);

	if ((size) && (err)) {
		log_error("%s", data);
		free(data);
	}

	return err;
}

static int tap_exec_updown(const knet_tap_t knet_tap, const char *action)
{
	char command[PATH_MAX];

	memset(command, 0, PATH_MAX);

	snprintf(command, PATH_MAX, "%s%s/%s", knet_tap->updownpath, action, knet_tap->ifname);

	return tap_execute_shell(command);
}

static int tap_check(const knet_tap_t knet_tap)
{
	knet_tap_t temp = tap_cfg.tap_head;

	if (!knet_tap)
		return 0;

	while (temp != NULL) {
		if (knet_tap == temp)
			return 1;

		temp = temp->next;
	}

	return 0;
}

static void tap_close(knet_tap_t knet_tap)
{
	if (!knet_tap)
		return;

	if (knet_tap->knet_tap_fd)
		close(knet_tap->knet_tap_fd);

	free(knet_tap);

	return;
}

static void tap_close_cfg(void)
{
	if (tap_cfg.tap_head == NULL) {
		close(tap_cfg.tap_sockfd);
		tap_init = 0;
	}
}

static int tap_get_mtu(const knet_tap_t knet_tap)
{
	int err;

	err = ioctl(tap_cfg.tap_sockfd, SIOCGIFMTU, &knet_tap->ifr);
	if (err)
		goto out_clean;

	err = knet_tap->ifr.ifr_mtu;

out_clean:
	return err;
}

static int tap_get_mac(const knet_tap_t knet_tap, char **ether_addr)
{
	int err;
	char mac[MAX_MAC_CHAR];

	err = ioctl(tap_cfg.tap_sockfd, SIOCGIFHWADDR, &knet_tap->ifr);
	if (err)
		goto out_clean;

	ether_ntoa_r((struct ether_addr *)knet_tap->ifr.ifr_hwaddr.sa_data, mac);

	*ether_addr = strdup(mac);
	if (!*ether_addr)
		err = -1;

out_clean:

	return err;
}

knet_tap_t knet_tap_find(char *dev, size_t dev_size)
{
	knet_tap_t knet_tap;

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

	pthread_mutex_lock(&tap_mutex);

	knet_tap = tap_cfg.tap_head;
	while (knet_tap != NULL) {
		if (!strcmp(dev, knet_tap->ifname))
			break;
		knet_tap = knet_tap->next;
	}

	pthread_mutex_unlock(&tap_mutex);
	return knet_tap;
}

knet_tap_t knet_tap_open(char *dev, size_t dev_size, const char *updownpath)
{
	knet_tap_t knet_tap;
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

	pthread_mutex_lock(&tap_mutex);

	knet_tap = malloc(sizeof(struct tap_iface));
	if (!knet_tap)
		return NULL;

	memset(knet_tap, 0, sizeof(struct tap_iface));

	if ((knet_tap->knet_tap_fd = open("/dev/net/tun", O_RDWR)) < 0)
		goto out_error;

	strncpy(knet_tap->ifname, dev, IFNAMSIZ);
	knet_tap->ifr.ifr_flags = IFF_TAP | IFF_NO_PI;

	if (ioctl(knet_tap->knet_tap_fd, TUNSETIFF, &knet_tap->ifr) < 0)
		goto out_error;

	if ((strlen(dev) > 0) && (strcmp(dev, knet_tap->ifname) != 0)) {
		errno = EBUSY;
		goto out_error;
	}

	strcpy(dev, knet_tap->ifname);

	if (!tap_init) {
		tap_cfg.tap_head = NULL;
		tap_cfg.tap_sockfd = socket(AF_INET, SOCK_STREAM, 0);
			if (tap_cfg.tap_sockfd < 0)
				goto out_error;
		tap_init = 1;
	}

	if (ioctl(tap_cfg.tap_sockfd, SIOGIFINDEX, &knet_tap->ifr) < 0)
		goto out_error;

	knet_tap->default_mtu = tap_get_mtu(knet_tap);
	if (knet_tap->default_mtu < 0)
		goto out_error;

	if (tap_get_mac(knet_tap, &temp_mac) < 0)
		goto out_error;

	strncpy(knet_tap->default_mac, temp_mac, 18);
	free(temp_mac);

	if (updownpath) {
		int len = strlen(updownpath);

		strcpy(knet_tap->updownpath, updownpath);
		if (knet_tap->updownpath[len-1] != '/') {
			knet_tap->updownpath[len] = '/';
		}
		knet_tap->hasupdown = 1;
	}

	knet_tap->next = tap_cfg.tap_head;
	tap_cfg.tap_head = knet_tap;

	pthread_mutex_unlock(&tap_mutex);
	return knet_tap;

out_error:
	tap_close(knet_tap);
	tap_close_cfg();
	pthread_mutex_unlock(&tap_mutex);
	return NULL;
}

int knet_tap_close(knet_tap_t knet_tap)
{
	int err = 0;
	knet_tap_t temp = tap_cfg.tap_head;
	knet_tap_t prev = tap_cfg.tap_head;
	struct tap_ip *tap_ip, *tap_ip_next;

	pthread_mutex_lock(&tap_mutex);

	if (!tap_check(knet_tap)) {
		errno = EINVAL;
		err = -1;
		goto out_clean;
	}

	while ((temp) && (temp != knet_tap)) {
		prev = temp;
		temp = temp->next;
	}

	if (knet_tap == prev) {
		tap_cfg.tap_head = knet_tap->next;
	} else {
		prev->next = knet_tap->next;
	}

	tap_set_down(knet_tap);

	tap_ip = knet_tap->tap_ip;
	while (tap_ip) {
		tap_ip_next = tap_ip->next;
		tap_set_ip(knet_tap, "del", tap_ip->ip_addr, tap_ip->prefix);
		free(tap_ip);
		tap_ip = tap_ip_next;
	}

	tap_close(knet_tap);
	tap_close_cfg();

out_clean:
	pthread_mutex_unlock(&tap_mutex);

	return err;
}

int knet_tap_get_mtu(const knet_tap_t knet_tap)
{
	int err;

	pthread_mutex_lock(&tap_mutex);

	if (!tap_check(knet_tap)) {
		errno = EINVAL;
		err = -1;
		goto out_clean;
	}

	err = tap_get_mtu(knet_tap);

out_clean:
	pthread_mutex_unlock(&tap_mutex);

	return err;
}

int knet_tap_set_mtu(knet_tap_t knet_tap, const int mtu)
{
	int err, oldmtu;

	pthread_mutex_lock(&tap_mutex);

	if (!tap_check(knet_tap)) {
		errno = EINVAL;
		err = -1;
		goto out_clean;
	}

	oldmtu = knet_tap->ifr.ifr_mtu;
	knet_tap->ifr.ifr_mtu = mtu;

	err = ioctl(tap_cfg.tap_sockfd, SIOCSIFMTU, &knet_tap->ifr);
	if (err)
		knet_tap->ifr.ifr_mtu = oldmtu;

out_clean:
	pthread_mutex_unlock(&tap_mutex);

	return err;
}

int knet_tap_reset_mtu(knet_tap_t knet_tap)
{
	return knet_tap_set_mtu(knet_tap, knet_tap->default_mtu);
}

int knet_tap_get_mac(const knet_tap_t knet_tap, char **ether_addr)
{
	int err;

	pthread_mutex_lock(&tap_mutex);

	if ((!tap_check(knet_tap)) || (!ether_addr)) {
		errno = EINVAL;
		err = -1;
		goto out_clean;
	}

	err = tap_get_mac(knet_tap, ether_addr);

out_clean:
	pthread_mutex_unlock(&tap_mutex);

	return err;
}

int knet_tap_set_mac(knet_tap_t knet_tap, const char *ether_addr)
{
	struct ether_addr oldmac;
	int err;

	pthread_mutex_lock(&tap_mutex);

	if ((!tap_check(knet_tap)) || (!ether_addr)) {
		errno = EINVAL;
		err = -1;
		goto out_clean;
	}

	memcpy(&oldmac, knet_tap->ifr.ifr_hwaddr.sa_data, ETH_ALEN);
	memcpy(knet_tap->ifr.ifr_hwaddr.sa_data, ether_aton(ether_addr), ETH_ALEN);

	err = ioctl(tap_cfg.tap_sockfd, SIOCSIFHWADDR, &knet_tap->ifr);
	if (err)
		memcpy(knet_tap->ifr.ifr_hwaddr.sa_data, &oldmac, ETH_ALEN);

out_clean:
	pthread_mutex_unlock(&tap_mutex);

	return err;
}

int knet_tap_reset_mac(knet_tap_t knet_tap)
{
	return knet_tap_set_mac(knet_tap, knet_tap->default_mac);
}

int knet_tap_set_up(knet_tap_t knet_tap)
{
	int err = 0;
	short int oldflags;

	pthread_mutex_lock(&tap_mutex);

	if (!tap_check(knet_tap)) {
		errno = EINVAL;
		err = -1;
		goto out_clean;
	}

	if (knet_tap->up)
		goto out_clean;

	tap_exec_updown(knet_tap, "pre-up.d");

	oldflags = knet_tap->ifr.ifr_flags;
	knet_tap->ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
	err=ioctl(tap_cfg.tap_sockfd, SIOCSIFFLAGS, &knet_tap->ifr);

	if (err)
		knet_tap->ifr.ifr_flags = oldflags;

	tap_exec_updown(knet_tap, "up.d");

	knet_tap->up = 1;
out_clean:
	pthread_mutex_unlock(&tap_mutex);

	return err;
}

static int tap_set_down(knet_tap_t knet_tap)
{
	int err = 0;
	short int oldflags;

	if (!knet_tap->up)
		goto out_clean;

	tap_exec_updown(knet_tap, "down.d");

	oldflags = knet_tap->ifr.ifr_flags;
	knet_tap->ifr.ifr_flags &= ~IFF_UP;
	err=ioctl(tap_cfg.tap_sockfd, SIOCSIFFLAGS, &knet_tap->ifr);

	if (err) {
		knet_tap->ifr.ifr_flags = oldflags;
		goto out_clean;
	}

	tap_exec_updown(knet_tap, "post-down.d");

	knet_tap->up = 0;

out_clean:
	return err;
}

int knet_tap_set_down(knet_tap_t knet_tap)
{
	int err = 0;

	pthread_mutex_lock(&tap_mutex);

	if (!tap_check(knet_tap)) {
		errno = EINVAL;
		err = -1;
		goto out_clean;
	}

	err=tap_set_down(knet_tap);

out_clean:
	pthread_mutex_unlock(&tap_mutex);

	return err;
}

static char *tap_get_v4_broadcast(const char *ip_addr, const char *prefix)
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

static int tap_set_ip(knet_tap_t knet_tap, const char *command,
		       const char *ip_addr, const char *prefix)
{
	char *broadcast = NULL;
	char cmdline[4096];

	if (!strchr(ip_addr, ':')) {
		broadcast = tap_get_v4_broadcast(ip_addr, prefix);
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
			 knet_tap->ifname, broadcast);
		free(broadcast);
	} else {
		snprintf(cmdline, sizeof(cmdline)-1,
			"ip addr %s %s/%s dev %s",
			command, ip_addr, prefix,
			knet_tap->ifname);
	}

	return tap_execute_shell(cmdline);
}

static int tap_find_ip(knet_tap_t knet_tap,
			const char *ip_addr, const char *prefix,
			struct tap_ip **tap_ip, struct tap_ip **tap_ip_prev)
{
	struct tap_ip *local_tap_ip, *local_tap_ip_prev;
	int found = 0;

	local_tap_ip = local_tap_ip_prev = knet_tap->tap_ip;

	while(local_tap_ip) {
		if ((!strcmp(local_tap_ip->ip_addr, ip_addr)) && (!strcmp(local_tap_ip->prefix, prefix))) {
			found = 1;
			break;
		}
		local_tap_ip_prev = local_tap_ip;
		local_tap_ip = local_tap_ip->next;
	}

	if (found) {
		*tap_ip = local_tap_ip;
		*tap_ip_prev = local_tap_ip_prev;
	}

	return found;
}

int knet_tap_add_ip(knet_tap_t knet_tap, const char *ip_addr, const char *prefix)
{
	int err = 0, found;
	struct tap_ip *tap_ip = NULL, *tap_ip_prev = NULL;

	pthread_mutex_lock(&tap_mutex);

	if ((!tap_check(knet_tap)) || (!ip_addr) || (!prefix)) {
		errno = EINVAL;
		err = -1;
		goto out_clean;
	}

	found = tap_find_ip(knet_tap, ip_addr, prefix, &tap_ip, &tap_ip_prev);
	if (found)
		goto out_clean;

	tap_ip = malloc(sizeof(struct tap_ip));
	if (!tap_ip) {
		err = -1 ;
		goto out_clean;
	}
	memset(tap_ip, 0, sizeof(struct tap_ip));
	strncpy(tap_ip->ip_addr, ip_addr, MAX_IP_CHAR);
	strncpy(tap_ip->prefix, prefix, MAX_PREFIX_CHAR);

	err = tap_set_ip(knet_tap, "add", ip_addr, prefix);
	if (err) {
		free(tap_ip);
		goto out_clean;
	}

	tap_ip->next = knet_tap->tap_ip;
	knet_tap->tap_ip = tap_ip;

out_clean:
	pthread_mutex_unlock(&tap_mutex);

	return err;
}

int knet_tap_del_ip(knet_tap_t knet_tap, const char *ip_addr, const char *prefix)
{
	int err = 0, found;
	struct tap_ip *tap_ip = NULL, *tap_ip_prev = NULL;

	pthread_mutex_lock(&tap_mutex);

	if ((!tap_check(knet_tap)) || (!ip_addr) || (!prefix)) {
		errno = EINVAL;
		err = -1;
		goto out_clean;
	}

	found = tap_find_ip(knet_tap, ip_addr, prefix, &tap_ip, &tap_ip_prev);
	if (!found)
		goto out_clean;

	err = tap_set_ip(knet_tap, "del", ip_addr, prefix);

	if (!err) {
		if (tap_ip == tap_ip_prev) {
			knet_tap->tap_ip = tap_ip->next;
		} else {
			tap_ip_prev->next = tap_ip->next;
		}
		free(tap_ip);
	}

out_clean:
	pthread_mutex_unlock(&tap_mutex);

	return err;
}

int knet_tap_get_fd(const knet_tap_t knet_tap)
{
	int fd;

	pthread_mutex_lock(&tap_mutex);

	if (!tap_check(knet_tap)) {
		errno = EINVAL;
		fd = -1;
		goto out_clean;
	}

	fd = knet_tap->knet_tap_fd;

out_clean:
	pthread_mutex_unlock(&tap_mutex);

	return fd;
}

const char *knet_tap_get_name(const knet_tap_t knet_tap)
{
	char *name = NULL;

	pthread_mutex_lock(&tap_mutex);

	if (!tap_check(knet_tap)) {
		errno = EINVAL;
		goto out_clean;
	}

	name = knet_tap->ifname;

out_clean:
	pthread_mutex_unlock(&tap_mutex);

	return name;
}

int knet_tap_get_ips(const knet_tap_t knet_tap, char **ip_addr_list, int *entries)
{
	int err = 0;
	int found = 0;
	char *ip_list = NULL;
	int size = 0, offset = 0, len;
	struct tap_ip *tap_ip = knet_tap->tap_ip;

	pthread_mutex_lock(&tap_mutex);

	while (tap_ip) {
		found++;
		tap_ip = tap_ip->next;
	}

	size = found * (MAX_IP_CHAR + MAX_PREFIX_CHAR + 2);
	ip_list = malloc(size);
	if (!ip_list) {
		err = -1;
		goto out_clean;
	}

	memset(ip_list, 0, size);

	tap_ip = knet_tap->tap_ip;

	while (tap_ip) {
		len = strlen(tap_ip->ip_addr);
		memcpy(ip_list + offset, tap_ip->ip_addr, len);
		offset = offset + len + 1;
		len = strlen(tap_ip->prefix);
		memcpy(ip_list + offset, tap_ip->prefix, len);
		offset = offset + len + 1;
		tap_ip = tap_ip->next;
	}

	*ip_addr_list = ip_list;
	*entries = found;

out_clean:
	pthread_mutex_unlock(&tap_mutex);

	return err;
}
