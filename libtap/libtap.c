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

#include "utils.h"
#include "libtap.h"
#include "libtap_private.h"

STATIC int tap_init = 0;
STATIC struct tap_config tap_cfg;
STATIC pthread_mutex_t tap_mutex = PTHREAD_MUTEX_INITIALIZER;

/* forward declarations */
STATIC int tap_execute_shell(const char *command);

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

static void tap_close_unsafe(knet_tap_t knet_tap)
{
	if (!knet_tap)
		return;

	if (knet_tap->knet_tap_fd)
		close(knet_tap->knet_tap_fd);

	free(knet_tap);

	return;
}

static void tap_close_cfg(void) {
	if (tap_cfg.tap_head == NULL) {
		close(tap_cfg.tap_sockfd);
		tap_init = 0;
	}
}

static int tap_get_mtu_unsafe(const knet_tap_t knet_tap)
{
	int err;

	if (!knet_tap) {
		errno = EINVAL;
		err = -1;
		goto out;
	}

	err = ioctl(tap_cfg.tap_sockfd, SIOCGIFMTU, &knet_tap->ifr);
	if (err)
		goto out;

	err = knet_tap->ifr.ifr_mtu;

out:
	return err;
}

static int tap_get_mac_unsafe(const knet_tap_t knet_tap, char **ether_addr)
{
	int err;
	char mac[18];

	if ((!knet_tap) || (!ether_addr)) {
		errno = EINVAL;
		err = -1;
		goto out;
	}

	err = ioctl(tap_cfg.tap_sockfd, SIOCGIFHWADDR, &knet_tap->ifr);
	if (err)
		goto out;

	ether_ntoa_r((struct ether_addr *)knet_tap->ifr.ifr_hwaddr.sa_data, mac);

	*ether_addr = strdup(mac);
	if (!*ether_addr)
		err = -1;

out:

	return err;
}


knet_tap_t knet_tap_open(char *dev, size_t dev_size)
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

	pthread_mutex_lock(&tap_mutex);

	knet_tap = malloc(sizeof(struct knet_tap));
	if (!knet_tap)
		return NULL;

	memset(knet_tap, 0, sizeof(struct knet_tap));

	if ((knet_tap->knet_tap_fd = open("/dev/net/tun", O_RDWR)) < 0)
		goto out_error;

	strncpy(knet_tap->ifr.ifr_name, dev, IFNAMSIZ);
	knet_tap->ifr.ifr_flags = IFF_TAP | IFF_NO_PI;

	if (ioctl(knet_tap->knet_tap_fd, TUNSETIFF, &knet_tap->ifr) < 0)
		goto out_error;

	if ((strlen(dev) > 0) && (strcmp(dev, knet_tap->ifr.ifr_name) != 0)) {
		errno = EBUSY;
		goto out_error;
	}

	if (!tap_init) {
		tap_cfg.tap_head = NULL;
		tap_cfg.tap_sockfd = socket(AF_INET, SOCK_STREAM, 0);
			if (tap_cfg.tap_sockfd < 0)
				goto out_error;
		tap_init = 1;
	}

	if (ioctl(tap_cfg.tap_sockfd, SIOGIFINDEX, &knet_tap->ifr) < 0)
		goto out_error;

	knet_tap->default_mtu = tap_get_mtu_unsafe(knet_tap);
	if (knet_tap->default_mtu < 0)
		goto out_error;

	if (tap_get_mac_unsafe(knet_tap, &temp_mac) < 0)
		goto out_error;

	strncpy(knet_tap->default_mac, temp_mac, 18);
	free(temp_mac);

	knet_tap->next = tap_cfg.tap_head;
	tap_cfg.tap_head = knet_tap;

	pthread_mutex_unlock(&tap_mutex);
	return knet_tap;

out_error:
	tap_close_unsafe(knet_tap);
	tap_close_cfg();
	pthread_mutex_unlock(&tap_mutex);
	return NULL;
}

void knet_tap_close(knet_tap_t knet_tap)
{
	knet_tap_t temp = tap_cfg.tap_head;
	knet_tap_t prev = tap_cfg.tap_head;

	if (!knet_tap)
		return;

	pthread_mutex_lock(&tap_mutex);

	while (temp != knet_tap) {
		prev = temp;
		temp = temp->next;
	}

	if (temp == knet_tap) {
		if (knet_tap == prev) {
			tap_cfg.tap_head = knet_tap->next;
		} else {
			prev->next = knet_tap->next;
		}
		tap_close_unsafe(knet_tap);
	}

	tap_close_cfg();

	pthread_mutex_unlock(&tap_mutex);

	return;
}

int knet_tap_get_mtu(const knet_tap_t knet_tap)
{
	int err;

	pthread_mutex_lock(&tap_mutex);

	err = tap_get_mtu_unsafe(knet_tap);

	pthread_mutex_unlock(&tap_mutex);

	return err;
}

int knet_tap_set_mtu(knet_tap_t knet_tap, const int mtu)
{
	int err, oldmtu;

	pthread_mutex_lock(&tap_mutex);

	if (!knet_tap) {
		errno = EINVAL;
		err = -1;
		goto out;
	}

	oldmtu = knet_tap->ifr.ifr_mtu;
	knet_tap->ifr.ifr_mtu = mtu;

	err = ioctl(tap_cfg.tap_sockfd, SIOCSIFMTU, &knet_tap->ifr);
	if (err)
		knet_tap->ifr.ifr_mtu = oldmtu;

out:
	pthread_mutex_unlock(&tap_mutex);

	return err;
}

int knet_tap_get_mac(const knet_tap_t knet_tap, char **ether_addr)
{
	int err;

	pthread_mutex_lock(&tap_mutex);

	err = tap_get_mac_unsafe(knet_tap, ether_addr);

	pthread_mutex_unlock(&tap_mutex);

	return err;
}

int knet_tap_set_mac(knet_tap_t knet_tap, const char *ether_addr)
{
	struct ether_addr oldmac;
	int err;

	pthread_mutex_lock(&tap_mutex);

	if ((!knet_tap) || (!ether_addr)) {
		errno = EINVAL;
		err = -1;
		goto out;
	}

	memcpy(&oldmac, knet_tap->ifr.ifr_hwaddr.sa_data, ETH_ALEN);
	memcpy(knet_tap->ifr.ifr_hwaddr.sa_data, ether_aton(ether_addr), ETH_ALEN);

	err = ioctl(tap_cfg.tap_sockfd, SIOCSIFHWADDR, &knet_tap->ifr);
	if (err)
		memcpy(knet_tap->ifr.ifr_hwaddr.sa_data, &oldmac, ETH_ALEN);

out:
	pthread_mutex_unlock(&tap_mutex);

	return err;
}

int knet_tap_set_up(knet_tap_t knet_tap)
{
	int err;
	short int oldflags;

	pthread_mutex_lock(&tap_mutex);

	if (!knet_tap) {
		errno = EINVAL;
		err = -1;
		goto out;
	}

	oldflags = knet_tap->ifr.ifr_flags;
	knet_tap->ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
	err=ioctl(tap_cfg.tap_sockfd, SIOCSIFFLAGS, &knet_tap->ifr);

	if (err)
		knet_tap->ifr.ifr_flags = oldflags;

out:
	pthread_mutex_unlock(&tap_mutex);

	return err;
}

int knet_tap_set_down(knet_tap_t knet_tap)
{
	int err;
	short int oldflags;

	pthread_mutex_lock(&tap_mutex);

	if (!knet_tap) {
		errno = EINVAL;
		err = -1;
		goto out;
	}

	oldflags = knet_tap->ifr.ifr_flags;
	knet_tap->ifr.ifr_flags &= ~IFF_UP;
	err=ioctl(tap_cfg.tap_sockfd, SIOCSIFFLAGS, &knet_tap->ifr);

	if (err)
		knet_tap->ifr.ifr_flags = oldflags;

out:
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

	if ((!knet_tap) || (!ip_addr) || (!prefix) || (!command)) {
		errno = EINVAL;
		return -1;
	}

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
			 knet_tap->ifr.ifr_name, broadcast);
		free(broadcast);
	} else {
		snprintf(cmdline, sizeof(cmdline)-1,
			"ip addr %s %s/%s dev %s",
			command, ip_addr, prefix,
			knet_tap->ifr.ifr_name);
	}

	return tap_execute_shell(cmdline);
}

int knet_tap_add_ip(knet_tap_t knet_tap, const char *ip_addr, const char *prefix)
{
	int err;

	pthread_mutex_lock(&tap_mutex);
	err = tap_set_ip(knet_tap, "add", ip_addr, prefix);
	pthread_mutex_unlock(&tap_mutex);

	return err;
}

int knet_tap_del_ip(knet_tap_t knet_tap, const char *ip_addr, const char *prefix)
{
	int err;

	pthread_mutex_lock(&tap_mutex);
	err = tap_set_ip(knet_tap, "del", ip_addr, prefix);
	pthread_mutex_unlock(&tap_mutex);

	return err;
}

int knet_tap_get_fd(const knet_tap_t knet_tap)
{
	return knet_tap->knet_tap_fd;
}
