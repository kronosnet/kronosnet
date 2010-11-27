#include "config.h"

#include <errno.h>
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
#include "knet.h"

STATIC int knet_sockfd = 0;
STATIC pthread_mutex_t knet_eth_mutex = PTHREAD_MUTEX_INITIALIZER;

/* forward declarations */
STATIC int knet_execute_shell(const char *command);

static int knet_read_pipe(int fd, char **file, size_t *length)
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

STATIC int knet_execute_shell(const char *command)
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
		err = knet_read_pipe(fd[0], &data, &size);
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

static void knet_close_unsafe(struct knet_eth *knet_eth)
{
	if (!knet_eth)
		return;

	if (knet_eth->knet_etherfd)
		close(knet_eth->knet_etherfd);

	free(knet_eth);

	return;
}

struct knet_eth *knet_open(char *dev, size_t dev_size)
{
	struct knet_eth *knet_eth;

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

	pthread_mutex_lock(&knet_eth_mutex);

	knet_eth = malloc(sizeof(struct knet_eth));
	if (!knet_eth)
		return NULL;

	memset(knet_eth, 0, sizeof(struct knet_eth));

	if ((knet_eth->knet_etherfd = open("/dev/net/tun", O_RDWR)) < 0)
		goto out_error;

	strncpy(knet_eth->ifr.ifr_name, dev, IFNAMSIZ);
	knet_eth->ifr.ifr_flags = IFF_TAP | IFF_NO_PI;

	if (ioctl(knet_eth->knet_etherfd, TUNSETIFF, &knet_eth->ifr) < 0)
		goto out_error;

	if ((strlen(dev) > 0) && (strcmp(dev, knet_eth->ifr.ifr_name) != 0)) {
		errno = EBUSY;
		goto out_error;
	}

	strcpy(dev, knet_eth->ifr.ifr_name);

	if (!knet_sockfd)
		knet_sockfd = socket(AF_INET, SOCK_STREAM, 0);
			if (knet_sockfd < 0)
				goto out_error;

	if (ioctl(knet_sockfd, SIOGIFINDEX, &knet_eth->ifr) < 0)
		goto out_error;

	pthread_mutex_unlock(&knet_eth_mutex);
	return knet_eth;

out_error:
	knet_close_unsafe(knet_eth);
	pthread_mutex_unlock(&knet_eth_mutex);
	return NULL;
}

void knet_close(struct knet_eth *knet_eth)
{
	pthread_mutex_lock(&knet_eth_mutex);

	knet_close_unsafe(knet_eth);

	pthread_mutex_unlock(&knet_eth_mutex);

	return;
}

int knet_get_mtu(const struct knet_eth *knet_eth)
{
	int err;

	pthread_mutex_lock(&knet_eth_mutex);

	if (!knet_eth) {
		errno = EINVAL;
		err = -1;
		goto out;
	}

	err = ioctl(knet_sockfd, SIOCGIFMTU, &knet_eth->ifr);
	if (err)
		goto out;

	err = knet_eth->ifr.ifr_mtu;

out:
	pthread_mutex_unlock(&knet_eth_mutex);

	return err;
}

int knet_set_mtu(struct knet_eth *knet_eth, const int mtu)
{
	int err, oldmtu;

	pthread_mutex_lock(&knet_eth_mutex);

	if (!knet_eth) {
		errno = EINVAL;
		err = -1;
		goto out;
	}

	oldmtu = knet_eth->ifr.ifr_mtu;
	knet_eth->ifr.ifr_mtu = mtu;

	err = ioctl(knet_sockfd, SIOCSIFMTU, &knet_eth->ifr);
	if (err)
		knet_eth->ifr.ifr_mtu = oldmtu;

out:
	pthread_mutex_unlock(&knet_eth_mutex);

	return err;
}

int knet_get_mac(const struct knet_eth *knet_eth, char **ether_addr)
{
	int err;
	char mac[18];

	pthread_mutex_lock(&knet_eth_mutex);

	if ((!knet_eth) || (!ether_addr)) {
		errno = EINVAL;
		err = -1;
		goto out;
	}

	err = ioctl(knet_sockfd, SIOCGIFHWADDR, &knet_eth->ifr);
	if (err)
		goto out;

	ether_ntoa_r((struct ether_addr *)knet_eth->ifr.ifr_hwaddr.sa_data, mac);

	*ether_addr = strdup(mac);
	if (!*ether_addr)
		err = -1;

out:
	pthread_mutex_unlock(&knet_eth_mutex);

	return err;
}

int knet_set_mac(struct knet_eth *knet_eth, const char *ether_addr)
{
	struct ether_addr oldmac;
	int err;

	pthread_mutex_lock(&knet_eth_mutex);

	if ((!knet_eth) || (!ether_addr)) {
		errno = EINVAL;
		err = -1;
		goto out;
	}

	memcpy(&oldmac, knet_eth->ifr.ifr_hwaddr.sa_data, ETH_ALEN);
	memcpy(knet_eth->ifr.ifr_hwaddr.sa_data, ether_aton(ether_addr), ETH_ALEN);

	err = ioctl(knet_sockfd, SIOCSIFHWADDR, &knet_eth->ifr);
	if (err)
		memcpy(knet_eth->ifr.ifr_hwaddr.sa_data, &oldmac, ETH_ALEN);

out:
	pthread_mutex_unlock(&knet_eth_mutex);

	return err;
}

int knet_set_up(struct knet_eth *knet_eth)
{
	int err;
	short int oldflags;

	pthread_mutex_lock(&knet_eth_mutex);

	if (!knet_eth) {
		errno = EINVAL;
		err = -1;
		goto out;
	}

	oldflags = knet_eth->ifr.ifr_flags;
	knet_eth->ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
	err=ioctl(knet_sockfd, SIOCSIFFLAGS, &knet_eth->ifr);

	if (err)
		knet_eth->ifr.ifr_flags = oldflags;

out:
	pthread_mutex_unlock(&knet_eth_mutex);

	return err;
}

int knet_set_down(struct knet_eth *knet_eth)
{
	int err;
	short int oldflags;

	pthread_mutex_lock(&knet_eth_mutex);

	if (!knet_eth) {
		errno = EINVAL;
		err = -1;
		goto out;
	}

	oldflags = knet_eth->ifr.ifr_flags;
	knet_eth->ifr.ifr_flags &= ~IFF_UP;
	err=ioctl(knet_sockfd, SIOCSIFFLAGS, &knet_eth->ifr);

	if (err)
		knet_eth->ifr.ifr_flags = oldflags;

out:
	pthread_mutex_unlock(&knet_eth_mutex);

	return err;
}

static char *knet_get_v4_broadcast(const char *ip_addr, const char *prefix)
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

static int knet_set_ip(struct knet_eth *knet_eth, const char *command,
		       const char *ip_addr, const char *prefix)
{
	char *broadcast = NULL;
	char cmdline[4096];

	if ((!knet_eth) || (!ip_addr) || (!prefix) || (!command)) {
		errno = EINVAL;
		return -1;
	}

	if (!strchr(ip_addr, ':')) {
		broadcast = knet_get_v4_broadcast(ip_addr, prefix);
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
			 knet_eth->ifr.ifr_name, broadcast);
		free(broadcast);
	} else {
		snprintf(cmdline, sizeof(cmdline)-1,
			"ip addr %s %s/%s dev %s",
			command, ip_addr, prefix,
			knet_eth->ifr.ifr_name);
	}

	return knet_execute_shell(cmdline);
}

int knet_add_ip(struct knet_eth *knet_eth, const char *ip_addr, const char *prefix)
{
	int err;

	pthread_mutex_lock(&knet_eth_mutex);
	err = knet_set_ip(knet_eth, "add", ip_addr, prefix);
	pthread_mutex_unlock(&knet_eth_mutex);

	return err;
}

int knet_del_ip(struct knet_eth *knet_eth, const char *ip_addr, const char *prefix)
{
	int err;

	pthread_mutex_lock(&knet_eth_mutex);
	err = knet_set_ip(knet_eth, "del", ip_addr, prefix);
	pthread_mutex_unlock(&knet_eth_mutex);

	return err;
}
