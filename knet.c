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

#include "utils.h"
#include "knet.h"

STATIC int knet_sockfd = 0;
STATIC int knet_sockfd6 = 0;

/* forward declarations */
STATIC int knet_execute_shell(const char *command);
STATIC int knet_read_pipe(int fd, char **file, size_t *length);

struct knet_eth *knet_open(char *dev, size_t dev_size)
{
	int err;
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

	knet_eth = malloc(sizeof(struct knet_eth));
	if (!knet_eth)
		return NULL;

	memset(knet_eth, 0, sizeof(struct knet_eth));

	if ((knet_eth->knet_etherfd = open("/dev/net/tun", O_RDWR)) < 0) {
		errno = ENOENT;
		free(knet_eth);
		return NULL;
	}

	strncpy(knet_eth->ifr.ifr_name, dev, IFNAMSIZ);
	knet_eth->ifr.ifr_flags = IFF_TAP | IFF_NO_PI;

	if ((err = ioctl(knet_eth->knet_etherfd, TUNSETIFF, (void *)&knet_eth->ifr)) < 0) {
		close(knet_eth->knet_etherfd);
		free(knet_eth);
		return NULL;
	}

	strcpy(dev, knet_eth->ifr.ifr_name);

	if (!knet_sockfd)
		knet_sockfd = socket(AF_INET, SOCK_STREAM, 0);
			if (knet_sockfd < 0)
				return NULL;

	if (!knet_sockfd6)
		knet_sockfd6 = socket(AF_INET6, SOCK_STREAM, 0);
			if (knet_sockfd6 < 0)
				return NULL; 

	return knet_eth;
}

void knet_close(struct knet_eth *knet_eth)
{
	if (!knet_eth)
		return;

	close(knet_eth->knet_etherfd);
	free(knet_eth);
	return;
}

int knet_get_mtu(const struct knet_eth *knet_eth)
{
	int err;

	if (!knet_eth) {
		errno = EINVAL;
		return -1;
	}

	err = ioctl(knet_sockfd, SIOCGIFMTU, (void *)&knet_eth->ifr);
	if (err)
		return err;

	return knet_eth->ifr.ifr_mtu;
}

int knet_set_mtu(struct knet_eth *knet_eth, const int mtu)
{
	int err, oldmtu;

	if (!knet_eth) {
		errno = EINVAL;
		return -1;
	}

	oldmtu = knet_eth->ifr.ifr_mtu;
	knet_eth->ifr.ifr_mtu = mtu;

	err = ioctl(knet_sockfd, SIOCSIFMTU, (void *)&knet_eth->ifr);
	if (err)
		knet_eth->ifr.ifr_mtu = oldmtu;

	return err;
}

int knet_get_mac(const struct knet_eth *knet_eth, char **ether_addr)
{
	int err;
	char mac[18];

	if ((!knet_eth) || (!ether_addr)) {
		errno = EINVAL;
		return -1;
	}

	err = ioctl(knet_sockfd, SIOCGIFHWADDR, &knet_eth->ifr);
	if (err)
		return err;

	ether_ntoa_r((struct ether_addr *)knet_eth->ifr.ifr_hwaddr.sa_data, mac);

	*ether_addr = strdup(mac);
	if (!*ether_addr)
		return -1;

	return 0;
}

int knet_set_mac(struct knet_eth *knet_eth, const char *ether_addr)
{
	struct ether_addr oldmac;
	int err;

	if ((!knet_eth) || (!ether_addr)) {
		errno = EINVAL;
		return -1;
	}

	memcpy(&oldmac, knet_eth->ifr.ifr_hwaddr.sa_data, ETH_ALEN);
	memcpy(knet_eth->ifr.ifr_hwaddr.sa_data, ether_aton(ether_addr), ETH_ALEN);

	err = ioctl(knet_sockfd, SIOCSIFHWADDR, &knet_eth->ifr);
	if (err)
		memcpy(knet_eth->ifr.ifr_hwaddr.sa_data, &oldmac, ETH_ALEN);

	return err;
}

int knet_set_up(struct knet_eth *knet_eth)
{
	if (!knet_eth) {
		errno = EINVAL;
		return -1;
	}

	knet_eth->ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
	return ioctl(knet_sockfd, SIOCSIFFLAGS, &knet_eth->ifr);
}

int knet_set_down(struct knet_eth *knet_eth)
{
	if (!knet_eth) {
		errno = EINVAL;
		return -1;
	}

	knet_eth->ifr.ifr_flags &= ~IFF_UP;
	return ioctl(knet_sockfd, SIOCSIFFLAGS, &knet_eth->ifr);
}

STATIC int knet_read_pipe(int fd, char **file, size_t *length)
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
