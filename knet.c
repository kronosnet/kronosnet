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
#include <net/if.h>
#include <linux/if_tun.h>
#include <net/ethernet.h>

#include "utils.h"
#include "knet.h"

STATIC int knet_sockfd = 0;
STATIC struct ifreq ifr;

/* forward declarations */
STATIC int knet_execute_shell(const char *command);
STATIC int knet_read_pipe(int fd, char **file, size_t *length);

int knet_open(char *dev, size_t dev_size)
{
	int fd, err;

	if (dev == NULL) {
		errno = EINVAL;
		return -1;
	}

	if (dev_size < IFNAMSIZ) {
		errno = EINVAL;
		return -1;
	}

	if (strlen(dev) > IFNAMSIZ) {
		errno = E2BIG;
		return -1;
	}

	if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
		errno = ENOENT;
		return -1;
	}

	memset(&ifr, 0, sizeof(ifr));

	ifr.ifr_flags = IFF_TAP | IFF_NO_PI;

	strncpy(ifr.ifr_name, dev, IFNAMSIZ);

	if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0) {
		close(fd);
		return err;
	}

	strcpy(dev, ifr.ifr_name);

	knet_sockfd =  socket(AF_INET, SOCK_STREAM, 0);
	if (knet_sockfd < 0)
		return knet_sockfd;

	return fd;
}

int knet_close(int fd)
{
	close(knet_sockfd);
	knet_sockfd = 0;
	return close(fd);
}

int knet_get_mtu(void)
{
	int err;

	err = ioctl(knet_sockfd, SIOCGIFMTU, (void *)&ifr);
	if (err)
		return err;

	return ifr.ifr_mtu;
}

int knet_set_mtu(const int mtu)
{
	ifr.ifr_mtu = mtu;

	return ioctl(knet_sockfd, SIOCSIFMTU, (void *)&ifr);
}

int knet_get_mac(struct ether_addr *mac)
{
	int err;

	if (!mac) {
		errno = EINVAL;
		return -1;
	}

	err = ioctl(knet_sockfd, SIOCGIFHWADDR, &ifr);

	memcpy(mac->ether_addr_octet, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

	return err;
}

int knet_set_mac(const struct ether_addr *mac)
{
	if (!mac) {
		errno = EINVAL;
		return -1;
	}

	memcpy(ifr.ifr_hwaddr.sa_data, mac->ether_addr_octet, ETH_ALEN);

	return ioctl(knet_sockfd, SIOCSIFHWADDR, &ifr);
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
			log_error("Unable to redirect stdout: %s", strerror(errno));
		if(dup2(fd[1], 2) < 0)
			log_error("Unable to redirect stderr: %s", strerror(errno));
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
