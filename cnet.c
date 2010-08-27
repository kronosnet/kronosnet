#include "config.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>

#include "cnet.h"
#include "utils.h"

int cnet_open(char *dev, size_t dev_size)
{
	struct ifreq ifr;
	int fd, err;

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
	if (*dev)
		strncpy(ifr.ifr_name, dev, IFNAMSIZ);

	if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0) {
		close(fd);
		return err;
	}
	strcpy(dev, ifr.ifr_name);
	return fd;
}

int cnet_get_mtu(char *dev)
{
	struct ifreq ifr;
	int sockfd, err;

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0)
		return sockfd;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, dev, IFNAMSIZ);

	err = ioctl(sockfd, SIOCGIFMTU, (void *)&ifr);
	close(sockfd);
	if (err < 0)
		return err;

	return ifr.ifr_mtu;
}

int cnet_close(int fd)
{
	return close(fd);
}

int cnet_read(int fd, char *buf, int len)
{
	return do_read(fd, buf, len);
}

int cnet_write(int fd, char *buf, int len)
{
	return do_write(fd, buf, len);
}
