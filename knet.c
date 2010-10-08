#include "config.h"

#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
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
