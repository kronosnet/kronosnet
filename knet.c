#include "config.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <arpa/inet.h>

#include "knet.h"
#include "logging.h"
#include "utils.h"

int knet_open(char *dev, size_t dev_size)
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

int knet_set_hwid(char *dev, uint32_t nodeid)
{
	struct ifreq ifr;
	int sockfd, ret;
	uint32_t machwid;

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0)
		return sockfd;

	memset(&ifr, 0, sizeof(struct ifreq));
	strncpy(ifr.ifr_name, dev, IFNAMSIZ);

	ret = ioctl(sockfd, SIOCGIFHWADDR, &ifr);
	if (ret != 0) goto exit_clean;

	ifr.ifr_hwaddr.sa_data[0] = 0x16;
	ifr.ifr_hwaddr.sa_data[1] = 0x07;

	machwid = htonl(nodeid);
	memmove(ifr.ifr_hwaddr.sa_data + 2, &machwid, ETH_ALEN - 2);

	ret = ioctl(sockfd, SIOCSIFHWADDR, &ifr);

exit_clean:
	close(sockfd);
	return ret;
}

int knet_get_mtu(char *dev)
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

int knet_close(int fd)
{
	return close(fd);
}

int knet_read(int fd, char *buf, int len)
{
	return do_read(fd, buf, len);
}

int knet_write(int fd, char *buf, int len)
{
	return do_write(fd, buf, len);
}

/*
 * TODO:
 * - knet_up + add_ip - add one function to run /sbin/ip
 * - use fork + dup2 + exec?? to redirect stderr
 * - correctly handle broadcast address (only for ipv4)
 */

/*
 * Bring tun interface up and set mtu. If mtu is 0, system default is used.
 */
int knet_up(const char *dev_name, int mtu)
{
	char cmd[512];
	int res;

	snprintf(cmd, sizeof(cmd), "%s link set %s up", IPROUTE_CMD, dev_name);

	if (mtu != 0) {
		snprintf(cmd + strlen(cmd), sizeof(cmd) - strlen(cmd), " mtu %d", mtu);
	}
	log_printf(LOGSYS_LEVEL_DEBUG, "Spawning %s\n", cmd);

	res = system(cmd);

	if (res == -1 || res == 127) {
		log_printf(LOGSYS_LEVEL_INFO, "Unable to spawn shell\n");
		return -1;
	}

	if (!WIFEXITED(res)) {
		log_printf(LOGSYS_LEVEL_INFO, "Shell not exited properly\n");
		return -1;
	}

	if (WIFEXITED(res) && WEXITSTATUS(res) != 0) {
		log_printf(LOGSYS_LEVEL_INFO, "Shell return code %d is not 0\n", WEXITSTATUS(res));
		return -1;
	}

	return 0;
}

/*
 * Add IP to tun interface.
 */
int knet_add_ip(const char *dev_name, const char *ip)
{
	char cmd[512];
	int res;

	snprintf(cmd, sizeof(cmd), "%s addr add %s dev %s", IPROUTE_CMD, ip, dev_name);

	log_printf(LOGSYS_LEVEL_DEBUG, "Spawning %s\n", cmd);

	res = system(cmd);

	if (res == -1 || res == 127) {
		log_printf(LOGSYS_LEVEL_INFO, "Unable to spawn shell\n");
		return -1;
	}

	if (!WIFEXITED(res)) {
		log_printf(LOGSYS_LEVEL_INFO, "Shell not exited properly\n");
		return -1;
	}

	if (WIFEXITED(res) && WEXITSTATUS(res) != 0) {
		log_printf(LOGSYS_LEVEL_INFO, "Shell return code %d is not 0\n", WEXITSTATUS(res));
		return -1;
	}

	return 0;
}

