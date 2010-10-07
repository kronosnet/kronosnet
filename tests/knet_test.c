#include "config.h"

#include <string.h>
#include <errno.h>
#include <net/if.h>
#include <sys/types.h>
#include <ifaddrs.h>

#include "knet.h"
#include "utils.h"

extern int knet_sockfd;
extern struct ifreq ifr;

static int is_if_in_system(char *name)
{
	struct ifaddrs *ifap = NULL;
	struct ifaddrs *ifa;
	int found = 0;

	if (getifaddrs(&ifap) < 0) {
		log_error("Unable to get interface list: %s", strerror(errno));
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

static int test_iface(char *name, size_t size)
{
	int knet_fd;
	char *oldname = NULL;

	if ((name) && (strlen(name))) {
		oldname = strdup(name);
		if (!oldname) {
			log_error("Not enough memory to run the test");
			exit(1);
		}
	}

	knet_fd=knet_open(name, size);
	if (knet_fd < 0) {
		if (knet_sockfd < 0)
			log_error("Unable to open knet_socket");
		log_error("Unable to open knet: %s", strerror(errno));
		if (oldname)
			free(oldname);
		return -1;
	}
	log_info("Created interface: %s", name);

	if (oldname) {
		if (strcmp(oldname, name) != 0)
			log_error("New name does NOT match request name... NOT FATAL");
	}

	if (is_if_in_system(name) > 0) {
		log_info("Found interface %s on the system", name);
	} else {
		log_info("Unable to find interface %s on the system", name);
	}

	knet_close(knet_fd);

	if (is_if_in_system(name) == 0)
		log_info("Successfully removed interface %s from the system", name);

	if (oldname)
		free(oldname);

	return 0;
}

static int check_knet_open_close(void)
{
	char device_name[2*IFNAMSIZ];
	size_t size = IFNAMSIZ;

	memset(device_name, 0, sizeof(device_name));

	log_info("Creating random tap interface:");
	if (test_iface(device_name, size) < 0) {
		log_error("Unable to create random interface");
		return -1;
	}

	log_info("Creating kronosnet tap interface:");
	strncpy(device_name, "kronosnet", IFNAMSIZ);
	if (test_iface(device_name, size) < 0) {
		log_error("Unable to create kronosnet interface");
		return -1;
	}

	log_info("Testing ERROR conditions");

	log_info("Testing dev == NULL");
	errno=0;
	if ((test_iface(NULL, size) >= 0) || (errno != EINVAL)) {
		log_error("Something is wrong in knet_open sanity checks");
		return -1;
	}

	log_info("Testing size < IFNAMSIZ");
	errno=0;
	if ((test_iface(device_name, 1) >= 0) || (errno != EINVAL)) {
		log_error("Something is wrong in knet_open sanity checks");
		return -1;
	}

	log_info("Testing device_name size > IFNAMSIZ");
	errno=0;
	strcpy(device_name, "abcdefghilmnopqrstuvwz");
	if ((test_iface(device_name, IFNAMSIZ) >= 0) || (errno != E2BIG)) {
		log_error("Something is wrong in knet_open sanity checks");
		return -1;
	}

	return 0;
}

int main(void)
{
	if (check_knet_open_close() < 0)
		return -1;

	return 0;
}
