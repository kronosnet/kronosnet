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

static int check_knet_mtu(void)
{
	char device_name[IFNAMSIZ];
	size_t size = IFNAMSIZ;
	int knet_fd, err=0;

	int current_mtu = 0;
	int expected_mtu = 1500;

	log_info("Testing get/set MTU");

	memset(device_name, 0, size);
	strncpy(device_name, "kronostest", size);
	knet_fd = knet_open(device_name, size);
	if (knet_fd < 0) {
		log_error("Unable to init %s: %s", device_name, strerror(errno));
		return -1;
	}

	log_info("Comparing default MTU");
	current_mtu = knet_get_mtu();
	if (current_mtu != expected_mtu) {
		log_error("current mtu [%d] does not match expected default [%d]", current_mtu, expected_mtu);
		err = -1;
		goto out_clean;
	}

	log_info("Setting MTU to 9000");
	expected_mtu = 9000;
	if (knet_set_mtu(expected_mtu) < 0) {
		log_error("Unable to set MTU to %d: %s", expected_mtu, strerror(errno));
		err = -1;
		goto out_clean;
	}

	current_mtu = knet_get_mtu();
	if (current_mtu != expected_mtu) {
		log_error("current mtu [%d] does not match expected value [%d]", current_mtu, expected_mtu);
		err = -1;
		goto out_clean;
	}

	log_info("Testing ERROR conditions");

	log_info("Setting MTU to -1");
	expected_mtu = -1;
	errno = 0;
	if ((knet_set_mtu(expected_mtu) >= 0) || (errno != EINVAL)) {
		log_error("Something is wrong in knet_set_mtu sanity checks");
		err = -1;
		goto out_clean;
	}

	log_info("Setting MTU to 0");
	expected_mtu = 0;
	errno = 0;
	if ((knet_set_mtu(expected_mtu) >= 0) || (errno != EINVAL)) {
		log_error("Something is wrong in knet_set_mtu sanity checks");
		err = -1;
		goto out_clean;
	}

	log_info("Setting MTU to 65522 (max is 65521)");
	expected_mtu = 65522;
	errno = 0;
	if ((knet_set_mtu(expected_mtu) >= 0) || (errno != E2BIG)) {
		log_error("Something is wrong in knet_set_mtu sanity checks");
		err = -1;
		goto out_clean;
	}

out_clean:
	knet_close(knet_fd);

	return err;
}

int main(void)
{
	if (check_knet_open_close() < 0)
		return -1;

	if (check_knet_mtu() < 0)
		return -1;

	return 0;
}
