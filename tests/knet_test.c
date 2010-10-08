#include "config.h"

#include <string.h>
#include <errno.h>
#include <net/if.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <netinet/ether.h>
#include <stdint.h>
#include <unistd.h>

#include "knet.h"
#include "utils.h"

extern int knet_sockfd;
extern struct ifreq ifr;
int knet_execute_shell(const char *);

static int is_if_in_system(char *name)
{
	struct ifaddrs *ifap = NULL;
	struct ifaddrs *ifa;
	int found = 0;

	if (getifaddrs(&ifap) < 0) {
		log_error("Unable to get interface list.");
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
		log_error("Unable to open knet.");
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

	log_info("Creating kronostest tap interface:");
	strncpy(device_name, "kronostest", IFNAMSIZ);
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
		log_error("Unable to init %s.", device_name);
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
		log_error("Unable to set MTU to %d.", expected_mtu);
		err = -1;
		goto out_clean;
	}

	current_mtu = knet_get_mtu();
	if (current_mtu != expected_mtu) {
		log_error("current mtu [%d] does not match expected value [%d]", current_mtu, expected_mtu);
		err = -1;
		goto out_clean;
	}

out_clean:
	knet_close(knet_fd);

	return err;
}

static int check_knet_mac(void)
{
	char device_name[IFNAMSIZ];
	size_t size = IFNAMSIZ;
	int knet_fd, err=0;
	struct ether_addr mac;
	struct ether_addr tempmac;

	log_info("Testing get/set MAC");

	memset(device_name, 0, size);
	strncpy(device_name, "kronostest", size);
	knet_fd = knet_open(device_name, size);
	if (knet_fd < 0) {
		log_error("Unable to init %s.", device_name);
		return -1;
	}

	log_info("Get current MAC");

	if (knet_get_mac(&mac) < 0) {
		log_error("Unable to get current MAC address.");
		err = -1;
		goto out_clean;
	}

	log_info("Current MAC: %s", ether_ntoa(&mac));

	mac.ether_addr_octet[3] = 0;

	log_info("Setting MAC: %s", ether_ntoa(&mac));

	if (knet_set_mac(&mac) < 0) {
		log_error("Unable to set current MAC address.");
		err = -1;
		goto out_clean;
	}

	if (knet_get_mac(&tempmac) < 0) {
		log_error("Unable to get current MAC address.");
		err = -1;
		goto out_clean;
	}

	log_info("Current MAC: %s", ether_ntoa(&tempmac));

	if (memcmp(mac.ether_addr_octet, tempmac.ether_addr_octet, ETH_ALEN)) {
		log_error("MAC adddress are not matching");
		err = -1;
		goto out_clean;
	}

	log_info("Testing ERROR conditions");

	log_info("Pass NULL to get_mac");
	errno = 0;
	if ((knet_get_mac(NULL) >= 0) || (errno != EINVAL)) {
		log_error("Something is wrong in knet_get_mac sanity checks");
		err = -1;
		goto out_clean;
	}

	log_info("Pass NULL to set_mac");
	errno = 0;
	if ((knet_set_mac(NULL) >= 0) || (errno != EINVAL)) {
		log_error("Something is wrong in knet_set_mac sanity checks");
		err = -1;
		goto out_clean;
	}

out_clean:

	knet_close(knet_fd);

	return err;
}

static int check_knet_execute_shell(void)
{
	int err = 0;
	char command[4096];

	memset(command, 0, sizeof(command));

	log_info("Testing knet_execute_shell");

	log_info("command /bin/true");

	if (knet_execute_shell("/bin/true") < 0) {
		log_error("Unable to execute /bin/true ?!?!");
		err = -1;
		goto out_clean;
	}

	log_info("Testing ERROR conditions");

	log_info("command /bin/false");

	if (!knet_execute_shell("/bin/false")) {
		log_error("Can we really execute /bin/false successfully?!?!");
		err = -1;
		goto out_clean;
	}

	log_info("command that outputs to stdout (enforcing redirect)");
	if (!knet_execute_shell("/bin/grep -h 2>&1")) {
		log_error("Can we really execute /bin/grep -h successfully?!?");
		err = -1;
		goto out_clean;
	} 

	log_info("command that outputs to stderr");
	if (!knet_execute_shell("/bin/grep -h")) {
		log_error("Can we really execute /bin/grep -h successfully?!?");
		err = -1;
		goto out_clean;
	} 

	log_info("empty command");
	if (!knet_execute_shell(NULL)) {
		log_error("Can we really execute (nil) successfully?!?!");
		err = -1;
		goto out_clean;
	}

out_clean:

	return err;
}

int main(void)
{
	if (check_knet_open_close() < 0)
		return -1;

	if (check_knet_mtu() < 0)
		return -1;

	if (check_knet_mac() < 0)
		return -1;

	if (check_knet_execute_shell() < 0)
		return -1;

	return 0;
}
