#include "config.h"

#include <string.h>
#include <errno.h>
#include <net/if.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <netinet/ether.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#include "libtap.h"
#include "libtap_private.h"
#include "utils.h"

extern struct tap_config tap_cfg;

extern int tap_execute_shell(const char *command);

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
	knet_tap_t knet_tap;

	knet_tap=knet_tap_open(name, size, NULL);
	if (!knet_tap) {
		if (tap_cfg.tap_sockfd < 0)
			log_error("Unable to open knet_socket");
		log_error("Unable to open knet.");
		return -1;
	}
	log_info("Created interface: %s", name);

	if (is_if_in_system(name) > 0) {
		log_info("Found interface %s on the system", name);
	} else {
		log_info("Unable to find interface %s on the system", name);
	}

	if (!knet_tap_find(name, size)) {
		log_info("Unable to find interface %s in tap db", name);
	} else {
		log_info("Found interface %s in tap db", name);
	}

	knet_tap_close(knet_tap);

	if (is_if_in_system(name) == 0)
		log_info("Successfully removed interface %s from the system", name);

	return 0;
}

static int check_knet_tap_open_close(void)
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
		log_error("Something is wrong in knet_tap_open sanity checks");
		return -1;
	}

	log_info("Testing size < IFNAMSIZ");
	errno=0;
	if ((test_iface(device_name, 1) >= 0) || (errno != EINVAL)) {
		log_error("Something is wrong in knet_tap_open sanity checks");
		return -1;
	}

	log_info("Testing device_name size > IFNAMSIZ");
	errno=0;
	strcpy(device_name, "abcdefghilmnopqrstuvwz");
	if ((test_iface(device_name, IFNAMSIZ) >= 0) || (errno != E2BIG)) {
		log_error("Something is wrong in knet_tap_open sanity checks");
		return -1;
	}

	return 0;
}

static int check_knet_multi_eth(void)
{
	char device_name1[IFNAMSIZ];
	char device_name2[IFNAMSIZ];
	size_t size = IFNAMSIZ;
	int err=0;
	knet_tap_t knet_tap1 = NULL;
	knet_tap_t knet_tap2 = NULL;

	log_info("Testing multiple knet interface instances");

	memset(device_name1, 0, size);
	memset(device_name2, 0, size);

	strncpy(device_name1, "kronostest1", size);
	strncpy(device_name2, "kronostest2", size);

	knet_tap1 = knet_tap_open(device_name1, size, NULL);
	if (!knet_tap1) {
		log_error("Unable to init %s.", device_name1);
		err = -1;
		goto out_clean;
	}

	if (is_if_in_system(device_name1) > 0) {
		log_info("Found interface %s on the system", device_name1);
	} else {
		log_info("Unable to find interface %s on the system", device_name1);
	}

	knet_tap2 = knet_tap_open(device_name2, size, NULL);
	if (!knet_tap2) {
		log_error("Unable to init %s.", device_name2);
		err = -1;
		goto out_clean;
	}

	if (is_if_in_system(device_name2) > 0) {
		log_info("Found interface %s on the system", device_name2);
	} else {
		log_info("Unable to find interface %s on the system", device_name2);
	}

	if (knet_tap1)
		knet_tap_close(knet_tap1);
	if (knet_tap2)
		knet_tap_close(knet_tap2);

	log_info("Testing error conditions");

	log_info("Open same device twice");

	knet_tap1 = knet_tap_open(device_name1, size, NULL);
	if (!knet_tap1) {
		log_error("Unable to init %s.", device_name1);
		err = -1;
		goto out_clean;
	}

	if (is_if_in_system(device_name1) > 0) {
		log_info("Found interface %s on the system", device_name1);
	} else {
		log_info("Unable to find interface %s on the system", device_name1);
	}

	knet_tap2 = knet_tap_open(device_name1, size, NULL);
	if (knet_tap2) {
		log_error("We were able to init 2 interfaces with the same name!");
		err = -1;
		goto out_clean;
	}

out_clean:
	if (knet_tap1)
		knet_tap_close(knet_tap1);
	if (knet_tap2)
		knet_tap_close(knet_tap2);
	return err;
}

static int check_knet_mtu(void)
{
	char device_name[IFNAMSIZ];
	size_t size = IFNAMSIZ;
	int err=0;
	knet_tap_t knet_tap;

	int current_mtu = 0;
	int expected_mtu = 1500;

	log_info("Testing get/set MTU");

	memset(device_name, 0, size);
	strncpy(device_name, "kronostest", size);
	knet_tap = knet_tap_open(device_name, size, NULL);
	if (!knet_tap) {
		log_error("Unable to init %s.", device_name);
		return -1;
	}

	log_info("Comparing default MTU");
	current_mtu = knet_tap_get_mtu(knet_tap);
	if (current_mtu < 0) {
		log_error("Unable to get MTU");
		err = -1;
		goto out_clean;
	}
	if (current_mtu != expected_mtu) {
		log_error("current mtu [%d] does not match expected default [%d]", current_mtu, expected_mtu);
		err = -1;
		goto out_clean;
	}

	log_info("Setting MTU to 9000");
	expected_mtu = 9000;
	if (knet_tap_set_mtu(knet_tap, expected_mtu) < 0) {
		log_error("Unable to set MTU to %d.", expected_mtu);
		err = -1;
		goto out_clean;
	}

	current_mtu = knet_tap_get_mtu(knet_tap);
	if (current_mtu < 0) {
		log_error("Unable to get MTU");
		err = -1;
		goto out_clean;
	}
	if (current_mtu != expected_mtu) {
		log_error("current mtu [%d] does not match expected value [%d]", current_mtu, expected_mtu);
		err = -1;
		goto out_clean;
	}

	log_info("Testing ERROR conditions");

	log_info("Passing empty struct to get_mtu");
	if (knet_tap_get_mtu(NULL) > 0) {
		log_error("Something is wrong in knet_tap_get_mtu sanity checks");
		err = -1;
		goto out_clean;
	}

	log_info("Passing empty struct to set_mtu");
	if (knet_tap_set_mtu(NULL, 1500) == 0) {
		log_error("Something is wrong in knet_tap_set_mtu sanity checks"); 
		err = -1;
		goto out_clean;
	}

out_clean:
	knet_tap_close(knet_tap);

	return err;
}

static int check_knet_mac(void)
{
	char device_name[IFNAMSIZ];
	size_t size = IFNAMSIZ;
	int err=0;
	knet_tap_t knet_tap;
	char *current_mac = NULL, *temp_mac = NULL, *err_mac = NULL;
	struct ether_addr *cur_mac, *tmp_mac;

	log_info("Testing get/set MAC");

	memset(device_name, 0, size);
	strncpy(device_name, "kronostest", size);
	knet_tap = knet_tap_open(device_name, size, NULL);
	if (!knet_tap) {
		log_error("Unable to init %s.", device_name);
		return -1;
	}

	log_info("Get current MAC");

	if (knet_tap_get_mac(knet_tap, &current_mac) < 0) {
		log_error("Unable to get current MAC address.");
		err = -1;
		goto out_clean;
	}

	log_info("Current MAC: %s", current_mac);

	log_info("Setting MAC: 00:01:01:01:01:01");

	if (knet_tap_set_mac(knet_tap, "00:01:01:01:01:01") < 0) {
		log_error("Unable to set current MAC address.");
		err = -1;
		goto out_clean;
	}

	if (knet_tap_get_mac(knet_tap, &temp_mac) < 0) {
		log_error("Unable to get current MAC address.");
		err = -1;
		goto out_clean;
	}

	log_info("Current MAC: %s", temp_mac);

	cur_mac = ether_aton(current_mac);
	tmp_mac = ether_aton(temp_mac);

	log_info("Comparing MAC addresses");
	if (memcmp(cur_mac, tmp_mac, sizeof(struct ether_addr))) {
		log_error("Mac addresses are not the same?!");
		err = -1;
		goto out_clean;
	}

	log_info("Testing ERROR conditions");

	log_info("Pass NULL to get_mac (pass1)");
	errno = 0;
	if ((knet_tap_get_mac(NULL, &err_mac) >= 0) || (errno != EINVAL)) {
		log_error("Something is wrong in knet_tap_get_mac sanity checks");
		err = -1;
		goto out_clean;
	}

	log_info("Pass NULL to get_mac (pass2)");
	errno = 0;
	if ((knet_tap_get_mac(knet_tap, NULL) >= 0) || (errno != EINVAL)) {
		log_error("Something is wrong in knet_tap_get_mac sanity checks");
		err = -1;
		goto out_clean;
	}

	log_info("Pass NULL to set_mac (pass1)");
	errno = 0;
	if ((knet_tap_set_mac(knet_tap, NULL) >= 0) || (errno != EINVAL)) {
		log_error("Something is wrong in knet_tap_set_mac sanity checks");
		err = -1;
		goto out_clean;
	}

	log_info("Pass NULL to set_mac (pass2)");
	errno = 0;
	if ((knet_tap_set_mac(NULL, err_mac) >= 0) || (errno != EINVAL)) {
		log_error("Something is wrong in knet_tap_set_mac sanity checks");
		err = -1;
		goto out_clean;
	}

out_clean:
	if (err_mac) {
		log_error("Something managed to set err_mac!");
		err = -1;
		free(err_mac);
	}

	if (current_mac)
		free(current_mac);
	if (temp_mac)
		free(temp_mac);

	knet_tap_close(knet_tap);

	return err;
}

static int check_tap_execute_shell(void)
{
	int err = 0;
	char command[4096];

	memset(command, 0, sizeof(command));

	log_info("Testing tap_execute_shell");

	log_info("command /bin/true");

	if (tap_execute_shell("/bin/true") < 0) {
		log_error("Unable to execute /bin/true ?!?!");
		err = -1;
		goto out_clean;
	}

	log_info("Testing ERROR conditions");

	log_info("command /bin/false");

	if (!tap_execute_shell("/bin/false")) {
		log_error("Can we really execute /bin/false successfully?!?!");
		err = -1;
		goto out_clean;
	}

	log_info("command that outputs to stdout (enforcing redirect)");
	if (!tap_execute_shell("/bin/grep -h 2>&1")) {
		log_error("Can we really execute /bin/grep -h successfully?!?");
		err = -1;
		goto out_clean;
	} 

	log_info("command that outputs to stderr");
	if (!tap_execute_shell("/bin/grep -h")) {
		log_error("Can we really execute /bin/grep -h successfully?!?");
		err = -1;
		goto out_clean;
	} 

	log_info("empty command");
	if (!tap_execute_shell(NULL)) {
		log_error("Can we really execute (nil) successfully?!?!");
		err = -1;
		goto out_clean;
	}

out_clean:

	return err;
}

static int check_knet_up_down(void)
{
	char device_name[IFNAMSIZ];
	size_t size = IFNAMSIZ;
	int err=0;
	knet_tap_t knet_tap;

	log_info("Testing interface up/down");

	memset(device_name, 0, size);
	strncpy(device_name, "kronostest", size);
	knet_tap = knet_tap_open(device_name, size, NULL);
	if (!knet_tap) {
		log_error("Unable to init %s.", device_name);
		return -1;
	}

	log_info("Put the interface up");

	if (knet_tap_set_up(knet_tap) < 0) {
		log_error("Unable to set interface up");
		err = -1;
		goto out_clean;
	}

	if (tap_execute_shell("ip addr show dev kronostest | grep -q UP") < 0) {
		log_error("Unable to verify inteface UP");
		err = -1;
		goto out_clean;
	}

	log_info("Put the interface down");

	if (knet_tap_set_down(knet_tap) < 0) {
		log_error("Unable to put the interface down");
		err = -1;
		goto out_clean;
	}

	log_info("A shell error here is NORMAL");

	if (!tap_execute_shell("ifconfig kronostest | grep -q UP")) {
		log_error("Unable to verify inteface DOWN");
		err = -1;
		goto out_clean;
	}

	log_info("Test ERROR conditions");

	log_info("Pass NULL to set_up");
	errno = 0;
	if ((knet_tap_set_up(NULL) >= 0) || (errno != EINVAL)) {
		log_error("Something is wrong in knet_tap_set_up sanity checks");
		err = -1;
		goto out_clean;
	}

	log_info("Pass NULL to set_down");
	errno = 0;
	if ((knet_tap_set_down(NULL) >= 0) || (errno != EINVAL)) {
		log_error("Something is wrong in knet_tap_set_down sanity checks");
		err = -1;
		goto out_clean;
	}

out_clean:

	knet_tap_close(knet_tap);

	return err;
}

static int check_knet_close_leak(void)
{
	char device_name[IFNAMSIZ];
	size_t size = IFNAMSIZ;
	int err=0;
	knet_tap_t knet_tap;

	log_info("Testing close leak (needs valgrind)");

	memset(device_name, 0, size);
	strncpy(device_name, "kronostest", size);
	knet_tap = knet_tap_open(device_name, size, NULL);
	if (!knet_tap) {
		log_error("Unable to init %s.", device_name);
		return -1;
	}

	log_info("Adding ip: 192.168.168.168/24");

	if (knet_tap_add_ip(knet_tap, "192.168.168.168", "24") < 0) {
		log_error("Unable to assign IP address");
		err=-1;
		goto out_clean;
	}

	log_info("Adding ip: 192.168.169.169/24");

	if (knet_tap_add_ip(knet_tap, "192.168.169.169", "24") < 0) {
		log_error("Unable to assign IP address");
		err=-1;
		goto out_clean;
	}

out_clean:

	knet_tap_close(knet_tap);

	return err;
}

static int check_knet_set_del_ip(void)
{
	char device_name[IFNAMSIZ];
	size_t size = IFNAMSIZ;
	int err=0;
	knet_tap_t knet_tap;
	char *ip_list = NULL;
	int ip_list_entries = 0, i, offset = 0;

	log_info("Testing interface add/remove ip");

	memset(device_name, 0, size);
	strncpy(device_name, "kronostest", size);
	knet_tap = knet_tap_open(device_name, size, NULL);
	if (!knet_tap) {
		log_error("Unable to init %s.", device_name);
		return -1;
	}

	log_info("Adding ip: 192.168.168.168/24");

	if (knet_tap_add_ip(knet_tap, "192.168.168.168", "24") < 0) {
		log_error("Unable to assign IP address");
		err=-1;
		goto out_clean;
	}

	log_info("Adding ip: 192.168.169.169/24");

	if (knet_tap_add_ip(knet_tap, "192.168.169.169", "24") < 0) {
		log_error("Unable to assign IP address");
		err=-1;
		goto out_clean;
	}

	log_info("Adding duplicate ip: 192.168.168.168/24");

	if (knet_tap_add_ip(knet_tap, "192.168.168.168", "24") < 0) {
		log_error("Unable to find IP address in libtap db");
		err=-1;
		goto out_clean;
	}

	log_info("Checking ip: 192.168.168.168/24");

	if (tap_execute_shell("ip addr show dev kronostest | grep -q 192.168.168.168/24")) {
		log_error("Unable to verify IP address");
		err=-1;
		goto out_clean;
	}

	log_info("Get ip list from libtap:");

	if (knet_tap_get_ips(knet_tap, &ip_list, &ip_list_entries) < 0) {
		log_error("Not enough mem?");
		err=-1;
		goto out_clean;
	}

	if (ip_list_entries != 2) {
		log_error("Didn't get enough ip back from libtap?");
		err=-1;
		goto out_clean;
	}

	for (i = 1; i <= ip_list_entries; i++) {
		log_info("Found IP %s %s in libtap db", ip_list + offset, ip_list + offset + strlen(ip_list + offset) + 1);
		offset = offset + strlen(ip_list) + 1;
		offset = offset + strlen(ip_list + offset) + 1;
	}

	free(ip_list);

	log_info("Deleting ip: 192.168.168.168/24");

	if (knet_tap_del_ip(knet_tap, "192.168.168.168", "24") < 0) {
		log_error("Unable to delete IP address");
		err=-1;
		goto out_clean;
	}

	log_info("Deleting ip: 192.168.169.169/24");

	if (knet_tap_del_ip(knet_tap, "192.168.169.169", "24") < 0) {
		log_error("Unable to delete IP address");
		err=-1;
		goto out_clean;
	}

	log_info("Deleting again ip: 192.168.168.168/24");

	if (knet_tap_del_ip(knet_tap, "192.168.168.168", "24") < 0) {
		log_error("Unable to delete IP address");
		err=-1;
		goto out_clean;
	}

	log_info("A shell error here is NORMAL");
	if (!tap_execute_shell("ip addr show dev kronostest | grep -q 192.168.168.168/24")) {
		log_error("Unable to verify IP address");
		err=-1;
		goto out_clean;
	}

	log_info("Adding ip: 3ffe::1/64");

	if (knet_tap_add_ip(knet_tap, "3ffe::1", "64") < 0) {
		log_error("Unable to assign IP address");
		err=-1;
		goto out_clean;
	}

	if (tap_execute_shell("ip addr show dev kronostest | grep -q 3ffe::1/64")) {
		log_error("Unable to verify IP address");
		err=-1;
		goto out_clean;
	}

	log_info("Deleting ip: 3ffe::1/64");

	if (knet_tap_del_ip(knet_tap, "3ffe::1", "64") < 0) {
		log_error("Unable to delete IP address");
		err=-1;
		goto out_clean;
	}

	log_info("A shell error here is NORMAL");
	if (!tap_execute_shell("ip addr show dev kronostest | grep -q 3ffe::1/64")) {
		log_error("Unable to verify IP address");
		err=-1;
		goto out_clean;
	}

out_clean:

	knet_tap_close(knet_tap);

	return err;
}

int main(void)
{
	if (check_knet_tap_open_close() < 0)
		return -1;

	if (check_knet_multi_eth() < 0)
		return -1;

	if (check_knet_mtu() < 0)
		return -1;

	if (check_knet_mac() < 0)
		return -1;

	if (check_tap_execute_shell() < 0)
		return -1;

	if (check_knet_up_down() < 0)
		return -1;

	if (check_knet_set_del_ip() < 0)
		return -1;

	if (check_knet_close_leak() < 0)
		return -1;

	return 0;
}
