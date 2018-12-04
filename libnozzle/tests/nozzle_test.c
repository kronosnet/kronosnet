/*
 * Copyright (C) 2010-2017 Red Hat, Inc.  All rights reserved.
 *
 * Author: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *
 * This software licensed under GPL-2.0+, LGPL-2.0+
 */

#include "config.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <errno.h>
#include <ifaddrs.h>
#include <stdint.h>
#include <limits.h>
#include <sys/socket.h>
#include <net/ethernet.h>

#ifdef KNET_LINUX
#include <linux/if_tun.h>
#include <netinet/ether.h>
#endif
#ifdef KNET_BSD
#include <net/if_dl.h>
#endif

#include "libnozzle.h"
#include "internals.h"

char testipv4_1[1024];
char testipv4_2[1024];
char testipv6_1[1024];
char testipv6_2[1024];
/*
 * use this one to randomize knet interface name
 * for named creation test
 */
uint8_t randombyte = 0;

static int is_if_in_system(char *name)
{
	struct ifaddrs *ifap = NULL;
	struct ifaddrs *ifa;
	int found = 0;

	if (getifaddrs(&ifap) < 0) {
		printf("Unable to get interface list.\n");
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

static int test_iface(char *name, size_t size, const char *updownpath)
{
	nozzle_t nozzle;

	nozzle=nozzle_open(name, size, updownpath);
	if (!nozzle) {
		printf("Unable to open knet.\n");
		return -1;
	}
	printf("Created interface: %s\n", name);

	if (is_if_in_system(name) > 0) {
		printf("Found interface %s on the system\n", name);
	} else {
		printf("Unable to find interface %s on the system\n", name);
	}

	if (!nozzle_get_handle_by_name(name)) {
		printf("Unable to find interface %s in nozzle db\n", name);
	} else {
		printf("Found interface %s in nozzle db\n", name);
	}

	nozzle_close(nozzle);

	if (is_if_in_system(name) == 0)
		printf("Successfully removed interface %s from the system\n", name);

	return 0;
}

static int check_nozzle_open_close(void)
{
	char device_name[2*IFNAMSIZ];
	char fakepath[PATH_MAX];
	size_t size = IFNAMSIZ;

	memset(device_name, 0, sizeof(device_name));

	printf("Creating random nozzle interface:\n");
	if (test_iface(device_name, size,  NULL) < 0) {
		printf("Unable to create random interface\n");
		return -1;
	}

#ifdef KNET_LINUX
	printf("Creating kronostest%u nozzle interface:\n", randombyte);
	snprintf(device_name, IFNAMSIZ, "kronostest%u", randombyte);
	if (test_iface(device_name, size, NULL) < 0) {
		printf("Unable to create kronostest%u interface\n", randombyte);
		return -1;
	}
#endif
#ifdef KNET_BSD
	printf("Creating tap%u nozzle interface:\n", randombyte);
	snprintf(device_name, IFNAMSIZ, "tap%u", randombyte);
	if (test_iface(device_name, size, NULL) < 0) {
		printf("Unable to create tap%u interface\n", randombyte);
		return -1;
	}

	printf("Creating kronostest%u nozzle interface:\n", randombyte);
	snprintf(device_name, IFNAMSIZ, "kronostest%u", randombyte);
	if (test_iface(device_name, size, NULL) == 0) {
		printf("BSD should not accept kronostest%u interface\n", randombyte);
		return -1;
	}
#endif

	printf("Testing ERROR conditions\n");

	printf("Testing dev == NULL\n");
	errno=0;
	if ((test_iface(NULL, size, NULL) >= 0) || (errno != EINVAL)) {
		printf("Something is wrong in nozzle_open sanity checks\n");
		return -1;
	}

	printf("Testing size < IFNAMSIZ\n");
	errno=0;
	if ((test_iface(device_name, 1, NULL) >= 0) || (errno != EINVAL)) {
		printf("Something is wrong in nozzle_open sanity checks\n");
		return -1;
	}

	printf("Testing device_name size > IFNAMSIZ\n");
	errno=0;
	strcpy(device_name, "abcdefghilmnopqrstuvwz");
	if ((test_iface(device_name, IFNAMSIZ, NULL) >= 0) || (errno != E2BIG)) {
		printf("Something is wrong in nozzle_open sanity checks\n");
		return -1;
	}

	printf("Testing updown path != abs\n");
	errno=0;

	memset(device_name, 0, IFNAMSIZ);
	if ((test_iface(device_name, IFNAMSIZ, "foo")  >= 0) || (errno != EINVAL)) {
		printf("Something is wrong in nozzle_open sanity checks\n");
		return -1;
	}

	memset(fakepath, 0, PATH_MAX);
	memset(fakepath, '/', PATH_MAX - 2);

	printf("Testing updown path > PATH_MAX\n");
	errno=0;

	memset(device_name, 0, IFNAMSIZ);
	if ((test_iface(device_name, IFNAMSIZ, fakepath)  >= 0) || (errno != E2BIG)) {
		printf("Something is wrong in nozzle_open sanity checks\n");
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
	nozzle_t nozzle1 = NULL;
	nozzle_t nozzle2 = NULL;

	printf("Testing multiple knet interface instances\n");

	memset(device_name1, 0, size);
	memset(device_name2, 0, size);

	nozzle1 = nozzle_open(device_name1, size, NULL);
	if (!nozzle1) {
		printf("Unable to init %s\n", device_name1);
		err = -1;
		goto out_clean;
	}

	if (is_if_in_system(device_name1) > 0) {
		printf("Found interface %s on the system\n", device_name1);
	} else {
		printf("Unable to find interface %s on the system\n", device_name1);
	}

	nozzle2 = nozzle_open(device_name2, size, NULL);
	if (!nozzle2) {
		printf("Unable to init %s\n", device_name2);
		err = -1;
		goto out_clean;
	}

	if (is_if_in_system(device_name2) > 0) {
		printf("Found interface %s on the system\n", device_name2);
	} else {
		printf("Unable to find interface %s on the system\n", device_name2);
	}

	if (nozzle1) {
		nozzle_close(nozzle1);
	}

	if (nozzle2) {
		nozzle_close(nozzle2);
	}

	printf("Testing error conditions\n");

	printf("Open same device twice\n");

	memset(device_name1, 0, size);

	nozzle1 = nozzle_open(device_name1, size, NULL);
	if (!nozzle1) {
		printf("Unable to init %s\n", device_name1);
		err = -1;
		goto out_clean;
	}

	if (is_if_in_system(device_name1) > 0) {
		printf("Found interface %s on the system\n", device_name1);
	} else {
		printf("Unable to find interface %s on the system\n", device_name1);
	}

	nozzle2 = nozzle_open(device_name1, size, NULL);
	if (nozzle2) {
		printf("We were able to init 2 interfaces with the same name!\n");
		err = -1;
		goto out_clean;
	}

out_clean:
	if (nozzle1) {
		nozzle_close(nozzle1);
	}

	if (nozzle2) {
		nozzle_close(nozzle2);
	}

	return err;
}

static int check_knet_mtu(void)
{
	char device_name[IFNAMSIZ];
	size_t size = IFNAMSIZ;
	int err=0;
	nozzle_t nozzle;

	int current_mtu = 0;
	int expected_mtu = 1500;

	printf("Testing get/set MTU\n");

	memset(device_name, 0, size);
	nozzle = nozzle_open(device_name, size, NULL);
	if (!nozzle) {
		printf("Unable to init %s\n", device_name);
		return -1;
	}

	printf("Comparing default MTU\n");
	current_mtu = nozzle_get_mtu(nozzle);
	if (current_mtu < 0) {
		printf("Unable to get MTU\n");
		err = -1;
		goto out_clean;
	}
	if (current_mtu != expected_mtu) {
		printf("current mtu [%d] does not match expected default [%d]\n", current_mtu, expected_mtu);
		err = -1;
		goto out_clean;
	}

	printf("Setting MTU to 9000\n");
	expected_mtu = 9000;
	if (nozzle_set_mtu(nozzle, expected_mtu) < 0) {
		printf("Unable to set MTU to %d\n", expected_mtu);
		err = -1;
		goto out_clean;
	}

	current_mtu = nozzle_get_mtu(nozzle);
	if (current_mtu < 0) {
		printf("Unable to get MTU\n");
		err = -1;
		goto out_clean;
	}
	if (current_mtu != expected_mtu) {
		printf("current mtu [%d] does not match expected value [%d]\n", current_mtu, expected_mtu);
		err = -1;
		goto out_clean;
	}

	printf("Testing ERROR conditions\n");

	printf("Passing empty struct to get_mtu\n");
	if (nozzle_get_mtu(NULL) > 0) {
		printf("Something is wrong in nozzle_get_mtu sanity checks\n");
		err = -1;
		goto out_clean;
	}

	printf("Passing empty struct to set_mtu\n");
	if (nozzle_set_mtu(NULL, 1500) == 0) {
		printf("Something is wrong in nozzle_set_mtu sanity checks\n");
		err = -1;
		goto out_clean;
	}

out_clean:
	if (nozzle) {
		nozzle_close(nozzle);
	}

	return err;
}

static int check_knet_mtu_ipv6(void)
{
	char device_name[IFNAMSIZ];
	size_t size = IFNAMSIZ;
	char verifycmd[1024];
	int err=0;
	nozzle_t nozzle;
	char *error_string = NULL;

	printf("Testing get/set MTU with IPv6 address\n");

	memset(device_name, 0, size);

	nozzle = nozzle_open(device_name, size, NULL);
	if (!nozzle) {
		printf("Unable to init %s\n", device_name);
		return -1;
	}

	printf("Adding ip: %s/64\n", testipv6_1);

	err = nozzle_add_ip(nozzle, testipv6_1, "64");
	if (err) {
		printf("Unable to assign IP address\n");
		err=-1;
		goto out_clean;
	}

	memset(verifycmd, 0, sizeof(verifycmd));
	snprintf(verifycmd, sizeof(verifycmd)-1,
#ifdef KNET_LINUX
		 "ip addr show dev %s | grep -q %s/64", nozzle->name, testipv6_1);
#endif
#ifdef KNET_BSD
		 "ifconfig %s | grep -q %s", nozzle->name, testipv6_1);
#endif
	err = execute_bin_sh_command(verifycmd, &error_string);
	if (error_string) {
		printf("Error string: %s\n", error_string);
		free(error_string);
		error_string = NULL;
	}
	if (err) {
		printf("Unable to verify IP address\n");
		err=-1;
		goto out_clean;
	}

	printf("Setting MTU to 1200\n");
	if (nozzle_set_mtu(nozzle, 1200) < 0) {
		printf("Unable to set MTU to 1200\n");
		err = -1;
		goto out_clean;
	}

	err = execute_bin_sh_command(verifycmd, &error_string);
	if (error_string) {
		printf("Error string: %s\n", error_string);
		free(error_string);
		error_string = NULL;
	}
#ifdef KNET_LINUX
	if (!err) {
#endif
#ifdef KNET_BSD
	if (err) {
#endif
		printf("Unable to verify IP address\n");
		err=-1;
		goto out_clean;
	}

	printf("Adding ip: %s/64\n", testipv6_2);
	err = nozzle_add_ip(nozzle, testipv6_2, "64");
	if (err < 0) {
		printf("Unable to assign IP address\n");
		err=-1;
		goto out_clean;
	}

	memset(verifycmd, 0, sizeof(verifycmd));
	snprintf(verifycmd, sizeof(verifycmd)-1,
#ifdef KNET_LINUX
		 "ip addr show dev %s | grep -q %s/64", nozzle->name, testipv6_2);
#endif
#ifdef KNET_BSD
		 "ifconfig %s | grep -q %s", nozzle->name, testipv6_2);
#endif
	err = execute_bin_sh_command(verifycmd, &error_string);
	if (error_string) {
		printf("Error string: %s\n", error_string);
		free(error_string);
		error_string = NULL;
	}
	if (!err) {
		printf("Unable to verify IP address\n");
		err=-1;
		goto out_clean;
	}

	printf("Restoring MTU to default\n");
	if (nozzle_reset_mtu(nozzle) < 0) {
		printf("Unable to reset mtu\n");
		err = -1;
		goto out_clean;
	}

	memset(verifycmd, 0, sizeof(verifycmd));
	snprintf(verifycmd, sizeof(verifycmd)-1,
#ifdef KNET_LINUX
		 "ip addr show dev %s | grep -q %s/64", nozzle->name, testipv6_1);
#endif
#ifdef KNET_BSD
		 "ifconfig %s | grep -q %s", nozzle->name, testipv6_1);
#endif
	err = execute_bin_sh_command(verifycmd, &error_string);
	if (error_string) {
		printf("Error string: %s\n", error_string);
		free(error_string);
		error_string = NULL;
	}
	if (err) {
		printf("Unable to verify IP address\n");
		err=-1;
		goto out_clean;
	}

	memset(verifycmd, 0, sizeof(verifycmd));
	snprintf(verifycmd, sizeof(verifycmd)-1,
#ifdef KNET_LINUX
		 "ip addr show dev %s | grep -q %s/64", nozzle->name, testipv6_2);
#endif
#ifdef KNET_BSD
		 "ifconfig %s | grep -q %s", nozzle->name, testipv6_2);
#endif
	err = execute_bin_sh_command(verifycmd, &error_string);
	if (error_string) {
		printf("Error string: %s\n", error_string);
		free(error_string);
		error_string = NULL;
	}
	if (err) {
		printf("Unable to verify IP address\n");
		err=-1;
		goto out_clean;
	}

out_clean:
	if (nozzle) {
		nozzle_close(nozzle);
	}

	return err;
}

static int check_knet_mac(void)
{
	char device_name[IFNAMSIZ];
	size_t size = IFNAMSIZ;
	int err=0;
	nozzle_t nozzle;
	char *current_mac = NULL, *temp_mac = NULL, *err_mac = NULL;
	struct ether_addr *cur_mac, *tmp_mac;

	printf("Testing get/set MAC\n");

	memset(device_name, 0, size);
	nozzle = nozzle_open(device_name, size, NULL);
	if (!nozzle) {
		printf("Unable to init %s\n", device_name);
		return -1;
	}

	printf("Get current MAC\n");

	if (nozzle_get_mac(nozzle, &current_mac) < 0) {
		printf("Unable to get current MAC address.\n");
		err = -1;
		goto out_clean;
	}

	printf("Current MAC: %s\n", current_mac);

	printf("Setting MAC: 00:01:01:01:01:01\n");

	if (nozzle_set_mac(nozzle, "00:01:01:01:01:01") < 0) {
		printf("Unable to set current MAC address.\n");
		err = -1;
		goto out_clean;
	}

	if (nozzle_get_mac(nozzle, &temp_mac) < 0) {
		printf("Unable to get current MAC address.\n");
		err = -1;
		goto out_clean;
	}

	printf("Current MAC: %s\n", temp_mac);

	cur_mac = ether_aton(current_mac);
	tmp_mac = ether_aton(temp_mac);

	printf("Comparing MAC addresses\n");
	if (memcmp(cur_mac, tmp_mac, sizeof(struct ether_addr))) {
		printf("Mac addresses are not the same?!\n");
		err = -1;
		goto out_clean;
	}

	printf("Testing ERROR conditions\n");

	printf("Pass NULL to get_mac (pass1)\n");
	errno = 0;
	if ((nozzle_get_mac(NULL, &err_mac) >= 0) || (errno != EINVAL)) {
		printf("Something is wrong in nozzle_get_mac sanity checks\n");
		err = -1;
		goto out_clean;
	}

	printf("Pass NULL to get_mac (pass2)\n");
	errno = 0;
	if ((nozzle_get_mac(nozzle, NULL) >= 0) || (errno != EINVAL)) {
		printf("Something is wrong in nozzle_get_mac sanity checks\n");
		err = -1;
		goto out_clean;
	}

	printf("Pass NULL to set_mac (pass1)\n");
	errno = 0;
	if ((nozzle_set_mac(nozzle, NULL) >= 0) || (errno != EINVAL)) {
		printf("Something is wrong in nozzle_set_mac sanity checks\n");
		err = -1;
		goto out_clean;
	}

	printf("Pass NULL to set_mac (pass2)\n");
	errno = 0;
	if ((nozzle_set_mac(NULL, err_mac) >= 0) || (errno != EINVAL)) {
		printf("Something is wrong in nozzle_set_mac sanity checks\n");
		err = -1;
		goto out_clean;
	}

out_clean:
	if (err_mac) {
		printf("Something managed to set err_mac!\n");
		err = -1;
		free(err_mac);
	}

	if (current_mac)
		free(current_mac);
	if (temp_mac)
		free(temp_mac);

	if (nozzle) {
		nozzle_close(nozzle);
	}

	return err;
}

static int check_nozzle_execute_bin_sh_command(void)
{
	int err = 0;
	char command[4096];
	char *error_string = NULL;

	memset(command, 0, sizeof(command));

	printf("Testing execute_bin_sh_command\n");

	printf("command true\n");

	err = execute_bin_sh_command("true", &error_string);
	if (error_string) {
		printf("Error string: %s\n", error_string);
		free(error_string);
		error_string = NULL;
	}
	if (err) {
		printf("Unable to execute true ?!?!\n");
		goto out_clean;
	}

	printf("Testing ERROR conditions\n");

	printf("command false\n");

	err = execute_bin_sh_command("false", &error_string);
	if (error_string) {
		printf("Error string: %s\n", error_string);
		free(error_string);
		error_string = NULL;
	}
	if (!err) {
		printf("Can we really execute false successfully?!?!\n");
		err = -1;
		goto out_clean;
	}

	printf("command that outputs to stdout (enforcing redirect)\n");

	err = execute_bin_sh_command("grep -h 2>&1", &error_string);
	if (error_string) {
		printf("Error string: %s\n", error_string);
		free(error_string);
		error_string = NULL;
	}
	if (!err) {
		printf("Can we really execute grep -h successfully?!?\n");
		err = -1;
		goto out_clean;
	}

	printf("command that outputs to stderr\n");
	err = execute_bin_sh_command("grep -h", &error_string);
	if (error_string) {
		printf("Error string: %s\n", error_string);
		free(error_string);
		error_string = NULL;
	}
	if (!err) {
		printf("Can we really execute grep -h successfully?!?\n");
		err = -1;
		goto out_clean;
	}

	printf("empty command\n");
	err = execute_bin_sh_command(NULL, &error_string);
	if (error_string) {
		printf("Error string: %s\n", error_string);
		free(error_string);
		error_string = NULL;
	}
	if (!err) {
		printf("Can we really execute (nil) successfully?!?!\n");
		err = -1;
		goto out_clean;
	}

	printf("empty error\n");
	err = execute_bin_sh_command("true", NULL);
	if (!err) {
		printf("Check EINVAL filter for no error_string!\n");
		err = -1;
		goto out_clean;
	}

	err = 0;

out_clean:

	return err;
}

static int check_knet_up_down(void)
{
	char verifycmd[1024];
	char device_name[IFNAMSIZ];
	size_t size = IFNAMSIZ;
	int err=0;
	nozzle_t nozzle;
	char *error_string = NULL;

	printf("Testing interface up/down\n");

	memset(device_name, 0, size);
	nozzle = nozzle_open(device_name, size, NULL);
	if (!nozzle) {
		printf("Unable to init %s\n", device_name);
		return -1;
	}

	printf("Put the interface up\n");

	err = nozzle_set_up(nozzle);
	if (err < 0) {
		printf("Unable to set interface up\n");
		err = -1;
		goto out_clean;
	}

	memset(verifycmd, 0, sizeof(verifycmd));
	snprintf(verifycmd, sizeof(verifycmd)-1,
#ifdef KNET_LINUX
		 "ip addr show dev %s | grep -q UP", nozzle->name);
#endif
#ifdef KNET_BSD
		 "ifconfig %s | grep -q UP", nozzle->name);
#endif
	err = execute_bin_sh_command(verifycmd, &error_string);
	if (error_string) {
		printf("Error string: %s\n", error_string);
		free(error_string);
		error_string = NULL;
	}
	if (err < 0) {
		printf("Unable to verify inteface UP\n");
		err = -1;
		goto out_clean;
	}

	printf("Put the interface down\n");

	err = nozzle_set_down(nozzle);
	if (err < 0) {
		printf("Unable to put the interface down\n");
		err = -1;
		goto out_clean;
	}

	memset(verifycmd, 0, sizeof(verifycmd));
	snprintf(verifycmd, sizeof(verifycmd)-1,
#ifdef KNET_LINUX
		 "ip addr show dev %s | grep -q UP", nozzle->name);
#endif
#ifdef KNET_BSD
		 "ifconfig %s | grep -q UP", nozzle->name);
#endif
	err = execute_bin_sh_command(verifycmd, &error_string);
	if (error_string) {
		printf("Error string: %s\n", error_string);
		free(error_string);
		error_string = NULL;
	}
	if (!err) {
		printf("Unable to verify inteface DOWN\n");
		err = -1;
		goto out_clean;
	}

	nozzle_close(nozzle);

	printf("Testing interface pre-up/up/down/post-down (exec errors)\n");

	memset(device_name, 0, size);
	nozzle = nozzle_open(device_name, size, ABSBUILDDIR "/nozzle_updown_bad");
	if (!nozzle) {
		printf("Unable to init %s\n", device_name);
		return -1;
	}

	printf("Put the interface up\n");

	err = nozzle_run_updown(nozzle, NOZZLE_PREUP, &error_string);
	if (err) {
		printf("nozzle_run_updown NOZZLE_PREUP error: %s\n", strerror(errno));
	}
	if (error_string) {
		printf("preup output: %s\n", error_string);
		free(error_string);
		error_string = NULL;
	}
	err = nozzle_set_up(nozzle);
	if (err < 0) {
		printf("Unable to put the interface up\n");
		err = -1;
		goto out_clean;
	}
	err = nozzle_run_updown(nozzle, NOZZLE_UP, &error_string);
	if (err) {
		printf("nozzle_run_updown NOZZLE_UP error: %s\n", strerror(errno));
	}
	if (error_string) {
		printf("up output: %s\n", error_string);
		free(error_string);
		error_string = NULL;
	}

	printf("Put the interface down\n");

	err = nozzle_run_updown(nozzle, NOZZLE_DOWN, &error_string);
	if (err) {
		printf("nozzle_run_updown NOZZLE_DOWN error: %s\n", strerror(errno));
	}
	if (error_string) {
		printf("down output: %s\n", error_string);
		free(error_string);
		error_string = NULL;
	}
	err = nozzle_set_down(nozzle);
	if (err < 0) {
		printf("Unable to put the interface down\n");
		err = -1;
		goto out_clean;
	}
	err = nozzle_run_updown(nozzle, NOZZLE_POSTDOWN, &error_string);
	if (err) {
		printf("nozzle_run_updown NOZZLE_POSTDOWN error: %s\n", strerror(errno));
	}
	if (error_string) {
		printf("postdown output: %s\n", error_string);
		free(error_string);
		error_string = NULL;
	}

	nozzle_close(nozzle);

	printf("Testing interface pre-up/up/down/post-down\n");

	memset(device_name, 0, size);

	nozzle = nozzle_open(device_name, size, ABSBUILDDIR "/nozzle_updown_good");
	if (!nozzle) {
		printf("Unable to init %s\n", device_name);
		return -1;
	}

	printf("Put the interface up\n");

	err = nozzle_run_updown(nozzle, NOZZLE_PREUP, &error_string);
	if (err) {
		printf("nozzle_run_updown NOZZLE_PREUP error: %s\n", strerror(errno));
	}
	if (error_string) {
		printf("preup output: %s\n", error_string);
		free(error_string);
		error_string = NULL;
	}
	err = nozzle_set_up(nozzle);
	if (err < 0) {
		printf("Unable to put the interface up\n");
		err = -1;
		goto out_clean;
	}
	err = nozzle_run_updown(nozzle, NOZZLE_UP, &error_string);
	if (err) {
		printf("nozzle_run_updown NOZZLE_UP error: %s\n", strerror(errno));
	}
	if (error_string) {
		printf("up output: %s\n", error_string);
		free(error_string);
		error_string = NULL;
	}

	printf("Put the interface down\n");

	err = nozzle_run_updown(nozzle, NOZZLE_DOWN, &error_string);
	if (err) {
		printf("nozzle_run_updown NOZZLE_DOWN error: %s\n", strerror(errno));
	}
	if (error_string) {
		printf("down output: %s\n", error_string);
		free(error_string);
		error_string = NULL;
	}
	err = nozzle_set_down(nozzle);
	if (err < 0) {
		printf("Unable to put the interface down\n");
		err = -1;
		goto out_clean;
	}
	err = nozzle_run_updown(nozzle, NOZZLE_POSTDOWN, &error_string);
	if (err) {
		printf("nozzle_run_updown NOZZLE_POSTDOWN error: %s\n", strerror(errno));
	}
	if (error_string) {
		printf("postdown output: %s\n", error_string);
		free(error_string);
		error_string = NULL;
	}

	nozzle_close(nozzle);

	printf("Test ERROR conditions\n");

	printf("Pass NULL to nozzle set_up\n");
	err = 0;
	errno = 0;
	if ((nozzle_set_up(NULL) >= 0) || (errno != EINVAL)) {
		printf("Something is wrong in nozzle_set_up sanity checks\n");
		err = -1;
		goto out_clean;
	}

	printf("Pass NULL to nozzle set_down\n");
	errno = 0;
	if ((nozzle_set_down(NULL) >= 0) || (errno != EINVAL)) {
		printf("Something is wrong in nozzle_set_down sanity checks\n");
		err = -1;
		goto out_clean;
	}

out_clean:
	nozzle_close(nozzle);

	return err;
}

static int check_knet_close_leak(void)
{
	char device_name[IFNAMSIZ];
	size_t size = IFNAMSIZ;
	int err=0;
	nozzle_t nozzle;

	printf("Testing close leak (needs valgrind)\n");

	memset(device_name, 0, size);

	nozzle = nozzle_open(device_name, size, NULL);
	if (!nozzle) {
		printf("Unable to init %s\n", device_name);
		return -1;
	}

	printf("Adding ip: %s/24\n", testipv4_1);

	err = nozzle_add_ip(nozzle, testipv4_1, "24");
	if (err < 0) {
		printf("Unable to assign IP address\n");
		err=-1;
		goto out_clean;
	}

	printf("Adding ip: %s/24\n", testipv4_2);

	err = nozzle_add_ip(nozzle, testipv4_2, "24");
	if (err < 0) {
		printf("Unable to assign IP address\n");
		err=-1;
		goto out_clean;
	}

out_clean:
	nozzle_close(nozzle);

	return err;
}

static int check_knet_set_del_ip(void)
{
	char device_name[IFNAMSIZ];
	size_t size = IFNAMSIZ;
	char verifycmd[1024];
	int err=0;
	nozzle_t nozzle;
	char *ip_list = NULL;
	int ip_list_entries = 0, i, offset = 0;
	char *error_string = NULL;

	printf("Testing interface add/remove ip\n");

	memset(device_name, 0, size);

	nozzle = nozzle_open(device_name, size, NULL);
	if (!nozzle) {
		printf("Unable to init %s\n", device_name);
		return -1;
	}

	printf("Adding ip: %s/24\n", testipv4_1);

	err = nozzle_add_ip(nozzle, testipv4_1, "24");
	if (err < 0) {
		printf("Unable to assign IP address\n");
		err=-1;
		goto out_clean;
	}

	printf("Adding ip: %s/24\n", testipv4_2);

	err = nozzle_add_ip(nozzle, testipv4_2, "24");
	if (err < 0) {
		printf("Unable to assign IP address\n");
		err=-1;
		goto out_clean;
	}

	printf("Adding duplicate ip: %s/24\n", testipv4_1);

	err = nozzle_add_ip(nozzle, testipv4_1, "24");
	if (err < 0) {
		printf("Unable to find IP address in libnozzle db\n");
		err=-1;
		goto out_clean;
	}

	printf("Checking ip: %s/24\n", testipv4_1);

	memset(verifycmd, 0, sizeof(verifycmd));
	snprintf(verifycmd, sizeof(verifycmd)-1,
#ifdef KNET_LINUX
		 "ip addr show dev %s | grep -q %s/24", nozzle->name, testipv4_1);
#endif
#ifdef KNET_BSD
		 "ifconfig %s | grep -q %s", nozzle->name, testipv4_1);
#endif
	err = execute_bin_sh_command(verifycmd, &error_string);
	if (error_string) {
		printf("Error string: %s\n", error_string);
		free(error_string);
		error_string = NULL;
	}
	if (err) {
		printf("Unable to verify IP address\n");
		err=-1;
		goto out_clean;
	}

	printf("Get ip list from libnozzle:\n");

	if (nozzle_get_ips(nozzle, &ip_list, &ip_list_entries) < 0) {
		printf("Not enough mem?\n");
		err=-1;
		goto out_clean;
	}

	if (ip_list_entries != 2) {
		printf("Didn't get enough ip back from libnozzle?\n");
		err=-1;
		goto out_clean;
	}

	for (i = 1; i <= ip_list_entries; i++) {
		printf("Found IP %s %s in libnozzle db\n", ip_list + offset, ip_list + offset + strlen(ip_list + offset) + 1);
		offset = offset + strlen(ip_list) + 1;
		offset = offset + strlen(ip_list + offset) + 1;
	}

	free(ip_list);

	printf("Deleting ip: %s/24\n", testipv4_1);

	err = nozzle_del_ip(nozzle, testipv4_1, "24");
	if (err < 0) {
		printf("Unable to delete IP address\n");
		err=-1;
		goto out_clean;
	}

	printf("Deleting ip: %s/24\n", testipv4_2);

	err = nozzle_del_ip(nozzle, testipv4_2, "24");
	if (err < 0) {
		printf("Unable to delete IP address\n");
		err=-1;
		goto out_clean;
	}

	printf("Deleting again ip: %s/24\n", testipv4_1);

	err = nozzle_del_ip(nozzle, testipv4_1, "24");
	if (err < 0) {
		printf("Unable to delete IP address\n");
		err=-1;
		goto out_clean;
	}

	memset(verifycmd, 0, sizeof(verifycmd));
	snprintf(verifycmd, sizeof(verifycmd)-1,
#ifdef KNET_LINUX
		 "ip addr show dev %s | grep -q %s/24", nozzle->name, testipv4_1);
#endif
#ifdef KNET_BSD
		 "ifconfig %s | grep -q %s", nozzle->name, testipv4_1);
#endif
	err = execute_bin_sh_command(verifycmd, &error_string);
	if (error_string) {
		printf("Error string: %s\n", error_string);
		free(error_string);
		error_string = NULL;
	}
	if (!err) {
		printf("Unable to verify IP address\n");
		err=-1;
		goto out_clean;
	}

	printf("Adding ip: %s/64\n", testipv6_1);

	err = nozzle_add_ip(nozzle, testipv6_1, "64");
	if (err < 0) {
		printf("Unable to assign IP address\n");
		err=-1;
		goto out_clean;
	}

	memset(verifycmd, 0, sizeof(verifycmd));
	snprintf(verifycmd, sizeof(verifycmd)-1,
#ifdef KNET_LINUX
		 "ip addr show dev %s | grep -q %s/64", nozzle->name, testipv6_1);
#endif
#ifdef KNET_BSD
		 "ifconfig %s | grep -q %s", nozzle->name, testipv6_1);
#endif
	err = execute_bin_sh_command(verifycmd, &error_string);
	if (error_string) {
		printf("Error string: %s\n", error_string);
		free(error_string);
		error_string = NULL;
	}
	if (err) {
		printf("Unable to verify IP address\n");
		err=-1;
		goto out_clean;
	}

	printf("Deleting ip: %s/64\n", testipv6_1);

	err = nozzle_del_ip(nozzle, testipv6_1, "64");
	if (err) {
		printf("Unable to delete IP address\n");
		err=-1;
		goto out_clean;
	}

	memset(verifycmd, 0, sizeof(verifycmd));
	snprintf(verifycmd, sizeof(verifycmd)-1,
#ifdef KNET_LINUX
		 "ip addr show dev %s | grep -q %s/64", nozzle->name, testipv6_1);
#endif
#ifdef KNET_BSD
		 "ifconfig %s | grep -q %s", nozzle->name, testipv6_1);
#endif
	err = execute_bin_sh_command(verifycmd, &error_string);
	if (error_string) {
		printf("Error string: %s\n", error_string);
		free(error_string);
		error_string = NULL;
	}
	if (!err) {
		printf("Unable to verify IP address\n");
		err=-1;
		goto out_clean;
	}

out_clean:
	nozzle_close(nozzle);

	return err;
}

static void make_local_ips(void)
{
	pid_t mypid;
	uint8_t *pid;
	uint8_t i;

	if (sizeof(pid_t) < 4) {
		printf("pid_t is smaller than 4 bytes?\n");
		exit(77);
	}

	memset(testipv4_1, 0, sizeof(testipv4_1));
	memset(testipv4_2, 0, sizeof(testipv4_2));
	memset(testipv6_1, 0, sizeof(testipv6_1));
	memset(testipv6_2, 0, sizeof(testipv6_2));

	mypid = getpid();
	pid = (uint8_t *)&mypid;

	for (i = 0; i < sizeof(pid_t); i++) {
		if (pid[i] == 0) {
			pid[i] = 128;
		}
	}

	randombyte = pid[1];

	snprintf(testipv4_1,
		 sizeof(testipv4_1) - 1,
		 "127.%u.%u.%u",
		 pid[1],
		 pid[2],
		 pid[0]);

	snprintf(testipv4_2,
		 sizeof(testipv4_2) - 1,
		 "127.%u.%d.%u",
		 pid[1],
		 pid[2]+1,
		 pid[0]);

	snprintf(testipv6_1,
		 sizeof(testipv6_1) - 1,
		 "fd%x:%x%x::1",
		 pid[1],
		 pid[2],
		 pid[0]);

	snprintf(testipv6_2,
		 sizeof(testipv6_2) - 1,
		 "fd%x:%x%x:1::1",
		 pid[1],
		 pid[2],
		 pid[0]);
}

int main(void)
{
	if (geteuid() != 0) {
		printf("This test requires root privileges\n");
		exit(77);
	}

	make_local_ips();

	if (check_nozzle_open_close() < 0)
		return -1;

	if (check_knet_multi_eth() < 0)
		return -1;

	if (check_knet_mtu() < 0)
		return -1;

	if (check_knet_mtu_ipv6() < 0)
		return -1;

	if (check_knet_mac() < 0)
		return -1;

	if (check_nozzle_execute_bin_sh_command() < 0)
		return -1;

	if (check_knet_up_down() < 0)
		return -1;

	if (check_knet_set_del_ip() < 0)
		return -1;

	if (check_knet_close_leak() < 0)
		return -1;

	return 0;
}
