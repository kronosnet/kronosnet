/*
 * Copyright (C) 2018-2024 Red Hat, Inc.  All rights reserved.
 *
 * Author: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *
 * This software licensed under GPL-2.0+
 */

#include "config.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <limits.h>

#include "test-common.h"

char testipv4_1[IPBUFSIZE];
char testipv4_2[IPBUFSIZE];
char testipv6_1[IPBUFSIZE];
char testipv6_2[IPBUFSIZE];

static int test(void)
{
	char device_name[IFNAMSIZ];
	size_t size = IFNAMSIZ;
	int err=0;
	nozzle_t nozzle;

	int current_mtu = 0;
	int expected_mtu = 1500;

	printf("Testing set MTU\n");

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

	printf("Restoring MTU to default\n");
	expected_mtu = 1500;
	if (nozzle_reset_mtu(nozzle) < 0) {
		printf("Unable to reset mtu\n");
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

	printf("Passing empty struct to set_mtu\n");
	if (nozzle_set_mtu(NULL, 1500) == 0) {
		printf("Something is wrong in nozzle_set_mtu sanity checks\n");
		err = -1;
		goto out_clean;
	}

	printf("Passing 0 mtu to set_mtu\n");
	if (nozzle_set_mtu(nozzle, 0) == 0) {
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

static int test_ipv6(void)
{
	char device_name[IFNAMSIZ];
	size_t size = IFNAMSIZ;
	char verifycmd[2048];
	int err=0;
	nozzle_t nozzle;
	char *error_string = NULL;
	int current_mtu = 0;

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

	current_mtu = nozzle_get_mtu(nozzle);
	if (current_mtu != 1500) {
		printf("current mtu [%d] does not match expected value [1500]\n", current_mtu);
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

int main(void)
{
	need_root();
	need_tun();

	make_local_ips(testipv4_1, testipv4_2, testipv6_1, testipv6_2);

	if (test() < 0)
		return FAIL;

	if (test_ipv6() < 0)
		return FAIL;

	return PASS;
}
