/*
 * Copyright (C) 2018-2026 Red Hat, Inc.  All rights reserved.
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
	nozzle_t nozzle = NULL;

	int current_mtu = 0;
	int expected_mtu = 1500;

	printf("Testing set MTU\n");

	memset(device_name, 0, size);
	printf("Creating nozzle interface\n");
	FAIL_ON_NULL(nozzle, nozzle_open(device_name, size, NULL));

	printf("Comparing default MTU\n");
	current_mtu = nozzle_get_mtu(nozzle);
	FAIL_ON_NONZERO(current_mtu < 0, "Unable to get MTU");
	FAIL_ON_NONZERO(current_mtu != expected_mtu, "current mtu does not match expected default");

#ifdef KNET_SOLARIS
	// Solaris doesn't allow MTU > 1500
	expected_mtu = 900;
#else
	expected_mtu = 9000;
#endif
	printf("Setting MTU to %d\n", expected_mtu);
	FAIL_ON_ERR(nozzle_set_mtu(nozzle, expected_mtu));

	current_mtu = nozzle_get_mtu(nozzle);
	FAIL_ON_NONZERO(current_mtu < 0, "Unable to get MTU");
	FAIL_ON_NONZERO(current_mtu != expected_mtu, "current mtu does not match expected value");

	printf("Restoring MTU to default\n");
	expected_mtu = 1500;
	FAIL_ON_ERR(nozzle_reset_mtu(nozzle));

	current_mtu = nozzle_get_mtu(nozzle);
	FAIL_ON_NONZERO(current_mtu < 0, "Unable to get MTU");
	FAIL_ON_NONZERO(current_mtu != expected_mtu, "current mtu does not match expected value");

	printf("Testing ERROR conditions\n");

	printf("Testing NULL nozzle handle\n");
	FAIL_ON_SUCCESS(nozzle_set_mtu(NULL, 1500), EINVAL);

	printf("Testing 0 mtu\n");
	FAIL_ON_SUCCESS(nozzle_set_mtu(nozzle, 0), EINVAL);

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
	nozzle_t nozzle = NULL;
	char *error_string = NULL;
	int current_mtu = 0;

	printf("Testing get/set MTU with IPv6 address\n");

	memset(device_name, 0, size);

	printf("Creating nozzle interface\n");
	FAIL_ON_NULL(nozzle, nozzle_open(device_name, size, NULL));

	printf("Adding ip: %s/64\n", testipv6_1);
	FAIL_ON_ERR(nozzle_add_ip(nozzle, testipv6_1, "64"));

	memset(verifycmd, 0, sizeof(verifycmd));
	snprintf(verifycmd, sizeof(verifycmd)-1,
#ifdef KNET_LINUX
		 "ip addr show dev %s | grep -q %s/64", nozzle->name, testipv6_1);
#endif
#ifdef KNET_SOLARIS
		 "ifconfig %s:1 inet6| grep -q %s", nozzle->name, testipv6_1);
#endif
#ifdef KNET_BSD
		 "ifconfig %s | grep -q %s", nozzle->name, testipv6_1);
#endif
	FAIL_ON_CMD(err, execute_bin_sh_command(verifycmd, &error_string), error_string, "Unable to verify IP address");

	printf("Setting MTU to 1200\n");
	FAIL_ON_ERR(nozzle_set_mtu(nozzle, 1200));

	err = execute_bin_sh_command(verifycmd, &error_string);
	if (error_string) {
		printf("Error string: %s\n", error_string);
		free(error_string);
		error_string = NULL;
	}
#ifdef KNET_LINUX
	FAIL_ON_ZERO(err, "Unable to verify IP address");
#endif
#if defined(KNET_BSD) || defined(KNET_SOLARIS)
	FAIL_ON_NONZERO(err, "Unable to verify IP address");
#endif

	printf("Adding ip: %s/64\n", testipv6_2);
	FAIL_ON_ERR(nozzle_add_ip(nozzle, testipv6_2, "64"));

	memset(verifycmd, 0, sizeof(verifycmd));
	snprintf(verifycmd, sizeof(verifycmd)-1,
#ifdef KNET_LINUX
		 "ip addr show dev %s | grep -q %s/64", nozzle->name, testipv6_2);
#endif
#ifdef KNET_SOLARIS
		 "ifconfig %s:1 inet6| grep -q %s", nozzle->name, testipv6_2);
#endif
#ifdef KNET_BSD
		 "ifconfig %s | grep -q %s", nozzle->name, testipv6_2);
#endif
	FAIL_ON_CMD_SUCCESS(err, execute_bin_sh_command(verifycmd, &error_string), error_string, "Unable to verify IP address");

	printf("Restoring MTU to default\n");
	FAIL_ON_ERR(nozzle_reset_mtu(nozzle));

	current_mtu = nozzle_get_mtu(nozzle);
	FAIL_ON_NONZERO(current_mtu != 1500, "current mtu does not match expected value 1500");

	memset(verifycmd, 0, sizeof(verifycmd));
	snprintf(verifycmd, sizeof(verifycmd)-1,
#ifdef KNET_LINUX
		 "ip addr show dev %s | grep -q %s/64", nozzle->name, testipv6_1);
#endif
#ifdef KNET_SOLARIS
		 "ifconfig %s:1 inet6| grep -q %s", nozzle->name, testipv6_1);
#endif
#ifdef KNET_BSD
		 "ifconfig %s | grep -q %s", nozzle->name, testipv6_1);
#endif
	FAIL_ON_CMD(err, execute_bin_sh_command(verifycmd, &error_string), error_string, "Unable to verify IP address");

	memset(verifycmd, 0, sizeof(verifycmd));
	snprintf(verifycmd, sizeof(verifycmd)-1,
#ifdef KNET_LINUX
		 "ip addr show dev %s | grep -q %s/64", nozzle->name, testipv6_2);
#endif
#ifdef KNET_SOLARIS
		 "ifconfig %s:3 inet6| grep -q %s", nozzle->name, testipv6_2);
#endif
#ifdef KNET_BSD
		 "ifconfig %s | grep -q %s", nozzle->name, testipv6_2);
#endif
	FAIL_ON_CMD(err, execute_bin_sh_command(verifycmd, &error_string), error_string, "Unable to verify IP address");

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
