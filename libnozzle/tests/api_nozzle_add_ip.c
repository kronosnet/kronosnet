/*
 * Copyright (C) 2010-2026 Red Hat, Inc.  All rights reserved.
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
#include <sys/socket.h>

#include "test-common.h"

char testipv4_1[IPBUFSIZE];
char testipv4_2[IPBUFSIZE];
char testipv6_1[IPBUFSIZE];
char testipv6_2[IPBUFSIZE];

static int test(void)
{
	char device_name[IFNAMSIZ];
	size_t size = IFNAMSIZ;
	char verifycmd[2048];
	int err = 0;
	nozzle_t nozzle = NULL;
	char *error_string = NULL;

	printf("Testing interface add ip\n");

	memset(device_name, 0, size);

	printf("Creating nozzle interface\n");
	FAIL_ON_NULL(nozzle, nozzle_open(device_name, size, NULL));

	printf("Testing error conditions\n");

	printf("Testing invalid nozzle handle\n");
	FAIL_ON_SUCCESS(nozzle_add_ip(NULL, testipv4_1, "24"), EINVAL);

	printf("Testing NULL ip address\n");
	FAIL_ON_SUCCESS(nozzle_add_ip(nozzle, NULL, "24"), EINVAL);

	printf("Testing NULL netmask\n");
	FAIL_ON_SUCCESS(nozzle_add_ip(nozzle, testipv4_1, NULL), EINVAL);

	printf("Adding ip: %s/24\n", testipv4_1);
	FAIL_ON_ERR(nozzle_add_ip(nozzle, testipv4_1, "24"));

	printf("Adding ip: %s/24\n", testipv4_2);
	FAIL_ON_ERR(nozzle_add_ip(nozzle, testipv4_2, "24"));

	printf("Adding duplicate ip: %s/24\n", testipv4_1);
	FAIL_ON_ERR(nozzle_add_ip(nozzle, testipv4_1, "24"));

	printf("Checking ip: %s/24\n", testipv4_1);

	memset(verifycmd, 0, sizeof(verifycmd));
	snprintf(verifycmd, sizeof(verifycmd)-1,
#ifdef KNET_LINUX
		 "ip addr show dev %s | grep -q %s/24", nozzle->name, testipv4_1);
#endif
#ifdef KNET_BSD
		 "ifconfig %s | grep -q %s", nozzle->name, testipv4_1);
#endif
#ifdef KNET_SOLARIS
		 "ifconfig %s | grep -q %s", nozzle->name, testipv4_1);
#endif
	FAIL_ON_CMD(err, execute_bin_sh_command(verifycmd, &error_string), error_string, "Unable to verify IP address");

	printf("Checking ip: %s/24\n", testipv4_2);

	memset(verifycmd, 0, sizeof(verifycmd));
	snprintf(verifycmd, sizeof(verifycmd)-1,
#ifdef KNET_LINUX
		 "ip addr show dev %s | grep -q %s/24", nozzle->name, testipv4_2);
#endif
#ifdef KNET_BSD
		 "ifconfig %s | grep -q %s", nozzle->name, testipv4_2);
#endif
#ifdef KNET_SOLARIS
		 "ifconfig %s:1 | grep -q %s", nozzle->name, testipv4_2);
#endif
	FAIL_ON_CMD(err, execute_bin_sh_command(verifycmd, &error_string), error_string, "Unable to verify IP address");

	printf("Deleting ip: %s/24\n", testipv4_2);
	FAIL_ON_ERR(nozzle_del_ip(nozzle, testipv4_2, "24"));

	printf("Deleting ip: %s/24\n", testipv4_1);
	FAIL_ON_ERR(nozzle_del_ip(nozzle, testipv4_1, "24"));

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

	printf("Deleting ip: %s/64\n", testipv6_1);
	FAIL_ON_ERR(nozzle_del_ip(nozzle, testipv6_1, "64"));

	printf("Testing adding an IPv6 address with mtu < 1280 and restore\n");
	printf("Lowering interface MTU\n");
	FAIL_ON_ERR(nozzle_set_mtu(nozzle, 1200));

	printf("Adding ip: %s/64\n", testipv6_1);
	FAIL_ON_ERR(nozzle_add_ip(nozzle, testipv6_1, "64"));

	memset(verifycmd, 0, sizeof(verifycmd));
	snprintf(verifycmd, sizeof(verifycmd)-1,
#ifdef KNET_LINUX
		 "ip addr show dev %s | grep -q %s/64", nozzle->name, testipv6_1);
#endif
#if defined(KNET_BSD) || defined(KNET_SOLARIS)
		 "ifconfig %s | grep -q %s", nozzle->name, testipv6_1);
#endif
	FAIL_ON_CMD_SUCCESS(err, execute_bin_sh_command(verifycmd, &error_string), error_string, "Unable to verify IP address");

	printf("Resetting MTU\n");
	FAIL_ON_ERR(nozzle_reset_mtu(nozzle));

	memset(verifycmd, 0, sizeof(verifycmd));
	snprintf(verifycmd, sizeof(verifycmd)-1,
#ifdef KNET_LINUX
		 "ip addr show dev %s | grep -q %s/64", nozzle->name, testipv6_1);
#endif
#ifdef KNET_BSD
		 "ifconfig %s | grep -q %s", nozzle->name, testipv6_1);
#endif
#ifdef KNET_SOLARIS
		 "ifconfig %s:1 inet6 | grep -q %s", nozzle->name, testipv6_1);
#endif
	FAIL_ON_CMD(err, execute_bin_sh_command(verifycmd, &error_string), error_string, "Unable to verify IP address");

	printf("Deleting ip: %s/64\n", testipv6_1);
	FAIL_ON_ERR(nozzle_del_ip(nozzle, testipv6_1, "64"));

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

	return PASS;
}
