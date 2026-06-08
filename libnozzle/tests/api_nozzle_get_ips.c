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
	int err = 0;
	nozzle_t nozzle = NULL;
	struct nozzle_ip *ip_list = NULL, *ip_list_tmp = NULL;
	int ip_list_entries = 0, ipv4_list_entries = 0, ipv6_list_entries = 0;

	printf("Testing get ips\n");

	memset(device_name, 0, size);

	printf("Creating nozzle interface\n");
	FAIL_ON_NULL(nozzle, nozzle_open(device_name, size, NULL));

	printf("Testing error conditions\n");

	printf("Testing invalid nozzle handle\n");
	FAIL_ON_SUCCESS(nozzle_get_ips(NULL, &ip_list), EINVAL);

	printf("Testing NULL ip list pointer\n");
	FAIL_ON_SUCCESS(nozzle_get_ips(nozzle, NULL), EINVAL);

	printf("Adding ip: %s/24\n", testipv4_1);
	FAIL_ON_ERR(nozzle_add_ip(nozzle, testipv4_1, "24"));

	printf("Adding ip: %s/24\n", testipv4_2);
	FAIL_ON_ERR(nozzle_add_ip(nozzle, testipv4_2, "24"));

	printf("Adding ip: %s/64\n", testipv6_1);
	FAIL_ON_ERR(nozzle_add_ip(nozzle, testipv6_1, "64"));

	printf("Adding ip: %s/64\n", testipv6_2);
	FAIL_ON_ERR(nozzle_add_ip(nozzle, testipv6_2, "64"));

	printf("Get ip list from libnozzle:\n");
	FAIL_ON_ERR(nozzle_get_ips(nozzle, &ip_list));

	ip_list_tmp = ip_list;
	ip_list_entries = 0;

	while(ip_list_tmp) {
		ip_list_entries++;
		if (ip_list_tmp->domain == AF_INET) {
			ipv4_list_entries++;
		} else {
			ipv6_list_entries++;
		}
		printf("Found IP %s %s in libnozzle db\n", ip_list_tmp->ipaddr, ip_list_tmp->prefix);
		ip_list_tmp = ip_list_tmp->next;
	}

	if ((ip_list_entries != 4) ||
	    (ipv4_list_entries != 2) ||
	    (ipv6_list_entries != 2)) {
		printf("*** FAIL on line %d. Didn't get enough ip back from libnozzle?\n", __LINE__);
		err = -1;
		goto out_clean;
	}

	printf("Deleting ip: %s/24\n", testipv4_1);
	FAIL_ON_ERR(nozzle_del_ip(nozzle, testipv4_1, "24"));

	printf("Deleting ip: %s/24\n", testipv4_2);
	FAIL_ON_ERR(nozzle_del_ip(nozzle, testipv4_2, "24"));

	printf("Deleting ip: %s/64\n", testipv6_1);
	FAIL_ON_ERR(nozzle_del_ip(nozzle, testipv6_1, "64"));

	printf("Deleting ip: %s/64\n", testipv6_2);
	FAIL_ON_ERR(nozzle_del_ip(nozzle, testipv6_2, "64"));

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
