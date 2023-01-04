/*
 * Copyright (C) 2018-2023 Red Hat, Inc.  All rights reserved.
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
	nozzle_t nozzle;
	struct nozzle_ip *ip_list = NULL, *ip_list_tmp = NULL;
	int ip_list_entries = 0, ipv4_list_entries = 0, ipv6_list_entries = 0;

	printf("Testing get ips\n");

	memset(device_name, 0, size);

	nozzle = nozzle_open(device_name, size, NULL);
	if (!nozzle) {
		printf("Unable to init %s\n", device_name);
		return -1;
	}

	printf("Testing error conditions\n");

	printf("Testing invalid nozzle\n");
	err = nozzle_get_ips(NULL, &ip_list);
	if ((!err) || (errno != EINVAL)) {
		printf("nozzle_get_ips accepted invalid nozzle\n");
		err = -1;
		goto out_clean;
	}

	printf("Testing invalid ip list\n");
	err = nozzle_get_ips(nozzle, NULL);
	if ((!err) || (errno != EINVAL)) {
		printf("nozzle_get_ips accepted invalid ip list\n");
		err = -1;
		goto out_clean;
	}

	printf("Adding ip: %s/24\n", testipv4_1);

	err = nozzle_add_ip(nozzle, testipv4_1, "24");
	if (err < 0) {
		printf("Unable to assign IP address\n");
		err = -1;
		goto out_clean;
	}

	printf("Adding ip: %s/24\n", testipv4_2);

	err = nozzle_add_ip(nozzle, testipv4_2, "24");
	if (err < 0) {
		printf("Unable to assign IP address\n");
		err = -1;
		goto out_clean;
	}

	printf("Adding ip: %s/64\n", testipv6_1);

	err = nozzle_add_ip(nozzle, testipv6_1, "64");
	if (err < 0) {
		printf("Unable to assign IP address\n");
		err = -1;
		goto out_clean;
	}

	printf("Adding ip: %s/64\n", testipv6_2);

	err = nozzle_add_ip(nozzle, testipv6_2, "64");
	if (err < 0) {
		printf("Unable to assign IP address\n");
		err = -1;
		goto out_clean;
	}

	printf("Get ip list from libnozzle:\n");

	if (nozzle_get_ips(nozzle, &ip_list) < 0) {
		printf("Not enough mem?\n");
		err = -1;
		goto out_clean;
	}

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
		printf("Didn't get enough ip back from libnozzle?\n");
		err = -1;
		goto out_clean;
	}

	printf("Deleting ip: %s/24\n", testipv4_1);

	err = nozzle_del_ip(nozzle, testipv4_1, "24");
	if (err < 0) {
		printf("Unable to delete IP address\n");
		err = -1;
		goto out_clean;
	}

	printf("Deleting ip: %s/24\n", testipv4_2);

	err = nozzle_del_ip(nozzle, testipv4_2, "24");
	if (err < 0) {
		printf("Unable to delete IP address\n");
		err = -1;
		goto out_clean;
	}

	printf("Deleting ip: %s/64\n", testipv6_1);

	err = nozzle_del_ip(nozzle, testipv6_1, "64");
	if (err) {
		printf("Unable to delete IP address\n");
		err = -1;
		goto out_clean;
	}

	printf("Deleting ip: %s/64\n", testipv6_2);

	err = nozzle_del_ip(nozzle, testipv6_2, "64");
	if (err) {
		printf("Unable to delete IP address\n");
		err = -1;
		goto out_clean;
	}

out_clean:
	nozzle_close(nozzle);

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
